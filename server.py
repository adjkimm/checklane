#!/usr/bin/env python3
"""
Checklane M1 demo server. Stdlib only.

Serves the landing page + audit widget API locally:
  GET  /                        -> landing page
  GET  /static/<path>            -> static assets
  GET  /api/audit?domain=X       -> run live audit (score-only JSON + report_token)
  GET  /api/config               -> public config (report price display)
  GET  /api/report?session_id=X  -> full report after verified Stripe payment
  GET  /report?session_id=X       -> paid full report as print-ready HTML
                                     (Download PDF via the browser print dialog)
  POST /api/checkout             -> create Stripe Checkout Session {report_token}
  POST /api/stripe-webhook       -> Stripe webhook (signature-verified):
                                     checkout.session.completed = fulfill order
                                     (re-audit on cache miss, ledger, buyer receipt);
                                     charge.refunded / charge.dispute.created =
                                     mark purchase accordingly
  POST /api/message              -> visitor message (JSON body), emailed via Resend
  POST /api/lead                 -> capture lead (JSON body), returns lead_id
  POST /api/beta                 -> record beta waitlist opt-in {lead_id}
  GET  /lost-report              -> "lost your report?" page (email form)
  POST /api/resend-report        -> re-email receipt+report link for a buyer email
                                     (always returns ok; never reveals matches)
  GET  /terms /privacy /refund   -> legal pages (static/legal/*.html)

Fulfillment design (Gate A): the Stripe Checkout Session is the durable key.
verified_paid_report / fulfill_paid_session verify the session against the
Stripe API, and on cache miss re-run the audit from the session metadata so
a paid session can NEVER 410 — even across restarts/deploys. Purchases are
recorded to purchases.jsonl AND to stdout as rich "fulfillment" events
(Render log retention is the durable backup; the free tier's disk is
ephemeral). The webhook is the source of truth; the buyer also gets a
receipt email with a permanent /report?session_id=... link.

Local demo only. Leads are stored in data/*.jsonl on disk. Nothing is sent
anywhere — except an email notification to NOTIFY_EMAIL via Resend when a
lead or beta opt-in is captured (set RESEND_API_KEY to enable; failures
never block the signup).

2026-09-23: deployed to Render free tier per Principal approval (Option B,
decision packet P-11). Binds 0.0.0.0:$PORT when PORT is set; otherwise
localhost-only as before. Audit/lead/beta events are also logged as JSON
lines to stdout (PII-free) because the free tier's disk is ephemeral.

Run:  python3 server.py [port]      (default 8077)
"""

import hashlib
import hmac
import json
import os
import re
import threading
import time
import uuid
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import audit as audit_engine
import report_html

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(HERE, "static")
DATA_DIR = os.path.join(HERE, "data")
LEADS_FILE = os.path.join(DATA_DIR, "leads.jsonl")
BETA_FILE = os.path.join(DATA_DIR, "beta.jsonl")
AUDITS_FILE = os.path.join(DATA_DIR, "audits.jsonl")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
}


def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def append_jsonl(path, obj):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")


def log_event(kind, obj):
    """PII-free JSON event line to stdout. Backup demand-signal record:
    the free hosting tier's disk is ephemeral, stdout logs are not."""
    try:
        print(json.dumps({"event": kind, "ts": int(time.time()), **obj}),
              flush=True)
    except Exception:
        pass


NOTIFY_EMAIL = os.environ.get("NOTIFY_EMAIL", "adjkimm@gmail.com")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")

# --- Paid full reports (Stripe Checkout) ---------------------------------- #
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
# Webhook signing secret (Stripe dashboard -> Developers -> Webhooks ->
# "Signing secret" for the endpoint). Set as STRIPE_WEBHOOK_SECRET on the
# hosting service. Never the API secret key.
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
WEBHOOK_TOLERANCE_S = 5 * 60
REPORT_PRICE_CENTS = int(os.environ.get("REPORT_PRICE_CENTS", "900"))
REPORT_CURRENCY = os.environ.get("REPORT_CURRENCY", "usd")
BASE_URL = os.environ.get("BASE_URL", "https://getchecklane.com")
PURCHASES_FILE = os.path.join(DATA_DIR, "purchases.jsonl")

# Guarantee wording shown on the paywall's legal page and in buyer receipts
# (agreed with the site workstream; keep in sync with static/legal/refund.html).
RECEIPT_GUARANTEE = (
    "Love it or your money back — full refund within 7 days, no questions asked. "
    "And if your report ever fails to generate or you lose access, "
    "we'll re-run it for you or refund you — your choice. "
    "Refunds go back to your card, typically within 5–10 business days."
)

# --- Rate limiting (H5): per-IP token buckets ---------------------------- #
# In-memory is fine (single Render instance). Buckets: (key, ip) -> [tokens, last].
_RATE_LOCK = threading.Lock()
_RATE_BUCKETS = {}


def _client_ip(handler):
    fwd = handler.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    try:
        return handler.client_address[0]
    except Exception:
        return "unknown"


def _rate_limit_ok(ip, key="api", per_minute=10.0, burst=20):
    """Per-IP token bucket. Returns (ok, retry_after_seconds)."""
    now = time.time()
    refill = per_minute / 60.0
    with _RATE_LOCK:
        tokens, last = _RATE_BUCKETS.get((key, ip), (float(burst), now))
        tokens = min(float(burst), tokens + (now - last) * refill)
        if tokens < 1.0:
            _RATE_BUCKETS[(key, ip)] = (tokens, now)
            retry_after = int((1.0 - tokens) / refill) + 1 if refill > 0 else 60
            return False, max(1, retry_after)
        _RATE_BUCKETS[(key, ip)] = (tokens - 1.0, now)
        return True, 0


# --- Audit concurrency cap (H5): max 2 concurrent audits ------------------ #
# A 429 with Retry-After beats an exhausted free tier.
AUDIT_SEM = threading.Semaphore(2)
AUDIT_BUSY_RETRY_AFTER = "30"

# In-memory cache: report_token -> (full report dict, timestamp).
# Lets /api/report serve the paid report without re-running the audit.
REPORT_CACHE = {}
REPORT_TTL_S = 2 * 3600


def price_display():
    if REPORT_PRICE_CENTS % 100 == 0:
        return "$%d" % (REPORT_PRICE_CENTS // 100)
    return "$%.2f" % (REPORT_PRICE_CENTS / 100)


def prune_report_cache():
    now = time.time()
    for token in [t for t, (_, ts) in REPORT_CACHE.items()
                  if now - ts > REPORT_TTL_S]:
        del REPORT_CACHE[token]


def stripe_api(method, path, params=None):
    """Minimal Stripe REST client (stdlib only). Raises on failure."""
    import urllib.request
    import urllib.parse
    if not STRIPE_SECRET_KEY:
        raise RuntimeError("STRIPE_SECRET_KEY is not set")
    data = None
    headers = {"Authorization": "Bearer " + STRIPE_SECRET_KEY}
    if params is not None:
        data = urllib.parse.urlencode(params).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request("https://api.stripe.com" + path, data=data,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:200]
        raise RuntimeError("stripe %s: %s" % (e.code, detail))


# session_ids already recorded as purchases (dedupe: /api/report and /report
# share verification; a customer may hit both).
_LOGGED_PURCHASES = set()
# session_ids that already got their buyer receipt email (webhook +
# browser-return paths must not double-send).
_RECEIPTED = set()


def verify_stripe_signature(payload, sig_header, secret):
    """Verify a Stripe webhook signature.

    payload: raw request bytes. sig_header: the Stripe-Signature header
    value ("t=...,v1=..."). secret: the endpoint's signing secret.
    Uses hmac.compare_digest; rejects stale timestamps (~5 min tolerance).
    """
    if not secret or not sig_header:
        return False
    t = None
    sigs = []
    for part in str(sig_header).split(","):
        k, _, v = part.strip().partition("=")
        if k == "t":
            try:
                t = int(v)
            except ValueError:
                return False
        elif k == "v1":
            sigs.append(v)
    if t is None or not sigs:
        return False
    if abs(time.time() - t) > WEBHOOK_TOLERANCE_S:
        return False
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    signed = ("%d." % t).encode("utf-8") + payload
    expected = hmac.new(secret.encode("utf-8"), signed,
                        hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, s) for s in sigs)


def _session_buyer_email(session):
    try:
        return (((session.get("customer_details") or {}).get("email")
                 or "").strip().lower())
    except Exception:
        return ""


def fulfill_paid_session(session, source="webhook"):
    """Idempotent fulfillment for a paid Checkout Session.

    Verifies against the Stripe session object passed in. On report-cache
    miss, re-runs the audit from the session metadata (the session is the
    durable key) — a paid session can never 410, even across restarts.
    Records the purchase (ledger + rich stdout event) and emails the buyer
    a receipt with a permanent report link, once per session_id.
    Returns (True, None, report_token) on success, (False, reason, None) when
    the report could not be produced yet (caller should return non-2xx so
    Stripe retries).
    """
    session_id = str(session.get("id", ""))
    if not session_id:
        return False, "missing session id", None
    meta = session.get("metadata") or {}
    token = str(meta.get("report_token", ""))
    entry = REPORT_CACHE.get(token) if token else None
    if entry is None:
        domain = str(meta.get("domain", ""))
        if not domain:
            return False, "no domain in session metadata", None
        try:
            prune_report_cache()
            report = audit_engine.audit(domain)
        except Exception as e:
            log_event("fulfillment_audit_failed", {
                "session_id": session_id, "domain": domain,
                "error": str(e)[:200]})
            return False, "audit failed", None
        if not token:
            token = uuid.uuid4().hex
        REPORT_CACHE[token] = (report, time.time())
        entry = REPORT_CACHE[token]
    report = entry[0]
    domain = report.get("domain") or str(meta.get("domain", ""))
    buyer_email = _session_buyer_email(session)
    amount_cents = session.get("amount_total")
    currency = session.get("currency")
    if session_id not in _LOGGED_PURCHASES:
        _LOGGED_PURCHASES.add(session_id)
        append_jsonl(PURCHASES_FILE, {
            "ts": int(time.time()),
            "session_id": session_id,
            "domain": domain,
            "score": report.get("score"),
            "amount_cents": amount_cents,
            "currency": currency,
            "buyer_email": buyer_email or None,
            "report_token": token,
            "fulfilled_via": source,
        })
        # Rich stdout event: Render log retention is the durable backup of
        # the purchase ledger (the free tier's disk is ephemeral).
        log_event("fulfillment", {
            "session_id": session_id,
            "domain": domain,
            "score": report.get("score"),
            "amount_cents": amount_cents,
            "currency": currency,
            "buyer_email": buyer_email or None,
            "via": source,
        })
    if buyer_email and session_id not in _RECEIPTED:
        _RECEIPTED.add(session_id)
        send_buyer_receipt(buyer_email, session_id, domain,
                           amount_cents, currency)
    return True, None, token


def mark_charge_event(etype, charge):
    """Record a refund or dispute on the purchase ledger + stdout."""
    kind = "refund" if etype == "charge.refunded" else "dispute"
    row = {
        "ts": int(time.time()),
        "type": kind,
        "charge_id": charge.get("id"),
        "payment_intent": charge.get("payment_intent"),
        "amount_cents": charge.get("amount"),
        "currency": charge.get("currency"),
        "dispute_reason": ((charge.get("dispute") or {}).get("reason")
                           if kind == "dispute" else None),
        # Correlate back to the original purchase via payment_intent in the
        # Stripe dashboard; the charge object carries no session id.
    }
    append_jsonl(PURCHASES_FILE, row)
    log_event("purchase_" + kind, {
        "charge_id": row["charge_id"],
        "payment_intent": row["payment_intent"],
        "amount_cents": row["amount_cents"],
        "currency": row["currency"],
        "dispute_reason": row["dispute_reason"],
    })


def verified_paid_report(session_id):
    """Verify a Stripe Checkout session and return the full report.

    Returns (report_dict, None) on success, or (None, (http_code, err_dict)).
    Records the purchase once per session_id. A paid session never 410s:
    on report-cache miss the audit is re-run from the session metadata
    (the Stripe session is the durable key), so a restart between payment
    and report fetch still delivers. Only an unverifiable session 410s.
    """
    if not session_id.startswith("cs_"):
        return None, (400, {"error": "invalid checkout session"})
    try:
        session = stripe_api("GET", "/v1/checkout/sessions/" + session_id)
    except Exception:
        return None, (502, {"error": "couldn't verify payment"})
    if session.get("payment_status") != "paid":
        return None, (402, {"error": "payment not completed yet"})
    ok, reason, token = fulfill_paid_session(session, source="browser_return")
    if not ok:
        return None, (410, {"error": "this report is unavailable right now — "
                                     "please try again in a minute"})
    entry = REPORT_CACHE.get(token) if token else None
    if entry is None:
        return None, (410, {"error": "this report is unavailable right now — "
                                     "please try again in a minute"})
    return entry[0], None


def _resend_email(to, subject, text):
    """Send one email via Resend. Best-effort: never raises.

    The email itself is the durable record — the free tier's disk is
    ephemeral. Returns True on apparent success, False otherwise.
    """
    if not RESEND_API_KEY:
        print(json.dumps({"event": "notify_skipped",
                          "ts": int(time.time()),
                          "reason": "no RESEND_API_KEY",
                          "subject": subject}), flush=True)
        return False
    try:
        import urllib.request
        payload = json.dumps({
            "from": "Checklane <notify@getchecklane.com>",
            "to": list(to),
            "subject": subject,
            "text": text,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.resend.com/emails", data=payload,
            headers={"Authorization": "Bearer " + RESEND_API_KEY,
                     "Content-Type": "application/json",
                     # api.resend.com sits behind Cloudflare, which 403s the
                     # default Python-urllib User-Agent before the request
                     # ever reaches Resend (looks like an auth failure).
                     "User-Agent": "Checklane/1.0 (https://getchecklane.com)"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
        print(json.dumps({"event": "notify_sent", "ts": int(time.time()),
                          "subject": subject}), flush=True)
        return True
    except Exception as e:
        print(json.dumps({"event": "notify_failed", "ts": int(time.time()),
                          "error": str(e)[:200],
                          "subject": subject}), flush=True)
        return False


def send_notification(subject, body):
    """Email the Principal about a lead/beta event via Resend.

    Best-effort: never raises, never blocks the signup. If RESEND_API_KEY
    is unset, the event is only logged to stdout.
    """
    _resend_email([NOTIFY_EMAIL], subject, body)


def _format_amount(amount_cents, currency):
    try:
        cents = int(amount_cents)
    except (TypeError, ValueError):
        return "—"
    cur = (currency or "usd").upper()
    if cur == "USD":
        return "$%.2f" % (cents / 100.0)
    return "%.2f %s" % (cents / 100.0, cur)


def send_buyer_receipt(email, session_id, domain, amount_cents, currency):
    """Email the BUYER their receipt + permanent report link.

    This is the durable delivery path: the report link never expires (the
    Stripe session is re-verified and the audit re-run on demand), so a
    closed tab or a lost bookmark is recoverable from this email or from
    /lost-report.
    """
    report_link = BASE_URL + "/report?session_id=" + session_id
    lost_link = BASE_URL + "/lost-report"
    subject = "Your Checklane report for %s" % (domain or "your store")
    body = (
        "Thanks for your purchase — your full Checklane report is ready.\n"
        "\n"
        "  Domain:  {domain}\n"
        "  Amount:  {amount}\n"
        "  Report:  {report_link}\n"
        "\n"
        "Your report link is permanent — bookmark it. If you ever lose it,\n"
        "enter your email at {lost_link} and we'll resend it.\n"
        "\n"
        "{guarantee}\n"
        "\n"
        "— Checklane\n"
    ).format(domain=domain or "your store",
             amount=_format_amount(amount_cents, currency),
             report_link=report_link,
             lost_link=lost_link,
             guarantee=RECEIPT_GUARANTEE)
    ok = _resend_email([email], subject, body)
    log_event("buyer_receipt", {"sent": ok,
                                "session_id": session_id,
                                "domain": domain})
    return ok


def notify_lead(lead):
    when = time.strftime("%Y-%m-%d %H:%M PT", time.localtime(lead["ts"]))
    body = (
        "New Checklane lead — {when}\n\n"
        "Name:     {name}\n"
        "Business: {business}\n"
        "Domain:   {domain}\n"
        "Email:    {email}\n"
        "Free-mail: {freemail} (doesn't count toward the M1 gate)\n"
        "Lead ID:  {id}\n"
    ).format(when=when, **lead)
    send_notification(
        "New Checklane lead: {business} ({domain})".format(**lead), body)


def notify_beta_signup(entry):
    when = time.strftime("%Y-%m-%d %H:%M PT", time.localtime(entry["ts"]))
    body = (
        "New Checklane beta waiting-list signup — {when}\n\n"
        "Name:  {name}\n"
        "Email: {email}\n"
    ).format(when=when, **entry)
    send_notification(
        "Checklane beta waiting list: {name}".format(**entry), body)


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    return rows


def email_domain(email):
    return email.rsplit("@", 1)[-1].lower() if "@" in email else ""


# "Lost your report?" page (M8). Inline HTML: an email form that POSTs to
# /api/resend-report. Always shows the same confirmation — it never reveals
# whether the email matched a purchase.
LOST_REPORT_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lost your Checklane report? — Checklane</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  background:#0f172a;color:#e2e8f0;margin:0;padding:2rem 1rem;line-height:1.6}
main{max-width:34rem;margin:4rem auto;background:#1e293b;border-radius:12px;
  padding:2rem;box-shadow:0 8px 32px rgba(0,0,0,.4)}
h1{margin-top:0;font-size:1.6rem}
p.dim{color:#94a3b8}
form{display:flex;gap:.5rem;margin:1.5rem 0;flex-wrap:wrap}
input[type=email]{flex:1;min-width:12rem;padding:.7rem .9rem;border-radius:8px;
  border:1px solid #475569;background:#0f172a;color:#e2e8f0;font-size:1rem}
button{padding:.7rem 1.2rem;border-radius:8px;border:0;background:#38bdf8;
  color:#082f49;font-weight:700;font-size:1rem;cursor:pointer}
button:disabled{opacity:.6;cursor:default}
#msg{margin:0;min-height:1.6em}
a{color:#38bdf8}
@media (max-width:640px){
body{padding:1rem .75rem}
main{margin:2rem auto;padding:1.5rem}
form{flex-direction:column}
input[type=email]{min-width:0;width:100%}
button{width:100%;min-height:44px}
}
</style>
</head>
<body>
<main>
<h1>Lost your report?</h1>
<p class="dim">Enter the email you used at checkout and we&rsquo;ll resend
your receipt with your report link.</p>
<form id="f">
<input type="email" id="email" name="email" required
  placeholder="you@yourbusiness.com" autocomplete="email">
<button type="submit" id="btn">Resend my report</button>
</form>
<p id="msg" role="status"></p>
<p class="dim"><a href="/">Back to Checklane</a></p>
</main>
<script>
document.getElementById("f").addEventListener("submit", function (ev) {
  ev.preventDefault();
  var btn = document.getElementById("btn");
  var msg = document.getElementById("msg");
  btn.disabled = true;
  msg.textContent = "Sending…";
  fetch("/api/resend-report", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({email: document.getElementById("email").value})
  }).then(function (r) { return r.json(); }).then(function () {
    msg.textContent = "If that email matches a purchase, your receipt with " +
      "a permanent report link is on its way. Please check your inbox " +
      "(and spam folder).";
  }).catch(function () {
    msg.textContent = "Something went wrong — please try again in a minute.";
  }).finally(function () { btn.disabled = false; });
});
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ChecklaneM1/1.0"

    # -- helpers -------------------------------------------------------- #
    def _send(self, code, body, ctype="application/json; charset=utf-8",
              extra_headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if ctype.startswith("text/html"):
            # H8: security headers on HTML responses (the payments page and
            # everything else that renders in a browser).
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "frame-ancestors 'self'")
            host = (self.headers.get("Host") or "").split(":")[0].lower()
            if host not in ("localhost", "127.0.0.1", ""):
                # HSTS only on real hosts — never on localhost, where it
                # would pin a non-TLS origin in the browser.
                self.send_header("Strict-Transport-Security",
                                 "max-age=31536000; includeSubDomains")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json; charset=utf-8")

    def _not_found(self):
        self._json(404, {"error": "not found"})

    def _read_body(self, limit=65536):
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > limit:
            return None
        return self.rfile.read(n)

    def log_message(self, fmt, *args):  # quieter logs
        pass

    # -- routing --------------------------------------------------------- #
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query or "")

        # Board condition 2: per-IP rate limit on GET /api/* too (the
        # concurrency cap alone lets one hostile IP hold both audit slots).
        if path.startswith("/api/"):
            ip = _client_ip(self)
            ok, retry = _rate_limit_ok(ip, key="api-get")
            if not ok:
                return self._send(
                    429, json.dumps({"error": "rate limit exceeded — "
                                              "please slow down"}),
                    "application/json; charset=utf-8",
                    {"Retry-After": str(retry)})
        if path == "/sitemap.xml":
            # Legal §5 blocker fix: the teaser draft claims we fixed the
            # missing sitemap — make it true.
            return self._serve_file("sitemap.xml",
                                    "application/xml; charset=utf-8")
        if path == "/":
            return self._serve_file("index.html")
        if path.startswith("/static/"):
            return self._serve_file(path[len("/static/"):])
        if path in ("/terms", "/privacy", "/refund"):
            # Legal pages (C6). The site workstream owns static/legal/*.html;
            # routes stay 404-safe until the files land.
            return self._serve_file("legal/" + path[1:] + ".html")
        if path == "/lost-report":
            # "Lost your report?" re-delivery page (M8): an email form that
            # POSTs to /api/resend-report. The response never reveals
            # whether the email matched a purchase.
            return self._send(200, LOST_REPORT_HTML, "text/html; charset=utf-8")
        if path == "/api/audit":
            domain = (qs.get("domain") or [""])[0]
            # H5: concurrency cap — a 429 with Retry-After beats an
            # exhausted free tier when audits hold threads up to ~130s.
            if not AUDIT_SEM.acquire(blocking=False):
                return self._send(
                    429, json.dumps({"error": "audit servers are busy — "
                                              "please retry in a minute"}),
                    "application/json; charset=utf-8",
                    {"Retry-After": AUDIT_BUSY_RETRY_AFTER})
            try:
                try:
                    report = audit_engine.audit(domain)
                except ValueError as e:
                    return self._json(400, {"error": "invalid domain: %s" % e})
                except Exception as e:
                    return self._json(500, {"error": "audit failed: %s" % e})
            finally:
                AUDIT_SEM.release()
            append_jsonl(AUDITS_FILE, {
                "ts": int(time.time()),
                "domain": report.get("domain"),
                "score": report.get("score"),
                "grade": report.get("grade"),
                "error": report.get("error"),
                "duration_s": report.get("duration_s"),
            })
            log_event("audit", {
                "domain": report.get("domain"),
                "score": report.get("score"),
                "grade": report.get("grade"),
            })
            # Free tier: score only. Full report is cached server-side and
            # served via /api/report after a verified Stripe payment.
            prune_report_cache()
            token = uuid.uuid4().hex
            REPORT_CACHE[token] = (report, time.time())
            return self._json(200, {
                "domain": report.get("domain"),
                "score": report.get("score"),
                "grade": report.get("grade"),
                "summary": report.get("summary"),
                "engine": report.get("engine"),
                "duration_s": report.get("duration_s"),
                "report_token": token,
            })
        if path == "/api/config":
            return self._json(200, {
                "price_cents": REPORT_PRICE_CENTS,
                "currency": REPORT_CURRENCY,
                "price_display": price_display(),
                "stripe_configured": bool(STRIPE_SECRET_KEY),
            })
        if path == "/api/report":
            # Paid full report (JSON). Verifies the Stripe Checkout Session
            # server-side, then serves the cached full audit.
            session_id = (qs.get("session_id") or [""])[0].strip()
            report, err = verified_paid_report(session_id)
            if err:
                code, obj = err
                return self._json(code, obj)
            return self._json(200, report)
        if path == "/report":
            # Paid full report as a print-ready HTML page. Same Stripe
            # verification as /api/report; the Download PDF button uses the
            # browser print dialog (Save as PDF). No new dependencies.
            session_id = (qs.get("session_id") or [""])[0].strip()
            report, err = verified_paid_report(session_id)
            if err:
                code, obj = err
                if code in (402, 410):
                    # Customer-facing states get a friendly page, not JSON.
                    return self._send(code, report_html.render_report(
                        {"domain": "", "score": 0, "grade": "F",
                         "error": obj["error"]}), "text/html; charset=utf-8")
                return self._json(code, obj)
            return self._send(200, report_html.render_report(report),
                              "text/html; charset=utf-8")
        return self._not_found()

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        raw = self._read_body()
        if raw is None:
            return self._json(400, {"error": "missing or oversized body"})

        if path == "/api/stripe-webhook":
            # Webhook needs the RAW body for HMAC signature verification —
            # handled before JSON parsing.
            return self._handle_stripe_webhook(raw)

        # H5: per-IP token bucket on all /api/* POST endpoints.
        ip = _client_ip(self)
        if path.startswith("/api/"):
            ok, retry = _rate_limit_ok(ip)
            if not ok:
                return self._send(
                    429, json.dumps({"error": "rate limit exceeded — "
                                              "please slow down"}),
                    "application/json; charset=utf-8",
                    {"Retry-After": str(retry)})
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return self._json(400, {"error": "body must be JSON"})

        if path == "/api/resend-report":
            # "Lost your report?" re-delivery (M8). Matches recent paid
            # checkout sessions by buyer email and re-emails the receipt
            # with the permanent report link. ALWAYS returns ok — never
            # reveals whether an email matched. Extra-strict rate limit.
            email = str(data.get("email", "")).strip().lower()
            ok, retry = _rate_limit_ok(ip, key="resend",
                                       per_minute=3.0, burst=3)
            if not ok:
                return self._send(
                    429, json.dumps({"error": "rate limit exceeded — "
                                              "please try again later"}),
                    "application/json; charset=utf-8",
                    {"Retry-After": str(retry)})
            if EMAIL_RE.match(email):
                try:
                    sessions = stripe_api("GET", "/v1/checkout/sessions",
                                          {"limit": "100"})
                    for s in sessions.get("data", []):
                        if s.get("payment_status") != "paid":
                            continue
                        if _session_buyer_email(s) != email:
                            continue
                        meta = s.get("metadata") or {}
                        domain = str(meta.get("domain", ""))
                        send_buyer_receipt(
                            email, s.get("id"), domain,
                            s.get("amount_total"), s.get("currency"))
                except Exception as e:
                    log_event("resend_failed", {"error": str(e)[:100]})
            return self._json(200, {"ok": True})

        if path == "/api/lead":
            name = str(data.get("name", "")).strip()
            business = str(data.get("business", "")).strip()
            domain = str(data.get("domain", "")).strip()
            email = str(data.get("email", "")).strip().lower()
            errors = {}
            if len(name) < 2:
                errors["name"] = "please enter your name"
            if len(business) < 2:
                errors["business"] = "please enter your business name"
            if not EMAIL_RE.match(email):
                errors["email"] = "please enter a valid email address"
            try:
                domain = audit_engine.normalize_domain(domain)
            except ValueError:
                errors["domain"] = "please enter a valid domain"
            if errors:
                return self._json(400, {"error": "invalid fields", "fields": errors})
            freemail = email_domain(email) in audit_engine.FREEMAIL_DOMAINS
            lead = {
                "id": uuid.uuid4().hex[:12],
                "ts": int(time.time()),
                "name": name, "business": business,
                "domain": domain, "email": email,
                "freemail": freemail,
            }
            append_jsonl(LEADS_FILE, lead)
            log_event("lead", {"id": lead["id"], "domain": domain,
                               "freemail": freemail})
            notify_lead(lead)
            return self._json(200, {
                "ok": True, "lead_id": lead["id"], "freemail": freemail,
                "note": ("Heads up: gate counting uses business-domain emails — "
                         "free-mail signups don't count as verifiable merchants.")
                        if freemail else None,
            })

        if path == "/api/beta":
            # Beta waiting list: direct name + email signup.
            name = str(data.get("name", "")).strip()
            email = str(data.get("email", "")).strip().lower()
            errors = {}
            if len(name) < 2:
                errors["name"] = "please enter your name"
            if not EMAIL_RE.match(email):
                errors["email"] = "please enter a valid email address"
            if errors:
                return self._json(400, {"error": "invalid fields", "fields": errors})
            entry = {"ts": int(time.time()), "name": name, "email": email,
                     "id": uuid.uuid4().hex[:12]}
            append_jsonl(BETA_FILE, entry)
            log_event("beta", {"id": entry["id"]})
            notify_beta_signup(entry)
            return self._json(200, {"ok": True})

        if path == "/api/message":
            name = str(data.get("name", "")).strip()
            email = str(data.get("email", "")).strip().lower()
            message = str(data.get("message", "")).strip()
            domain = str(data.get("domain", "")).strip()
            errors = {}
            if len(name) < 2:
                errors["name"] = "please enter your name"
            if not EMAIL_RE.match(email):
                errors["email"] = "please enter a valid email address"
            if len(message) < 10:
                errors["message"] = "please write a few words so we know how to help"
            if len(message) > 2000:
                errors["message"] = "please keep it under 2000 characters"
            if errors:
                return self._json(400, {"error": "invalid fields", "fields": errors})
            body = ("New Checklane message\n\n"
                    "Name:   {name}\n"
                    "Email:  {email}\n"
                    "Store:  {domain}\n\n"
                    "{message}\n").format(
                        name=name, email=email,
                        domain=domain or "(no store checked)", message=message)
            send_notification("Checklane message from %s" % name, body)
            log_event("message", {"domain": domain or None})
            return self._json(200, {"ok": True})

        if path == "/api/checkout":
            # Creates a Stripe Checkout Session for the full report.
            # The report_token links the paid session back to the cached audit.
            token = str(data.get("report_token", "")).strip()
            entry = REPORT_CACHE.get(token)
            if not entry:
                return self._json(400, {
                    "error": "report expired — please re-run the free audit"})
            domain = entry[0].get("domain") or "your store"
            try:
                session = stripe_api("POST", "/v1/checkout/sessions", {
                    "mode": "payment",
                    "success_url": BASE_URL + "/?paid=1&session_id={CHECKOUT_SESSION_ID}",
                    "cancel_url": BASE_URL + "/",
                    "line_items[0][price_data][currency]": REPORT_CURRENCY,
                    "line_items[0][price_data][product_data][name]":
                        "Checklane full report — " + domain,
                    "line_items[0][price_data][unit_amount]": str(REPORT_PRICE_CENTS),
                    "line_items[0][quantity]": "1",
                    # M10: statement descriptor — Stripe allows max 22 chars,
                    # uppercase, no special characters.
                    "payment_intent_data[statement_descriptor]": "CHECKLANE",
                    "metadata[report_token]": token,
                    "metadata[domain]": domain,
                })
            except Exception as e:
                return self._json(502, {
                    "error": "couldn't start checkout (%s)" % str(e)[:100]})
            log_event("checkout_created", {"domain": domain})
            return self._json(200, {"ok": True, "url": session.get("url")})

        return self._not_found()

    # -- stripe webhook -------------------------------------------------- #
    def _handle_stripe_webhook(self, raw):
        """POST /api/stripe-webhook — Stripe's source of truth for fulfillment.

        Requires STRIPE_WEBHOOK_SECRET (set from the Stripe dashboard on the
        hosting service). checkout.session.completed fulfills the order —
        ledger row, rich stdout event, buyer receipt email — and re-runs
        the audit on cache miss so a paid customer is never stranded.
        Returns 400 on bad signature, 200 on handled events, non-2xx only
        when fulfillment failed and Stripe should retry.
        """
        sig = self.headers.get("Stripe-Signature", "")
        if not verify_stripe_signature(raw, sig, STRIPE_WEBHOOK_SECRET):
            log_event("webhook_bad_signature", {})
            return self._json(400, {"error": "invalid webhook signature"})
        try:
            event = json.loads(raw.decode("utf-8"))
        except Exception:
            return self._json(400, {"error": "invalid payload"})
        etype = str(event.get("type", ""))
        obj = (event.get("data") or {}).get("object") or {}
        if etype == "checkout.session.completed":
            ok, reason, _token = fulfill_paid_session(obj, source="webhook")
            if not ok:
                log_event("webhook_fulfill_failed",
                          {"session_id": obj.get("id"), "reason": reason})
                return self._json(500, {"error": reason})
            return self._json(200, {"ok": True})
        if etype in ("charge.refunded", "charge.dispute.created"):
            mark_charge_event(etype, obj)
            return self._json(200, {"ok": True})
        return self._json(200, {"ok": True, "ignored": etype})

    # -- static ----------------------------------------------------------- #
    def _serve_file(self, rel, ctype=None):
        rel = rel.lstrip("/")
        if ".." in rel or rel.startswith("/"):
            return self._not_found()
        full = os.path.join(STATIC_DIR, rel)
        if not os.path.isfile(full):
            return self._not_found()
        if ctype is None:
            _, ext = os.path.splitext(full)
            ctype = CONTENT_TYPES.get(ext.lower(), "application/octet-stream")
        try:
            with open(full, "rb") as f:
                body = f.read()
        except OSError:
            return self._not_found()
        self._send(200, body, ctype)


def main():
    import sys
    ensure_data_dir()
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = int(os.environ.get("PORT", 8077))
    # Hosting platforms (Render, etc.) inject $PORT and require binding
    # all interfaces. Local runs stay localhost-only.
    host = "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1"
    srv = ThreadingHTTPServer((host, port), Handler)
    print("Checklane M1: http://%s:%d/  (Ctrl-C to stop)" % (host, port),
          flush=True)
    print("Data dir:", DATA_DIR, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
