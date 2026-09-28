#!/usr/bin/env python3
"""
Checklane M1 demo server. Stdlib only.

Serves the landing page + audit widget API locally:
  GET  /                        -> landing page
  GET  /static/<path>            -> static assets
  GET  /sample-report            -> anonymized sample audit (static JSON)
  GET  /api/audit?domain=X       -> run live audit (score-only JSON + report_token)
  GET  /api/config               -> public config (report price display)
  GET  /api/report?session_id=X  -> full report after verified Stripe payment
  GET  /report?session_id=X       -> paid full report as print-ready HTML
                                     (Download PDF via the browser print dialog)
  POST /api/checkout             -> create Stripe Checkout Session {report_token}
  POST /api/message              -> visitor message (JSON body), emailed via Resend
  POST /api/lead                 -> capture lead (JSON body), returns lead_id
  POST /api/beta                 -> record beta waitlist opt-in {lead_id}
  GET  /api/stats                -> local counters (audits, leads, beta opt-ins)

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

import json
import os
import re
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
REPORT_PRICE_CENTS = int(os.environ.get("REPORT_PRICE_CENTS", "900"))
REPORT_CURRENCY = os.environ.get("REPORT_CURRENCY", "usd")
BASE_URL = os.environ.get("BASE_URL", "https://getchecklane.com")
PURCHASES_FILE = os.path.join(DATA_DIR, "purchases.jsonl")

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


def verified_paid_report(session_id):
    """Verify a Stripe Checkout session and return the cached full report.

    Returns (report_dict, None) on success, or (None, (http_code, err_dict)).
    Records the purchase once per session_id.
    """
    if not session_id.startswith("cs_"):
        return None, (400, {"error": "invalid checkout session"})
    try:
        session = stripe_api("GET", "/v1/checkout/sessions/" + session_id)
    except Exception:
        return None, (502, {"error": "couldn't verify payment"})
    if session.get("payment_status") != "paid":
        return None, (402, {"error": "payment not completed yet"})
    meta = session.get("metadata") or {}
    token = str(meta.get("report_token", ""))
    entry = REPORT_CACHE.get(token)
    if not entry:
        return None, (410, {
            "error": "this report expired — please re-run the free audit"})
    report = entry[0]
    if session_id not in _LOGGED_PURCHASES:
        _LOGGED_PURCHASES.add(session_id)
        append_jsonl(PURCHASES_FILE, {
            "ts": int(time.time()),
            "session_id": session_id,
            "domain": report.get("domain"),
            "score": report.get("score"),
            "amount_cents": session.get("amount_total"),
            "currency": session.get("currency"),
        })
        log_event("purchase", {"domain": report.get("domain"),
                               "score": report.get("score")})
    return report, None


def send_notification(subject, body):
    """Email the Principal about a lead/beta event via Resend.

    Best-effort: never raises, never blocks the signup. If RESEND_API_KEY
    is unset, the event is only logged to stdout. The email itself is the
    durable record — the free tier's disk is ephemeral.
    """
    if not RESEND_API_KEY:
        print(json.dumps({"event": "notify_skipped",
                          "ts": int(time.time()),
                          "reason": "no RESEND_API_KEY"}), flush=True)
        return
    try:
        import urllib.request
        payload = json.dumps({
            "from": "Checklane <notify@getchecklane.com>",
            "to": [NOTIFY_EMAIL],
            "subject": subject,
            "text": body,
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
    except Exception as e:
        print(json.dumps({"event": "notify_failed", "ts": int(time.time()),
                          "error": str(e)[:200]}), flush=True)


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


class Handler(BaseHTTPRequestHandler):
    server_version = "ChecklaneM1/1.0"

    # -- helpers -------------------------------------------------------- #
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
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

        if path == "/":
            return self._serve_file("index.html")
        if path == "/sample-report":
            return self._serve_file("sample-report.json",
                                    "application/json; charset=utf-8")
        if path.startswith("/static/"):
            return self._serve_file(path[len("/static/"):])
        if path == "/api/audit":
            domain = (qs.get("domain") or [""])[0]
            try:
                report = audit_engine.audit(domain)
            except ValueError as e:
                return self._json(400, {"error": "invalid domain: %s" % e})
            except Exception as e:
                return self._json(500, {"error": "audit failed: %s" % e})
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
        if path == "/api/stats":
            audits = read_jsonl(AUDITS_FILE)
            leads = read_jsonl(LEADS_FILE)
            betas = read_jsonl(BETA_FILE)
            purchases = read_jsonl(PURCHASES_FILE)
            verifiable = [l for l in leads if not l.get("freemail")]
            return self._json(200, {
                "audits_run": len(audits),
                "leads": len(leads),
                "verifiable_leads": len(verifiable),
                "beta_waitlist": len(betas),
                "purchases": len(purchases),
            })
        return self._not_found()

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        raw = self._read_body()
        if raw is None:
            return self._json(400, {"error": "missing or oversized body"})
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return self._json(400, {"error": "body must be JSON"})

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
                    "metadata[report_token]": token,
                    "metadata[domain]": domain,
                })
            except Exception as e:
                return self._json(502, {
                    "error": "couldn't start checkout (%s)" % str(e)[:100]})
            log_event("checkout_created", {"domain": domain})
            return self._json(200, {"ok": True, "url": session.get("url")})

        return self._not_found()

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
