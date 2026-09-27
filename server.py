#!/usr/bin/env python3
"""
Checklane M1 demo server. Stdlib only.

Serves the landing page + audit widget API locally:
  GET  /                        -> landing page
  GET  /static/<path>            -> static assets
  GET  /sample-report            -> anonymized sample audit (static JSON)
  GET  /api/audit?domain=X       -> run live audit (JSON report)
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
            "from": "Checklane <onboarding@resend.dev>",
            "to": [NOTIFY_EMAIL],
            "subject": subject,
            "text": body,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.resend.com/emails", data=payload,
            headers={"Authorization": "Bearer " + RESEND_API_KEY,
                     "Content-Type": "application/json"})
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


def notify_beta(lead):
    body = (
        "Beta waitlist opt-in for lead {id}:\n\n"
        "Name:     {name}\n"
        "Business: {business}\n"
        "Email:    {email}\n"
    ).format(**lead)
    send_notification(
        "Checklane beta opt-in: {business}".format(**lead), body)


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
            return self._json(200, report)
        if path == "/api/stats":
            audits = read_jsonl(AUDITS_FILE)
            leads = read_jsonl(LEADS_FILE)
            betas = read_jsonl(BETA_FILE)
            beta_ids = {b.get("lead_id") for b in betas}
            verifiable = [l for l in leads if not l.get("freemail")]
            return self._json(200, {
                "audits_run": len(audits),
                "leads": len(leads),
                "verifiable_leads": len(verifiable),
                "beta_optins": len(beta_ids),
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
            lead_id = str(data.get("lead_id", "")).strip()
            leads = {l.get("id"): l for l in read_jsonl(LEADS_FILE)}
            if not lead_id or lead_id not in leads:
                return self._json(400, {"error": "unknown lead_id"})
            append_jsonl(BETA_FILE, {"ts": int(time.time()), "lead_id": lead_id})
            log_event("beta", {"lead_id": lead_id})
            notify_beta(leads[lead_id])
            return self._json(200, {"ok": True})

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
