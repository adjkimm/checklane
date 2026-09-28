#!/usr/bin/env python3
"""Regression tests for Checklane Stripe live-readiness (Workstream A).

Covers:
  1. Webhook HMAC signature verification (known-answer vector, tampering,
     stale/future timestamps, malformed headers).
  2. Idempotent, durable fulfillment (double delivery, restart simulation,
     concurrent redelivery).
  3. Idempotent refund/dispute charge events.
  4. Report TTL semantics in the durable store.
  5. Legacy purchases.jsonl migration.
  6. HTTP-level webhook handling (good/bad signature, unknown events).
  7. Checkout token fallback to the durable store after a restart.

Run: python3 tests/test_stripe_readiness.py
Stdlib only. No network except localhost. No real Stripe keys.
"""
import hashlib
import hmac
import http.client
import json
import os
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer

# Self-locating: test the modules shipped in this tree, not the cwd.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The webhook secret is read at server import time; use a test-only value.
os.environ["STRIPE_WEBHOOK_SECRET"] = "whsec_test_readiness_secret"
os.environ["STRIPE_SECRET_KEY"] = ""  # no Stripe API calls in these tests

import server
import store

PASS, FAIL = 0, 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok  %s" % name)
    else:
        FAIL += 1
        print("  FAIL %s %s" % (name, extra))


def fresh_store():
    """Point the store at a fresh temp DB; clear the in-memory cache."""
    tmp = tempfile.mkdtemp(prefix="checklane-store-test-")
    db = os.path.join(tmp, "checklane.db")
    store.close()
    store.configure(db)
    server.REPORT_CACHE.clear()
    return db


FAKE_REPORT = {"domain": "example.com", "score": 80, "grade": "B",
               "engine": "test", "summary": "test report"}


def make_session(sid="cs_test_1", token="tok-test-1",
                 email="buyer@example.com", pi="pi_test_1"):
    return {
        "id": sid,
        "payment_status": "paid",
        "payment_intent": pi,
        "amount_total": 900,
        "currency": "usd",
        "customer_details": {"email": email},
        "metadata": {"report_token": token, "domain": "example.com"},
    }


class Stubs:
    """Monkeypatch audit + receipt sending; restore on exit."""

    def __init__(self, audit_delay=0.0):
        self.audit_calls = 0
        self.receipt_calls = []
        self.audit_delay = audit_delay

    def __enter__(self):
        self._orig_audit = server.audit_engine.audit
        self._orig_receipt = server.send_buyer_receipt

        def fake_audit(domain):
            self.audit_calls += 1
            if self.audit_delay:
                time.sleep(self.audit_delay)
            rep = dict(FAKE_REPORT)
            rep["domain"] = domain
            return rep

        def fake_receipt(email, session_id, domain, amount_cents, currency):
            self.receipt_calls.append(session_id)
            return True

        server.audit_engine.audit = fake_audit
        server.send_buyer_receipt = fake_receipt
        return self

    def __exit__(self, *exc):
        server.audit_engine.audit = self._orig_audit
        server.send_buyer_receipt = self._orig_receipt
        return False


# ------------------------------------------------- 1. signature verification
print("== webhook signature verification ==")
# Known-answer vector, generated independently (see workstream notes):
#   secret = "whsec_test_vector_secret"
#   t = 1727486400
#   payload = b'{"id":"evt_known_vector_1","type":"checkout.session.completed"}'
#   v1 = HMAC-SHA256(secret, "1727486400." + payload)
KV_SECRET = "whsec_test_vector_secret"
KV_T = 1727486400
KV_PAYLOAD = b'{"id":"evt_known_vector_1","type":"checkout.session.completed"}'
KV_V1 = ("68f14efefa68058d104e0f19040d9a42b6d93bb09c0a3cef509890220977f5fc")
KV_HEADER = "t=%d,v1=%s" % (KV_T, KV_V1)

_real_time = time.time
try:
    # Pin "now" to the vector timestamp so the vector is not stale.
    time.time = lambda: float(KV_T)
    check("known-answer vector verifies",
          server.verify_stripe_signature(KV_PAYLOAD, KV_HEADER, KV_SECRET))
    check("tampered payload rejected",
          not server.verify_stripe_signature(KV_PAYLOAD + b" ",
                                             KV_HEADER, KV_SECRET))
    check("wrong secret rejected",
          not server.verify_stripe_signature(KV_PAYLOAD, KV_HEADER,
                                             "whsec_wrong"))
    check("second v1 accepted when one matches",
          server.verify_stripe_signature(
              KV_PAYLOAD,
              "t=%d,v1=deadbeef,v1=%s" % (KV_T, KV_V1), KV_SECRET))
    check("str payload accepted",
          server.verify_stripe_signature(KV_PAYLOAD.decode("utf-8"),
                                         KV_HEADER, KV_SECRET))
finally:
    time.time = _real_time

now = int(time.time())


def _sig(payload, t, secret):
    signed = ("%d." % t).encode("utf-8") + payload
    return hmac.new(secret.encode("utf-8"), signed,
                    hashlib.sha256).hexdigest()


def _hdr(payload, t, secret):
    return "t=%d,v1=%s" % (t, _sig(payload, t, secret))


p = b'{"id":"evt_1"}'
s = "whsec_live_test"
check("fresh signature verifies",
      server.verify_stripe_signature(p, _hdr(p, now, s), s))
check("stale timestamp rejected",
      not server.verify_stripe_signature(p, _hdr(p, now - 400, s), s))
check("future timestamp beyond tolerance rejected",
      not server.verify_stripe_signature(p, _hdr(p, now + 400, s), s))
check("timestamp just inside tolerance accepted",
      server.verify_stripe_signature(p, _hdr(p, now - 290, s), s))
check("malformed header rejected",
      not server.verify_stripe_signature(p, "garbage", s))
check("missing t rejected",
      not server.verify_stripe_signature(p, "v1=abc", s))
check("missing v1 rejected",
      not server.verify_stripe_signature(p, "t=%d" % now, s))
check("non-numeric t rejected",
      not server.verify_stripe_signature(p, "t=abc,v1=abc", s))
check("empty secret rejected",
      not server.verify_stripe_signature(p, _hdr(p, now, s), ""))
check("empty header rejected",
      not server.verify_stripe_signature(p, "", s))
check("whitespace-tolerant header",
      server.verify_stripe_signature(p, "t=%d, v1=%s" % (now, _sig(p, now, s)),
                                     s))

# ------------------------------------------------- 2. idempotent fulfillment
print("== idempotent durable fulfillment ==")
db = fresh_store()
with Stubs() as stubs:
    sess = make_session()
    ok1, reason1, tok1 = server.fulfill_paid_session(sess, source="webhook")
    check("first fulfillment succeeds", ok1 and tok1 == "tok-test-1", reason1)
    check("audit ran once", stubs.audit_calls == 1, stubs.audit_calls)
    check("one purchase row", store.purchase_count() == 1)
    check("receipt attempted once", stubs.receipt_calls == ["cs_test_1"],
          stubs.receipt_calls)

    ok2, reason2, tok2 = server.fulfill_paid_session(sess, source="webhook")
    check("redelivery succeeds", ok2 and tok2 == tok1, reason2)
    check("no second audit on redelivery", stubs.audit_calls == 1)
    check("no duplicate purchase row", store.purchase_count() == 1)
    check("no duplicate receipt", len(stubs.receipt_calls) == 1)

    # Restart simulation: close + reopen the DB, drop the memory cache.
    store.close()
    store.configure(db)
    server.REPORT_CACHE.clear()
    ok3, reason3, tok3 = server.fulfill_paid_session(sess,
                                                    source="browser_return")
    check("fulfillment works after restart", ok3 and tok3 == tok1, reason3)
    check("no re-audit after restart", stubs.audit_calls == 1,
          stubs.audit_calls)
    check("still one purchase row", store.purchase_count() == 1)
    check("still one receipt after restart", len(stubs.receipt_calls) == 1)
    rep = store.get_report(tok1)
    check("paid report readable after reopen",
          rep is not None and rep.get("score") == 80)

# ------------------------------------------------- 3. concurrent redelivery
print("== concurrent redelivery ==")
fresh_store()
with Stubs(audit_delay=0.05) as stubs:
    sess = make_session(sid="cs_race_1")
    results = []

    def worker():
        results.append(server.fulfill_paid_session(sess, source="webhook"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check("all 8 concurrent fulfillments succeed",
          all(r[0] for r in results) and len(results) == 8)
    check("one audit despite race", stubs.audit_calls == 1, stubs.audit_calls)
    check("one purchase row despite race", store.purchase_count() == 1)
    check("one receipt despite race", len(stubs.receipt_calls) == 1,
          stubs.receipt_calls)

# ------------------------------------------------- 4. charge events
print("== refund / dispute charge events ==")
fresh_store()
with Stubs():
    # Purchase first, so the refund can link back via payment_intent.
    server.fulfill_paid_session(make_session(sid="cs_ref_1", pi="pi_ref_1"))
    charge = {"id": "ch_ref_1", "payment_intent": "pi_ref_1",
              "amount": 900, "currency": "usd"}
    server.mark_charge_event("charge.refunded", charge, event_id="evt_ref_1")
    check("refund event recorded", store.charge_event_count() == 1)
    server.mark_charge_event("charge.refunded", charge, event_id="evt_ref_1")
    check("redelivered refund event ignored",
          store.charge_event_count() == 1)
    server.mark_charge_event("charge.refunded", charge, event_id="evt_ref_2")
    check("second event id (partial refund) recorded",
          store.charge_event_count() == 2)
    prow = store.get_purchase("cs_ref_1")
    check("purchase row marked refunded",
          prow is not None and prow.get("status") == "refunded",
          prow.get("status") if prow else None)

    dispute = {"id": "ch_disp_1", "payment_intent": "pi_missing",
               "amount": 900, "currency": "usd",
               "dispute": {"reason": "fraudulent"}}
    server.mark_charge_event("charge.dispute.created", dispute,
                             event_id="evt_disp_1")
    check("dispute event recorded", store.charge_event_count() == 3)

# ------------------------------------------------- 5. TTL semantics
print("== report TTL in durable store ==")
fresh_store()
old = int(time.time()) - 3 * 3600
store.save_report("tok-unpaid-old", FAKE_REPORT, domain="example.com",
                  paid=0, created_at=old)
check("unpaid report past TTL reads as expired",
      store.get_report("tok-unpaid-old", ttl_s=server.REPORT_TTL_S) is None)
check("expired unpaid row pruned",
      store.get_report("tok-unpaid-old") is None)
store.save_report("tok-paid-old", FAKE_REPORT, domain="example.com",
                  paid=1, created_at=old)
check("paid report never expires",
      store.get_report("tok-paid-old",
                       ttl_s=server.REPORT_TTL_S) is not None)
store.save_report("tok-unpaid-fresh", FAKE_REPORT, domain="example.com",
                  paid=0)
check("fresh unpaid report readable",
      store.get_report("tok-unpaid-fresh",
                       ttl_s=server.REPORT_TTL_S) is not None)
n = store.prune_unpaid(server.REPORT_TTL_S)
check("prune_unpaid only touches old unpaid rows", n == 0, n)

# ------------------------------------------------- 6. jsonl migration
print("== legacy purchases.jsonl migration ==")
dbpath = fresh_store()
tmpdir = os.path.dirname(dbpath)
jl = os.path.join(tmpdir, "purchases.jsonl")
with open(jl, "w", encoding="utf-8") as f:
    f.write(json.dumps({"ts": 1, "session_id": "cs_mig_1",
                        "domain": "example.com", "score": 77,
                        "amount_cents": 900, "currency": "usd",
                        "buyer_email": "a@b.com",
                        "report_token": "tok-mig-1"}) + "\n")
    f.write(json.dumps({"ts": 2, "type": "refund",
                        "charge_id": "ch_old"}) + "\n")  # not a purchase row
    f.write(json.dumps({"ts": 3, "nope": True}) + "\n")  # no session id
check("one purchase row imported", store.migrate_jsonl(jl) == 1)
check("second migrate imports nothing", store.migrate_jsonl(jl) == 0)
prow = store.get_purchase("cs_mig_1")
check("migrated row readable",
      prow is not None and prow.get("domain") == "example.com")

# ------------------------------------------------- 7. HTTP webhook handling
print("== HTTP webhook handling ==")
fresh_store()
httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
port = httpd.server_address[1]
t = threading.Thread(target=httpd.serve_forever, daemon=True)
t.start()


def post_webhook(event, secret="whsec_test_readiness_secret"):
    body = json.dumps(event).encode("utf-8")
    ts = int(time.time())
    sig = hmac.new(secret.encode("utf-8"),
                   ("%d." % ts).encode("utf-8") + body,
                   hashlib.sha256).hexdigest()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    conn.request("POST", "/api/stripe-webhook", body=body,
                 headers={"Content-Type": "application/json",
                          "Stripe-Signature": "t=%d,v1=%s" % (ts, sig)})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, json.loads(data.decode("utf-8"))


def post_webhook_raw(body, sig_header):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    conn.request("POST", "/api/stripe-webhook", body=body,
                 headers={"Content-Type": "application/json",
                          "Stripe-Signature": sig_header})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


with Stubs() as stubs:
    evt = {"id": "evt_http_1", "type": "checkout.session.completed",
           "data": {"object": make_session(sid="cs_http_1")}}
    code, body = post_webhook(evt)
    check("webhook checkout.session.completed -> 200", code == 200, code)
    check("purchase recorded via webhook", store.purchase_count() == 1)
    code2, _ = post_webhook(evt)
    check("webhook redelivery -> 200", code2 == 200, code2)
    check("redelivery did not duplicate",
          store.purchase_count() == 1 and stubs.audit_calls == 1)

    code, _ = post_webhook_raw(json.dumps(evt).encode("utf-8"),
                               "t=123,v1=deadbeef")
    check("bad signature -> 400", code == 400, code)

    unknown = {"id": "evt_http_2", "type": "customer.created",
               "data": {"object": {"id": "cus_1"}}}
    code, body = post_webhook(unknown)
    check("unknown event -> 200 ignored",
          code == 200 and body.get("ignored") == "customer.created",
          (code, body))

    refund_evt = {"id": "evt_http_3", "type": "charge.refunded",
                  "data": {"object": {"id": "ch_http_1",
                                      "payment_intent": "pi_test_1",
                                      "amount": 900, "currency": "usd"}}}
    code, _ = post_webhook(refund_evt)
    check("charge.refunded -> 200", code == 200, code)
    check("charge event stored", store.charge_event_count() == 1)
    code, _ = post_webhook(refund_evt)
    check("charge.refunded redelivery -> 200, still one row",
          code == 200 and store.charge_event_count() == 1, code)

    bad_body = b"this is not json"
    ts = int(time.time())
    sig = hmac.new(b"whsec_test_readiness_secret",
                   ("%d." % ts).encode() + bad_body,
                   hashlib.sha256).hexdigest()
    code, _ = post_webhook_raw(bad_body, "t=%d,v1=%s" % (ts, sig))
    check("valid signature but bad JSON -> 400", code == 400, code)

httpd.shutdown()

# ------------------------------------------------- 8. checkout token fallback
print("== checkout token fallback after restart ==")
fresh_store()
store.save_report("tok-fallback-1", FAKE_REPORT, domain="example.com",
                  paid=0)
server.REPORT_CACHE.clear()
report, from_store = server._report_entry_for_token("tok-fallback-1")
check("token resolves from durable store",
      report is not None and report.get("domain") == "example.com"
      and from_store is True)
check("cache repopulated",
      "tok-fallback-1" in server.REPORT_CACHE)
store.save_report("tok-fallback-old", FAKE_REPORT, domain="example.com",
                  paid=0, created_at=int(time.time()) - 3 * 3600)
server.REPORT_CACHE.clear()
report, from_store = server._report_entry_for_token("tok-fallback-old")
check("expired token still rejected", report is None)
report, _ = server._report_entry_for_token("no-such-token")
check("unknown token rejected", report is None)

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
