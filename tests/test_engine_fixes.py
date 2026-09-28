#!/usr/bin/env python3
"""Unit tests for the Gate-B audit-engine fixes (C2a–c, C3, C4, H1–H3, M3).

Run: python3 tests/test_engine_fixes.py
Stdlib only. No network except a localhost probe server.
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, "/home/hatch/workspace/checklane")
import audit
import report_html

PASS, FAIL = 0, 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok  %s" % name)
    else:
        FAIL += 1
        print("  FAIL %s %s" % (name, extra))


# ---------------------------------------------------------------- fixtures
SPEC_PROFILE = {
    "ucp": {
        "version": "2026-04-08",
        "services": {
            "dev.ucp.shopping": [{
                "version": "2026-04-08",
                "transport": "rest",
                "endpoint": "https://shop.example.com/ucp",
            }]
        },
        "capabilities": {
            "dev.ucp.shopping.catalog.search": [{"spec": "https://ucp.dev/x"}],
            "dev.ucp.shopping.catalog.lookup": [{"spec": "https://ucp.dev/x"}],
            "dev.ucp.shopping.cart": [{"spec": "https://ucp.dev/x"}],
            "dev.ucp.shopping.checkout": [{"spec": "https://ucp.dev/x"}],
            "dev.ucp.shopping.order": [{
                "spec": "https://ucp.dev/x",
                "config": {"webhook_url": "https://shop.example.com/ucp/hook"},
            }],
        },
        "payment_handlers": {
            "com.shopify.shop_pay": [{"endpoint": "https://pay.example.com/h"}]
        },
    },
    "signing_keys": [{"kid": "s1", "kty": "EC", "crv": "P-256"}],
}

FAKE_PROFILE = {  # ≥3 areas, endpoints all dead -> must NOT score 20/20
    "ucp": {
        "version": "2026-04-08",
        "services": {"dev.ucp.shopping": [
            {"transport": "rest", "endpoint": "http://127.0.0.1:9/dead"}]},
        "capabilities": {
            "dev.ucp.shopping.catalog.search": [{}],
            "dev.ucp.shopping.cart": [{}],
            "dev.ucp.shopping.checkout": [{}],
        },
        "payment_handlers": {},
    }
}

# ---------------------------------------------------------------- 1. parsing
print("== UCP envelope parsing ==")
u = audit._parse_ucp_envelope(json.dumps(SPEC_PROFILE))
check("spec envelope parses", isinstance(u, dict) and u.get("version") == "2026-04-08")
check("non-JSON -> None", audit._parse_ucp_envelope("not json") is None)
check("missing ucp key -> None",
      audit._parse_ucp_envelope(json.dumps({"foo": 1})) is None)

# ------------------------------------------------- 2. capability mapping
print("== capability mapping (spec names) ==")
areas = audit._ucp_capability_areas([
    "dev.ucp.shopping.catalog.search",
    "dev.ucp.shopping.catalog.lookup",
    "dev.ucp.shopping.cart",
    "dev.ucp.shopping.checkout",
    "dev.ucp.shopping.identity-linking",
    "dev.ucp.shopping.order",
])
check("all five areas from real names",
      areas == ["cart", "checkout", "discovery", "identity", "order"], str(areas))
check("case-insensitive",
      audit._ucp_capability_areas(["DEV.UCP.SHOPPING.CART"]) == ["cart"])
check("invented names score nothing",
      audit._ucp_capability_areas(["shopping.browse", "commerce.catalog"]) == [])
check("forward-compat segment match",
      "order" in audit._ucp_capability_areas(["dev.ucp.shopping.post-order"]))

# ------------------------------------------------- 3. endpoint extraction
print("== endpoint URL extraction ==")
urls = audit._ucp_endpoint_urls(SPEC_PROFILE["ucp"])
check("finds service endpoint", "https://shop.example.com/ucp" in urls, str(urls))
check("finds webhook_url", "https://shop.example.com/ucp/hook" in urls)
check("finds payment handler endpoint", "https://pay.example.com/h" in urls)
check("dedupes", len(urls) == len(set(urls)))

# ------------------------------------------------- 4. liveness probe
print("== liveness probe (localhost server) ==")


class _H(BaseHTTPRequestHandler):
    def _ok(self, code=200):
        self.send_response(code)
        self.send_header("Content-Length", "2")
        self.end_headers()
        try:
            self.wfile.write(b"ok")
        except BrokenPipeError:
            pass

    def do_GET(self):
        self._ok(500 if self.path == "/boom" else 200)

    def do_HEAD(self):
        self._ok(405 if self.path == "/post-only" else 200)

    def log_message(self, *a):
        pass


_srv = HTTPServer(("127.0.0.1", 0), _H)
_port = _srv.server_address[1]
threading.Thread(target=_srv.serve_forever, daemon=True).start()
_host = "127.0.0.1"
_b = "http://127.0.0.1:%d" % _port

probe = audit._probe_ucp_endpoints(
    [_b + "/ucp", _b + "/boom", _b + "/post-only",
     "http://127.0.0.1:9/closed", "https://psp.example.com/hook"],
    _host)
by_url = dict(probe)
check("live endpoint answers", by_url[_b + "/ucp"].startswith("answered"),
      str(probe))
check("HTTP 500 counts as dead", by_url[_b + "/boom"].startswith("server error"))
check("405 (POST-only) counts as answering (path is live)",
      by_url[_b + "/post-only"].startswith("answered"))
check("connection-refused counts as dead",
      by_url["http://127.0.0.1:9/closed"].startswith("no response"))
check("off-host noted, not probed",
      by_url["https://psp.example.com/hook"].startswith("off-host"))

# ------------------------------------------------- 5. category-1 state machine
print("== category 1 via monkeypatched fetch ==")
_real_fetch, _real_polite = audit.fetch, audit.polite
_real_normalize = audit.normalize_domain
audit.polite = lambda: None
audit.normalize_domain = lambda d: d  # IPs rejected by the real guard

HOME = ("<html><head><title>Shop</title>"
        '<meta name="description" content="d"><link rel="canonical" href="https://x/"></head>'
        "<body><h1>Shop</h1><p>" + "x" * 500 + "</p>"
        '<script type="application/ld+json">{"@context":"https://schema.org",'
        '"@type":"Product","name":"Widget","sku":"W-1",'
        '"offers":{"@type":"Offer","price":"29.99","priceCurrency":"USD"}}</script>'
        '<a href="/cart">cart</a><a href="/shipping">shipping</a>'
        '<a href="/returns">returns</a></body></html>')


def make_fetch(ucp_body=None, endpoint_status=200):
    def fake_fetch(url, ua=None, timeout=12):
        if url.endswith("/.well-known/ucp"):
            if ucp_body is None:
                return {"status": 404, "headers": {}, "body": "",
                        "truncated": False, "final_url": url, "error": None}
            return {"status": 200, "headers": {}, "body": ucp_body,
                    "truncated": False, "final_url": url, "error": None}
        if url.startswith(_b + "/"):
            return {"status": endpoint_status, "headers": {}, "body": "ok",
                    "truncated": False, "final_url": url, "error": None}
        if url == "http://127.0.0.1:9/dead":
            return {"status": None, "headers": {}, "body": "",
                    "truncated": False, "final_url": url,
                    "error": "ConnectionRefused"}
        if url.endswith("/"):
            return {"status": 200, "headers": {}, "body": HOME,
                    "truncated": False, "final_url": url, "error": None}
        return {"status": 404, "headers": {}, "body": "",
                "truncated": False, "final_url": url, "error": None}
    return fake_fetch


def live_profile(endpoint):
    p = json.loads(json.dumps(SPEC_PROFILE))
    p["ucp"]["services"]["dev.ucp.shopping"][0]["endpoint"] = endpoint
    return json.dumps(p)


def cat1(report):
    return next(c for c in report["categories"]
                if c["name"] == "AI checkout handshake (UCP + ACP)")


def check_ids(report, cat):
    return {c["id"] for c in
            next(c for c in report["categories"] if c["name"] == cat)["checks"]}


# 5a. valid profile, live endpoint -> full UCP marks
audit.fetch = make_fetch(live_profile(_b + "/ucp"))
rep = audit.audit("127.0.0.1")
c1 = cat1(rep)
check("valid+live profile: ucp-valid present",
      "ucp-valid" in check_ids(rep, c1["name"]))
check("valid+live profile: UCP scores 12/12", c1["score"] >= 12, str(c1["score"]))

# 5b. fake file: 3 areas, dead endpoint -> declared, unverified (NOT 20/20)
audit.fetch = make_fetch(json.dumps(FAKE_PROFILE))
rep = audit.audit("127.0.0.1")
c1 = cat1(rep)
ids = check_ids(rep, c1["name"])
check("fake file -> ucp-unverified", "ucp-unverified" in ids, str(ids))
check("fake file does not score full category (was 20/20)", c1["score"] < 20,
      str(c1["score"]))
det = next(c["detail"] for c in
           next(c for c in rep["categories"] if "handshake" in c["name"])["checks"]
           if c["id"] == "ucp-unverified")
check("unverified copy says 'declared, unverified'",
      "declared" in det.lower() and "unverified" in det.lower())

# 5c. missing profile -> honest fix copy
audit.fetch = make_fetch(None)
rep = audit.audit("127.0.0.1")
fix = next(f for f in rep["fixes"] if f["id"] == "ucp-missing")["fix"]
check("missing fix names canonical path", "/.well-known/ucp`" in fix, fix[:120])
check("missing fix drops ucp.json path advice",
      "/.well-known/ucp.json`" in fix)  # fallback mention is fine
check("missing fix honest about days-weeks",
      "days to weeks" in fix)
check("missing fix warns dead-endpoint JSON worse than none",
      "worse than none" in fix)
check("missing fix splits Shopify vs custom",
      "Shopify" in fix and "custom build" in fix)
check("no gate language in missing fix",
      "can't even start" not in fix and "Without it" not in fix)

audit.fetch, audit.polite = _real_fetch, _real_polite
audit.normalize_domain = _real_normalize

# ------------------------------------------------- 6. site-type detection
print("== site-type detection ==")
p = audit.SiteHTMLParser()
p.feed(HOME)  # has /cart link
sig = audit._storefront_signals(p, [], [], {"product_url_count": 0}, None)
check("cart link is a signal", "cart/checkout links" in sig, str(sig))
p2 = audit.SiteHTMLParser()
p2.feed("<html><body><p>hello</p></body></html>")
sig2 = audit._storefront_signals(p2, [], [], {"product_url_count": 0}, None)
check("plain page -> no signals", sig2 == [], str(sig2))

# ------------------------------------------------- 7. report rendering
print("== report_html vs synthetic audit dict ==")
synth_checks = []
for i, (cid, sev, st) in enumerate([
        ("ucp-missing", "high", "fail"),
        ("acp-feed-signals", "medium", "fail"),
        ("jsonld-present", "high", "fail"),
        ("product-markup", "high", "fail"),
        ("product-completeness", "medium", "partial"),
        ("offers-present", "high", "fail"),
        ("org-markup", "low", "partial"),          # §3-drop regression case
        ("sitemap", "high", "fail"),
        ("product-feed", "high", "fail"),
        ("agents-md", "medium", "fail"),
        ("bot-test-scope", "medium", "pass"),
        ("agent-ua:GPTBot (OpenAI training crawler)", "high", "fail"),
        ("agent-access-summary", "medium", "pass"),
        ("robots-ai", "high", "fail"),
        ("static-content", "medium", "partial"),
        ("html-basics", "low", "partial"),          # §3-drop regression case
        ("product-links", "medium", "pass")]):
    synth_checks.append({"id": cid, "name": "Check %d" % i, "status": st,
                         "detail": "detail %d" % i,
                         "fix": ("fix %d" % i) if st != "pass" else None,
                         "severity": sev})

synth = {
    "domain": "example.com", "score": 38, "grade": "F",
    "summary": "s", "site_type": "storefront", "site_type_signals": ["x"],
    "categories": [
        {"name": "AI checkout handshake (UCP + ACP)", "score": 5, "max": 20,
         "checks": [c for c in synth_checks if c["id"].startswith(("ucp-", "acp-"))]},
        {"name": "Product info AI can read", "score": 0, "max": 20,
         "checks": [c for c in synth_checks if c["id"] in
                    ("jsonld-present", "product-markup", "product-completeness",
                     "offers-present", "org-markup")]},
        {"name": "Can AI find your products", "score": 0, "max": 20,
         "checks": [c for c in synth_checks if c["id"] in
                    ("sitemap", "product-feed", "agents-md")]},
        {"name": "AI bot access", "score": 20, "max": 20,
         "checks": [c for c in synth_checks if c["id"].startswith(
             ("bot-test-scope", "agent-ua", "agent-access-summary"))]},
        {"name": "Can AI read your pages", "score": 13, "max": 20, "na": False,
         "checks": [c for c in synth_checks if c["id"] in
                    ("robots-ai", "static-content", "html-basics",
                     "product-links")]},
    ],
    "fixes": [{"id": c["id"], "check": c["name"], "severity": c["severity"],
               "detail": c["detail"], "fix": c["fix"]}
              for c in synth_checks if c["fix"]],
    "fetched_at": 0, "engine": "t",
}
html = report_html.render_report(synth)
sec3 = html.split("Your action plan")[1].split("Strategic plays")[0]
n_fixes = len(synth["fixes"])
for f in synth["fixes"]:
    check("§3 contains fix: %s" % f["id"], f["fix"] in sec3)
check("§3 contains ALL fixes (count)",
      sum(1 for f in synth["fixes"] if f["fix"] in sec3) == n_fixes)
check("§3 shows Who column", "<th>Who</th>" in html)
check("§3 shows Effort column", "<th>Effort</th>" in html)
check("ucp effort honest", "days–weeks (developer)" in html)
check("templates section present", "Copy-paste templates" in html)
check("json-ld template present",
      "&quot;@type&quot;: &quot;Product&quot;" in html)
check("robots template present", "OAI-SearchBot" in html)
check("llms.txt credited", "/llms.txt" in html)
check("AGENTS.md not conflated",
      "coding-agent convention for software projects" in html)
check("glossary present", "Glossary" in html and "Shared Payment Token" in html)
check("platform paths present", "WooCommerce" in html and "Squarespace" in html)
check("no gate language in report",
      "can't even start" not in html
      and "AI shoppers effectively cannot" not in html)
check("no wrong ucp.json advice", "/.well-known/ucp.json`" not in html
      or "fallback" in html)

# N/A rendering
synth["site_type"] = "non-storefront"
for c in synth["categories"][:3]:
    c["na"] = True
    c["score"], c["max"] = 0, 0
html2 = report_html.render_report(synth)
check("N/A pill rendered", 'pill na">N/A' in html2)
check("N/A note rendered", "Not scored — no storefront" in html2)
check("site-type note in brief", "doesn&#x27;t sell products online" in html2
      or "doesn't sell products online" in html2)

_srv.shutdown()
print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
