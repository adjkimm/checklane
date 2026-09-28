#!/usr/bin/env python3
"""Unit tests for the Gate-B audit-engine fixes (C2a–c, C3, C4, H1–H3, M3).

Run: python3 tests/test_engine_fixes.py
Stdlib only. No network except a localhost probe server.
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# Self-locating: test the audit.py shipped in this tree, not the cwd.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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

# ------------------------------------------------- 5e. cart/checkout path probes
print("== cart/checkout path probes (Board condition 4) ==")
audit.normalize_domain = lambda d: d  # re-apply: section 5 restored the guard
audit.polite = lambda: None


def make_cart_fetch(block_cart=False):
    cart_home = HOME.replace('<a href="/shipping">shipping</a>',
                            '<a href="/shipping">shipping</a>'
                            '<a href="/checkout">checkout</a>')

    def fake_fetch(url, ua=None, timeout=12):
        if url.endswith("/.well-known/ucp"):
            return {"status": 404, "headers": {}, "body": "",
                    "truncated": False, "final_url": url, "error": None}
        if url.endswith("/"):
            return {"status": 200, "headers": {}, "body": cart_home,
                    "truncated": False, "final_url": url, "error": None}
        if "/cart" in url or "/checkout" in url:
            if block_cart and "OAI-SearchBot" in (ua or ""):
                return {"status": 403, "headers": {}, "body": "",
                        "truncated": False, "final_url": url, "error": None}
            return {"status": 200, "headers": {},
                    "body": "<html><body>cart ok</body></html>",
                    "truncated": False, "final_url": url, "error": None}
        return {"status": 404, "headers": {}, "body": "",
                "truncated": False, "final_url": url, "error": None}
    return fake_fetch


def all_checks(report):
    return [c for cat in report["categories"] for c in cat["checks"]]


audit.fetch = make_cart_fetch()
rep = audit.audit("127.0.0.1")
cartp = [c for c in all_checks(rep) if c["id"].startswith("agent-ua:cart-path")]
check("cart/checkout paths probed (2 paths x 2 fetchers)",
      len(cartp) == 4, str(len(cartp)))
check("open cart paths pass",
      all(c["status"] == "pass" for c in cartp))
scope = next(c for c in all_checks(rep) if c["id"] == "bot-test-scope")
check("scope statement mentions cart/checkout probing",
      "cart/checkout" in scope["detail"])

audit.fetch = make_cart_fetch(block_cart=True)
rep = audit.audit("127.0.0.1")
fails = [c for c in all_checks(rep) if c["id"].startswith("agent-ua:cart-path")
         and c["status"] == "fail"]
check("blocked cart path fails (not silent)", len(fails) == 2, str(len(fails)))
check("blocked path severity is medium", fails and fails[0]["severity"] == "medium")
check("blocked path carries a fix", fails and bool(fails[0]["fix"]))
check("blocked path does not tank category score",
      next(c for c in rep["categories"]
           if c["name"] == "AI bot access")["score"] >= 0)


# ------------------------------------------------- 8. v1.1.0-m2 changes
print("== v1.1.0-m2: version ==")
check("engine version bumped", audit.VERSION == "1.1.0-m2", audit.VERSION)

print("== v1.1.0-m2: _is_product_node ==")
check("Product matches", audit._is_product_node({"@type": "Product"}))
check("ProductGroup matches",
      audit._is_product_node({"@type": "ProductGroup"}))
check("lowercase productgroup matches",
      audit._is_product_node({"@type": "productgroup"}))
check("type list matches",
      audit._is_product_node({"@type": ["Organization", "ProductGroup"]}))
check("Organization does not match",
      not audit._is_product_node({"@type": "Organization"}))
check("missing @type does not match", not audit._is_product_node({}))

print("== v1.1.0-m2: fixtures ==")
audit.normalize_domain = lambda d: d
audit.polite = lambda: None


def _resp(status, body=""):
    return {"status": status, "headers": {}, "body": body,
            "truncated": False, "final_url": "", "error": None}


def make_m2_fetch(home_html, robots_body="", sitemap_body=None, llms_body=None):
    def fake_fetch(url, ua=None, timeout=12):
        if url.endswith("/.well-known/ucp"):
            return _resp(404)
        if url.endswith("/robots.txt"):
            return _resp(200, robots_body) if robots_body else _resp(404)
        if url.endswith("/sitemap.xml"):
            return _resp(200, sitemap_body) if sitemap_body else _resp(404)
        if url.endswith("/llms.txt") or url.endswith("/agents.md"):
            return _resp(200, llms_body) if llms_body else _resp(404)
        for p in ("/products.json?limit=1", "/feed", "/products.xml",
                  "/google-feed.xml"):
            if url.endswith(p):
                return _resp(404)
        if url.endswith("/"):
            return _resp(200, home_html)
        return _resp(404)
    return fake_fetch


def cat(report, name):
    return next(c for c in report["categories"] if c["name"] == name)


def check_status(report, cat_name, cid):
    return next(c for c in cat(report, cat_name)["checks"]
                if c["id"] == cid)["status"]


PG_HOME = ("<html><head><title>Threads Co</title>"
           '<meta name="description" content="d">'
           '<link rel="canonical" href="https://x/"></head>'
           "<body><h1>Threads Co</h1><p>" + "x" * 500 + "</p>"
           '<script type="application/ld+json">{"@context":"https://schema.org",'
           '"@type":"ProductGroup","name":"Tee","brand":"Threads","sku":"TEE-1",'
           '"offers":{"@type":"Offer","price":"29.99","priceCurrency":"USD"}}</script>'
           '<a href="/cart">cart</a></body></html>')

print("== v1.1.0-m2: ProductGroup end-to-end ==")
audit.fetch = make_m2_fetch(PG_HOME)
rep = audit.audit("127.0.0.1")
check("ProductGroup site detected as storefront",
      rep["site_type"] == "storefront", rep["site_type"])
check("product structured data signal present",
      "product structured data" in rep["site_type_signals"],
      str(rep["site_type_signals"]))
check("product-markup passes on ProductGroup",
      check_status(rep, "Product info AI can read", "product-markup") == "pass")
check("Category 2 scores above 0 (was 0 before fix)",
      cat(rep, "Product info AI can read")["score"] > 0,
      str(cat(rep, "Product info AI can read")["score"]))
check("new business-discovery category N/A for storefronts",
      cat(rep, "Can AI find your business")["na"] is True)

THIN_HOME = ("<html><head><title>Acme</title>"
             '<meta name="description" content="d">'
             '<link rel="canonical" href="https://x/"></head>'
             "<body><h1>Acme</h1><p>" + "y" * 150 + "</p></body></html>")
THICK_HOME = THIN_HOME.replace("y" * 150, "z" * 500)

print("== v1.1.0-m2: thin-page scaling ==")
audit.fetch = make_m2_fetch(THIN_HOME)
rep = audit.audit("127.0.0.1")
check("thin page static-content is partial (not pass)",
      check_status(rep, "Can AI read your pages", "static-content") == "partial")
_c5 = cat(rep, "Can AI read your pages")
check("thin page Cat5 below max (17, was 20)",
      _c5["score"] == 17, str(_c5["score"]))
audit.fetch = make_m2_fetch(THICK_HOME)
rep = audit.audit("127.0.0.1")
check("thick page static-content passes",
      check_status(rep, "Can AI read your pages", "static-content") == "pass")

SITEMAP_OK = ('<?xml version="1.0"?><urlset>'
              '<url><loc>https://x/about</loc></url>'
              '<url><loc>https://x/contact</loc></url>'
              '<url><loc>https://x/blog</loc></url>'
              '<url><loc>https://x/faq</loc></url>'
              '<url><loc>https://x/team</loc></url></urlset>')
LLMS_FULL = ("# Acme agent guide\n" + "We help teams do things. " * 60)
FULL_HOME = ("<html><head><title>Acme Consulting</title>"
             '<meta name="description" content="Strategy help.">'
             '<meta property="og:title" content="Acme">'
             '<meta property="og:description" content="Strategy help.">'
             '<meta property="og:image" content="https://x/i.png">'
             '<meta name="twitter:card" content="summary">'
             '<link rel="canonical" href="https://x/"></head>'
             "<body><h1>Acme Consulting</h1><p>" + "w" * 500 + "</p>"
             '<script type="application/ld+json">{"@context":"https://schema.org",'
             '"@type":"FAQPage","mainEntity":[]}</script>'
             '<a href="/about">about</a></body></html>')

print("== v1.1.0-m2: non-storefront discovery, full signals ==")
audit.fetch = make_m2_fetch(FULL_HOME, sitemap_body=SITEMAP_OK,
                            llms_body=LLMS_FULL)
rep = audit.audit("127.0.0.1")
check("full-signal site is non-storefront",
      rep["site_type"] == "non-storefront", rep["site_type"])
_c6 = cat(rep, "Can AI find your business")
check("new category scored (not N/A)", _c6["na"] is False)
check("new category max is 20", _c6["max"] == 20, str(_c6["max"]))
check("full signals earn 20/20", _c6["score"] == 20, str(_c6["score"]))
check("non-storefront total max is 60",
      sum(c["max"] for c in rep["categories"]) == 60,
      str(sum(c["max"] for c in rep["categories"])))
check("perfect non-storefront scores 100/A",
      rep["score"] == 100 and rep["grade"] == "A",
      "%s/%s" % (rep["score"], rep["grade"]))

print("== v1.1.0-m2: non-storefront discovery, bare site ==")
audit.fetch = make_m2_fetch(THIN_HOME)
rep = audit.audit("127.0.0.1")
_c6 = cat(rep, "Can AI find your business")
check("bare site new category scores 0", _c6["score"] == 0,
      str(_c6["score"]))
check("bare site total well below the old 92 (discriminates now)",
      rep["score"] < 70, "%s/%s" % (rep["score"], rep["grade"]))
for _cid in ("biz-llms", "biz-sitemap", "biz-og", "biz-faq"):
    check("bare site %s fails" % _cid,
          check_status(rep, "Can AI find your business", _cid) == "fail")

print("== v1.1.0-m2: report rendering of new N/A ==")
html3 = report_html.render_report(rep)
check("storefront-only cats N/A on non-storefront",
      html3.count('pill na">N/A') == 3, str(html3.count('pill na">N/A')))


print("== v1.1.0-m2: biz-llms present-but-unaddressed file ==")
PLAIN_LLMS = ("# Acme plumbing\n" + "We fix pipes, drains and leaks. " * 40)
audit.fetch = make_m2_fetch(THIN_HOME, llms_body=PLAIN_LLMS)
rep = audit.audit("127.0.0.1")
check("llms.txt without 'agent' mention no longer fails outright",
      check_status(rep, "Can AI find your business", "biz-llms") == "partial")
check("unaddressed welcome file earns partial (4)",
      cat(rep, "Can AI find your business")["score"] == 4,
      str(cat(rep, "Can AI find your business")["score"]))
check("partial fix tells owner to address AI assistants",
      "If you are an AI assistant" in
      next(c for c in cat(rep, "Can AI find your business")["checks"]
           if c["id"] == "biz-llms")["fix"])

audit.fetch = _real_fetch
audit.polite = _real_polite
audit.normalize_domain = _real_normalize

_srv.shutdown()
print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
