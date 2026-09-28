#!/usr/bin/env python3
"""Regression tests for Workstream B (pre-live hardening batch).

Run: python3 tests/test_workstream_b.py
Stdlib only. Starts a localhost probe server for the HTTP assertions;
no external network.

Covers:
  B1  OG + Twitter share-preview tags in static/index.html, and a pass
      against our own grader's share-tag field list (audit.py ~line 1375).
  B2  Referrer-Policy on all responses; security headers on error
      responses and HEAD responses; the app never emits
      x-render-origin-server (Render infrastructure sets it upstream).
  B3  Share/forward prompt markup + wiring in static/app.js.
  B4  llms.txt "AI agent findability" wording alignment.
  B5  terms.html "grades any public website" scope alignment.
  B6  do_HEAD: 200 with GET-identical headers and an empty body on
      content routes; 405 (no side effects) on /api/* and /report.
"""
import http.client
import os
import sys
import threading
from html.parser import HTMLParser
from http.server import ThreadingHTTPServer

# Self-locating: test the tree this file ships in, not the cwd.
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import audit as audit_engine
import server as srv

PASS, FAIL = 0, 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok  %s" % name)
    else:
        FAIL += 1
        print("  FAIL %s %s" % (name, extra))


def read(rel):
    with open(os.path.join(ROOT, rel), "r", encoding="utf-8") as f:
        return f.read()


class MetaSniffer(HTMLParser):
    """Collects name/property -> content for <meta> tags (same lookup the
    audit engine's SiteHTMLParser uses)."""

    def __init__(self):
        super().__init__()
        self.meta = {}

    def handle_starttag(self, tag, attrs):
        if tag != "meta":
            return
        a = dict(attrs)
        name = (a.get("name") or a.get("property") or "").lower()
        if name and "content" in a:
            self.meta[name] = a["content"]


print("== B1: share-preview tags ==")
index_html = read("static/index.html")
sniffer = MetaSniffer()
sniffer.feed(index_html)
meta = sniffer.meta

for tag in ("og:title", "og:description", "og:type", "og:url",
            "og:image", "twitter:card", "twitter:title",
            "twitter:description"):
    check("meta %s present and non-empty" % tag,
          bool(meta.get(tag, "").strip()))

check("og:url is the canonical site URL",
      meta.get("og:url", "").strip() == "https://getchecklane.com/",
      repr(meta.get("og:url")))
check("og:type is website", meta.get("og:type", "").strip() == "website",
      repr(meta.get("og:type")))
check("twitter:card is summary_large_image",
      meta.get("twitter:card", "").strip() == "summary_large_image",
      repr(meta.get("twitter:card")))
check("og:image points at a real shipped asset",
      meta.get("og:image", "").strip() ==
      "https://getchecklane.com/static/img/hero-ai-shopper.webp" and
      os.path.isfile(os.path.join(ROOT, "static/img/hero-ai-shopper.webp")),
      repr(meta.get("og:image")))
check("share copy mentions the free 0-100 audit",
      "0-100" in meta.get("og:description", "") and
      "free" in meta.get("og:description", "").lower(),
      repr(meta.get("og:description")))
check("share copy mentions the $9 full report",
      "$9" in meta.get("og:description", ""),
      repr(meta.get("og:description")))
check("no em dashes in share copy",
      "\u2014" not in meta.get("og:title", "") and
      "\u2014" not in meta.get("og:description", ""))

print("== B1b: our own grader passes on the homepage ==")
# The grader's share-tag field list lives in audit.py (biz-og check):
# ["og:title", "og:description", "og:image", "twitter:card"].
parser = audit_engine.SiteHTMLParser()
parser.feed(index_html)
grader_fields = ["og:title", "og:description", "og:image", "twitter:card"]
missing = [k for k in grader_fields if not parser.meta.get(k, "").strip()]
check("grader share-tag check passes (all 4 fields present)",
      not missing, "missing: %s" % ", ".join(missing))

print("== B4: llms.txt wording ==")
llms = read("static/llms.txt")
check("llms.txt says 'AI agent findability'",
      "AI agent findability" in llms)
check("llms.txt no longer says 'AI agent marketing'",
      "AI agent marketing" not in llms)

print("== B5: terms scope wording ==")
terms = read("static/legal/terms.html")
check("terms scope matches homepage FAQ ('grades any public website')",
      "grades any public website" in terms)
check("terms no longer says 'technical audit service for small online stores'",
      "technical audit service for small online stores" not in terms)

print("== B3: share/forward prompt in app.js ==")
app_js = read("static/app.js")
check("sharePrompt() renders a share block", "function sharePrompt()" in app_js)
check("share block has a Copy link button",
      'id="copy-link-btn"' in app_js and "Copy link" in app_js)
check("share copy invites forwarding to someone who runs a website",
      "Know someone with a website?" in app_js)
check("copy uses the clipboard API with a fallback",
      "navigator.clipboard" in app_js and "execCommand" in app_js)
check("copied URL is the canonical site URL",
      'var url = "https://getchecklane.com/";' in app_js)
check("sharePrompt() included in the free-audit score card",
      "messageBox(report.domain) +\n      sharePrompt();" in app_js)
check("wireShareButton() wired after a successful audit",
      "wireShareButton();" in app_js and
      "function wireShareButton()" in app_js)
check("no em dashes in share copy",
      "Know someone with a website?" in app_js and
      "\u2014" not in app_js[app_js.index("function sharePrompt()"):
                             app_js.index("function sharePrompt()") + 1200])

print("== B2/B6: HTTP behaviour (localhost probe server) ==")
_srv = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
_port = _srv.server_address[1]
_t = threading.Thread(target=_srv.serve_forever, daemon=True)
_t.start()


def req(method, path):
    c = http.client.HTTPConnection("127.0.0.1", _port, timeout=10)
    c.request(method, path)
    r = c.getresponse()
    body = r.read()
    hdrs = {k.lower(): v for k, v in r.getheaders()}
    status = r.status
    c.close()
    return status, hdrs, body


SEC = ["x-content-type-options", "content-security-policy",
       "referrer-policy", "cache-control"]


def check_headers(name, hdrs, expect_hsts=False):
    for h in SEC:
        check("%s: %s present" % (name, h), h in hdrs)
    check("%s: referrer-policy is strict-origin-when-cross-origin" % name,
          hdrs.get("referrer-policy") == "strict-origin-when-cross-origin",
          repr(hdrs.get("referrer-policy")))
    check("%s: x-content-type-options is nosniff" % name,
          hdrs.get("x-content-type-options") == "nosniff",
          repr(hdrs.get("x-content-type-options")))
    if expect_hsts:
        check("%s: HSTS on non-localhost" % name,
              "strict-transport-security" in hdrs)
    else:
        check("%s: no HSTS pinned on localhost" % name,
              "strict-transport-security" not in hdrs)
    check("%s: app never emits x-render-origin-server" % name,
          "x-render-origin-server" not in hdrs,
          "set by Render's proxy upstream; not removable from app code")


s_get, h_get, b_get = req("GET", "/")
check("GET / is 200", s_get == 200, str(s_get))
check("GET / serves the homepage", b"<title>Checklane" in b_get)
check_headers("GET / 200", h_get)

s_404, h_404, b_404 = req("GET", "/no-such-route")
check("GET /no-such-route is 404", s_404 == 404, str(s_404))
check("404 body is JSON", b_404.startswith(b'{"error"'))
check_headers("GET 404 error response", h_404)

s_head, h_head, b_head = req("HEAD", "/")
check("HEAD / is 200 (was 501)", s_head == 200, str(s_head))
check("HEAD / body is empty", b_head == b"", repr(b_head[:40]))
check("HEAD / content-length matches GET",
      h_head.get("content-length") == h_get.get("content-length"),
      "%s vs %s" % (h_head.get("content-length"),
                    h_get.get("content-length")))
check("HEAD / content-type matches GET",
      h_head.get("content-type") == h_get.get("content-type"))
check_headers("HEAD / 200", h_head)

s_h404, h_h404, b_h404 = req("HEAD", "/no-such-route")
check("HEAD /no-such-route is 404", s_h404 == 404, str(s_h404))
check("HEAD 404 body is empty", b_h404 == b"")
check_headers("HEAD 404 error response", h_h404)

s_hapi, h_hapi, b_hapi = req("HEAD", "/api/config")
check("HEAD /api/config is 405 (no side effects)", s_hapi == 405,
      str(s_hapi))
check("405 carries Allow: GET", h_hapi.get("allow") == "GET",
      repr(h_hapi.get("allow")))
check("HEAD 405 body is empty", b_hapi == b"")
check_headers("HEAD /api/* 405", h_hapi)

s_hrep, h_hrep, b_hrep = req("HEAD", "/report?session_id=x")
check("HEAD /report is 405 (no Stripe verification)", s_hrep == 405,
      str(s_hrep))
check("HEAD /report body is empty", b_hrep == b"")

s_put, h_put, b_put = req("PUT", "/")
check("PUT / is 501 via framework send_error", s_put == 501, str(s_put))
check_headers("PUT 501 framework error response", h_put)

s_hr, h_hr, _ = req("HEAD", "/robots.txt")
check("HEAD /robots.txt is 200", s_hr == 200, str(s_hr))
check_headers("HEAD /robots.txt 200", h_hr)

_srv.shutdown()

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
