#!/usr/bin/env python3
"""
Checklane agent-readiness audit engine — Milestone 1.

For a merchant-submitted domain, fetches the site's own public pages and scores
0-100 across five categories:
  1. UCP capability-profile validity (open Universal Commerce Protocol spec)
  2. Structured product data (schema.org / JSON-LD)
  3. Product feed discoverability (sitemap, platform feeds)
  4. Bot-wall / agent blockers (response to known AI-agent user agents)
  5. Machine-readability basics (robots.txt AI-crawler posture, static content)

Stdlib only. No paid APIs. Read-only fetches of the submitted domain only.
Run:  python3 audit.py example.com
"""

import concurrent.futures
import json
import ipaddress
import re
import socket
import time
import urllib.parse
import urllib.request
import urllib.error
from html.parser import HTMLParser

VERSION = "1.1.0-m4"
FETCH_TIMEOUT = 12
MAX_BODY = 1_000_000  # 1MB: some Shopify homepages carry 300KB+ of head scripts
POLITENESS_DELAY = 0.4  # seconds between requests; polite crawling

NORMAL_UA = ("ChecklaneAuditBot/1.0 (+https://checklane.example/audit; "
             "site-owner-requested readiness audit)")

# AI-agent / AI-crawler user agents, tested against the homepage.
#
# HONESTY NOTE (H1): these are crawlers and on-demand fetchers, NOT shoppers.
# Blocking a training crawler (GPTBot, ClaudeBot) does NOT block AI shopping:
# browser-driving agents (ChatGPT agent / Operator-class, Meta's Muse, xAI's
# Grok) buy through normal web checkout, and ChatGPT shopping runs on ACP
# product feeds. This check measures crawler/fetcher access only.
AGENT_UAS = {
    # label -> (user-agent string, what-it-is note)
    # Every UA below is documented by its vendor (source URLs in
    # docs/ai-agent-sources-2026-09-30.md). Chrome/W.X.Y.Z placeholders from
    # vendor docs are filled with a real current Chrome version.
    "GPTBot (OpenAI training crawler)": (
        "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
        "trains OpenAI models; blocking it does NOT block ChatGPT shopping"),
    "OAI-SearchBot (ChatGPT search fetcher)": (
        "Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/bot.html)",
        "fetches pages for ChatGPT search answers"),
    "ChatGPT-User (ChatGPT on-demand fetch)": (
        "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot.html)",
        "fetches a page when a ChatGPT user asks about it"),
    "ClaudeBot (Anthropic training crawler)": (
        "Mozilla/5.0 (compatible; ClaudeBot/1.0)",
        "trains Anthropic models; blocking it does NOT block Claude shopping"),
    "Claude-SearchBot (Claude search fetcher)": (
        "Mozilla/5.0 (compatible; Claude-SearchBot/1.0)",
        "fetches pages for Claude search answers"),
    "Claude-User (Claude on-demand fetch)": (
        "Mozilla/5.0 (compatible; Claude-User/1.0)",
        "fetches a page when a Claude user asks about it"),
    "GoogleOther (Google AI crawling)": (
        "Mozilla/5.0 (compatible; GoogleOther/1.0)",
        "Google's AI-feature crawling"),
    "Google-Agent (Google agentic fetch)": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
        "Gecko; compatible; Google-Agent; "
        "+https://developers.google.com/crawling/docs/crawlers-fetchers/google-agent) "
        "Chrome/126.0.0.0 Safari/537.36",
        "Google's agent-mode fetcher; does NOT honor robots.txt blocking"),
    "Meta-ExternalAgent (Meta AI training)": (
        "meta-externalagent/1.1 "
        "(+https://developers.facebook.com/docs/sharing/webmasters/crawler)",
        "crawls for Meta AI model training and indexing; honors robots.txt"),
    "Meta-ExternalFetcher (Meta user fetch)": (
        "meta-externalfetcher/1.1 "
        "(+https://developers.facebook.com/docs/sharing/webmasters/crawler)",
        "fetches pages when a Meta AI user asks; may bypass robots.txt"),
    "Meta-WebIndexer (Meta AI search)": (
        "meta-webindexer/1.1 "
        "(+https://developers.facebook.com/docs/sharing/webmasters/crawler)",
        "indexes pages for Meta AI search answers; honors robots.txt"),
    "Applebot (Apple search and AI)": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 "
        "Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)",
        "powers Siri, Spotlight and Safari search; data may also train "
        "Apple Intelligence"),
    "PerplexityBot (Perplexity discovery)": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
        "PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
        "discovers pages for Perplexity answers"),
    "Perplexity-User (Perplexity on-demand fetch)": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
        "Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)",
        "fetches a page when a Perplexity user asks; generally ignores "
        "robots.txt"),
    "CCBot (Common Crawl dataset)": (
        "CCBot/2.0 (https://commoncrawl.org/faq/)",
        "open-dataset crawl used to train many models"),
    "AI2Bot (Allen Institute research)": (
        "Mozilla/5.0 (compatible) AI2Bot (+https://www.allenai.org/crawler)",
        "research crawl that trains open language models"),
    "Bytespider (ByteDance training)": (
        "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Mobile Safari/537.36 "
        "(compatible; Bytespider; spider-feedback@bytedance.com)",
        "collects content for ByteDance model training; widely observed in "
        "the wild, no vendor documentation published"),
    "YouBot (You.com search)": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
        "YouBot/1.0; +https://docs.you.com/youbot; env:prod) "
        "Chrome/142.0.0.0 Safari/537.36",
        "indexes pages for You.com search answers"),
    "DuckAssistBot (DuckDuckGo AI answers)": (
        "DuckAssistBot/1.2; (+http://duckduckgo.com/duckassistbot.html)",
        "crawls pages in real time for DuckDuckGo AI-assisted answers; "
        "not used for training"),
    "MistralAI-User (Mistral on-demand fetch)": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
        "MistralAI-User/1.0; +https://docs.mistral.ai/robots)",
        "visits pages when a Mistral user asks; not used for crawling "
        "or training"),
    "MistralAI-Index (Mistral search index)": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
        "MistralAI-Index/1.0; +https://docs.mistral.ai/robots)",
        "indexes pages for Mistral search; not used for training"),
    "MistralAI-Training (Mistral training)": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
        "MistralAI-Training/1.0; +https://docs.mistral.ai/robots)",
        "crawls content to train Mistral models"),
    "Amazonbot (Amazon AI and products)": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
        "Amazonbot/0.1) Chrome/126.0.0.0 Safari/537.36",
        "improves Amazon products and services; may train Amazon AI models"),
    "Amzn-SearchBot (Alexa search)": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
        "Amzn-SearchBot/0.1) Chrome/126.0.0.0 Safari/537.36",
        "indexes pages for Alexa and Amazon search experiences; not "
        "for training"),
    "Amzn-User (Alexa on-demand fetch)": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
        "Amzn-User/0.1) Chrome/126.0.0.0 Safari/537.36",
        "fetches pages for Alexa answers; may not follow all robots.txt "
        "rules"),
    "KimiBot (Kimi training)": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; "
        "KimiBot/1.0; +https://www.kimi.com/policies/kimi-crawlers",
        "crawls content that may train Kimi's foundation models"),
    "Kimi-SearchBot (Kimi search index)": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; "
        "Kimi-SearchBot/1.0; +https://www.kimi.com/policies/kimi-crawlers",
        "builds the index behind Kimi search features"),
    "Kimi-User (Kimi on-demand fetch)": (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; "
        "Kimi-User/1.0; +https://www.kimi.com/policies/kimi-crawlers",
        "fetches pages when a Kimi user asks; user-triggered, robots.txt "
        "may not apply"),
}

# robots.txt tokens that control AI-crawler access.
# NOTE: Google-Agent, Meta-ExternalFetcher, Perplexity-User, Amzn-User and
# Kimi-User are deliberately absent — their vendors document them as
# user-triggered fetchers that may bypass or ignore robots.txt, so claiming
# a "blocked" posture for them would be false. (Google-Extended and
# Applebot-Extended are control-only tokens that never crawl; they stay here
# only so posture rules written for them are reported.)
AI_CRAWLER_TOKENS = [
    "gptbot", "oai-searchbot", "google-extended", "googleother",
    "claudebot", "claude-searchbot", "claude-user", "ccbot", "ai2bot",
    "perplexitybot", "chatgpt-user", "anthropic-ai", "cohere-ai",
    "bytespider", "youbot", "duckassistbot",
    "mistralai-user", "mistralai-index", "mistralai-training",
    "amazonbot", "amzn-searchbot",
    "meta-externalagent", "meta-webindexer",
    "applebot", "kimibot", "kimi-searchbot",
    "firecrawlagent",
]

# Candidate discovery locations for a UCP capability profile.
# Canonical FIRST: the UCP spec's discovery path is extensionless
# /.well-known/ucp. (/.well-known/commerce-capabilities.json appeared
# invented — dropped per review.)
UCP_CANDIDATES = [
    "/.well-known/ucp",
    "/.well-known/ucp.json",
    "/ucp.json",
]

BLOCKED_STATUSES = {401, 403, 407, 429}
CHALLENGE_MARKERS = [
    "captcha", "robot or human", "are you a robot", "perimeterx",
    "datadome", "cloudflare", "cf-challenge", "just a moment",
    "access denied", "request blocked",
]

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "icloud.com", "live.com", "msn.com", "protonmail.com", "pm.me",
}


# --------------------------------------------------------------------------- #
# Fetching
# --------------------------------------------------------------------------- #
def normalize_domain(raw):
    """Turn user input into a bare hostname. Raises ValueError if invalid."""
    raw = (raw or "").strip().lower()
    if not raw:
        raise ValueError("empty domain")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urllib.parse.urlsplit(raw)
    except Exception:
        raise ValueError("could not parse domain")
    host = parts.hostname or ""
    host = host.strip().strip(".")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,250}[a-z0-9])?", host):
        raise ValueError("invalid hostname")
    if "." not in host:
        raise ValueError("not a public domain")
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        raise ValueError("IP addresses are not accepted")
    if host in ("localhost",) or host.endswith(".local") or host.endswith(".internal"):
        raise ValueError("local hostnames are not accepted")
    _assert_public_host(host)
    return host


def _assert_public_host(host):
    """SSRF guard: host must resolve to at least one address, all of them
    globally routable. Raises ValueError otherwise."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("could not resolve host")
    except UnicodeError:
        # IDNA codec errors (e.g. empty labels like foo..bar) carry
        # interpreter internals; never let them escape as-is.
        raise ValueError("could not resolve host")
    ips = {info[4][0] for info in infos}
    if not ips:
        raise ValueError("could not resolve host")
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("unresolvable address")
        if not addr.is_global:
            raise ValueError("host does not resolve to a public address")


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirects whose target host fails the SSRF guard."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, newurl))
        host = (target.hostname or "").strip().strip(".")
        if not host:
            raise urllib.error.URLError("redirect to invalid host blocked")
        try:
            _assert_public_host(host)
        except ValueError as e:
            raise urllib.error.URLError("redirect blocked: %s" % e)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeRedirectHandler)


def fetch(url, ua=NORMAL_UA, timeout=FETCH_TIMEOUT):
    """GET url. Returns dict(status, headers, body, final_url, error)."""
    req = urllib.request.Request(url, headers={
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_BODY + 1)
            body = raw[:MAX_BODY].decode("utf-8", errors="replace")
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": body,
                "truncated": len(raw) > MAX_BODY,
                "final_url": resp.geturl(),
                "error": None,
            }
    except urllib.error.HTTPError as e:
        try:
            body = e.read(MAX_BODY).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {"status": e.code, "headers": dict(e.headers or {}),
                "body": body, "truncated": False,
                "final_url": url, "error": None}
    except Exception as e:  # timeout, DNS, TLS, connection refused...
        return {"status": None, "headers": {}, "body": "",
                "truncated": False, "final_url": url,
                "error": "%s: %s" % (type(e).__name__, e)}


def polite():
    time.sleep(POLITENESS_DELAY)


# --------------------------------------------------------------------------- #
# HTML parsing
# --------------------------------------------------------------------------- #
class SiteHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self._in_title = False
        self.meta = {}          # name/property -> content
        self.canonical = ""
        self.h1_count = 0
        self.links = []         # href values
        self.ld_json_raw = []   # raw JSON-LD script bodies
        self._in_ld = False
        self._ld_buf = []
        self.script_srcs = 0
        self.text_chunks = []
        self._skip = 0          # inside script/style

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
            if tag == "script":
                self.script_srcs += 1
                if a.get("type", "").lower() == "application/ld+json":
                    self._in_ld = True
                    self._ld_buf = []
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            if name and "content" in a:
                self.meta[name] = a["content"]
        elif tag == "link" and a.get("rel", "").lower() == "canonical":
            self.canonical = a.get("href", "")
        elif tag == "h1":
            self.h1_count += 1
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
            if tag == "script" and self._in_ld:
                self._in_ld = False
                self.ld_json_raw.append("".join(self._ld_buf))
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_ld:
            self._ld_buf.append(data)
        elif self._in_title:
            self.title += data
        elif not self._skip:
            self.text_chunks.append(data)

    @property
    def visible_text(self):
        return " ".join(" ".join(self.text_chunks).split())


def parse_ld_json(raw_blocks):
    """Return list of JSON-LD node dicts from raw script bodies."""
    nodes = []
    for raw in raw_blocks:
        raw = raw.strip()
        if not raw:
            continue
        try:
            doc = json.loads(raw)
        except Exception:
            continue
        docs = doc if isinstance(doc, list) else [doc]
        for d in docs:
            if not isinstance(d, dict):
                continue
            graph = d.get("@graph")
            if isinstance(graph, list):
                nodes.extend([n for n in graph if isinstance(n, dict)])
            else:
                nodes.append(d)
    return nodes


def node_types(node):
    t = node.get("@type", [])
    if isinstance(t, str):
        t = [t]
    return [str(x).lower() for x in t if isinstance(x, str)]


def _is_product_node(node):
    """True for Product and ProductGroup nodes.

    ProductGroup is Schema.org's standard type for variant listings
    (ubiquitous on Shopify/apparel): the name, brand, SKU, and offers
    live on the group node, so it must count as a product node.
    """
    return any(t in ("product", "productgroup") for t in node_types(node))


# --------------------------------------------------------------------------- #
# robots.txt
# --------------------------------------------------------------------------- #
def parse_robots_ai_posture(robots_body):
    """Return {token: 'blocked'|'unspecified'} for AI crawler tokens.

    A token counts as blocked only when it (or a wildcard group) is
    disallowed from "/". Anything else is 'unspecified' — we make no claim
    about it.
    """
    posture = {t: "unspecified" for t in AI_CRAWLER_TOKENS}
    if not robots_body:
        return posture
    # Group consecutive User-agent lines with the Disallow lines that follow.
    groups = []
    cur_uas, cur_dis = [], []
    for line in robots_body.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field, value = field.strip().lower(), value.strip()
        if field == "user-agent":
            if cur_dis:
                # rules were seen: previous group is complete, start a new one
                groups.append((cur_uas, cur_dis))
                cur_uas, cur_dis = [], []
            cur_uas.append(value.lower())
        elif field == "disallow":
            cur_dis.append(value)
    if cur_uas or cur_dis:
        groups.append((cur_uas, cur_dis))
    for uas, dis in groups:
        # An empty Disallow means "allow everything" per the robots spec.
        blocked_all = any(d.strip() == "/" for d in dis)
        if not blocked_all:
            continue
        for ua in uas:
            for token in AI_CRAWLER_TOKENS:
                if token == ua or ua == "*":
                    posture[token] = "blocked"
    return posture


# --------------------------------------------------------------------------- #
# UCP validation helpers
# --------------------------------------------------------------------------- #
def _parse_ucp_envelope(body):
    """Return the 'ucp' object from a UCP JSON doc, or None."""
    try:
        doc = json.loads(body)
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    u = doc.get("ucp")
    return u if isinstance(u, dict) else None


def _ucp_capability_areas(cap_names):
    """Map UCP capability names to the areas the engine scores.

    Uses the spec's REAL capability names (namespace dev.ucp.shopping.*),
    not invented ones. Unknown names fall back to matching on the final
    dotted segment, so forward-compatible spec additions still score.
    """
    areas = set()
    for n in cap_names:
        nl = str(n).strip().lower()
        if nl in UCP_CAPABILITY_AREAS:
            areas.add(UCP_CAPABILITY_AREAS[nl])
            continue
        seg = nl.rsplit(".", 1)[-1]
        for full, area in UCP_CAPABILITY_AREAS.items():
            if full.rsplit(".", 1)[-1] == seg:
                areas.add(area)
                break
    return sorted(areas)


# UCP capability names per the spec (namespace dev.ucp.shopping.*),
# mapped to the five areas the engine scores.
UCP_CAPABILITY_AREAS = {
    "dev.ucp.shopping.catalog.search": "discovery",
    "dev.ucp.shopping.catalog.lookup": "discovery",
    "dev.ucp.shopping.cart": "cart",
    "dev.ucp.shopping.checkout": "checkout",
    "dev.ucp.shopping.identity": "identity",
    "dev.ucp.shopping.identity-linking": "identity",
    "dev.ucp.shopping.order": "order",
    "dev.ucp.shopping.fulfillment": "order",
    "dev.ucp.shopping.post-order": "order",
}

_URL_KEYS = ("endpoint", "url", "webhook_url", "webhook")


def _ucp_endpoint_urls(node):
    """Collect absolute http(s) URLs declared under endpoint-ish keys.

    Walks the whole UCP profile (services, capabilities, payment_handlers)
    so a profile can't score full marks while pointing at nothing.
    """
    found = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if (isinstance(k, str) and k.lower() in _URL_KEYS
                        and isinstance(v, str)):
                    u = v.strip()
                    if u.startswith("http://") or u.startswith("https://"):
                        found.append(u)
                else:
                    walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v)

    walk(node)
    seen, out = set(), []
    for u in found:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _probe_ucp_endpoints(urls, host, limit=6, timeout=5):
    """Bounded liveness probe of endpoints declared in a UCP profile.

    Only same-host endpoints are probed (off-host entries, e.g. a PSP's
    webhook, are noted, not scored). Any HTTP response below 500 counts as
    "answering" — UCP REST endpoints are POST, so a 405 still proves the
    path is live. Returns [(url, verdict)].
    """
    results = []
    for url in urls[:limit]:
        try:
            uh = (urllib.parse.urlsplit(url).hostname or "").lower()
        except Exception:
            continue
        if uh != host.lower():
            results.append((url, "off-host (not probed)"))
            continue
        r = fetch(url, ua=NORMAL_UA, timeout=timeout)
        polite()
        if r["status"] is None:
            results.append((url, "no response (%s)" % (r["error"] or "error")))
        elif r["status"] < 500:
            results.append((url, "answered (HTTP %s)" % r["status"]))
        else:
            results.append((url, "server error (HTTP %s)" % r["status"]))
    return results


def _page_title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body[:50_000],
                  flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:80]


def _discover_sitemap(base):
    """Fetch /sitemap.xml; follow sitemap indexes to find product URLs.

    Returns dict(ok, is_index, url_count, product_url_count, first_product_url).
    """
    import html as _html
    info = {"ok": False, "is_index": False, "url_count": 0,
            "product_url_count": 0, "first_product_url": None}

    def _locs(body, cap=300_000):
        return [_html.unescape(u) for u in
                re.findall(r"<loc>\s*([^<]+?)\s*</loc>", body[:cap],
                           flags=re.IGNORECASE)]

    sm = fetch(base + "/sitemap.xml", ua=NORMAL_UA)
    polite()
    if sm["status"] != 200:
        info["status"] = sm["status"]
        return info
    head = sm["body"][:5000].lower()
    if "sitemapindex" in head:
        info["is_index"] = True
        children = _locs(sm["body"])
        info["url_count"] = len(children)
        # follow the first product-ish child sitemap
        child = next((u for u in children if "product" in u.lower()), None)
        if child:
            cs = fetch(child, ua=NORMAL_UA)
            polite()
            if cs["status"] == 200:
                urls = _locs(cs["body"])
                info["url_count"] = len(urls)
                prods = [u for u in urls if "/product" in u.lower()]
                info["product_url_count"] = len(prods)
                info["first_product_url"] = prods[0] if prods else None
                info["ok"] = True
        return info
    if "<url" in head:
        urls = _locs(sm["body"])
        info["url_count"] = len(urls)
        prods = [u for u in urls if "/product" in u.lower() or "/shop" in u.lower()]
        info["product_url_count"] = len(prods)
        info["first_product_url"] = prods[0] if prods else None
        info["ok"] = True
        return info
    info["status"] = sm["status"]
    return info


def _looks_like_challenge(body):
    """Heuristic: challenge pages are small AND mention challenge markers.

    Guards against false positives from templates that merely contain words
    like 'captcha' (e.g. Shopify's form scripts in a 300KB homepage).
    """
    if len(body) > 50_000:
        return None
    low = body[:50_000].lower()
    return next((m for m in CHALLENGE_MARKERS if m in low), None)


# Categories that only make sense for an online storefront. When no
# storefront is detected these are marked N/A and excluded from scoring
# (H2) — a lead-gen/marketing site should never score F for not selling.
STOREFRONT_ONLY_CATS = {
    "AI checkout handshake (UCP + ACP)",
    "Product info AI can read",
    "Can AI find your products",
}

# Mirror of the above: scored only for non-storefronts. Storefront
# discovery (product sitemaps, feeds, llms.txt) is Category 3; a
# marketing/lead-gen site still needs AI to FIND it, so non-storefronts
# get their own discovery category instead of a free pass.
NON_STOREFRONT_ONLY_CATS = {
    "Can AI find your business",
}


def _storefront_signals(parser, product_nodes, ld_nodes, sitemap_info,
                        feed_found):
    """Return human-readable storefront signals found on the site."""
    signals = []
    for h in parser.links:
        hl = h.lower()
        if (re.search(r"/(cart|checkout|basket)(\W|$)", hl)
                or "add-to-cart" in hl or "add_to_cart" in hl):
            signals.append("cart/checkout links")
            break
    if product_nodes:
        signals.append("product structured data")
    for n in ld_nodes:
        offs = n.get("offers")
        offs = offs if isinstance(offs, list) else [offs]
        if any(isinstance(o, dict)
               and (o.get("price") or o.get("priceSpecification"))
               for o in offs):
            signals.append("readable prices")
            break
    if sitemap_info.get("product_url_count"):
        signals.append("product pages in sitemap")
    if feed_found:
        signals.append("product feed")
    return signals
# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
def check(url, name, status, detail, fix=None, severity="medium"):
    return {"id": url, "name": name, "status": status,
            "detail": detail, "fix": fix, "severity": severity}


def audit(domain):
    """Run the full audit. Returns a report dict."""
    domain = normalize_domain(domain)
    base = "https://" + domain
    started = time.time()
    checks = []
    scores = {}  # category -> (earned, max)

    # ---- fetch homepage (baseline) -------------------------------------- #
    home = fetch(base + "/", ua=NORMAL_UA)
    polite()
    if home["status"] is None:
        return {
            "domain": domain, "score": 0, "grade": "F",
            "error": "Could not reach %s (%s). Check the domain and try again."
                     % (domain, home["error"]),
            "categories": [], "fixes": [], "fetched_at": int(time.time()),
            "engine": "checklane-audit/" + VERSION,
        }
    if home["status"] >= 400:
        return {
            "domain": domain, "score": 0, "grade": "F",
            "error": "Homepage returned HTTP %s. The audit cannot score an unreachable site."
                     % home["status"],
            "categories": [], "fixes": [], "fetched_at": int(time.time()),
            "engine": "checklane-audit/" + VERSION,
        }

    parser = SiteHTMLParser()
    try:
        parser.feed(home["body"])
    except Exception:
        pass
    ld_nodes = parse_ld_json(parser.ld_json_raw)
    faq_nodes = [n for n in ld_nodes if "faqpage" in node_types(n)]
    faq_questions = 0
    for _fq in faq_nodes:
        _me = _fq.get("mainEntity", [])
        if isinstance(_me, dict):
            _me = [_me]
        if isinstance(_me, list):
            faq_questions += sum(1 for _q in _me if isinstance(_q, dict))
    visible_len = len(parser.visible_text)

    # ---- fetch robots.txt ----------------------------------------------- #
    robots = fetch(base + "/robots.txt", ua=NORMAL_UA)
    polite()
    robots_body = robots["body"] if robots["status"] == 200 else ""
    ai_posture = parse_robots_ai_posture(robots_body)

    # ---- discover sitemap early (feeds Cat2 product-page fallback + Cat3) - #
    sitemap_info = _discover_sitemap(base)

    # ============ Category 1: AI checkout handshake — UCP + ACP (20) ==== #
    # Covers BOTH protocols, with per-protocol findings:
    #   UCP (Google): 12 pts — capability profile at /.well-known/ucp
    #   ACP (OpenAI + Stripe, behind ChatGPT shopping): 8 pts — feed signals
    # Neither is a prerequisite: browser-driving agents buy through normal
    # web checkout today. These are the faster, more reliable machine paths —
    # an optimization, not a gate.
    cat, cmax = "AI checkout handshake (UCP + ACP)", 20
    ucp_state = "missing"   # missing | discovery-only | profile-invalid |
                            # unverified | valid
    ucp_areas, ucp_url, ucp_probe = [], None, []
    for path in UCP_CANDIDATES:
        r = fetch(base + path, ua=NORMAL_UA)
        polite()
        if r["status"] != 200 or not r["body"].strip():
            continue
        u = _parse_ucp_envelope(r["body"])
        if u is None:
            continue  # 200 but not a UCP document; keep looking
        ucp_url = base + path
        versions = u.get("supported_versions")
        if isinstance(versions, dict) and versions:
            # Discovery document: follow the newest versioned profile.
            ucp_state = "discovery-only"
            latest = sorted(versions.keys())[-1]
            prof_url = urllib.parse.urljoin(base + path, str(versions[latest]))
            pr = fetch(prof_url, ua=NORMAL_UA)
            polite()
            pu = _parse_ucp_envelope(pr["body"]) if pr["status"] == 200 else None
            if pu is not None:
                u, ucp_url = pu, prof_url
            else:
                break
        caps = u.get("capabilities")
        cap_names = []
        if isinstance(caps, dict):
            cap_names = list(caps.keys())
        elif isinstance(caps, list):
            for c in caps:
                if isinstance(c, str):
                    cap_names.append(c)
                elif isinstance(c, dict) and isinstance(c.get("name"), str):
                    cap_names.append(c["name"])
        ucp_areas = _ucp_capability_areas(cap_names)
        if len(ucp_areas) >= 3:
            # Fake-file guard (C2c): a profile only counts if its declared
            # endpoints actually answer.
            ucp_probe = _probe_ucp_endpoints(_ucp_endpoint_urls(u), domain)
            live = [p for p in ucp_probe if p[1].startswith("answered")]
            ucp_state = "valid" if live else "unverified"
        else:
            ucp_state = "profile-invalid"
        break
    if ucp_state == "valid":
        s = 12
        checks.append(check("ucp-valid", "UCP checkout file found and verified",
                            "pass", "Found at %s covering %s, and its declared "
                            "endpoints answered our probe. This is the fast machine "
                            "path for UCP-capable agents (e.g. in Google AI Mode / "
                            "Gemini). Browser-driving agents buy through your normal "
                            "checkout with or without it."
                            % (ucp_url, ", ".join(ucp_areas)), None))
    elif ucp_state == "unverified":
        s = 7
        probe_note = ("declared endpoints: " +
                      "; ".join("%s → %s" % (u_, v) for u_, v in ucp_probe)
                      if ucp_probe else "no endpoints declared in the profile")
        checks.append(check("ucp-unverified",
                            "UCP checkout file declared, UNVERIFIED",
                            "partial", "Found a profile at %s covering %s. "
                            "status: declared, unverified. We could not confirm "
                            "its endpoints work (%s). A static profile "
                            "pointing at dead endpoints is worse than none: agents "
                            "that trust it will fail where normal browsing would "
                            "have worked."
                            % (ucp_url, ", ".join(ucp_areas), probe_note),
                            "Make the declared endpoints live, or take the file "
                            "down until they are. A profile is a promise. Only "
                            "publish what actually answers. (Developer work: "
                            "working REST endpoints, payment handlers with signing "
                            "keys, order webhooks.)", "high"))
    elif ucp_state == "discovery-only":
        s = 6
        checks.append(check("ucp-discovery-only",
                            "UCP checkout file found, but unverified",
                            "partial", "There's a file at %s, but we couldn't "
                            "verify it fully." % ucp_url,
                            "Make sure your UCP profile loads and spells out what "
                            "agents can do (browse, cart, checkout, order help), "
                            "and that the endpoints it names actually answer. "
                            "Publishing the file is hours; the working backend "
                            "behind it is days to weeks of engineering.",
                            "medium"))
    elif ucp_state == "profile-invalid":
        s = 5
        checks.append(check("ucp-invalid", "UCP checkout file is incomplete",
                            "partial", "Found a file at %s, but it only covers %s. "
                            "agents on the UCP machine path need the full picture."
                            % (ucp_url, ", ".join(ucp_areas) or "nothing"),
                            "Complete your UCP profile using the spec's real "
                            "capability names (`dev.ucp.shopping.*`): catalog "
                            "search/lookup, cart, checkout, identity, order. And "
                            "verify every endpoint it declares actually answers. "
                            "a half-done file limits what agents can do with your "
                            "store.", "high"))
    else:
        s = 0
        checks.append(check("ucp-missing", "No UCP checkout file found",
                            "fail", "We checked the standard discovery paths "
                            "(starting with the canonical `/.well-known/ucp`). "
                            "nothing there. Note: this is the faster machine path "
                            "for UCP-capable agents, not a prerequisite. "
                            "browser-driving agents buy through normal checkout "
                            "today.",
                            "Publish your UCP capability profile at `/.well-known/ucp` "
                            "(extensionless: the canonical discovery path in the "
                            "UCP spec; `/.well-known/ucp.json` also works as a "
                            "fallback). Be honest about the work: the file itself "
                            "is hours, but a REAL UCP implementation (working "
                            "REST endpoints, payment handlers with signing keys, "
                            "order webhooks) is days to weeks of backend "
                            "engineering. A static JSON pointing at dead endpoints "
                            "is worse than none. Platform shortcuts: on Shopify, "
                            "turn on Shopify's Agentic sales channel / AI tools. "
                            "they publish the manifest for you (fast path). On a "
                            "custom build, scope it as a backend project "
                            "(days–weeks), not an afternoon task.", "high"))
    scores[cat] = (s, 12)
    CAT1 = cat  # ACP checks (below, after product sampling) add to this bucket

    # ============ Category 2: Structured product data (20) =============== #
    cat, cmax = "Product info AI can read", 20
    product_nodes = [n for n in ld_nodes if _is_product_node(n)]
    org_nodes = [n for n in ld_nodes
                 if "organization" in node_types(n) or "localbusiness" in node_types(n)]
    product_source = "homepage"
    if not product_nodes and sitemap_info["first_product_url"]:
        # Fairness: Product markup usually lives on product pages, not the home
        # page. Sample one before scoring.
        pp = fetch(sitemap_info["first_product_url"], ua=NORMAL_UA)
        polite()
        if pp["status"] == 200:
            p2 = SiteHTMLParser()
            try:
                p2.feed(pp["body"])
            except Exception:
                pass
            pnodes = parse_ld_json(p2.ld_json_raw)
            pprods = [n for n in pnodes if _is_product_node(n)]
            if pprods:
                product_nodes = pprods
                ld_nodes = pnodes
                product_source = "sampled product page"
    s = 0
    if ld_nodes:
        s += 6
        checks.append(check("jsonld-present", "Labeled data found",
                            "pass", "Found %d labeled data block(s) on your homepage. "
                            "AI reads labels first. Good." % len(ld_nodes), None))
    else:
        checks.append(check("jsonld-present", "No labeled data found",
                            "fail", "No labeled product data on your homepage.",
                            "Add labeled product info to your pages (the technical "
                            "name is 'structured data'). AI reads labels before "
                            "anything else. Unlabeled pages are invisible to it.",
                            "high"))
    if product_nodes:
        s += 6
        checks.append(check("product-markup", "Products are labeled",
                            "pass", "Found labels on %d product(s), spotted on your %s."
                            % (len(product_nodes), product_source), None))
        # completeness across product nodes
        fields = ["name", "image", "brand", "sku", "gtin", "mpn",
                  "offers", "description"]
        present = set()
        for n in product_nodes:
            for f in fields:
                if n.get(f):
                    present.add(f)
        offers_ok = any(isinstance(n.get("offers"), (dict, list)) and n.get("offers")
                        for n in product_nodes)
        completeness = len(present) / len(fields)
        s += round(8 * completeness)
        missing = [f for f in fields if f not in present]
        if missing:
            checks.append(check("product-completeness", "Product labels complete",
                                "partial" if completeness >= 0.5 else "fail",
                                "%d of %d recommended details present. Missing: %s."
                                % (len(present), len(fields), ", ".join(missing)),
                                "Fill in the missing details: %s. AI uses price and "
                                "stock info to compare and buy. Gaps mean lost sales."
                                % ", ".join(missing), "medium"))
        else:
            checks.append(check("product-completeness", "Product labels complete",
                                "pass", "All %d recommended details filled in."
                                % len(fields), None))
        if not offers_ok:
            checks.append(check("offers-present", "Prices AI can read",
                                "fail", "Your products are labeled, but none show a "
                                "price AI can read.",
                                "Add price, currency, and stock status to each "
                                "product's labels. Without readable prices, AI can't "
                                "show or sell your products.", "high"))
            s = max(0, s - 4)
        # ---- Google merchant-listing fields (non-critical per Google) ---- #
        # Dogfood lesson: Search Console flags missing shippingDetails and
        # hasMerchantReturnPolicy inside offers as merchant-listing issues.
        # Scores only move up: these add points, never subtract.
        # RC-2 (Board m4): a stub with only @type and no content earns
        # nothing; merchants must state something real to score.
        def _has_content(node):
            return (isinstance(node, dict)
                    and any(k != "@type" for k in node.keys()))
        _offer_nodes = []
        for _n in product_nodes:
            _offs = _n.get("offers")
            if isinstance(_offs, dict):
                _offer_nodes.append(_offs)
            elif isinstance(_offs, list):
                _offer_nodes.extend(o for o in _offs if isinstance(o, dict))
        _has_ship = any(_has_content(o.get("shippingDetails"))
                        for o in _offer_nodes)
        _has_ret = any(_has_content(o.get("hasMerchantReturnPolicy"))
                       for o in _offer_nodes)
        if _has_ship and _has_ret:
            s += 2
            checks.append(check("merchant-listing-details",
                                "Shipping and return labels present",
                                "pass", "Your offers include shipping details "
                                "and a return policy AI can read. AI shoppers "
                                "check both before deciding they can complete "
                                "a purchase confidently.", None))
        elif _has_ship or _has_ret:
            s += 1
            _have = "shipping details" if _has_ship else "a return policy"
            _miss = "a return policy" if _has_ship else "shipping details"
            checks.append(check("merchant-listing-details",
                                "One merchant-listing detail missing",
                                "partial", "Your offers include %s but not "
                                "%s. Google lists both as merchant-listing "
                                "suggestions." % (_have, _miss),
                                "Add %s to your offers' labels "
                                "(shippingDetails, hasMerchantReturnPolicy). "
                                "AI shoppers check shipping and returns before "
                                "they buy; unlabeled policies look like hidden "
                                "terms." % _miss, "low"))
        else:
            checks.append(check("merchant-listing-details",
                                "Shipping and return labels missing",
                                "partial", "Your offers don't label shipping "
                                "details or a return policy. Google lists both "
                                "as merchant-listing suggestions (non-critical, "
                                "they never block search results).",
                                "Add shippingDetails and hasMerchantReturnPolicy "
                                "to your offers' labels. AI shoppers check "
                                "shipping cost and returns before they buy; "
                                "unlabeled policies look like hidden terms.",
                                "low"))
        # ---- Review labels: informational only, never scored --------------- #
        # Google suggests aggregateRating/review as a non-critical
        # improvement. We report presence and NEVER penalize absence:
        # pressuring merchants toward reviews they haven't earned invites
        # fabricated social proof.
        if any(n.get("aggregateRating") or n.get("review")
               for n in product_nodes):
            checks.append(check("review-signals", "Review labels found",
                                "pass", "Your products carry review labels "
                                "(aggregateRating/review). Google can show "
                                "your ratings in search results.", None))
        else:
            checks.append(check("review-signals", "No review labels",
                                "partial", "No review labels on your products. "
                                "Google suggests them so products can show "
                                "ratings in search, but they never block "
                                "results.",
                                "Add aggregateRating and review labels only "
                                "if you have real customer reviews. Never "
                                "invent reviews or ratings: fabricated social "
                                "proof gets penalized and destroys trust.",
                                "low"))
    else:
        checks.append(check("product-markup", "Products aren't labeled",
                            "fail", "No product labels on your homepage%s."
                            % (" or a sampled product page"
                               if sitemap_info["first_product_url"] else ""),
                            "Label your products: name, photo, price, stock status, "
                            "brand. This is the single biggest win for most stores.",
                            "high"))
    if org_nodes:
        s += 2
        checks.append(check("org-markup", "Store identity labels",
                            "pass", "Found your site's identity labels. AI can "
                            "verify who you are.", None))
    else:
        checks.append(check("org-markup", "Store identity labels",
                            "partial", "No identity labels found for your site.",
                            "Add your business name, web address, and logo in labeled "
                            "format. It's the easiest way for AI to verify you're "
                            "legit.", "low"))
    scores[cat] = (min(s, cmax), cmax)

    # ---- Category 1 (continued): ACP feed-eligibility signals (8) ------- #
    # ACP (Agentic Commerce Protocol, OpenAI + Stripe) powers ChatGPT
    # shopping. There is NO on-site discovery file for ACP: merchant
    # eligibility is a product-feed upload + OpenAI partner onboarding, both
    # handled off-site. What a remote audit CAN verify are the signals that
    # make a catalog feed-eligible: product identifiers and policy URLs.
    acp_s = 0
    id_fields = set()
    for _n in product_nodes:
        for _f in ("gtin", "gtin8", "gtin13", "gtin14", "mpn", "sku"):
            if _n.get(_f):
                id_fields.add(_f)
    _strong_ids = id_fields & {"gtin", "gtin8", "gtin13", "gtin14", "mpn"}
    if _strong_ids:
        acp_s += 4
        checks.append(check("acp-feed-signals",
                            "ChatGPT feed signals: product IDs",
                            "pass", "Your product labels include %s. The "
                            "identifier fields ChatGPT's product feed (ACP) keys "
                            "on." % ", ".join(sorted(id_fields)), None))
    elif "sku" in id_fields:
        acp_s += 2
        checks.append(check("acp-feed-signals",
                            "ChatGPT feed signals: product IDs",
                            "partial", "You label SKUs, but no GTIN/MPN. ChatGPT's "
                            "feed spec keys on GTINs. SKUs alone weaken matching.",
                            "Add GTIN/MPN to your product labels wherever your "
                            "products have barcodes or manufacturer part numbers. "
                            "It's the field ChatGPT's product feed matches on.",
                            "medium"))
    elif product_nodes:
        checks.append(check("acp-feed-signals",
                            "ChatGPT feed signals: product IDs",
                            "fail", "Your products are labeled, but none carry a "
                            "GTIN, MPN, or SKU that a product feed could key on.",
                            "Add product identifiers (GTIN/MPN/SKU) to your product "
                            "labels. ChatGPT's feed spec keys on GTINs. Without "
                            "identifiers your catalog is hard to match.",
                            "medium"))
    else:
        checks.append(check("acp-feed-signals",
                            "ChatGPT feed signals: product IDs",
                            "fail", "No product labels found, so no product IDs "
                            "either.",
                            "Without product labels there is nothing for ChatGPT's "
                            "product feed to key on. Label your products first "
                            "(see 'Products are labeled' above), including "
                            "GTIN/MPN where your products have barcodes.",
                            "medium"))
    _ship_links = [h for h in parser.links if "ship" in h.lower()]
    _ret_links = [h for h in parser.links
                  if any(k in h.lower() for k in ("return", "refund"))]
    if _ship_links and _ret_links:
        acp_s += 4
        checks.append(check("acp-policies", "ChatGPT feed signals: policy pages",
                            "pass", "Found shipping and returns/refund policy "
                            "links. The policy signals ChatGPT's feed expects.",
                            None))
    elif _ship_links or _ret_links:
        acp_s += 2
        _which = "shipping" if _ship_links else "returns/refund"
        checks.append(check("acp-policies", "ChatGPT feed signals: policy pages",
                            "partial", "Found %s policy links, but not both "
                            "shipping and returns." % _which,
                            "Publish both a shipping policy and a returns/refund "
                            "policy page, linked from your homepage. ChatGPT's "
                            "product feed requires shipping info per item, and "
                            "buyers (human or agent) expect policy pages.",
                            "medium"))
    else:
        checks.append(check("acp-policies", "ChatGPT feed signals: policy pages",
                            "fail", "No shipping or returns/refund policy links "
                            "found on your homepage.",
                            "Publish a shipping policy page and a returns/refund "
                            "policy page, linked from your homepage. ChatGPT's "
                            "product feed requires shipping info per item. "
                            "ChatGPT-side path (ACP): there is no on-site file. "
                            "eligibility is a product feed upload plus OpenAI "
                            "partner onboarding, handled off-site. Apply via "
                            "OpenAI's merchant onboarding and publish your "
                            "catalog per OpenAI's Product Feed Spec (id, title, "
                            "price, availability, link, image, brand, GTIN, "
                            "shipping). On Shopify or Etsy you're auto-enrolled. "
                            "nothing to apply for. This audit can't confirm your "
                            "onboarding status; only OpenAI can.", "medium"))
    _s1, _ = scores[CAT1]
    scores[CAT1] = (_s1 + acp_s, 20)

    # ============ Category 3: Feed discoverability (20) ================== #
    cat, cmax = "Can AI find your products", 20
    s = 0
    si = sitemap_info
    if si["ok"]:
        s += 8
        detail = "%d page(s) listed" % si["url_count"]
        if si["is_index"]:
            detail += " (through your sitemap index)"
        if si["product_url_count"]:
            s += 4
            detail += "; about %d product pages" % si["product_url_count"]
        checks.append(check("sitemap", "Sitemap found",
                            "pass", detail + ".", None))
    elif si.get("status") == 200:
        s += 3
        checks.append(check("sitemap", "Sitemap found",
                            "partial", "Your sitemap exists, but we couldn't read "
                            "it properly.",
                            "Make sure /sitemap.xml is a valid sitemap listing your "
                            "product pages. It's how AI discovers your catalog.",
                            "medium"))
    else:
        checks.append(check("sitemap", "No sitemap found",
                            "fail", "No sitemap found (got a %s response)."
                            % si.get("status"),
                            "Publish a sitemap at /sitemap.xml listing your product "
                            "pages. It's the main way AI finds everything you sell.",
                            "high"))
    # Platform / feed signals
    pj = fetch(base + "/products.json?limit=1", ua=NORMAL_UA)
    polite()
    feed_found = None
    if pj["status"] == 200:
        try:
            doc = json.loads(pj["body"])
            if isinstance(doc, dict) and isinstance(doc.get("products"), list):
                feed_found = "Shopify product feed (%d product(s) checked)" % len(
                    doc["products"])
        except Exception:
            pass
    if not feed_found:
        for path, label in [("/feed", "RSS/Atom feed"),
                            ("/products.xml", "products.xml feed"),
                            ("/google-feed.xml", "Google Shopping-style feed")]:
            r = fetch(base + path, ua=NORMAL_UA)
            polite()
            if r["status"] == 200 and len(r["body"]) > 500:
                feed_found = "%s at %s" % (label, path)
                break
    if feed_found:
        s += 6
        checks.append(check("product-feed", "Product feed found",
                            "pass", "Found: %s." % feed_found, None))
    else:
        checks.append(check("product-feed", "No product feed found",
                            "fail", "Looked for a product feed at the usual addresses. "
                            "None found.",
                            "Publish a product feed (Shopify stores get one "
                            "automatically; others can use a Google-Shopping-style "
                            "feed). If AI can't list your catalog, it can't sell it.",
                            "high"))
    # Agent instructions file: /llms.txt (the established LLM-discovery
    # convention) and/or /agents.md. NOT repo-root AGENTS.md — that's a
    # separate coding-agent convention for software projects, not websites.
    welcome_found = None
    # welcome_present: any /llms.txt or /agents.md fetched OK (>200 bytes),
    # regardless of whether it mentions "agent". Used by the
    # business-discovery category so a plumber's plain-English file counts.
    welcome_present = None
    for _wpath in ("/llms.txt", "/agents.md"):
        _wr = fetch(base + _wpath, ua=NORMAL_UA)
        polite()
        if _wr["status"] == 200 and len(_wr["body"]) > 200:
            if welcome_present is None:
                welcome_present = (_wpath, len(_wr["body"]))
            if "agent" in _wr["body"][:2000].lower():
                welcome_found = (_wpath, len(_wr["body"]))
                break
    if welcome_found:
        s += 2
        checks.append(check("agents-md", "AI welcome note found",
                            "pass", "Found your %s (%d bytes). Your site talks "
                            "to AI visitors directly." % welcome_found, None))
    else:
        checks.append(check("agents-md", "No AI welcome note",
                            "fail", "No /llms.txt or /agents.md file found.",
                            "Publish an /llms.txt file. An emerging "
                            "convention some AI tools read, and/or an "
                            "/agents.md as your agent welcome file: what you "
                            "sell, how to browse your catalog, shipping basics, "
                            "and how to reach you. (A repo-root AGENTS.md is a "
                            "different thing: a coding-agent convention for "
                            "software projects, not websites.)", "medium"))
    scores[cat] = (min(s, cmax), cmax)

    # ============ Category 4: AI bot access (20) ========================= #
    # WHAT THIS ACTUALLY MEASURES (H1): whether known AI crawlers and
    # on-demand fetchers can load the homepage. It does NOT measure whether
    # "AI shoppers" are blocked — blocking a training crawler does not block
    # AI shopping. Browser-driving agents buy through normal web checkout,
    # and ChatGPT shopping runs on ACP product feeds.
    cat, cmax = "AI bot access", 20
    s = 0
    checks.append(check("bot-test-scope", "What this test measures",
                        "pass", "This checks whether known AI crawlers and "
                        "on-demand fetchers can load your homepage, not whether "
                        "\"AI shoppers\" are blocked. Blocking training crawlers "
                        "(GPTBot, ClaudeBot) does NOT block AI shopping: "
                        "browser-driving agents buy through normal checkout, and "
                        "ChatGPT shopping runs on product feeds. On storefronts "
                        "we also probe up to two cart/checkout pages you link "
                        "to, since some sites challenge bots there but not on "
                        "the homepage.", None))
    base_title = _page_title(home["body"]).lower()
    base_len = len(home["body"])
    # Sanity: is the baseline itself a challenge page?
    base_challenge = _looks_like_challenge(home["body"])
    if base_challenge:
        checks.append(check("agent-ua:baseline", "Basic read test",
                            "fail", "Even a normal visit got a bot-check page "
                            "mentioning %r. Your site challenges automated "
                            "readers." % base_challenge,
                            "Your security challenges automated readers before they "
                            "see any content. AI crawlers and fetchers read pages "
                            "the same way this test does. Let the discovery "
                            "fetchers (OAI-SearchBot, Claude-SearchBot, "
                            "PerplexityBot, ChatGPT-User) through, or they can't "
                            "include your pages in AI answers.", "high"))
    per_ua = round(cmax / len(AGENT_UAS), 2)
    # Fetch each agent UA in parallel (polite delay kept inside each worker).
    # Results are consumed in AGENT_UAS order so check output stays stable.
    def _agent_fetch(item):
        label, (ua, _role) = item
        r = fetch(base + "/", ua=ua)
        polite()
        return label, r

    agent_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for label, r in pool.map(_agent_fetch, list(AGENT_UAS.items())):
            agent_results[label] = r
    for label, (ua, role) in AGENT_UAS.items():
        r = agent_results[label]
        blocked, reason = False, ""
        if r["status"] is None:
            blocked, reason = True, "request failed (%s)" % r["error"]
        elif r["status"] in BLOCKED_STATUSES or r["status"] >= 400:
            blocked, reason = True, "HTTP %s" % r["status"]
        else:
            hit = _looks_like_challenge(r["body"])
            if hit:
                # Small body + challenge marker = challenge page, not content.
                # (Guards against templates that merely mention 'captcha'.)
                blocked = True
                reason = ("challenge page mentioning %r "
                          "(response far smaller than the normal page)" % hit)
            elif base_title and _page_title(r["body"]).lower() != base_title:
                blocked = True
                reason = ("unexpected page served (title %r differs from the "
                          "normal page, likely a bot wall)" %
                          _page_title(r["body"])[:60])
        if blocked:
            checks.append(check("agent-ua:" + label, "AI visitor: " + label,
                                "fail", "Couldn't load your store: %s. (%s.)"
                                % (reason, role),
                                "Your site blocked %s. %s. This test fetches like "
                                "an automated AI visitor. A block here means that "
                                "particular crawler/fetcher can't read your pages. "
                                "What it does NOT mean: that AI shopping is "
                                "blocked. If the block is deliberate (e.g. keeping "
                                "training crawlers out), fine, but make sure the "
                                "discovery fetchers stay allowed, or AI answers "
                                "can't cite you." % (label, role), "high"))
        else:
            s += per_ua
            checks.append(check("agent-ua:" + label, "AI visitor: " + label,
                                "pass", "Loaded fine. Sees the same page a person "
                                "does. (%s.)" % role, None))
    # ---- cart/checkout path probes (Board condition 4) ------------------ #
    # Homepage-only probing misses sites that let crawlers read marketing
    # pages but challenge them at /cart or /checkout. For storefronts,
    # probe up to two discovered same-host cart/checkout URLs with a small
    # set of discovery fetchers. Informational checks (medium severity);
    # scoring stays on the homepage probes so one weird path can't tank
    # the category.
    _CART_PATH_RE = re.compile(r"/(cart|checkout|basket)(\W|$)", re.I)
    cart_urls = []
    for h in parser.links:
        hl = (h or "").strip()
        if not hl or hl.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        lhl = hl.lower()
        if "add-to-cart" in lhl or "add_to_cart" in lhl \
                or _CART_PATH_RE.search(hl):
            absu = urllib.parse.urljoin(base + "/", hl)
            if urllib.parse.urlsplit(absu).netloc.lower() == domain.lower() \
                    and absu not in cart_urls:
                cart_urls.append(absu)
        if len(cart_urls) >= 2:
            break
    _PROBE_UAS = ["OAI-SearchBot (ChatGPT search fetcher)",
                  "PerplexityBot (Perplexity discovery)"]
    for curl in cart_urls:
        for label in _PROBE_UAS:
            ua, _role = AGENT_UAS[label]
            r = fetch(curl, ua=ua)
            polite()
            blocked, reason = False, ""
            if r["status"] is None:
                blocked, reason = True, "request failed (%s)" % r["error"]
            elif r["status"] in BLOCKED_STATUSES or r["status"] >= 400:
                blocked, reason = True, "HTTP %s" % r["status"]
            elif _looks_like_challenge(r["body"]):
                blocked, reason = True, "challenge page"
            path_disp = urllib.parse.urlsplit(curl).path or "/"
            short_label = label.split(" (")[0]
            cid = "agent-ua:cart-path:%s:%s" % (short_label, path_disp)
            if blocked:
                checks.append(check(
                    cid, "AI visitor at %s: %s" % (path_disp, short_label),
                    "fail",
                    "Couldn't load %s as %s: %s. AI assistants that fetch "
                    "pages on a shopper's behalf may hit the same wall at "
                    "checkout." % (path_disp, short_label, reason),
                    "Your site blocked %s at %s (%s). Anti-bot protection "
                    "on checkout is often deliberate and reasonable, but "
                    "know that AI assistants which fetch pages for shoppers "
                    "may be affected too. If the block wasn't intentional, "
                    "let the discovery fetchers through."
                    % (short_label, path_disp, reason), "medium"))
            else:
                checks.append(check(
                    cid, "AI visitor at %s: %s" % (path_disp, short_label),
                    "pass", "Loaded fine as %s." % short_label, None))
    s = min(round(s), cmax)
    if s == cmax:
        checks.append(check("agent-access-summary", "Overall AI bot access",
                            "pass", "All %d tested AI crawlers and fetchers can "
                            "read your homepage. Note: browser-driving shopping "
                            "agents were never blocked by crawler rules in the "
                            "first place. They buy through normal checkout."
                            % len(AGENT_UAS), None))
    scores[cat] = (s, cmax)

    # ============ Category 5: Machine-readability basics (20) ============= #
    # ---------------- site-type detection (H2) --------------------------- #
    sf_signals = _storefront_signals(parser, product_nodes, ld_nodes,
                                     sitemap_info, feed_found)
    site_type = "storefront" if len(sf_signals) >= 2 else "non-storefront"

    cat, cmax = "Can AI read your pages", 20
    s = 0
    blocked_tokens = [t for t, p in ai_posture.items() if p == "blocked"]
    if blocked_tokens:
        checks.append(check("robots-ai", "Site rules for AI visitors",
                            "fail", "Your site rules tell these AI visitors to stay "
                            "out: %s." % ", ".join(blocked_tokens),
                            "Your robots.txt blocks AI visitors (%s). If that's "
                            "deliberate (e.g. keeping training crawlers out of "
                            "your content), fine. Blocking them does not block "
                            "AI shopping. But a blanket block also keeps you out "
                            "of AI search answers and product discovery. If those "
                            "lines came from a template, delete them."
                            % ", ".join(blocked_tokens), "high"))
    else:
        s += 8
        checks.append(check("robots-ai", "Site rules for AI visitors",
                            "pass", "Your site rules don't block any AI visitors.",
                            None))
    # JS-only rendering heuristic
    if home.get("truncated") and visible_len < 300:
        s += 3
        checks.append(check("static-content", "Content AI can see",
                            "partial", "Your homepage is heavy on scripts, so we "
                            "couldn't fully confirm your content loads without "
                            "JavaScript.",
                            "If your titles, prices, and descriptions only appear "
                            "after JavaScript runs, AI reading the raw page misses "
                            "them. Make sure key content is in the initial page load.",
                            "medium"))
    elif visible_len < 300 and parser.script_srcs >= 5:
        checks.append(check("static-content", "Content AI can see",
                            "fail", "Only ~%d characters of readable text in the raw "
                            "page, with %d scripts. Your content probably needs "
                            "JavaScript to appear." % (visible_len,
                                                       parser.script_srcs),
                            "Put key content (titles, prices, descriptions) directly "
                            "in the page, not behind JavaScript. AI fetchers read "
                            "the raw page first. Content that only appears after "
                            "JavaScript runs is missed by simpler readers. "
                            "(Agent-mode shoppers drive real browsers, so this is "
                            "about robustness, not a hard block.)",
                            "high"))
    elif visible_len < 300:
        # Thin page: cap at partial marks, scaled by content length. A
        # near-empty page must not earn full marks for "content AI can see".
        thin_s = min(4, round(6 * visible_len / 300))
        s += thin_s
        checks.append(check("static-content", "Content AI can see",
                            "partial", "~%d characters of readable text. Thin "
                            "for AI readers. A few hundred characters of real "
                            "copy describing what you do helps AI understand "
                            "and cite your pages." % visible_len,
                            "Add substantive copy to your homepage: a few "
                            "hundred characters describing what you offer. AI "
                            "readers work from visible text; thin pages give "
                            "them little to work with.", "medium"))
    else:
        s += 6
        checks.append(check("static-content", "Content AI can see",
                            "pass", "~%d characters of readable text. Your content "
                            "loads without JavaScript." % visible_len, None))
    basics = [
        ("page-title", "Page title", bool(parser.title.strip())),
        ("meta-description", "Page description", bool(parser.meta.get("description", "").strip())),
        ("h1", "Main heading", parser.h1_count > 0),
        ("canonical", "Canonical link", bool(parser.canonical)),
    ]
    basics_ok = sum(1 for _, _, ok in basics if ok)
    s += round(6 * basics_ok / len(basics))
    missing_basics = [label for _, label, ok in basics if not ok]
    if missing_basics:
        checks.append(check("html-basics", "Page basics",
                            "partial" if basics_ok >= 2 else "fail",
                            "%d of 4 basics present. Missing: %s."
                            % (basics_ok, ", ".join(missing_basics)),
                            "Add what's missing (%s). Takes minutes, and every "
                            "reader, search engine or AI, relies on these."
                            % ", ".join(missing_basics), "low"))
    else:
        checks.append(check("html-basics", "Page basics",
                            "pass", "Page title, description, main heading, and "
                            "canonical link all present.", None))
    # FAQPage schema: storefronts only. Non-storefronts already score this as
    # biz-faq in Category 6; scoring it here too would double-count one signal.
    if site_type == "storefront":
        if faq_questions:
            s += 4 if faq_questions >= 3 else 2
            checks.append(check("faq-schema", "Q&A labels found",
                                "pass", "Found %d labeled questions and answers. "
                                "AI agents can use your answers directly."
                                % faq_questions, None))
        elif faq_nodes:
            checks.append(check("faq-schema", "Empty Q&A labels",
                                "partial", "Your Q&A labels list no questions.",
                                "Fill in your FAQPage structured data with real "
                                "questions and answers. Empty labels give AI "
                                "agents nothing to quote.", "low"))
        else:
            checks.append(check("faq-schema", "No Q&A labels",
                                "fail", "No labeled Q&A found on your homepage.",
                                "Add FAQPage structured data to your homepage's "
                                "FAQ section. It lets AI agents use your answers "
                                "directly when shoppers ask questions.", "low"))
    # product links in static HTML (informational)
    prod_links = sum(1 for h in parser.links
                     if "/product" in h.lower())
    if prod_links:
        checks.append(check("product-links", "Product links found",
                            "pass", "%d product links found. AI can browse your "
                            "catalog." % prod_links, None))
    scores[cat] = (min(s, cmax), cmax)

    # ============ Category 6: AI discovery, non-storefronts (20) ======== #
    # Storefront discovery (product sitemaps, feeds, welcome file) is
    # Category 3, which is N/A for non-storefronts. But a site that doesn't
    # sell online still needs AI to FIND it — so non-storefronts are scored
    # here instead. N/A for storefronts (their discovery is Category 3).
    # Reuses data already fetched above: no extra network calls.
    cat, cmax = "Can AI find your business", 20
    s = 0
    # AI welcome file: /llms.txt or /agents.md (fetched in Category 3)
    if welcome_found:
        _wpath, _wlen = welcome_found
        if _wlen >= 1000:
            s += 6
            checks.append(check("biz-llms", "AI welcome file",
                                "pass", "Found your %s (%d bytes): substantive "
                                "guidance for AI visitors." % (_wpath, _wlen),
                                None))
        else:
            s += 4
            checks.append(check("biz-llms", "AI welcome file",
                                "partial", "Found your %s, but it's thin (%d "
                                "bytes), so AI visitors get little guidance."
                                % (_wpath, _wlen),
                                "Flesh out your %s: what you do, who it's for, "
                                "your key pages, and how to reach you. A few "
                                "hundred words beats a stub." % _wpath, "low"))
    elif welcome_present:
        _wpath, _wlen = welcome_present
        s += 4
        checks.append(check("biz-llms", "AI welcome file",
                            "partial", "Found your %s, but it doesn't address "
                            "AI visitors: AI tools look for guidance addressed "
                            "to them." % _wpath,
                            "Add a short section addressed to AI assistants "
                            "(e.g. \"If you are an AI assistant...\") to your "
                            "%s: what you do, who it's for, and how to reach "
                            "you." % _wpath, "low"))
    else:
        checks.append(check("biz-llms", "AI welcome file",
                            "fail", "No /llms.txt or /agents.md file found.",
                            "Publish an /llms.txt file: what you do, who it's "
                            "for, your key pages, and how to reach you. It's "
                            "an emerging convention some AI tools read.",
                            "medium"))
    # sitemap.xml presence (product-page bonus is Category 3 territory)
    if sitemap_info["ok"]:
        s += 6
        checks.append(check("biz-sitemap", "Sitemap found",
                            "pass", "%d page(s) listed%s."
                            % (sitemap_info["url_count"],
                               " (through your sitemap index)"
                               if sitemap_info["is_index"] else ""), None))
    elif sitemap_info.get("status") == 200:
        s += 3
        checks.append(check("biz-sitemap", "Sitemap found",
                            "partial", "Your sitemap exists, but we couldn't "
                            "read it properly.",
                            "Make sure /sitemap.xml is a valid sitemap listing "
                            "your pages. It's how AI discovers everything you "
                            "offer.", "medium"))
    else:
        checks.append(check("biz-sitemap", "Sitemap found",
                            "fail", "No sitemap found (got a %s response)."
                            % sitemap_info.get("status"),
                            "Publish a sitemap at /sitemap.xml listing your "
                            "pages. It's how search engines and AI crawlers "
                            "discover all your pages.",
                            "high"))
    # Open Graph / share-tag completeness
    _og_fields = ["og:title", "og:description", "og:image", "twitter:card"]
    _og_ok = sum(1 for _k in _og_fields if parser.meta.get(_k, "").strip())
    s += round(4 * _og_ok / len(_og_fields))
    _og_missing = [_k for _k in _og_fields
                   if not parser.meta.get(_k, "").strip()]
    if _og_missing:
        checks.append(check("biz-og", "Social/share tags",
                            "partial" if _og_ok >= 2 else "fail",
                            "%d of 4 share tags present. Missing: %s."
                            % (_og_ok, ", ".join(_og_missing)),
                            "Add the missing share tags (%s). They control how "
                            "your pages look when shared or cited, including "
                            "by AI assistants that show link previews."
                            % ", ".join(_og_missing), "low"))
    else:
        checks.append(check("biz-og", "Social/share tags",
                            "pass", "og:title, og:description, og:image, and "
                            "twitter:card all present.", None))
    # FAQ content presence
    if any("faqpage" in node_types(n) for n in ld_nodes):
        s += 4
        checks.append(check("biz-faq", "FAQ content",
                            "pass", "Found FAQ structured data. AI can lift "
                            "your answers directly.", None))
    elif re.search(r"frequently asked|\bfaq\b", parser.visible_text,
                   re.IGNORECASE):
        s += 2
        checks.append(check("biz-faq", "FAQ content",
                            "partial", "You mention a FAQ, but it isn't labeled "
                            "data.",
                            "Mark up your FAQ with FAQPage structured data so "
                            "AI can lift your answers directly into responses.",
                            "low"))
    else:
        checks.append(check("biz-faq", "FAQ content",
                            "fail", "No FAQ content found.",
                            "If you answer the same questions repeatedly, "
                            "publish a FAQ section and label it with FAQPage "
                            "structured data. FAQ answers are among the "
                            "easiest content for AI to quote directly.",
                            "low"))
    scores[cat] = (min(s, cmax), cmax)

    # ---------------- assemble report ------------------------------------ #
    categories = []
    for name, (earned, cmax_) in scores.items():
        if site_type == "non-storefront" and name in STOREFRONT_ONLY_CATS:
            na, na_reason = True, "no-storefront"
        elif site_type == "storefront" and name in NON_STOREFRONT_ONLY_CATS:
            na, na_reason = True, "is-storefront"
        else:
            na, na_reason = False, ""
        cat_checks = [c for c in checks if c["id"].split(":")[0] in
                      _cat_check_ids(name)]
        categories.append({"name": name,
                           "score": 0 if na else earned,
                           "max": 0 if na else cmax_,
                           "checks": cat_checks,
                           "na": na,
                           "na_reason": na_reason})
    na_ids = set()
    for _c in categories:
        if _c.get("na"):
            na_ids.update(x["id"] for x in _c["checks"])
    total = sum(c["score"] for c in categories)
    total_max = sum(c["max"] for c in categories)
    score = round(100 * total / total_max) if total_max else 0
    grade = ("A" if score >= 85 else "B" if score >= 70 else "C"
             if score >= 55 else "D" if score >= 40 else "F")
    # §3 guarantee: EVERY check with a fix is ranked — nothing skipped.
    fixes = [c for c in checks
             if c["status"] in ("fail", "partial") and c["fix"]
             and c["id"] not in na_ids]
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    fixes.sort(key=lambda c: (sev_rank.get(c["severity"], 3), c["name"]))
    return {
        "domain": domain,
        "score": score,
        "grade": grade,
        "summary": _summary(score, grade),
        "site_type": site_type,
        "site_type_signals": sf_signals,
        "categories": categories,
        "fixes": [{"id": f["id"], "check": f["name"], "severity": f["severity"],
                   "detail": f["detail"], "fix": f["fix"]} for f in fixes],
        "fetched_at": int(time.time()),
        "duration_s": round(time.time() - started, 1),
        "engine": "checklane-audit/" + VERSION,
    }


def _cat_check_ids(cat_name):
    return {
        "AI checkout handshake (UCP + ACP)": {
            "ucp-valid", "ucp-unverified", "ucp-discovery-only",
            "ucp-invalid", "ucp-missing",
            "acp-feed-signals", "acp-policies"},
        "Product info AI can read": {"jsonld-present", "product-markup",
                                    "product-completeness", "offers-present",
                                    "merchant-listing-details", "review-signals",
                                    "org-markup"},
        "Can AI find your products": {"sitemap", "product-feed", "agents-md"},
        "AI bot access": {"bot-test-scope", "agent-ua", "agent-access-summary"},
        "Can AI read your pages": {"robots-ai", "static-content",
                                       "html-basics", "faq-schema",
                                       "product-links"},
        "Can AI find your business": {"biz-llms", "biz-sitemap", "biz-og",
                                      "biz-faq"},
    }.get(cat_name, set())


def _summary(score, grade):
    if score >= 85:
        return ("Excellent. Your site speaks AI's language. The key signals AI "
                "agents need are all here; what's left is polish.")
    if score >= 70:
        return ("Nearly there. A few gaps keep some AI agents from fully reading "
                "or transacting with your site. The fix list closes them.")
    if score >= 55:
        return ("Halfway. AI can probably find you, but it'll struggle to read "
                "your content or use the fast machine paths. Start with the "
                "high-priority fixes.")
    if score >= 40:
        return ("Needs work. AI agents will struggle with the machine-readable "
                "layer of your site. Browser-based agents can still buy through "
                "normal checkout, but slowly, and you're hard to compare. The fix "
                "list is your roadmap.")
    return ("Not ready yet. The fast machine paths (UCP/ACP) are missing and the "
            "basics are thin. Browser-driving agents can still reach you through "
            "normal checkout, but you're hard to compare and slow to transact "
            "with. Start at the top of the fix list.")


def main():
    import sys
    if len(sys.argv) != 2:
        print("usage: python3 audit.py example.com", file=sys.stderr)
        sys.exit(2)
    report = audit(sys.argv[1])
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
