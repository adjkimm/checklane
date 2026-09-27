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

import json
import ipaddress
import re
import socket
import time
import urllib.parse
import urllib.request
import urllib.error
from html.parser import HTMLParser

VERSION = "1.0.0-m1"
FETCH_TIMEOUT = 12
MAX_BODY = 1_000_000  # 1MB: some Shopify homepages carry 300KB+ of head scripts
POLITENESS_DELAY = 0.4  # seconds between requests; polite crawling

NORMAL_UA = ("ChecklaneAuditBot/1.0 (+https://checklane.example/audit; "
             "site-owner-requested readiness audit)")

# AI-agent / AI-crawler user agents, tested against the homepage.
AGENT_UAS = {
    "GPTBot (OpenAI crawler)":
        "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
    "GoogleOther (Google AI crawling)":
        "Mozilla/5.0 (compatible; GoogleOther/1.0)",
    "ClaudeBot (Anthropic)":
        "Mozilla/5.0 (compatible; ClaudeBot/1.0; +https://anthropic.com)",
    "CCBot (Common Crawl)":
        "CCBot/2.0 (https://commoncrawl.org/faq/)",
    "PerplexityBot":
        "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai)",
    "ChatGPT-User (on-demand agent fetch)":
        "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot.html)",
}

# robots.txt tokens that control AI-crawler access.
AI_CRAWLER_TOKENS = [
    "gptbot", "google-extended", "googleother", "claudebot", "ccbot",
    "perplexitybot", "chatgpt-user", "anthropic-ai", "cohere-ai",
    "bytespider", "amazonbot",
]

# Candidate discovery locations for a UCP capability profile.
UCP_CANDIDATES = [
    "/.well-known/ucp.json",
    "/.well-known/ucp",
    "/ucp.json",
    "/.well-known/commerce-capabilities.json",
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
    """Map UCP capability names (e.g. dev.ucp.shopping.cart) to the five areas."""
    areas = set()
    for n in cap_names:
        nl = str(n).lower()
        if "catalog.search" in nl or "catalog.lookup" in nl or "discovery" in nl:
            areas.add("discovery")
        if ".cart" in nl:
            areas.add("cart")
        if "checkout" in nl:
            areas.add("checkout")
        if "identity" in nl:
            areas.add("identity")
        if ".order" in nl or "fulfillment" in nl:
            areas.add("order")
    return sorted(areas)


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
    visible_len = len(parser.visible_text)

    # ---- fetch robots.txt ----------------------------------------------- #
    robots = fetch(base + "/robots.txt", ua=NORMAL_UA)
    polite()
    robots_body = robots["body"] if robots["status"] == 200 else ""
    ai_posture = parse_robots_ai_posture(robots_body)

    # ---- discover sitemap early (feeds Cat2 product-page fallback + Cat3) - #
    sitemap_info = _discover_sitemap(base)

    # ============ Category 1: UCP capability profile (20) ================ #
    cat, cmax = "UCP capability profile", 20
    ucp_state = "missing"   # missing | discovery-only | profile-invalid | valid
    ucp_areas, ucp_url = [], None
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
                caps = pu.get("capabilities")
                cap_names = (list(caps.keys()) if isinstance(caps, dict)
                             else list(caps) if isinstance(caps, list) else [])
                ucp_areas = _ucp_capability_areas(cap_names)
                ucp_url = prof_url
                ucp_state = "valid" if len(ucp_areas) >= 3 else "profile-invalid"
            break
        # No version map: the doc itself may carry capabilities (non-Shopify impls).
        caps = u.get("capabilities")
        cap_names = (list(caps.keys()) if isinstance(caps, dict)
                     else list(caps) if isinstance(caps, list) else [])
        ucp_areas = _ucp_capability_areas(cap_names)
        ucp_state = "valid" if len(ucp_areas) >= 3 else "profile-invalid"
        break
    if ucp_state == "valid":
        s = 20
        checks.append(check("ucp-valid", "UCP capability profile found and valid",
                            "pass", "Published at %s; capability areas: %s."
                            % (ucp_url, ", ".join(ucp_areas)), None))
    elif ucp_state == "discovery-only":
        s = 10
        checks.append(check("ucp-discovery-only",
                            "UCP discovery file found; versioned profile unverified",
                            "partial", "A UCP discovery document exists at %s, but the "
                            "versioned capability profile could not be verified."
                            % ucp_url,
                            "Make sure your versioned UCP profile URLs resolve and "
                            "declare capabilities (discovery, cart, checkout, "
                            "identity linking, order management).", "medium"))
    elif ucp_state == "profile-invalid":
        s = 8
        checks.append(check("ucp-invalid", "UCP profile found but incomplete",
                            "partial", "A UCP document exists at %s but declares "
                            "fewer than 3 of the 5 capability areas (%s)."
                            % (ucp_url, ", ".join(ucp_areas) or "none"),
                            "Complete your UCP capability profile per the open "
                            "Universal Commerce Protocol spec (Apache 2.0): declare "
                            "discovery, cart, checkout, identity linking and order "
                            "management capabilities. Partial profiles limit what "
                            "agents can do with your store.", "high"))
    else:
        s = 0
        checks.append(check("ucp-missing", "No UCP capability profile found",
                            "fail", "Checked %s — none returned a UCP document."
                            % ", ".join(UCP_CANDIDATES),
                            "Publish a UCP capability profile at /.well-known/ucp.json "
                            "following the open Universal Commerce Protocol spec "
                            "(Apache 2.0). Without it, compliant shopping agents "
                            "cannot discover that your store accepts agent "
                            "transactions. (Shopify stores: this is available via "
                            "Shopify's agentic tooling.)", "high"))
    scores[cat] = (s, cmax)

    # ============ Category 2: Structured product data (20) =============== #
    cat, cmax = "Structured product data", 20
    product_nodes = [n for n in ld_nodes
                     if "product" in node_types(n)]
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
            pprods = [n for n in pnodes if "product" in node_types(n)]
            if pprods:
                product_nodes = pprods
                ld_nodes = pnodes
                product_source = "sampled product page"
    s = 0
    if ld_nodes:
        s += 6
        checks.append(check("jsonld-present", "JSON-LD structured data present",
                            "pass", "%d JSON-LD node(s) found in homepage HTML."
                            % len(ld_nodes), None))
    else:
        checks.append(check("jsonld-present", "JSON-LD structured data present",
                            "fail", "No application/ld+json blocks in homepage HTML.",
                            "Add JSON-LD structured data (schema.org) to your pages. "
                            "Agents parse structured data first; pages without it are "
                            "effectively invisible to them.", "high"))
    if product_nodes:
        s += 6
        checks.append(check("product-markup", "schema.org Product markup",
                            "pass", "%d Product node(s) found (%s)."
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
            checks.append(check("product-completeness", "Product markup completeness",
                                "partial" if completeness >= 0.5 else "fail",
                                "%d of %d recommended fields present; missing: %s."
                                % (len(present), len(fields), ", ".join(missing)),
                                "Complete your Product markup: add %s. Agents use "
                                "offers/price/availability to compare and transact; "
                                "missing fields mean lost agent checkouts."
                                % ", ".join(missing), "medium"))
        else:
            checks.append(check("product-completeness", "Product markup completeness",
                                "pass", "All %d recommended fields present." % len(fields),
                                None))
        if not offers_ok:
            checks.append(check("offers-present", "Offer/price data in markup",
                                "fail", "Product nodes exist but none carry offers "
                                "(price/availability).",
                                "Add offers with price, priceCurrency and availability to "
                                "each Product node. Without machine-readable pricing, "
                                "agents cannot present or buy your products.", "high"))
            s = max(0, s - 4)
    else:
        checks.append(check("product-markup", "schema.org Product markup",
                            "fail", "No Product-typed JSON-LD on the homepage%s."
                            % (" or a sampled product page"
                               if sitemap_info["first_product_url"] else ""),
                            "Add schema.org Product markup with name, image, offers "
                            "(price, currency, availability), brand and identifiers "
                            "to product pages. This is the single highest-leverage "
                            "agent-readiness fix for most stores.", "high"))
    if org_nodes:
        checks.append(check("org-markup", "Organization identity markup",
                            "pass", "Organization/LocalBusiness node found — agents "
                            "can verify who you are.", None))
    else:
        checks.append(check("org-markup", "Organization identity markup",
                            "partial", "No Organization JSON-LD found.",
                            "Add an Organization node (name, url, logo, sameAs links). "
                            "It is the cheapest identity signal an agent can verify.",
                            "low"))
    scores[cat] = (min(s, cmax), cmax)

    # ============ Category 3: Feed discoverability (20) ================== #
    cat, cmax = "Product feed discoverability", 20
    s = 0
    si = sitemap_info
    if si["ok"]:
        s += 8
        detail = "%d URL(s) listed" % si["url_count"]
        if si["is_index"]:
            detail += " (via sitemap index)"
        if si["product_url_count"]:
            s += 4
            detail += "; ~%d product pages" % si["product_url_count"]
        checks.append(check("sitemap", "XML sitemap present and parseable",
                            "pass", detail + ".", None))
    elif si.get("status") == 200:
        s += 3
        checks.append(check("sitemap", "XML sitemap present and parseable",
                            "partial", "sitemap.xml exists but did not parse as a "
                            "URL sitemap or product sitemap.",
                            "Make sure /sitemap.xml resolves to a valid sitemap or "
                            "sitemap index listing your product URLs. Agents discover "
                            "inventory through sitemaps.", "medium"))
    else:
        checks.append(check("sitemap", "XML sitemap present and parseable",
                            "fail", "No sitemap.xml (HTTP %s)." % si.get("status"),
                            "Publish an XML sitemap at /sitemap.xml listing product "
                            "URLs. It is the primary way automated agents discover "
                            "your catalog.", "high"))
    # Platform / feed signals
    pj = fetch(base + "/products.json?limit=1", ua=NORMAL_UA)
    polite()
    feed_found = None
    if pj["status"] == 200:
        try:
            doc = json.loads(pj["body"])
            if isinstance(doc, dict) and isinstance(doc.get("products"), list):
                feed_found = "Shopify /products.json (%d product(s) sampled)" % len(
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
        checks.append(check("product-feed", "Machine-readable product feed",
                            "pass", "Found: %s." % feed_found, None))
    else:
        checks.append(check("product-feed", "Machine-readable product feed",
                            "fail", "No /products.json, /feed, /products.xml or "
                            "/google-feed.xml found.",
                            "Expose a machine-readable product feed (Shopify's "
                            "/products.json, a Google-Shopping-format XML feed, or "
                            "equivalent). Agents that cannot enumerate your catalog "
                            "cannot sell it.", "high"))
    # Agent instructions file (agents.md — the agent-web's robots.txt)
    am = fetch(base + "/agents.md", ua=NORMAL_UA)
    polite()
    if am["status"] == 200 and len(am["body"]) > 200 and \
            "agent" in am["body"][:2000].lower():
        s += 2
        checks.append(check("agents-md", "Agent instructions file (agents.md)",
                            "pass", "/agents.md present (%d bytes) — your store "
                            "speaks directly to AI agents." % len(am["body"]), None))
    else:
        checks.append(check("agents-md", "Agent instructions file (agents.md)",
                            "fail", "No /agents.md found.",
                            "Publish an /agents.md file describing how AI agents "
                            "should interact with your store: what you sell, how "
                            "to search your catalog, checkout and shipping basics, "
                            "and contact info. It is the agent web's equivalent of "
                            "a store sign — cheap to write, and agents read it "
                            "first.", "medium"))
    scores[cat] = (min(s, cmax), cmax)

    # ============ Category 4: Bot-wall / agent blockers (20) ============= #
    cat, cmax = "Agent access (bot-wall check)", 20
    s = 0
    base_title = _page_title(home["body"]).lower()
    base_len = len(home["body"])
    # Sanity: is the baseline itself a challenge page?
    base_challenge = _looks_like_challenge(home["body"])
    if base_challenge:
        checks.append(check("agent-ua:baseline", "Baseline fetch",
                            "fail", "Even our normal audit fetch received a page "
                            "mentioning %r — the site challenges automated reads "
                            "outright." % base_challenge,
                            "Your bot defenses challenge automated readers before "
                            "they see any content. Shopping agents read pages the "
                            "way this probe does — allowlist known AI-agent user "
                            "agents or exempt them from bot challenges.", "high"))
    per_ua = round(cmax / len(AGENT_UAS), 2)
    for label, ua in AGENT_UAS.items():
        r = fetch(base + "/", ua=ua)
        polite()
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
                          "normal page — likely a bot wall)" %
                          _page_title(r["body"])[:60])
        if blocked:
            checks.append(check("agent-ua:" + label, "Access for " + label,
                                "fail", "Blocked: %s." % reason,
                                "Your site blocks automated reads from %s. Shopping "
                                "agents read pages the way this probe does — a bot "
                                "wall here means agents cannot see your products at "
                                "all. Allowlist known AI-agent user agents or move "
                                "bot management to behavior-based rules that exempt "
                                "them." % label, "high"))
        else:
            s += per_ua
            checks.append(check("agent-ua:" + label, "Access for " + label,
                                "pass", "HTTP %s, same page as a normal visit."
                                % r["status"], None))
    s = min(round(s), cmax)
    if s == cmax:
        checks.append(check("agent-access-summary", "Overall agent accessibility",
                            "pass", "All %d tested agent user agents can read the "
                            "homepage." % len(AGENT_UAS), None))
    scores[cat] = (s, cmax)

    # ============ Category 5: Machine-readability basics (20) ============= #
    cat, cmax = "Machine-readability basics", 20
    s = 0
    blocked_tokens = [t for t, p in ai_posture.items() if p == "blocked"]
    if blocked_tokens:
        checks.append(check("robots-ai", "robots.txt posture toward AI crawlers",
                            "fail", "robots.txt disallows: %s."
                            % ", ".join(blocked_tokens),
                            "Your robots.txt tells AI crawlers (%s) to stay out. "
                            "If that is intentional, keep it — but know it makes "
                            "your store invisible to AI shopping agents by design. "
                            "If it was copied from a template, remove those lines."
                            % ", ".join(blocked_tokens), "high"))
    else:
        s += 8
        checks.append(check("robots-ai", "robots.txt posture toward AI crawlers",
                            "pass", "No AI-crawler tokens are disallowed in "
                            "robots.txt.", None))
    # JS-only rendering heuristic
    if home.get("truncated") and visible_len < 300:
        s += 3
        checks.append(check("static-content", "Key content in static HTML",
                            "partial", "Homepage exceeds our 1MB fetch window and the "
                            "fetched portion is mostly scripts, so server-rendered "
                            "content could not be fully confirmed.",
                            "If product content (titles, prices, descriptions) "
                            "renders client-side, agents reading raw HTML cannot "
                            "see it. Verify key content is in the initial HTML "
                            "response.", "medium"))
    elif visible_len < 300 and parser.script_srcs >= 5:
        checks.append(check("static-content", "Key content in static HTML",
                            "fail", "Only ~%d characters of visible text in the raw "
                            "HTML with %d script tags — the page likely renders "
                            "product content client-side." % (visible_len,
                                                              parser.script_srcs),
                            "Render key product content (titles, prices, descriptions) "
                            "server-side or pre-render it. Agents read HTML, not your "
                            "JavaScript bundle — JS-only content is invisible to them.",
                            "high"))
    else:
        s += 6
        checks.append(check("static-content", "Key content in static HTML",
                            "pass", "~%d characters of visible text in raw HTML; "
                            "content is server-rendered." % visible_len, None))
    basics = [
        ("page-title", "Page <title>", bool(parser.title.strip())),
        ("meta-description", "Meta description", bool(parser.meta.get("description", "").strip())),
        ("h1", "H1 heading", parser.h1_count > 0),
        ("canonical", "Canonical URL", bool(parser.canonical)),
    ]
    basics_ok = sum(1 for _, _, ok in basics if ok)
    s += round(6 * basics_ok / len(basics))
    missing_basics = [label for _, label, ok in basics if not ok]
    if missing_basics:
        checks.append(check("html-basics", "HTML fundamentals",
                            "partial" if basics_ok >= 2 else "fail",
                            "%d of 4 present; missing: %s."
                            % (basics_ok, ", ".join(missing_basics)),
                            "Add the missing fundamentals (%s). They cost minutes "
                            "and every parser — search or agent — relies on them."
                            % ", ".join(missing_basics), "low"))
    else:
        checks.append(check("html-basics", "HTML fundamentals",
                            "pass", "Title, meta description, H1 and canonical all "
                            "present.", None))
    # product links in static HTML (informational)
    prod_links = sum(1 for h in parser.links
                     if "/product" in h.lower())
    if prod_links:
        checks.append(check("product-links", "Product links in static HTML",
                            "pass", "%d product-like links found in static HTML — "
                            "agents can crawl your catalog." % prod_links, None))
    scores[cat] = (min(s, cmax), cmax)

    # ---------------- assemble report ------------------------------------ #
    total = sum(v[0] for v in scores.values())
    total_max = sum(v[1] for v in scores.values())
    score = round(100 * total / total_max) if total_max else 0
    grade = ("A" if score >= 85 else "B" if score >= 70 else "C"
             if score >= 55 else "D" if score >= 40 else "F")
    categories = []
    for name, (earned, cmax_) in scores.items():
        cat_checks = [c for c in checks if c["id"].split(":")[0] in
                      _cat_check_ids(name)]
        categories.append({"name": name, "score": earned, "max": cmax_,
                           "checks": cat_checks})
    fixes = [c for c in checks if c["status"] in ("fail", "partial") and c["fix"]]
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    fixes.sort(key=lambda c: (sev_rank.get(c["severity"], 3), c["name"]))
    return {
        "domain": domain,
        "score": score,
        "grade": grade,
        "summary": _summary(score, grade),
        "categories": categories,
        "fixes": [{"check": f["name"], "severity": f["severity"],
                   "detail": f["detail"], "fix": f["fix"]} for f in fixes],
        "fetched_at": int(time.time()),
        "duration_s": round(time.time() - started, 1),
        "engine": "checklane-audit/" + VERSION,
    }


def _cat_check_ids(cat_name):
    return {
        "UCP capability profile": {"ucp-valid", "ucp-invalid", "ucp-missing"},
        "Structured product data": {"jsonld-present", "product-markup",
                                    "product-completeness", "offers-present",
                                    "org-markup"},
        "Product feed discoverability": {"sitemap", "product-feed"},
        "Agent access (bot-wall check)": {"agent-ua", "agent-access-summary"},
        "Machine-readability basics": {"robots-ai", "static-content",
                                       "html-basics", "product-links"},
    }.get(cat_name, set())


def _summary(score, grade):
    if score >= 85:
        return ("Strong agent-readiness. Your store publishes the machine-readable "
                "signals AI shopping agents need. Remaining fixes are polish.")
    if score >= 70:
        return ("Mostly ready. A few gaps keep some agents from fully reading or "
                "transacting with your store — the fix list below closes them.")
    if score >= 55:
        return ("Partially ready. Agents can likely find you but will struggle to "
                "read your catalog or verify your products. Work the high-severity "
                "fixes first.")
    if score >= 40:
        return ("Weak agent-readiness. Your store is largely invisible to AI "
                "shopping agents in its current state. The fix list is your roadmap.")
    return ("Not agent-ready. Automated agents effectively cannot discover, read, "
            "or transact with your store today. Start at the top of the fix list.")


def main():
    import sys
    if len(sys.argv) != 2:
        print("usage: python3 audit.py example.com", file=sys.stderr)
        sys.exit(2)
    report = audit(sys.argv[1])
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
