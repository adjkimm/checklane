#!/usr/bin/env python3
"""Expanded paid-report renderer for Checklane.

render_report(report) -> str: takes the audit dict produced by audit.audit()
and returns a standalone, print-optimized HTML document — the customer-facing
full report. The "Download PDF" button calls window.print(); the customer
saves as PDF from the browser dialog. No new dependencies (stdlib only).

Design rules:
- Every section is generated from the store's ACTUAL audit findings.
- Editorial layers (expert lenses, strategic plays) are static, general, and
  honest — no per-customer claims we can't verify, no fake score projections.
- All dynamic content is HTML-escaped.
"""

import html
import re
import time

# --------------------------------------------------------------------------- #
# Static editorial content
# --------------------------------------------------------------------------- #

CATEGORY_LENS = {
    # category name -> (lens label, why-it-matters HTML)
    "AI checkout handshake": (
        "Why it matters — the CMO view",
        "Think of this as your store's handshake. A human shopper sees "
        "\"Add to cart\" and knows what to do. An AI agent needs the machine "
        "equivalent — a file that declares, in a standard format, what commerce "
        "capabilities you support. Without it, agents built on emerging standards "
        "can't even <em>start</em> a transaction. This is the highest-leverage "
        "plumbing on most reports: one static file, unlocking the entire "
        "\"can AI buy from me\" question.",
    ),
    "Product info AI can read": (
        "Why it matters — the SEO-expert view",
        "This is the same discipline as SEO, one layer deeper. Google taught us "
        "to mark up content so <em>search engines</em> understand it; now we mark "
        "up products so <em>buying agents</em> understand it. An AI comparing "
        "\"which stores sell X at price Y with Z in stock\" can only compare "
        "stores whose data is labeled. <strong>Your product data is your new ad "
        "inventory:</strong> every field you leave unlabeled is shelf space "
        "you've given to someone else.",
    ),
    "Can AI find your products": (
        "Why it matters — the advertising-expert view",
        "A sitemap is your catalog's table of contents for machines. Without it, "
        "discovery depends on an agent crawling and hoping — most won't bother; "
        "they'll query the competitor whose feed hands them the full catalog in "
        "one fetch. If SEO taught us \"don't make Google guess,\" the AI era "
        "teaches \"don't make the agent guess.\" <strong>Distribution is a "
        "technical feature now</strong>, not just a marketing budget.",
    ),
    "Are AI shoppers blocked": (
        "Why it matters",
        "This is the silent killer category. Many sites block AI crawlers without "
        "knowing it — over-aggressive WAF rules, \"bot fight mode\" on Cloudflare, "
        "or blanket <code>Disallow: /</code> lines aimed at scrapers. The store "
        "owner sees a fine website; the AI shopper sees a locked door. A clean "
        "score here is worth protecting: it's the category most likely to "
        "<em>regress</em> without anyone noticing (one WAF toggle, one plugin "
        "update).",
    ),
    "Can AI read your pages": (
        "Why it matters",
        "Table stakes that many sites fail: if your content only renders in "
        "JavaScript, simpler agents see a blank page. A strong score here means "
        "fixes elsewhere land on solid ground rather than a broken foundation.",
    ),
}

# check-id prefix -> rough effort estimate for the fix
EFFORT = [
    ("ucp-", "under 1 hr"),
    ("jsonld-present", "2–4 hrs"),
    ("product-markup", "2–4 hrs"),
    ("product-completeness", "1–2 hrs"),
    ("offers-present", "1 hr"),
    ("org-markup", "30 min"),
    ("sitemap", "1 hr"),
    ("product-feed", "1–2 hrs"),
    ("agents-md", "30 min"),
    ("agent-ua", "15 min"),
    ("agent-access-summary", "15 min"),
    ("robots-ai", "15 min"),
    ("static-content", "1 hr"),
    ("html-basics", "1 hr"),
    ("product-links", "30 min"),
]

STRATEGIC_PLAYS = [
    ("Your product data is your new ad inventory",
     "In AI-mediated shopping, the \"ad\" isn't a banner — it's the structured "
     "record the agent reads when comparing options. Completeness, accuracy, and "
     "freshness of that record <em>is</em> the campaign. Budget accordingly: data "
     "hygiene is now a marketing function, not just engineering."),
    ("Write for two audiences",
     "Every product title and description now has two readers: the human and the "
     "parser. Humans want story; parsers want labeled facts (materials, "
     "dimensions, compatibility, price, availability). The winning pattern: "
     "human-readable copy up top, complete structured data underneath. Never "
     "sacrifice one for the other."),
    ("Be the easiest \"yes\" in the comparison",
     "Agents compare on structured fields. If your competitor's listing has price, "
     "stock, shipping time, and returns policy machine-readable and yours doesn't, "
     "you don't lose on merit — you're simply incomparable, and incomparable "
     "loses to comparable every time. Completeness beats cleverness."),
    ("Own the surfaces agents read",
     "Beyond your own site: reviews, Q&amp;A, and comparison content feed the "
     "models that recommend products. The technical work in this report gets you "
     "<em>considered</em>; reputation signals get you <em>chosen</em>. Both "
     "matter, in that order."),
    ("Move before it's crowded",
     "Machine-readable commerce signals — product markup, AI-native site "
     "summaries, agent-readable checkout handshakes — are still rare. The stores "
     "that implement them now get a window where they're among the few "
     "machine-legible options in their category. That window closes as the "
     "standards go mainstream."),
]

# score band -> (hero headline, one-liner, business paragraph)
BANDS = [
    (85, "Ready for AI shoppers",
     "AI shoppers can find, read, and buy from your store today.",
     "More than four-fifths of the technical surface AI shoppers need is in "
     "place. This report is about staying ahead: close the remaining gaps, then "
     "play offense in §4. Almost nothing here requires strategy changes — it's "
     "polish on a working foundation."),
    (70, "Nearly there",
     "AI shoppers can mostly work with your store — but a few gaps are costing you.",
     "The foundation is solid and most of what AI shoppers need is present. The "
     "remaining gaps are specific and fixable, and the phased plan in §3 closes "
     "them in roughly a day of focused work. No rebrand, no new products, no ad "
     "spend required."),
    (55, "Halfway visible",
     "AI can probably find you, but it struggles to read your catalog or complete a purchase.",
     "About half of the technical surface AI shoppers need is missing. The good "
     "news: nearly everything dragging this score down is plumbing, not "
     "strategy. Work the phases in §3 in order — Phase 1 alone usually moves the "
     "needle visibly."),
    (40, "Hard for AI to use",
     "Your store is mostly invisible to AI shoppers right now.",
     "Most of what AI shoppers need to find, read, or buy from you is missing. "
     "Treat this as a rebuild of the machine-readable layer of your site — the "
     "human-facing site stays exactly as it is. The phased plan in §3 is ordered "
     "by leverage: start at the top."),
    (0, "Not ready yet",
     "AI shoppers effectively cannot find, read, or buy from this site today.",
     "More than half of the technical surface AI shoppers need is missing. The "
     "good news: almost everything dragging this score down is <em>plumbing</em>, "
     "not strategy. No rebrand, no new products, no ad spend required. A few "
     "hours of focused technical work moves this score more than months of "
     "marketing would."),
]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _esc(s):
    return html.escape(str(s if s is not None else ""), quote=True)


def _rich(s):
    """Escape, then turn `backticked` spans into <code>."""
    e = _esc(s)
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", e)


def _band(score):
    for thresh, headline, oneliner, business in BANDS:
        if score >= thresh:
            return headline, oneliner, business
    return BANDS[-1][1], BANDS[-1][2], BANDS[-1][3]


def _ring_color(score):
    if score >= 70:
        return "#0f766e"
    if score >= 40:
        return "#d97706"
    return "#dc2626"


def _cat_pill(score, cmax):
    ratio = (score / cmax) if cmax else 0
    if ratio >= 0.8:
        return '<span class="pill green">STRONG</span>'
    if ratio >= 0.5:
        return '<span class="pill amber">NEEDS WORK</span>'
    return '<span class="pill red">REAL GAP</span>'


def _status_icon(status):
    if status == "pass":
        return '<span class="st pass">✓</span>'
    if status == "partial":
        return '<span class="st partial">!</span>'
    return '<span class="st fail">✗</span>'


def _effort(check_id):
    for prefix, est in EFFORT:
        if check_id.startswith(prefix):
            return est
    return "~1 hr"


def _check_lookup(report):
    """check id -> check dict (for effort + category mapping)."""
    out = {}
    for cat in report.get("categories", []):
        for c in cat.get("checks", []):
            out.setdefault(c.get("id", ""), c)
    return out

_CSS = """
  :root{
    --teal:#0f766e; --teal-dark:#0b5e57; --teal-soft:#e6f4f1;
    --cream:#faf7f0; --ink:#1c1917; --muted:#78716c; --line:#e7e0d3;
    --red:#dc2626; --red-soft:#fef2f2; --amber:#d97706; --amber-soft:#fffbeb;
    --green:#16a34a; --green-soft:#f0fdf4;
  }
  *{box-sizing:border-box}
  body{
    margin:0; background:#f3efe6; color:var(--ink);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    line-height:1.6; -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  .page{max-width:820px; margin:24px auto; background:#fffdf8; border:1px solid var(--line);
    border-radius:12px; overflow:hidden; box-shadow:0 8px 30px rgba(28,25,23,.08)}
  header.brand{background:var(--teal-dark); color:#fff; padding:28px 36px 24px}
  header.brand .wordmark{font-weight:800; font-size:22px; letter-spacing:.14em}
  header.brand .wordmark span{color:#99f6e4}
  header.brand h1{margin:10px 0 4px; font-size:30px; line-height:1.2}
  header.brand .meta{color:#ccfbf1; font-size:14px}
  .score-hero{display:flex; gap:28px; align-items:center; padding:28px 36px;
    background:var(--cream); border-bottom:1px solid var(--line); flex-wrap:wrap}
  .score-ring{width:150px; height:150px; border-radius:50%; flex:0 0 auto;
    display:flex; align-items:center; justify-content:center}
  .score-ring .inner{width:118px; height:118px; border-radius:50%; background:#fffdf8;
    display:flex; flex-direction:column; align-items:center; justify-content:center}
  .score-ring .num{font-size:38px; font-weight:800; line-height:1}
  .score-ring .den{font-size:13px; color:var(--muted)}
  .score-summary h2{margin:0 0 6px; font-size:22px}
  .grade{display:inline-block; color:#fff; font-weight:800;
    border-radius:8px; padding:2px 12px; font-size:15px; margin-left:8px; vertical-align:middle}
  .score-summary p{margin:6px 0 0; color:#44403c; font-size:15px}
  main{padding:8px 36px 36px}
  section{margin:30px 0; page-break-inside:avoid}
  section h2.sec{font-size:20px; color:var(--teal-dark); border-bottom:2px solid var(--teal-soft);
    padding-bottom:6px; margin:0 0 14px}
  section h3{font-size:17px; margin:22px 0 8px}
  p{margin:10px 0; font-size:15px}
  .pill{display:inline-block; font-size:12px; font-weight:700; letter-spacing:.04em;
    border-radius:999px; padding:3px 12px; margin-left:8px; vertical-align:middle}
  .pill.red{background:var(--red-soft); color:var(--red); border:1px solid #fecaca}
  .pill.amber{background:var(--amber-soft); color:var(--amber); border:1px solid #fde68a}
  .pill.green{background:var(--green-soft); color:var(--green); border:1px solid #bbf7d0}
  .card{background:#fff; border:1px solid var(--line); border-radius:10px; padding:18px 20px; margin:14px 0}
  .card h3{margin-top:0}
  .view-label{font-size:12px; font-weight:700; letter-spacing:.06em; text-transform:uppercase;
    color:var(--teal); margin:14px 0 4px}
  .note{margin:12px 0; padding:10px 16px; background:var(--amber-soft);
    border-left:4px solid var(--amber); border-radius:0 8px 8px 0; font-size:14px; color:#57534e}
  pre{background:#1c1917; color:#e7e5e4; border-radius:8px; padding:14px 16px;
    overflow-x:auto; font-size:12.5px; line-height:1.5}
  code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  p code, li code, td code{background:#f5f0e6; padding:1px 6px; border-radius:4px; font-size:13px}
  pre code{background:none; padding:0}
  table{width:100%; border-collapse:collapse; margin:12px 0; font-size:14px}
  th{background:var(--teal-dark); color:#fff; text-align:left; padding:10px 12px; font-size:13px}
  th:first-child{border-radius:8px 0 0 0} th:last-child{border-radius:0 8px 0 0}
  td{padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top}
  tr:last-child td{border-bottom:none}
  ul.plain, ol.plain{padding-left:22px; font-size:15px}
  ul.plain li, ol.plain li{margin:6px 0}
  .st{display:inline-block; width:22px; height:22px; border-radius:50%; text-align:center;
    font-size:13px; font-weight:800; line-height:22px; margin-right:8px; flex:0 0 auto}
  .st.pass{background:var(--green-soft); color:var(--green); border:1px solid #bbf7d0}
  .st.partial{background:var(--amber-soft); color:var(--amber); border:1px solid #fde68a}
  .st.fail{background:var(--red-soft); color:var(--red); border:1px solid #fecaca}
  .checkrow{display:flex; align-items:flex-start; padding:8px 0; border-bottom:1px solid var(--line); font-size:14px}
  .checkrow:last-child{border-bottom:none}
  .checkrow .cname{font-weight:700}
  .checkrow .cdetail{color:#57534e; font-size:13.5px}
  .phase{font-size:13px; font-weight:700; letter-spacing:.06em; text-transform:uppercase;
    color:#fff; background:var(--teal); display:inline-block; padding:4px 14px; border-radius:999px; margin:18px 0 4px}
  .strategy .card{position:relative; padding-left:64px}
  .strategy .card::before{counter-increment:strat; content:counter(strat);
    position:absolute; left:18px; top:16px; width:32px; height:32px; border-radius:50%;
    background:var(--teal-soft); color:var(--teal-dark); font-weight:800;
    display:flex; align-items:center; justify-content:center}
  .strategy{counter-reset:strat}
  footer{background:#1c1917; color:#a8a29e; padding:22px 36px; font-size:13px}
  footer strong{color:#e7e5e4}
  .toolbar{position:sticky; top:0; z-index:10; background:#fffdf8ee;
    border-bottom:1px solid var(--line); padding:10px 36px; display:flex; gap:12px; align-items:center}
  .btn{background:var(--teal); color:#fff; border:none; border-radius:8px; padding:10px 20px;
    font-size:15px; font-weight:700; cursor:pointer}
  .btn:hover{background:var(--teal-dark)}
  .toolbar .note2{font-size:13px; color:var(--muted)}
  @media print{
    body{background:#fff}
    .page{margin:0; border:none; border-radius:0; box-shadow:none; max-width:none}
    .toolbar{display:none}
    section, .card{page-break-inside:avoid}
  }
"""


def _section_categories(report):
    parts = []
    for cat in report.get("categories", []):
        name = cat.get("name", "")
        score, cmax = cat.get("score", 0), cat.get("max", 0)
        checks = cat.get("checks", [])
        lens_label, lens_body = CATEGORY_LENS.get(name, ("Why it matters", ""))
        rows = []
        for c in checks:
            rows.append(
                '<div class="checkrow">%s<div><span class="cname">%s</span>'
                '<div class="cdetail">%s</div></div></div>'
                % (_status_icon(c.get("status")), _esc(c.get("name")),
                   _rich(c.get("detail", "")))
            )
        fixes = [c for c in checks
                 if c.get("status") in ("fail", "partial") and c.get("fix")]
        fix_html = ""
        if fixes:
            items = "".join(
                "<li><strong>%s</strong> — %s</li>"
                % (_esc(c.get("name")), _rich(c.get("fix")))
                for c in fixes)
            fix_html = ('<div class="view-label">How to fix it</div>'
                        '<ol class="plain">%s</ol>') % items
        parts.append(
            '<div class="card"><h3>%s — %s/%s %s</h3>'
            '<div class="view-label">What we found</div>%s'
            '<div class="view-label">%s</div><p>%s</p>%s</div>'
            % (_esc(name), _esc(score), _esc(cmax), _cat_pill(score, cmax),
               "".join(rows) or "<p>No checks recorded for this category.</p>",
               _esc(lens_label), lens_body, fix_html)
        )
    return "\n".join(parts)


def _section_action_plan(report):
    fixes = report.get("fixes", []) or []
    lookup = _check_lookup(report)
    phases = [("Phase 1 — this week · quick wins",
               [f for f in fixes if f.get("severity") == "high"]),
              ("Phase 2 — this month",
               [f for f in fixes if f.get("severity") == "medium"]),
              ("Phase 3 — ongoing",
               [f for f in fixes if f.get("severity") == "low"])]
    out = ['<p>Each item is written so you (or your developer) can execute it '
           'without coming back to us. Ranked by impact.</p>']
    n = 0
    for title, items in phases:
        if not items and "ongoing" not in title:
            continue
        out.append('<div class="phase">%s</div>' % _esc(title))
        rows = []
        for f in items:
            n += 1
            chk = lookup.get(f.get("check", ""), {})
            rows.append(
                "<tr><td>%d</td><td><strong>%s</strong><div style='font-size:13px;color:#57534e'>%s</div></td>"
                "<td>%s</td></tr>"
                % (n, _esc(f.get("check")), _rich(f.get("fix")),
                   _esc(_effort(f.get("check", "")))))
        if "ongoing" in title:
            n += 1
            rows.append(
                "<tr><td>%d</td><td><strong>Re-run this audit</strong>"
                "<div style='font-size:13px;color:#57534e'>Scores should climb "
                "with each phase — re-audit to confirm.</div></td>"
                "<td>After each phase</td></tr>" % n)
            n += 1
            rows.append(
                "<tr><td>%d</td><td><strong>Watch server logs for AI agent "
                "user-agents</strong><div style='font-size:13px;color:#57534e'>"
                "GPTBot, ClaudeBot, and friends appearing in logs is the earliest "
                "signal you're being discovered.</div></td>"
                "<td>Monthly</td></tr>" % n)
            n += 1
            rows.append(
                "<tr><td>%d</td><td><strong>Keep machine-readable data in sync "
                "with reality</strong><div style='font-size:13px;color:#57534e'>"
                "Prices, availability, offerings — stale data trains agents to "
                "distrust you.</div></td><td>Whenever things change</td></tr>" % n)
        out.append("<table><tr><th>#</th><th>Action</th><th>Effort</th></tr>%s</table>"
                   % "".join(rows))
    if n == 0:
        out.append("<p>Nothing to fix — every check passed. Work §4 to stay ahead.</p>")
    return "\n".join(out)

def _section_brief(report, domain, score):
    headline, oneliner, business = _band(score)
    cats = {c.get("name"): c for c in report.get("categories", [])}
    prod = cats.get("Product info AI can read", {})
    find = cats.get("Can AI find your products", {})
    storefront_weak = (prod.get("max", 0) and prod.get("score", 0) == 0)
    caveat = ""
    if storefront_weak:
        caveat = (
            '<div class="note"><strong>An honest caveat, because a report that '
            'cries wolf is worthless:</strong> two of the five categories assume '
            'an online storefront (products, prices, a cart). If your site is '
            'primarily marketing or lead generation rather than a store, those '
            'categories will score low <em>by design</em> — your score understates '
            'how ready the site is for what it actually does. Focus on the '
            '<strong>Real gap</strong> markers below; those apply to every site.</div>'
        )
    return """
    <section><h2 class="sec">1 &nbsp; Executive brief — read this first</h2>
    <p><strong>The one-sentence version:</strong> %s</p>
    <p><strong>Why this matters now:</strong> Your customers are starting to let AI
    shop for them — ChatGPT, Claude, Muse, xAI, Google's AI. These shoppers don't
    browse like people do. They parse code: structured product data, sitemaps,
    machine-readable checkout signals. If your site doesn't speak that language, you
    don't get compared badly — you don't get considered at all. You're not losing to
    competitors on price or quality. You're losing before the comparison starts.</p>
    <p><strong>What a %s means in business terms:</strong> %s</p>
    %s
    <p><strong>The bottom line:</strong> Fix the plumbing (§2–3), then play offense
    (§4). The phased plan is ordered so the highest-leverage work comes first.</p>
    </section>""" % (_esc(oneliner), _esc(score), business, caveat)


def _section_strategy():
    cards = "".join(
        '<div class="card"><h3>%s</h3><p>%s</p></div>' % (_esc(t), b)
        for t, b in STRATEGIC_PLAYS)
    return """
    <section class="strategy"><h2 class="sec">4 &nbsp; Strategic plays — the thinking behind the checklist</h2>
    <p>The moves a CMO, an advertising lead, an SEO lead, and an AI engineer would
    all converge on. The checklist fixes the plumbing; these decide how much the
    plumbing is worth.</p>
    %s</section>""" % cards


def _section_measurement():
    return """
    <section><h2 class="sec">5 &nbsp; How to know it's working</h2>
    <ul class="plain">
      <li><strong>Re-audit:</strong> run the free Checklane audit after each phase —
      the score should climb as fixes land.</li>
      <li><strong>Log watch:</strong> AI crawler/agent user-agents appearing in your
      server logs is the earliest signal you're being discovered.</li>
      <li><strong>The real metric:</strong> over time, track orders or inquiries that
      originate from AI surfaces (ask "how did you hear about us" — add "AI assistant"
      as an option). Nobody has perfect attribution here yet; directional signal beats none.</li>
    </ul></section>"""


def render_report(report):
    """Build the full customer-facing HTML report from an audit dict."""
    domain = report.get("domain", "your site")
    score = report.get("score", 0)
    grade = report.get("grade", "F")
    if report.get("error") or not report.get("categories"):
        return _error_page(domain, report.get("error"))
    try:
        audit_ts = report.get("fetched_at", int(time.time()))
        audit_date = time.strftime("%B %d, %Y", time.localtime(audit_ts))
        report_id = "CL-%s-%s" % (time.strftime("%Y%m%d", time.localtime(audit_ts)),
                                  score)
    except Exception:
        audit_date, report_id = "", ""
    headline, oneliner, _ = _band(score)
    ring = _ring_color(score)

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Checklane Report — %s</title>
<style>%s</style>
</head>
<body>
<div class="toolbar">
  <button class="btn" onclick="window.print()">Download PDF</button>
  <span class="note2">Opens the print dialog — choose "Save as PDF" to keep a copy of your report.</span>
</div>
<div class="page">
  <header class="brand">
    <div class="wordmark">CHECK<span>LANE</span></div>
    <h1>AI-Readiness Report</h1>
    <div class="meta">%s &nbsp;·&nbsp; Audited %s &nbsp;·&nbsp; Report %s</div>
  </header>
  <div class="score-hero">
    <div class="score-ring" style="background:conic-gradient(%s 0 %s%%, #e7e0d3 %s%% 100%%)">
      <div class="inner"><div class="num">%s</div><div class="den">/ 100</div></div>
    </div>
    <div class="score-summary">
      <h2>%s <span class="grade" style="background:%s">%s</span></h2>
      <p>%s</p>
    </div>
  </div>
  <main>
    %s
    <section><h2 class="sec">2 &nbsp; Category-by-category: what we found, why it matters, how to fix it</h2>
    %s</section>
    <section><h2 class="sec">3 &nbsp; Your action plan — ranked, phased, handoff-ready</h2>
    %s</section>
    %s
    %s
  </main>
  <footer>
    <strong>Checklane</strong> grades what's technically verifiable about your store
    at audit time. This report is a roadmap, not a promise — a high score means
    nothing technical stands between you and the AI shopper; the rest is up to your
    products, prices, and reputation.
  </footer>
</div>
</body>
</html>""" % (
        _esc(domain), _CSS,
        _esc(domain), _esc(audit_date), _esc(report_id),
        ring, _esc(score), _esc(score),
        _esc(score), _esc(headline), ring, _esc(grade),
        _esc(report.get("summary", "")),
        _section_brief(report, domain, score),
        _section_categories(report),
        _section_action_plan(report),
        _section_strategy(),
        _section_measurement(),
    )


def _error_page(domain, error):
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Checklane Report — %s</title><style>%s</style></head>
<body><div class="page">
<header class="brand"><div class="wordmark">CHECK<span>LANE</span></div>
<h1>AI-Readiness Report</h1></header>
<main><section><h2 class="sec">Report unavailable</h2>
<p>We couldn't generate a full report for %s: %s</p>
<p>Please re-run the free audit and try again.</p></section></main>
</div></body></html>""" % (_esc(domain), _CSS, _esc(domain), _esc(error or "unknown error"))
