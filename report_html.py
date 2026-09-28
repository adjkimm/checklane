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
    "AI checkout handshake (UCP + ACP)": (
        "Why it matters: the CMO view",
        "Two protocols, one idea: give agents a <em>machine path</em> to buy, "
        "instead of making them drive your website like a human. "
        "<strong>UCP</strong> (Google) is a capability profile your site "
        "publishes at <code>/.well-known/ucp</code>; agents read it to learn "
        "what commerce actions you support. <strong>ACP</strong> (OpenAI + "
        "Stripe) is the protocol behind ChatGPT shopping; there is no on-site "
        "file; merchants qualify by uploading a product feed and completing "
        "OpenAI's partner onboarding. Be clear-eyed about what this buys: "
        "browser-driving agents already complete purchases through normal "
        "checkout today, with no protocol file at all. The handshake is a "
        "faster, more reliable path: an optimization, not a prerequisite. "
        "Its real cost is honesty: publishing the file is hours, but the "
        "working backend behind it (endpoints, payment handlers, webhooks) is "
        "days to weeks of engineering.",
    ),
    "Product info AI can read": (
        "Why it matters: the SEO-expert view",
        "This is the same discipline as SEO, one layer deeper. Google taught us "
        "to mark up content so <em>search engines</em> understand it; now we mark "
        "up products so <em>buying agents</em> understand it. An AI comparing "
        "\"which stores sell X at price Y with Z in stock\" can only compare "
        "stores whose data is labeled. <strong>Your product data is your new ad "
        "inventory:</strong> every field you leave unlabeled is shelf space "
        "you've given to someone else.",
    ),
    "Can AI find your products": (
        "Why it matters: the advertising-expert view",
        "A sitemap is your catalog's table of contents for machines. Without it, "
        "discovery depends on an agent crawling and hoping. Most won't bother; "
        "they'll query the competitor whose feed hands them the full catalog in "
        "one fetch. If SEO taught us \"don't make Google guess,\" the AI era "
        "teaches \"don't make the agent guess.\" <strong>Distribution is a "
        "technical feature now</strong>, not just a marketing budget.",
    ),
    "AI bot access": (
        "Why it matters: what this actually measures",
        "This is the silent killer category, with one important clarification "
        "about <em>what</em> it kills. We test whether known AI crawlers and "
        "on-demand fetchers can load your homepage: training crawlers (GPTBot, "
        "ClaudeBot), search fetchers (OAI-SearchBot, Claude-SearchBot), and "
        "agent-mode fetchers (ChatGPT-User, Google-Agent). Many sites block "
        "these without knowing it: over-aggressive WAF rules, \"bot fight "
        "mode\" on Cloudflare, or blanket <code>Disallow: /</code> lines aimed "
        "at scrapers. The store owner sees a fine website; the AI fetcher sees "
        "a locked door, and your pages can't appear in AI answers. What this "
        "does <em>not</em> measure: whether \"AI shoppers\" are blocked. "
        "Blocking a training crawler does not block AI shopping. "
        "browser-driving agents buy through normal checkout regardless. A "
        "clean score here is worth protecting: it's the category most likely "
        "to <em>regress</em> without anyone noticing (one WAF toggle, one "
        "plugin update).",
    ),
    "Can AI read your pages": (
        "Why it matters",
        "Table stakes that many sites fail: if your content only renders in "
        "JavaScript, simpler AI fetchers see a blank page. (Agent-mode shoppers "
        "drive real browsers, so this is about robustness across every kind of "
        "reader, not a hard block.) A strong score here means fixes elsewhere "
        "land on solid ground rather than a broken foundation.",
    ),
}

# check-id prefix -> honest effort estimate for the fix
EFFORT = [
    ("ucp-", "days–weeks (developer)"),
    ("acp-", "days + onboarding"),
    ("jsonld-present", "2–4 hrs"),
    ("product-markup", "2–4 hrs"),
    ("product-completeness", "1–2 hrs"),
    ("offers-present", "1 hr"),
    ("org-markup", "30 min"),
    ("sitemap", "1 hr"),
    ("product-feed", "1–2 hrs"),
    ("agents-md", "30 min"),
    ("bot-test-scope", "n/a"),
    ("agent-ua", "15 min"),
    ("agent-access-summary", "n/a"),
    ("robots-ai", "15 min"),
    ("static-content", "1 hr"),
    ("html-basics", "1 hr"),
    ("product-links", "30 min"),
    ("biz-llms", "1 hr"),
    ("biz-sitemap", "30 min"),
    ("biz-og", "30 min"),
    ("biz-faq", "1 hr"),
]

# check-id prefix -> who can do it: DIY (store owner, no code) or Developer.
# Shown in the §3 action plan so the customer knows what to hand off.
OWNER = [
    ("ucp-", "Developer (DIY on Shopify)"),
    ("acp-", "Developer (auto on Shopify/Etsy)"),
    ("jsonld-present", "Developer"),
    ("product-markup", "Developer"),
    ("product-completeness", "DIY"),
    ("offers-present", "Developer"),
    ("org-markup", "DIY"),
    ("sitemap", "DIY"),
    ("product-feed", "DIY on Shopify; Developer otherwise"),
    ("agents-md", "DIY"),
    ("bot-test-scope", "n/a"),
    ("agent-ua", "DIY"),
    ("agent-access-summary", "n/a"),
    ("robots-ai", "DIY"),
    ("static-content", "Developer"),
    ("html-basics", "DIY"),
    ("product-links", "Developer"),
    ("biz-llms", "DIY"),
    ("biz-sitemap", "DIY"),
    ("biz-og", "DIY"),
    ("biz-faq", "DIY"),
]

STRATEGIC_PLAYS = [
    ("Your product data is your new ad inventory",
     "In AI-mediated shopping, the \"ad\" isn't a banner. It's the structured "
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
     "you don't lose on merit. You're simply incomparable, and incomparable "
     "loses to comparable every time. Completeness beats cleverness."),
    ("Own the surfaces agents read",
     "Beyond your own site: reviews, Q&amp;A, and comparison content feed the "
     "models that recommend products. The technical work in this report gets you "
     "<em>considered</em>; reputation signals get you <em>chosen</em>. Both "
     "matter, in that order."),
    ("Move before it's crowded",
     "Machine-readable commerce signals (product markup, AI-native site "
     "summaries, agent-readable checkout handshakes) are still rare. The businesses "
     "that implement them now get a window where they're among the few "
     "machine-legible options in their category. That window closes as the "
     "standards go mainstream."),
]

# score band -> (hero headline, one-liner, business paragraph)
BANDS = [
    (85, "Ready for AI shoppers",
     "AI agents, browsing or via the machine paths, can find, read, and transact with your site today.",
     "More than four-fifths of the technical surface AI agents use is in "
     "place. This report is about staying ahead: close the remaining gaps, then "
     "play offense in §5. Almost nothing here requires strategy changes. It's "
     "polish on a working foundation."),
    (70, "Nearly there",
     "AI agents can mostly work with your site, but a few gaps are costing you.",
     "The foundation is solid and most of what AI agents need is present. The "
     "remaining gaps are specific and fixable, and the phased plan in §3 orders "
     "them by leverage. Most are days of focused work, not weeks. No rebrand, "
     "no new products, no ad spend required."),
    (55, "Halfway visible",
     "AI can probably find you, but it struggles to read your catalog or use the fast machine paths.",
     "About half of the technical surface AI agents prefer is missing. The good "
     "news: nearly everything dragging this score down is plumbing, not "
     "strategy. Work the phases in §3 in order. Phase 1 alone usually moves the "
     "needle visibly."),
    (40, "Hard for AI to use",
     "AI agents will struggle with the machine-readable layer of your site right now.",
     "Most of the machine-readable surface AI agents prefer is missing. While "
     "browser-based agents can still buy through your normal checkout, you're "
     "hard to compare and slow to transact with. Treat this as a rebuild of the "
     "machine-readable layer of your site. The human-facing site stays exactly "
     "as it is. The phased plan in §3 is ordered by leverage: start at the top."),
    (0, "Not ready yet",
     "The fast machine paths are missing and the basics are thin.",
     "More than half of the technical surface AI agents use is missing. The "
     "good news: almost everything dragging this score down is <em>plumbing</em>, "
     "not strategy. No rebrand, no new products, no ad spend required. Focused "
     "technical work moves this score more than months of marketing would, but "
     "note the UCP/ACP items are backend projects (days–weeks), not afternoon "
     "tasks."),
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


def _owner(check_id):
    for prefix, who in OWNER:
        if check_id.startswith(prefix):
            return who
    return "DIY"


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
  .pill.na{background:#f5f0e6; color:var(--muted); border:1px solid var(--line)}
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
  .twrap{overflow-x:auto; -webkit-overflow-scrolling:touch; margin:12px -4px; padding:0 4px}
  .twrap table{margin:0}
  @media (max-width:640px){
    .page{margin:12px 8px; border-radius:10px}
    header.brand{padding:22px 20px 18px}
    header.brand h1{font-size:24px}
    header.brand .wordmark{font-size:19px}
    .score-hero{padding:20px; gap:18px}
    .score-ring{width:120px; height:120px}
    .score-ring .inner{width:94px; height:94px}
    .score-ring .num{font-size:30px}
    main{padding:4px 16px 24px}
    section h2.sec{font-size:17px}
    .toolbar{padding:10px 16px; flex-wrap:wrap}
    .toolbar .note2{flex-basis:100%}
    footer{padding:18px 20px}
    .card{padding:14px 16px}
    .strategy .card{padding-left:56px}
    table{font-size:13px}
    th,td{padding:8px; white-space:normal}
    .btn{min-height:44px}
    p, li, td, code{overflow-wrap:break-word}
    pre{font-size:12px; padding:12px}
  }
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
                "<li><strong>%s</strong>: %s</li>"
                % (_esc(c.get("name")), _rich(c.get("fix")))
                for c in fixes)
            fix_html = ('<div class="view-label">How to fix it</div>'
                        '<ol class="plain">%s</ol>') % items
        if cat.get("na"):
            if cat.get("na_reason") == "is-storefront":
                na_note = ('<strong>Not scored: storefront detected.</strong> '
                           'This category only applies to sites that don\'t sell '
                           'online, so it doesn\'t count toward your score. The '
                           'checks below were still run; treat them as '
                           'informational.')
            else:
                na_note = ('<strong>Not scored: no storefront detected.</strong> '
                           'This category only applies to online stores, so it '
                           'doesn\'t count toward your score. The checks below '
                           'were still run; treat them as informational.')
            head = ('<h3>%s %s</h3>'
                    '<div class="note">%s</div>'
                    % (_esc(name), '<span class="pill na">N/A</span>', na_note))
        else:
            head = ('<h3>%s: %s/%s %s</h3>'
                    % (_esc(name), _esc(score), _esc(cmax),
                       _cat_pill(score, cmax)))
        parts.append(
            '<div class="card">%s'
            '<div class="view-label">What we found</div>%s'
            '<div class="view-label">%s</div><p>%s</p>%s</div>'
            % (head,
               "".join(rows) or "<p>No checks recorded for this category.</p>",
               _esc(lens_label), lens_body, fix_html)
        )
    return "\n".join(parts)


def _section_action_plan(report):
    fixes = report.get("fixes", []) or []
    lookup = _check_lookup(report)
    phases = [("Phase 1: highest leverage",
               [f for f in fixes if f.get("severity") == "high"]),
              ("Phase 2: this month",
               [f for f in fixes if f.get("severity") == "medium"]),
              ("Phase 3: ongoing",
               [f for f in fixes if f.get("severity") == "low"])]
    out = ['<p>Every finding with a fix is listed below. Nothing skipped. '
           'ranked by impact, with who can do it and an honest effort estimate. '
           'Copy-paste templates and per-platform paths are in §4.</p>']
    n = 0
    for title, items in phases:
        if not items and "ongoing" not in title:
            continue
        out.append('<div class="phase">%s</div>' % _esc(title))
        rows = []
        for f in items:
            n += 1
            fid = f.get("id") or f.get("check", "")
            chk = lookup.get(fid, {})
            rows.append(
                "<tr><td>%d</td><td><strong>%s</strong><div style='font-size:13px;color:#57534e'>%s</div></td>"
                "<td>%s</td><td>%s</td></tr>"
                % (n, _esc(f.get("check")), _rich(f.get("fix")),
                   _esc(_owner(fid)), _esc(_effort(fid))))
        if "ongoing" in title:
            n += 1
            rows.append(
                "<tr><td>%d</td><td><strong>Re-run this audit</strong>"
                "<div style='font-size:13px;color:#57534e'>Scores should climb "
                "with each phase. Re-audit to confirm.</div></td>"
                "<td>DIY</td><td>After each phase</td></tr>" % n)
            n += 1
            rows.append(
                "<tr><td>%d</td><td><strong>Watch server logs for AI bot "
                "user-agents</strong><div style='font-size:13px;color:#57534e'>"
                "GPTBot, OAI-SearchBot, ClaudeBot, and friends appearing in logs "
                "is the earliest signal you're being discovered.</div></td>"
                "<td>DIY</td><td>Monthly</td></tr>" % n)
            n += 1
            rows.append(
                "<tr><td>%d</td><td><strong>Keep machine-readable data in sync "
                "with reality</strong><div style='font-size:13px;color:#57534e'>"
                "Prices, availability, offerings: stale data trains agents to "
                "distrust you.</div></td><td>DIY</td><td>Whenever things change</td></tr>" % n)
        out.append("<div class=\"twrap\"><table><tr><th>#</th><th>Action</th><th>Who</th><th>Effort</th></tr>%s</table></div>"
                   % "".join(rows))
    if n == 0:
        out.append("<p>Nothing to fix. Every check passed. Work §5 to stay ahead.</p>")
    return "\n".join(out)

def _section_brief(report, domain, score):
    _, oneliner, business = _band(score)
    caveat = ""
    if report.get("site_type") == "non-storefront":
        caveat = (
            '<div class="note"><strong>Site-type note: read this before the '
            'score:</strong> this site doesn\'t sell products online (no '
            'storefront detected: no cart, no product data, no readable '
            'prices), so the three storefront-only categories are marked '
            '<strong>N/A</strong> below and your score is computed from the three '
            'categories that apply to non-storefront sites. The N/A checks were still '
            'run. They\'re informational, not failures.</div>'
        )
    return """
    <section><h2 class="sec">1 &nbsp; Executive brief: read this first</h2>
    <p><strong>The one-sentence version:</strong> %s</p>
    <p><strong>Why this matters now:</strong> Your customers are starting to let AI
    shop for them: ChatGPT shopping, Google AI Mode/Gemini, Perplexity. These
    shoppers don't browse like people do. They parse code: structured product
    data, sitemaps, machine-readable checkout signals. Browser-driving agents can
    still buy through your normal checkout without any of this. That's how most
    agent purchases happen today. What the machine path buys you is reliability
    and speed: structured signals make you <em>comparable</em> and directly
    <em>transactable</em> instead of merely browsable. Without them you don't
    lose on price or quality. You lose on being hard to compare.</p>
    <p><strong>What a %s means in business terms:</strong> %s</p>
    %s
    <p><strong>The bottom line:</strong> Fix the plumbing (§2–3), then play offense
    (§5). The phased plan is ordered so the highest-leverage work comes first.</p>
    </section>""" % (_esc(oneliner), _esc(score), business, caveat)


_TEMPLATE_JSONLD = """{
  "@context": "https://schema.org",
  "@type": "Organization",
  "name": "YOUR SITE NAME",
  "url": "https://yoursite.com",
  "logo": "https://yoursite.com/logo.png"
}
---
{
  "@context": "https://schema.org",
  "@type": "Product",
  "name": "Product name",
  "image": "https://yoursite.com/product.jpg",
  "description": "One honest sentence about the product.",
  "brand": { "@type": "Brand", "name": "Brand name" },
  "sku": "SKU-123",
  "gtin": "0123456789012",
  "offers": {
    "@type": "Offer",
    "price": "29.99",
    "priceCurrency": "USD",
    "availability": "https://schema.org/InStock"
  }
}"""

_TEMPLATE_ROBOTS = """# Let AI visitors read your site (fixes accidental blocks from templates).
User-agent: GPTBot
User-agent: OAI-SearchBot
User-agent: ClaudeBot
User-agent: Claude-SearchBot
User-agent: CCBot
User-agent: PerplexityBot
User-agent: ChatGPT-User
User-agent: GoogleOther
Allow: /

# Optional: block training crawlers ONLY if you don't want your content
# in AI training data. This does NOT block AI shopping — browser-driving
# agents and ChatGPT shopping are unaffected either way.
# User-agent: GPTBot
# User-agent: ClaudeBot
# User-agent: CCBot
# Disallow: /

# Note: Google-Agent does not honor robots.txt — manage it in your WAF/CDN."""

_TEMPLATE_LLMS = """# https://yoursite.com/llms.txt: what AI visitors should know first

## What we sell
One paragraph: who the store is for and what it sells.

## Products
- [Product name](https://yoursite.com/products/slug): one line, $price

## Shipping & returns
- Ships in X days from [place]: https://yoursite.com/shipping
- Returns: https://yoursite.com/returns

## Contact
- https://yoursite.com/contact"""


def _section_templates():
    return """
    <section><h2 class="sec">4 &nbsp; Copy-paste templates &amp; platform shortcuts</h2>
    <p>The <em>how</em>, not just the <em>what</em>. Start with the template,
    adapt the ALL-CAPS parts, and check the platform notes for where each fix
    lives on your stack.</p>
    <h3>Labeled store + product data (JSON-LD)</h3>
    <p>Paste each block inside
    <code>&lt;script type="application/ld+json"&gt; … &lt;/script&gt;</code>
    in your page <code>&lt;head&gt;</code>. The <code>gtin</code> line is what
    ChatGPT's product feed matches on it. Include it wherever your products have
    barcodes.</p>
    <pre>%s</pre>
    <h3>robots.txt: AI-visitor stanza</h3>
    <p>Replace any blanket <code>Disallow: /</code> AI-crawler blocks with this.
    It lets discovery fetchers read your site; the training-crawler block stays
    commented out unless you actively want it.</p>
    <pre>%s</pre>
    <h3>llms.txt starter</h3>
    <p>Save as <code>/llms.txt</code> at your domain root. The established
    convention LLM tools actually read. (An <code>/agents.md</code> with the
    same content also works; a repo-root <code>AGENTS.md</code> is a different
    thing: a coding-agent convention for software projects.)</p>
    <pre>%s</pre>
    <h3>Where each fix lives, by platform</h3>
    <div class="twrap"><table><tr><th>Platform</th><th>UCP file</th><th>ChatGPT / ACP</th><th>Product labels &amp; sitemap</th></tr>
    <tr><td><strong>Shopify</strong></td>
      <td>Turn on Shopify's Agentic sales channel / AI tools. They publish
      <code>/.well-known/ucp</code> for you.</td>
      <td>Auto-enrolled via Shopify Catalog. Nothing to apply for.</td>
      <td>JSON-LD built into most themes (extend via theme code or SEO apps);
      <code>/sitemap.xml</code> and <code>/products.json</code> automatic.</td></tr>
    <tr><td><strong>WooCommerce (WordPress)</strong></td>
      <td>No native path. Custom backend project (days–weeks): REST endpoints,
      payment handlers with signing keys, order webhooks.</td>
      <td>Product-feed plugin + OpenAI merchant onboarding (apply, then upload
      per OpenAI's Product Feed Spec).</td>
      <td>RankMath/Yoast output product markup; sitemap automatic via your SEO
      plugin.</td></tr>
    <tr><td><strong>Wix</strong></td>
      <td>No native path today. Custom development.</td>
      <td>Feed export + OpenAI merchant onboarding.</td>
      <td>Limited JSON-LD. Use Wix SEO settings + custom code; sitemap
      automatic.</td></tr>
    <tr><td><strong>Squarespace</strong></td>
      <td>No native path today. Custom development.</td>
      <td>Feed export + OpenAI merchant onboarding.</td>
      <td>Partial built-in product markup; sitemap automatic.</td></tr>
    </table></div>
    </section>""" % (_esc(_TEMPLATE_JSONLD), _esc(_TEMPLATE_ROBOTS),
                     _esc(_TEMPLATE_LLMS))


_GLOSSARY = [
    ("UCP: Universal Commerce Protocol",
     "Google's open standard letting AI agents transact with a merchant backend. "
     "Your site publishes a capability profile at <code>/.well-known/ucp</code>; "
     "agents read it to learn what commerce actions you support."),
    ("ACP: Agentic Commerce Protocol",
     "OpenAI + Stripe's protocol behind ChatGPT shopping. No on-site discovery "
     "file. Merchants qualify by uploading a product feed and completing "
     "OpenAI's partner onboarding."),
    ("JSON-LD / structured data",
     "Labels embedded in your pages (name, price, stock, brand…) that let "
     "machines read facts instead of guessing from layout. Schema.org is the "
     "shared vocabulary."),
    ("robots.txt",
     "A file at your domain root telling crawlers which paths they may fetch. "
     "AI-crawler blocks here do not block AI shopping, only crawler access."),
    ("sitemap.xml",
     "Your catalog's table of contents for machines: the main way agents "
     "discover every product you sell."),
    ("llms.txt",
     "The established convention for an LLM-readable summary of your site "
     "(what you sell, key links). Often paired with /agents.md."),
    ("agents.md",
     "An agent welcome file at your domain root. Not the same as a repo-root "
     "AGENTS.md, which is a coding-agent convention for software projects."),
    ("GTIN / UPC / MPN",
     "Global product identifiers (barcode numbers / manufacturer part numbers). "
     "ChatGPT's product feed keys on them. The strongest matching signal you "
     "can publish."),
    ("Shared Payment Token",
     "Stripe's mechanism in ACP: ChatGPT initiates payment without exposing the "
     "buyer's card details; you charge it on your own payment setup."),
    ("Well-known URI",
     "Standard discovery paths under <code>/.well-known/</code> where agents "
     "look for machine-readable files (e.g. <code>/.well-known/ucp</code>)."),
    ("User agent",
     "The identity string a visitor (browser, crawler, or agent) announces. "
     "This audit tests known AI user agents to see which ones your site lets in."),
]


def _section_glossary():
    rows = "".join(
        "<tr><td><strong>%s</strong></td><td>%s</td></tr>" % (_esc(t), b)
        for t, b in _GLOSSARY)
    return """
    <section><h2 class="sec">7 &nbsp; Glossary</h2>
    <p>Every jargon term in this report, in one place.</p>
    <div class="twrap"><table>%s</table></div>
    </section>""" % rows


def _section_strategy():
    cards = "".join(
        '<div class="card"><h3>%s</h3><p>%s</p></div>' % (_esc(t), b)
        for t, b in STRATEGIC_PLAYS)
    return """
    <section class="strategy"><h2 class="sec">5 &nbsp; Strategic plays: the thinking behind the checklist</h2>
    <p>The moves a CMO, an advertising lead, an SEO lead, and an AI engineer would
    all converge on. The checklist fixes the plumbing; these decide how much the
    plumbing is worth.</p>
    %s</section>""" % cards


def _section_measurement():
    return """
    <section><h2 class="sec">6 &nbsp; How to know it's working</h2>
    <ul class="plain">
      <li><strong>Re-audit:</strong> run the free Checklane audit after each phase.
      the score should climb as fixes land.</li>
      <li><strong>Log watch:</strong> AI crawler/agent user-agents appearing in your
      server logs is the earliest signal you're being discovered.</li>
      <li><strong>The real metric:</strong> over time, track orders or inquiries that
      originate from AI surfaces (ask "how did you hear about us"; add "AI assistant"
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
<title>Checklane Report: %s</title>
<style>%s</style>
</head>
<body>
<div class="toolbar">
  <button class="btn" onclick="window.print()">Download PDF</button>
  <span class="note2">Opens the print dialog. Choose "Save as PDF" to keep a copy of your report.</span>
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
    <section><h2 class="sec">3 &nbsp; Your action plan: ranked, phased, handoff-ready</h2>
    %s</section>
    %s
    %s
    %s
    %s
  </main>
  <footer>
    <strong>Checklane</strong> grades what's technically verifiable about your site
    at audit time. This report is a roadmap, not a promise. A high score means
    nothing technical stands between you and the AI shopper; the rest is up to your
    products, prices, and reputation.<br>
    Scoring updated Sep 2026: we now grade AI discoverability too, so this score
    isn't directly comparable to audits run before then.
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
        _section_templates(),
        _section_strategy(),
        _section_measurement(),
        _section_glossary(),
    )


def _error_page(domain, error):
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Checklane Report: %s</title><style>%s</style></head>
<body><div class="page">
<header class="brand"><div class="wordmark">CHECK<span>LANE</span></div>
<h1>AI-Readiness Report</h1></header>
<main><section><h2 class="sec">Report unavailable</h2>
<p>We couldn't generate a full report for %s: %s</p>
<p>Please re-run the free audit and try again.</p></section></main>
</div></body></html>""" % (_esc(domain), _CSS, _esc(domain), _esc(error or "unknown error"))
