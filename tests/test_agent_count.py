#!/usr/bin/env python3
"""Pin the engine's agent list to the published agent-list doc.

The site markets "28 AI crawlers and fetchers". The single source of truth
is AGENT_UAS in audit.py; ~/workspace/ai-agent-list.md is the published doc.
This test fails if they drift apart, so a count change can never ship in
one place and not the other.

Run: python3 tests/test_agent_count.py
Stdlib only. No network.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import audit

PASS, FAIL = 0, 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok  %s" % name)
    else:
        FAIL += 1
        print("  FAIL %s %s" % (name, extra))


DOC = os.path.expanduser("~/workspace/ai-agent-list.md")

# The doc lists one agent per "- **Name** — ..." line.
doc_names = []
if os.path.exists(DOC):
    for line in open(DOC, encoding="utf-8"):
        m = re.match(r"\s*-\s*\*\*(.+?)\*\*", line)
        if m:
            doc_names.append(m.group(1).strip())

engine_names = list(audit.AGENT_UAS.keys())


def _norm(n):
    # Engine keys carry a role note in parens: "GPTBot (OpenAI training
    # crawler)". The doc lists the bare name.
    n = n.split(" (")[0]
    return re.sub(r"[^a-z0-9]", "", n.lower())


check("agent-list doc exists", bool(doc_names),
      "doc missing or no entries parsed: %s" % DOC)
if doc_names:
    check("engine/doc counts match",
          len(engine_names) == len(doc_names),
          "engine=%d doc=%d" % (len(engine_names), len(doc_names)))
    check("engine/doc entries identical (normalized)",
          sorted(_norm(n) for n in engine_names) ==
          sorted(_norm(n) for n in doc_names),
          "engine-only=%s doc-only=%s"
          % (sorted(set(_norm(n) for n in engine_names)
                    - set(_norm(n) for n in doc_names)),
             sorted(set(_norm(n) for n in doc_names)
                    - set(_norm(n) for n in engine_names))))
    check("title count matches",
          "(%d)" % len(engine_names) in open(DOC, encoding="utf-8").read(),
          "doc title should carry the count in parentheses")

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
