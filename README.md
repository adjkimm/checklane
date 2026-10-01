# Checklane

**Live at [getchecklane.com](https://getchecklane.com)** — free AI-shopper-readiness audit for small businesses.

Free agent-readiness audit for SMBs — "SEO for AI shopping agents."

## Run

```bash
pip install -r requirements.txt
python server.py
```

The server binds `0.0.0.0:$PORT` (defaults to 8000) and serves the audit UI.

## What it does

Paste a product URL; Checklane probes how the listing appears to AI shopping
agents — structured data, agent-visible pricing, seller identity signals —
and returns a scored readiness report.
