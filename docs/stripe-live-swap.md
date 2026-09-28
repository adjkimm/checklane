# Stripe live-key swap: exact configuration and next actions

Status of this doc: the code is ready (Workstream A, branch
`workstream-a-stripe`). Nothing below has been applied to Stripe or Render;
every step that touches the dashboard or live keys needs the Principal.

## Readiness state

**READY**

- Webhook signature verification (HMAC-SHA256, `t` + `.` + payload, 5-min
  timestamp tolerance, constant-time compare). Bad signature -> 400, stale
  or malformed -> 400, retryable fulfillment failure -> 500, unknown
  events -> 200. Covered by 60 regression tests.
- Idempotent fulfillment: a redelivered `checkout.session.completed`
  cannot double-log a purchase, double-send a receipt, or double-run the
  audit, even across restarts (sqlite PRIMARY KEYs + per-session lock).
- Durable storage: paid reports and the purchase ledger live in
  `data/checklane.db` (sqlite, stdlib). `GET /api/report?session_id=X` and
  `/report?session_id=X` work after a process restart; legacy
  `purchases.jsonl` rows are imported once at startup.
- Refund/dispute handling: `charge.refunded` and `charge.dispute.created`
  are recorded idempotently (keyed by Stripe event id) and flip the
  purchase row to `refunded`/`disputed`.
- No secrets in the repo or in this branch's history (verified by grep and
  `git log -S` on 2026-09-28).

**NOT READY (needs the Principal or dashboard access)**

- Live Stripe keys have not been supplied. The service still runs on test
  keys. The live-mode swap itself is the remaining step.
- The webhook endpoint is not registered in the Stripe dashboard (could
  not verify without dashboard access).
- `STRIPE_WEBHOOK_SECRET` is not confirmed set on the Render service
  (could not verify remotely; without it every webhook 400s and Stripe
  eventually disables the endpoint).
- Render free-tier disk is ephemeral across deploys: the sqlite DB
  survives process restarts but not redeploys. The buyer receipt email
  (permanent report link) and the Stripe dashboard remain the durable
  records across deploys. A hosted database is the later upgrade path, not
  this workstream.
- Resend sending for buyer receipts was not re-verified in this
  workstream (code path unchanged; needs `RESEND_API_KEY` on the service).

## Exact configuration for the live swap

1. Webhook endpoint URL to register in Stripe:
   `https://getchecklane.com/api/stripe-webhook`
2. Events to subscribe to:
   - `checkout.session.completed` (required: fulfills the order)
   - `charge.refunded` (handled: marks the purchase refunded)
   - `charge.dispute.created` (handled: marks the purchase disputed)
3. Environment variables on the Render `checklane` service:
   - `STRIPE_SECRET_KEY` = the live secret key (`sk_live_...`)
   - `STRIPE_WEBHOOK_SECRET` = the signing secret (`whsec_...`) shown for
     the endpoint under Stripe Dashboard > Developers > Webhooks
     (click the endpoint, "Signing secret", Reveal). This is NOT the API
     key; the two must not be swapped.
   - `BASE_URL` = `https://getchecklane.com` (already the default)
   - `REPORT_PRICE_CENTS` = `900` (already the default; change only with
     Principal approval)

## Next actions, in order

1. **Principal:** supply the live keys via Secure Vault (`sk_live_...`
   restricted key and the webhook `whsec_...` signing secret). Never paste
   keys into chat or commit them.
2. **Principal (dashboard):** Stripe Dashboard > Developers > Webhooks >
   Add endpoint > URL `https://getchecklane.com/api/stripe-webhook` >
   select the three events above > create > copy the signing secret.
3. **Agent or Principal:** set `STRIPE_SECRET_KEY` and
   `STRIPE_WEBHOOK_SECRET` on the Render service; redeploy.
4. **Agent:** after deploy, confirm in Stripe Dashboard > Developers >
   Webhooks that the endpoint shows recent 200 deliveries; trigger a test
   event if needed. Then run one live test purchase and refund it to prove
   the full loop (purchase, receipt email, report link, refund marking).
5. **Principal:** assign the refund inbox owner in
   `docs/refund-procedure.md` (currently ASSIGNABLE).
6. **Principal:** confirm the refund response promise (2 business days)
   still matches the public refund page.

## Key rotation (only if a secret ever leaks)

1. Stripe Dashboard > Developers > API keys > roll the key (or
   Developers > Webhooks > roll the signing secret for `whsec_...`).
2. Update the matching Render environment variable
   (`STRIPE_SECRET_KEY` or `STRIPE_WEBHOOK_SECRET`).
3. Redeploy and confirm webhook deliveries return 200.
4. No rotation is currently required: no Stripe secret was ever committed
   to this repo or its history.
