# Deletion request runbook — Checklane

Handling data-deletion requests under the "Your data and deletion requests"
section of /privacy. Each request is handled manually by a person — there is
no automated or scheduled deletion workflow. This runbook does not assert any
legal obligation; the deletion process is a voluntary practice.

## Where the data lives

- **Form messages** (name, email, message): forwarded via Resend to the
  operator's Gmail inbox (currently adjkimm@gmail.com).
- **Beta waiting-list signups** (name, email): in `data/beta.jsonl` on the
  Render service (ephemeral disk), plus the Resend notification email to the
  operator's inbox. Stdout logs carry only a PII-free signup id.
- **Purchase email**: in `data/purchases.jsonl` on the Render service
  (ephemeral disk — Stripe session records are the durable system of record),
  in fulfillment stdout logs, and in buyer receipt emails sent via Resend.
- **Accounting/tax receipts**: kept by law and are NOT deleted.

## Steps

1. **Verify the requester.** The request must come from the same email address
   as the records. A reply from that address counts as verified. A homepage
   message-form submission only shows what email was *typed* — treat it as
   unverified on arrival: send a confirmation email to the address and proceed
   only after a reply. No confirmed match → do not proceed.
2. **Search Gmail** (operator inbox) for the requester's address; identify all
   matching form-forward and beta-signup notification messages.
3. **Delete the matching Gmail messages.** This is a destructive action —
   requires Andrew's per-request approval. Do not delete without it.
4. **Delete beta waiting-list entries** from `data/beta.jsonl` on the Render
   service (note: the disk is ephemeral; stdout logs carry only a PII-free
   signup id, so there is nothing personal to remove there). The matching
   inbox notification email is covered by step 3.
5. **Do not remove purchase/receipt records.** The purchase email stays in
   `data/purchases.jsonl` (ephemeral Render disk), in Render stdout logs, and
   in Stripe's session records, which are the durable accounting system of
   record. Per the /privacy retention policy and the open-ended /refund
   delivery guarantee, these are retained for accounting, tax, refund handling,
   and report re-delivery. Tell the requester the purchase email is kept and
   used only for those purposes.
6. **Confirm completion by email** to the requester from
   `Checklane <notify@getchecklane.com>` via Resend.
7. **Log the action** with the date (what was deleted, what was retained by
   law) in the family-office operations log.

## Response commitment

Respond within 2 business days (matches the /refund promise); send the
confirmation email when deletion is complete.

## Do not

- Do not promise automated or scheduled deletion — no such workflow exists.
- Do not assert CCPA, GDPR, or any other legal obligation.
- Do not delete anything from Gmail without Andrew's per-request approval.
