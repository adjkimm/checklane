# Checklane refund procedure (internal)

One page. The person named below owns the refund inbox and runs every step.

## Owner

**Refund inbox owner: ASSIGNABLE** (the Principal assigns this before the
live-key swap; until then, refund requests go to the Principal directly).

The owner watches the inbox the receipt emails reply to and the homepage
message form. Every refund request gets a first response within
**2 business days** (this is the promise on our refund page).

## What the guarantee says

1. **7-day satisfaction guarantee.** Not happy for any reason within 7 days
   of purchase: full refund, no questions asked.
2. **Delivery guarantee.** Report fails to generate, cannot be displayed,
   or the buyer cannot access it within 30 days of purchase: re-run the
   report or refund, the buyer's choice.
3. After 7 days with a delivered report, refunds are at our discretion
   (the delivery guarantee still applies within its 30 days).
4. Refunds go back to the card paid with and typically arrive within
   5-10 business days, depending on the buyer's bank.

## Manual refund steps (Stripe dashboard)

1. Find the payment: Stripe dashboard > Payments, search by the buyer's
   email, or by the payment intent id from the purchase ledger
   (`payment_intent` column). Confirm the amount and date.
2. Open the payment, click **Refund**. For a full refund leave the amount
   as-is; for a partial refund enter the agreed amount and note why.
3. In the refund reason field, write one line: the request date, who
   approved it, and which guarantee applied (7-day / delivery /
   discretionary).
4. Tell the buyer: confirm the refund is issued, the amount, and that it
   typically arrives within 5-10 business days.
5. Log it (see below). Mark the case closed only after the buyer confirms
   or 10 business days pass with no reply.

## Re-run instead of refund

If the buyer picks the delivery-guarantee re-run: verify the purchase in
the ledger, re-run their free audit for the same domain, and send them the
new report link. Log the re-run the same way as a refund.

## What to log for each case

Keep one running log (a simple sheet is fine). One row per case:

- date of request, buyer email, domain, purchase date and amount
- which guarantee applied (7-day / delivery / discretionary)
- outcome: refunded (full/partial + amount), re-run sent, or declined
- date resolved, who handled it

## Escalation

- **Chargeback / dispute filed:** do not refund through the dashboard once
  a dispute is open. Respond in Stripe dashboard > Disputes with the
  receipt email record and the delivery log, and notify the Principal the
  same day.
- **Buyer threatens legal action or asks for anything outside the
  guarantee:** pause, notify the Principal, do not promise anything.
- **Refund volume spikes** (more than a couple in a week): notify the
  Principal; it may signal a broken report, not unhappy buyers.
- **Anything unclear:** ask the Principal. A wrong refund costs less than
  a broken promise, but an unlogged one costs the most.

## After a refund

The webhook marks the purchase `refunded` in the ledger automatically
(`charge.refunded` event). If a refund was issued and the ledger does not
show it within a day, note it in the case log and tell the Principal.
