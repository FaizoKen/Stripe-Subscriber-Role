-- 008: per-account webhook dedupe, webhook + import health, multi-item
-- subscriptions. Re-run on every start, so every statement is idempotent.

-- Webhook idempotency per account. Two servers can connect the same Stripe
-- account (one row and one endpoint each), and Stripe then delivers the same
-- `evt_…` to both endpoints. Keyed on the event id alone, the second
-- delivery was "duplicate ignored" and that server's mirror never changed.
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS account_ref BIGINT NOT NULL DEFAULT 0;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'webhook_deliveries'::regclass
          AND contype = 'p'
          AND array_length(conkey, 1) = 1
    ) THEN
        ALTER TABLE webhook_deliveries DROP CONSTRAINT webhook_deliveries_pkey;
        ALTER TABLE webhook_deliveries
            ADD CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (account_ref, event_id);
    END IF;
END $$;

-- What the settings page tells an admin about their webhook: when Stripe last
-- delivered an event that verified, and the last reason one was refused
-- ('signature' — the signing secret doesn't match; 'thin' — the destination
-- sends Thin events, which carry no object to read; 'no_secret' — events
-- arrive but no signing secret is saved). An error only matters while it is
-- newer than the last good delivery.
ALTER TABLE stripe_accounts ADD COLUMN IF NOT EXISTS webhook_last_ok_at TIMESTAMPTZ;
ALTER TABLE stripe_accounts ADD COLUMN IF NOT EXISTS webhook_last_failed_at TIMESTAMPTZ;
ALTER TABLE stripe_accounts ADD COLUMN IF NOT EXISTS webhook_last_error TEXT;

-- Why the last import failed (Stripe's own message, e.g. a missing
-- permission), so the page can say so instead of "Importing…" forever.
-- Cleared by the next import that succeeds.
ALTER TABLE stripe_accounts ADD COLUMN IF NOT EXISTS last_import_error TEXT;
ALTER TABLE stripe_accounts ADD COLUMN IF NOT EXISTS last_import_error_at TIMESTAMPTZ;

-- Every item of a subscription, not just the first: an add-on in item 2 is a
-- product the member is subscribed to, and the period's charge is the sum of
-- all items. `price_id` / `product_id` / `unit_amount_cents` keep the first
-- item for anything that still reads them.
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS price_ids TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS product_ids TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE stripe_subscriptions ADD COLUMN IF NOT EXISTS period_amount_cents BIGINT;

-- Rows written before this migration: their one item. New writes always set
-- period_amount_cents, so after the first start this matches nothing.
UPDATE stripe_subscriptions SET
    price_ids = CASE WHEN price_id IS NULL THEN '{}' ELSE ARRAY[price_id] END,
    product_ids = CASE WHEN product_id IS NULL THEN '{}' ELSE ARRAY[product_id] END,
    period_amount_cents = unit_amount_cents * GREATEST(quantity, 1)
WHERE period_amount_cents IS NULL;
