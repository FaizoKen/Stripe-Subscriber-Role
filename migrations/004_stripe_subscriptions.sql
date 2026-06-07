-- Stripe subscriptions: local mirror, one row per (account, subscription).
--
-- Written by the webhook ingestor (customer.subscription.* events) and the
-- reconcile/backfill passes. The denormalized `stripe_member_facts` table is
-- recomputed from these rows after each change.
--
-- `discord_id` is resolved from subscription.metadata[discord_metadata_key],
-- the linked customer's metadata, or a checkout session's client_reference_id.
--
-- `status` is the raw Stripe value: active, trialing, past_due, canceled,
-- unpaid, incomplete, incomplete_expired, paused.
--
-- `current_period_end` is read from the subscription OR its first item (Stripe
-- moved the field to the item level on newer API versions).

CREATE TABLE IF NOT EXISTS stripe_subscriptions (
    account_ref           BIGINT NOT NULL REFERENCES stripe_accounts (id) ON DELETE CASCADE,
    subscription_id       TEXT NOT NULL,
    customer_id           TEXT,
    discord_id            TEXT,
    status                TEXT NOT NULL,
    price_id              TEXT,
    product_id            TEXT,
    unit_amount_cents     BIGINT NOT NULL DEFAULT 0,
    currency              TEXT,
    interval              TEXT,
    interval_count        INTEGER NOT NULL DEFAULT 1,
    quantity              INTEGER NOT NULL DEFAULT 1,
    cancel_at_period_end  BOOLEAN NOT NULL DEFAULT FALSE,
    current_period_end    TIMESTAMPTZ,
    trial_end             TIMESTAMPTZ,
    started_at            TIMESTAMPTZ,
    stripe_created_at     TIMESTAMPTZ,
    last_synced_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_ref, subscription_id)
);

CREATE INDEX IF NOT EXISTS idx_stripe_subs_discord
    ON stripe_subscriptions (account_ref, discord_id)
    WHERE discord_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_stripe_subs_customer
    ON stripe_subscriptions (account_ref, customer_id);
