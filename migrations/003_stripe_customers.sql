-- Stripe customers: local mirror, one row per (account, customer).
--
-- `discord_id` is resolved from customer.metadata[discord_metadata_key] (and
-- back-filled from a linked subscription's metadata / a checkout session's
-- client_reference_id). NULL means "we have a customer record but don't yet
-- know which Discord user it is" — that customer simply matches no rule.
--
-- `lifetime_spend_cents` / `successful_payments` are accumulated from
-- charge.succeeded webhooks and (best-effort) the reconcile charge pass.
-- Amounts are in the charge currency's smallest unit (e.g. cents).

CREATE TABLE IF NOT EXISTS stripe_customers (
    account_ref           BIGINT NOT NULL REFERENCES stripe_accounts (id) ON DELETE CASCADE,
    customer_id           TEXT NOT NULL,
    discord_id            TEXT,
    email                 TEXT,
    name                  TEXT,
    country               TEXT,
    currency              TEXT,
    delinquent            BOOLEAN NOT NULL DEFAULT FALSE,
    stripe_created_at     TIMESTAMPTZ,
    lifetime_spend_cents  BIGINT NOT NULL DEFAULT 0,
    successful_payments   INTEGER NOT NULL DEFAULT 0,
    last_synced_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_ref, customer_id)
);

CREATE INDEX IF NOT EXISTS idx_stripe_customers_discord
    ON stripe_customers (account_ref, discord_id)
    WHERE discord_id IS NOT NULL;
