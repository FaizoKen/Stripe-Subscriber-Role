-- Member facts: the denormalized table every rule evaluation reads from.
-- One row per (account, discord_id), aggregated from that member's customer
-- and subscription rows by `recompute_member_facts` (services/sync.rs).
--
-- Convention 6: every condition target that filters via SQL has its own column
-- here so `build_rule_where` emits straight `WHERE mf.has_active_subscription`
-- predicates instead of recomputing aggregates per query.
--
-- A row exists for a member as soon as they have any customer/subscription row
-- under the account (even cancelled / $0). "Active" subscription = status in
-- (active, trialing). Amounts are in the currency's smallest unit (cents).

CREATE TABLE IF NOT EXISTS stripe_member_facts (
    account_ref               BIGINT NOT NULL REFERENCES stripe_accounts (id) ON DELETE CASCADE,
    discord_id                TEXT NOT NULL,

    -- Customer-level facts
    is_customer               BOOLEAN NOT NULL DEFAULT FALSE,
    customer_created_at       TIMESTAMPTZ,
    country_code              TEXT,
    currency                  TEXT,
    email                     TEXT,
    email_domain              TEXT,
    is_delinquent             BOOLEAN NOT NULL DEFAULT FALSE,
    lifetime_spend_cents      BIGINT NOT NULL DEFAULT 0,
    successful_payments       INTEGER NOT NULL DEFAULT 0,

    -- Subscription-level facts (aggregated across the member's subscriptions)
    has_active_subscription   BOOLEAN NOT NULL DEFAULT FALSE,
    active_subscription_count INTEGER NOT NULL DEFAULT 0,
    subscription_status       TEXT,
    is_trialing               BOOLEAN NOT NULL DEFAULT FALSE,
    is_past_due               BOOLEAN NOT NULL DEFAULT FALSE,
    cancels_at_period_end     BOOLEAN NOT NULL DEFAULT FALSE,
    plan_amount_cents         BIGINT NOT NULL DEFAULT 0,
    billing_interval          TEXT,
    subscription_started_at   TIMESTAMPTZ,
    current_period_end        TIMESTAMPTZ,
    trial_end                 TIMESTAMPTZ,
    total_mrr_cents           BIGINT NOT NULL DEFAULT 0,
    product_ids               TEXT[] NOT NULL DEFAULT '{}',
    price_ids                 TEXT[] NOT NULL DEFAULT '{}',

    last_synced_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_ref, discord_id)
);

-- Hot path: bulk per-role-link sync filters `WHERE account_ref = $1 AND
-- discord_id = ANY(members) AND (rule)`. The partial index keeps the common
-- "active subscribers" scan cheap.
CREATE INDEX IF NOT EXISTS idx_member_facts_active
    ON stripe_member_facts (account_ref)
    WHERE has_active_subscription;
