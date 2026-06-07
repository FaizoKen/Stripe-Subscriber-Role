-- Stripe accounts: one row per Stripe account a server admin has connected.
--
-- Connection is by *restricted API key* (read-only) — no Stripe Connect
-- platform required, so the plugin is fully self-hostable. A single guild can
-- connect multiple accounts; a role link binds to exactly one via
-- `role_links.stripe_account_ref` (mirrors how a Kick role binds to a channel).
--
-- `api_key_enc` / `webhook_secret_enc` are AES-256-GCM ciphertexts whose key is
-- HKDF-derived from SESSION_SECRET (see services/crypto.rs). A DB dump alone
-- can't read the merchant's Stripe key.
--
-- `discord_metadata_key` is the Stripe metadata field that holds the buyer's
-- Discord user ID. Default `discord_user_id` matches the convention used by
-- RoleLogic's own billing (subscription_data.metadata.discord_user_id +
-- client_reference_id). Bot devs with a different convention just change this.
--
-- `stripe_account_id` (acct_...) is captured from GET /v1/account for display
-- and to dedupe re-connects of the same account within a guild.

CREATE TABLE IF NOT EXISTS stripe_accounts (
    id                      BIGSERIAL PRIMARY KEY,
    guild_id                TEXT NOT NULL,
    stripe_account_id       TEXT NOT NULL,
    display_name            TEXT NOT NULL,
    country                 TEXT,
    livemode                BOOLEAN NOT NULL DEFAULT TRUE,

    api_key_enc             BYTEA NOT NULL,
    webhook_secret_enc      BYTEA,
    discord_metadata_key    TEXT NOT NULL DEFAULT 'discord_user_id',

    last_synced_at          TIMESTAMPTZ,
    last_backfill_at        TIMESTAMPTZ,
    connected_by_discord_id TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (guild_id, stripe_account_id)
);

CREATE INDEX IF NOT EXISTS idx_stripe_accounts_guild
    ON stripe_accounts (guild_id);
