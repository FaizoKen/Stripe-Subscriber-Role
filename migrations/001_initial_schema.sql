-- Role links: one per guild+role pair registered via POST /register.
--
-- The rule tree is stored as JSONB and validated by `parse_rule_tree`.
-- Until an admin connects a Stripe account and sets eligibility,
-- rule_tree = '{"grant_on_any_relation":false,"groups":[]}' AND
-- grant_on_any_relation = FALSE means "grant to nobody" (Convention 42).
--
-- `stripe_account_ref` is nullable because POST /register fires the moment the
-- admin creates a role link in the RoleLogic dashboard — well before they
-- have a chance to open the iframe and connect a Stripe account. It is a plain
-- BIGINT (not an FK): on disconnect we NULL it out rather than cascade-delete
-- the role link, mirroring how a paused integration keeps its rule.
--
-- `rule_tree_version` powers optimistic locking on save: two tabs editing
-- the same role link cannot silently clobber each other. The save handler
-- bumps it inside the transaction; mismatched versions raise AppError::StaleVersion.

CREATE TABLE IF NOT EXISTS role_links (
    id                     BIGSERIAL PRIMARY KEY,
    guild_id               TEXT NOT NULL,
    role_id                TEXT NOT NULL,
    api_token              TEXT NOT NULL,
    stripe_account_ref     BIGINT,
    rule_tree              JSONB NOT NULL DEFAULT '{"grant_on_any_relation":false,"groups":[]}',
    rule_tree_version      INTEGER NOT NULL DEFAULT 1,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (guild_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_role_links_guild_role
    ON role_links (guild_id, role_id);
CREATE INDEX IF NOT EXISTS idx_role_links_account
    ON role_links (stripe_account_ref)
    WHERE stripe_account_ref IS NOT NULL;

-- Role assignments: local mirror of who currently has which Discord role.
-- The source of truth is RoleLogic; we keep this table to diff against
-- when computing add/remove deltas during sync. CASCADE keeps it in sync
-- with role_links automatically on DELETE /config.
CREATE TABLE IF NOT EXISTS role_assignments (
    guild_id        TEXT NOT NULL,
    role_id         TEXT NOT NULL,
    discord_id      TEXT NOT NULL,
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, role_id, discord_id),
    FOREIGN KEY (guild_id, role_id) REFERENCES role_links (guild_id, role_id) ON DELETE CASCADE
);
