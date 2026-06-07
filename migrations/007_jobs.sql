-- Durable background-job queue.
--
-- Workers claim rows with `FOR UPDATE SKIP LOCKED` so N replicas drain in
-- parallel without double-processing. NOTIFY/LISTEN on `jobs_pending` wakes
-- idle workers sub-second; the poll timer is a safety net for missed
-- notifications under pgBouncer transaction-pool mode.
--
-- `kind` discriminates the payload shape:
--   * 'player_sync'      → {"discord_id": "..."}            (re-eval one member)
--   * 'config_sync'      → {"guild_id": "...", "role_id": "..."}  (re-eval one role link)
--   * 'account_sync'     → {"account_ref": 123}            (fan out to bound role links)
--   * 'account_backfill' → {"account_ref": 123}            (full import from Stripe)
--
-- Lifecycle: pending → in_progress → (completed | pending-with-backoff | dead).

CREATE TABLE IF NOT EXISTS jobs (
    id              BIGSERIAL PRIMARY KEY,
    kind            TEXT NOT NULL,
    payload         JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 8,
    next_run_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT,
    locked_by       TEXT,
    locked_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    CONSTRAINT jobs_status_check
        CHECK (status IN ('pending','in_progress','completed','dead'))
);

CREATE INDEX IF NOT EXISTS idx_jobs_pending_next_run
    ON jobs (next_run_at)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_jobs_dead_recent
    ON jobs (completed_at DESC)
    WHERE status = 'dead';

CREATE INDEX IF NOT EXISTS idx_jobs_locked
    ON jobs (locked_at)
    WHERE status = 'in_progress';

-- Supports the WHERE-NOT-EXISTS de-dupe guard in `enqueue_account_*`, which
-- avoids piling up identical pending account_backfill / account_sync jobs for
-- the same account.
CREATE INDEX IF NOT EXISTS idx_jobs_account_pending
    ON jobs (kind, (payload->>'account_ref'))
    WHERE status = 'pending' AND kind IN ('account_backfill','account_sync');
