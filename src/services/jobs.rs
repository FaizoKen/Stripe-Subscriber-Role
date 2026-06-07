//! Durable background-job queue backed by the `jobs` table.
//!
//! Events survive replica crashes / SIGTERM (durable, transactional); any
//! replica can pick up a job (`FOR UPDATE SKIP LOCKED`); transient upstream
//! failures retry with exponential backoff + jitter; permanently-failing jobs
//! land in a DLQ (`status = 'dead'`).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgExecutor, PgPool};

use crate::error::AppError;

/// Postgres NOTIFY channel that fires when an immediately-runnable job is
/// inserted. `tasks::job_listener` LISTENs and wakes the shared `Notify`.
pub const JOBS_CHANNEL: &str = "jobs_pending";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum JobKind {
    PlayerSync,
    ConfigSync,
    AccountSync,
    AccountBackfill,
}

impl JobKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PlayerSync => "player_sync",
            Self::ConfigSync => "config_sync",
            Self::AccountSync => "account_sync",
            Self::AccountBackfill => "account_backfill",
        }
    }
    pub fn from_db(s: &str) -> Option<Self> {
        match s {
            "player_sync" => Some(Self::PlayerSync),
            "config_sync" => Some(Self::ConfigSync),
            "account_sync" => Some(Self::AccountSync),
            "account_backfill" => Some(Self::AccountBackfill),
            _ => None,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct Job {
    pub id: i64,
    pub kind: String,
    pub payload: Value,
    pub attempts: i32,
    pub max_attempts: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlayerSyncPayload {
    pub discord_id: String,
}

/// Enqueue a job. Pass a transaction reference for atomicity with the
/// surrounding write. `delay_secs` rolls into `next_run_at` (config_sync
/// debounces rapid saves into one delayed run).
pub async fn enqueue<'e, E>(
    executor: E,
    kind: JobKind,
    payload: Value,
    delay_secs: u64,
) -> Result<(), AppError>
where
    E: PgExecutor<'e>,
{
    sqlx::query(
        "WITH inserted AS ( \
             INSERT INTO jobs (kind, payload, next_run_at) \
             VALUES ($1, $2, now() + make_interval(secs => $3)) \
             RETURNING next_run_at \
         ) \
         SELECT pg_notify('jobs_pending', '') \
         FROM inserted WHERE next_run_at <= now()",
    )
    .bind(kind.as_str())
    .bind(payload)
    .bind(delay_secs as f64)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn claim_batch(
    pool: &PgPool,
    worker_id: &str,
    batch_size: i64,
) -> Result<Vec<Job>, AppError> {
    let rows = sqlx::query_as::<_, Job>(
        "UPDATE jobs SET status = 'in_progress', \
                          locked_by = $1, \
                          locked_at = now(), \
                          attempts = attempts + 1 \
         WHERE id IN ( \
             SELECT id FROM jobs \
             WHERE status = 'pending' AND next_run_at <= now() \
             ORDER BY id \
             LIMIT $2 \
             FOR UPDATE SKIP LOCKED \
         ) \
         RETURNING id, kind, payload, attempts, max_attempts",
    )
    .bind(worker_id)
    .bind(batch_size)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn complete(pool: &PgPool, id: i64) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE jobs SET status = 'completed', completed_at = now(), \
                         locked_by = NULL, locked_at = NULL WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn fail_retry(pool: &PgPool, job: &Job, err: &str) -> Result<(), AppError> {
    let delay = backoff_delay(job.attempts);
    sqlx::query(
        "UPDATE jobs SET status = 'pending', \
                         next_run_at = now() + make_interval(secs => $1), \
                         last_error = $2, locked_by = NULL, locked_at = NULL \
         WHERE id = $3",
    )
    .bind(delay.as_secs_f64())
    .bind(err)
    .bind(job.id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn fail_dead(pool: &PgPool, id: i64, err: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE jobs SET status = 'dead', completed_at = now(), \
                         last_error = $1, locked_by = NULL, locked_at = NULL \
         WHERE id = $2",
    )
    .bind(err)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn reap_stuck(pool: &PgPool, max_lock_secs: i64) -> Result<u64, AppError> {
    let res = sqlx::query(
        "UPDATE jobs SET status = 'pending', next_run_at = now(), \
                         locked_by = NULL, locked_at = NULL \
         WHERE status = 'in_progress' \
           AND locked_at < now() - make_interval(secs => $1)",
    )
    .bind(max_lock_secs as f64)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Exponential backoff with up-to-1s jitter. Attempts 1..=7 sleep 2s..128s;
/// attempt 8 caps at 256s.
pub fn backoff_delay(attempt: i32) -> std::time::Duration {
    use rand::Rng;
    let capped = attempt.clamp(1, 8);
    let base_secs = 2_u64.pow(capped as u32);
    let jitter_ms = rand::thread_rng().gen_range(0..1000);
    std::time::Duration::from_millis(base_secs * 1000 + jitter_ms)
}

// ---------------------------------------------------------------------------
// Typed enqueue helpers
// ---------------------------------------------------------------------------

pub async fn enqueue_player_sync<'e, E>(executor: E, discord_id: &str) -> Result<(), AppError>
where
    E: PgExecutor<'e>,
{
    let payload = serde_json::to_value(PlayerSyncPayload {
        discord_id: discord_id.to_string(),
    })
    .expect("PlayerSyncPayload serializes");
    enqueue(executor, JobKind::PlayerSync, payload, 0).await
}

/// Config-sync is debounced 5s to absorb autosave bursts.
pub async fn enqueue_config_sync<'e, E>(
    executor: E,
    guild_id: &str,
    role_id: &str,
) -> Result<(), AppError>
where
    E: PgExecutor<'e>,
{
    let payload = json!({ "guild_id": guild_id, "role_id": role_id });
    enqueue(executor, JobKind::ConfigSync, payload, 5).await
}

/// Re-evaluate every role link bound to a Stripe account after its data
/// changed (backfill / reconcile finished). De-duped: only enqueues if no
/// identical `account_sync` is already pending.
pub async fn enqueue_account_sync(pool: &PgPool, account_ref: i64) -> Result<(), AppError> {
    enqueue_account_job(pool, JobKind::AccountSync, account_ref, 0).await
}

/// Full import of a newly connected Stripe account. De-duped against pending.
pub async fn enqueue_account_backfill(pool: &PgPool, account_ref: i64) -> Result<(), AppError> {
    enqueue_account_job(pool, JobKind::AccountBackfill, account_ref, 0).await
}

async fn enqueue_account_job(
    pool: &PgPool,
    kind: JobKind,
    account_ref: i64,
    delay_secs: u64,
) -> Result<(), AppError> {
    sqlx::query(
        "WITH inserted AS ( \
             INSERT INTO jobs (kind, payload, next_run_at) \
             SELECT $1, $2, now() + make_interval(secs => $4) \
             WHERE NOT EXISTS ( \
                 SELECT 1 FROM jobs \
                 WHERE kind = $1 AND status = 'pending' \
                   AND payload->>'account_ref' = $3 \
             ) \
             RETURNING next_run_at \
         ) \
         SELECT pg_notify('jobs_pending', '') \
         FROM inserted WHERE next_run_at <= now()",
    )
    .bind(kind.as_str())
    .bind(json!({ "account_ref": account_ref }))
    .bind(account_ref.to_string())
    .bind(delay_secs as f64)
    .execute(pool)
    .await?;
    Ok(())
}
