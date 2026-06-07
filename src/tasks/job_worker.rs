//! Job-polling worker. N worker tasks (`WORKER_CONCURRENCY`) run in parallel;
//! each claims a batch via `FOR UPDATE SKIP LOCKED` and dispatches by job kind.
//! Workers stop accepting new work on shutdown but finish what's in-flight.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::error::AppError;
use crate::services::jobs::{self, Job, JobKind, PlayerSyncPayload};
use crate::services::sync;
use crate::tasks::shutdown::ShutdownGuard;
use crate::AppState;

const POLL_INTERVAL: Duration = Duration::from_secs(2);
const BATCH_SIZE: i64 = 8;
/// Reap in_progress jobs whose lock is older than this (worker crashed
/// mid-claim). Slightly above the longest legitimate sync / backfill.
const STUCK_LOCK_SECS: i64 = 60 * 45;

pub async fn run(state: Arc<AppState>, mut shutdown: ShutdownGuard, worker_id: String) {
    tracing::info!(worker_id, "Job worker started");

    let mut last_reap = std::time::Instant::now();
    let reap_every = Duration::from_secs(120);

    loop {
        if shutdown.is_triggered() {
            break;
        }

        if last_reap.elapsed() >= reap_every {
            if let Ok(n) = jobs::reap_stuck(&state.pool, STUCK_LOCK_SECS).await {
                if n > 0 {
                    tracing::warn!(reaped = n, "Reaped stuck-in-progress jobs");
                }
            }
            last_reap = std::time::Instant::now();
        }

        let claimed = match jobs::claim_batch(&state.pool, &worker_id, BATCH_SIZE).await {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(worker_id, "claim_batch failed: {e}");
                tokio::select! {
                    _ = tokio::time::sleep(POLL_INTERVAL) => {}
                    _ = shutdown.wait() => break,
                }
                continue;
            }
        };

        if claimed.is_empty() {
            tokio::select! {
                _ = state.jobs_notify.notified() => continue,
                _ = tokio::time::sleep(POLL_INTERVAL) => continue,
                _ = shutdown.wait() => break,
            }
        }

        for job in claimed {
            if shutdown.is_triggered() {
                if let Err(e) = jobs::fail_retry(&state.pool, &job, "worker shutting down").await {
                    tracing::error!(job.id, "failed to release job during shutdown: {e}");
                }
                continue;
            }

            let kind_for_log = job.kind.clone();
            let job_id = job.id;
            match dispatch(&job, &state).await {
                Ok(()) => {
                    if let Err(e) = jobs::complete(&state.pool, job_id).await {
                        tracing::error!(job_id, "complete failed: {e}");
                    }
                }
                Err(outcome) => match outcome {
                    JobError::Terminal(msg) => {
                        tracing::error!(job_id, kind = %kind_for_log, "Job dead (terminal): {msg}");
                        let _ = jobs::fail_dead(&state.pool, job_id, &msg).await;
                    }
                    JobError::Retry(msg) => {
                        if job.attempts >= job.max_attempts {
                            tracing::error!(
                                job_id,
                                kind = %kind_for_log,
                                attempts = job.attempts,
                                "Job dead (max attempts exceeded): {msg}"
                            );
                            let _ = jobs::fail_dead(&state.pool, job_id, &msg).await;
                        } else {
                            tracing::warn!(
                                job_id,
                                kind = %kind_for_log,
                                attempts = job.attempts,
                                "Job failed, will retry: {msg}"
                            );
                            let _ = jobs::fail_retry(&state.pool, &job, &msg).await;
                        }
                    }
                },
            }
        }
    }

    tracing::info!(worker_id, "Job worker drained and stopping");
}

enum JobError {
    Terminal(String),
    Retry(String),
}

impl From<AppError> for JobError {
    fn from(e: AppError) -> Self {
        match e {
            AppError::RoleLinkNotFound => {
                JobError::Terminal("role link no longer exists upstream".into())
            }
            AppError::UserLimitReached { limit } => JobError::Terminal(format!(
                "role link user limit reached ({limit}); retry won't help"
            )),
            other => JobError::Retry(other.to_string()),
        }
    }
}

async fn dispatch(job: &Job, state: &Arc<AppState>) -> Result<(), JobError> {
    let kind = JobKind::from_db(&job.kind)
        .ok_or_else(|| JobError::Terminal(format!("unknown job kind '{}'", job.kind)))?;

    match kind {
        JobKind::PlayerSync => {
            let payload: PlayerSyncPayload = serde_json::from_value(job.payload.clone())
                .map_err(|e| JobError::Terminal(format!("invalid player_sync payload: {e}")))?;
            sync::sync_for_player(&payload.discord_id, state).await?;
        }
        JobKind::ConfigSync => {
            let guild_id = job
                .payload
                .get("guild_id")
                .and_then(Value::as_str)
                .ok_or_else(|| JobError::Terminal("config_sync missing guild_id".into()))?;
            let role_id = job
                .payload
                .get("role_id")
                .and_then(Value::as_str)
                .ok_or_else(|| JobError::Terminal("config_sync missing role_id".into()))?;
            sync::sync_for_role_link(guild_id, role_id, state).await?;
        }
        JobKind::AccountSync => {
            let account_ref = job
                .payload
                .get("account_ref")
                .and_then(Value::as_i64)
                .ok_or_else(|| JobError::Terminal("account_sync missing account_ref".into()))?;
            sync::sync_for_account(account_ref, state).await?;
        }
        JobKind::AccountBackfill => {
            let account_ref = job
                .payload
                .get("account_ref")
                .and_then(Value::as_i64)
                .ok_or_else(|| JobError::Terminal("account_backfill missing account_ref".into()))?;
            crate::tasks::reconcile::import_account(state, account_ref, true).await?;
        }
    }
    Ok(())
}
