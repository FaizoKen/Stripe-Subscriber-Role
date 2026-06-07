//! Per-replica `LISTEN jobs_pending` task. Translates Postgres NOTIFYs
//! emitted by `services::jobs::enqueue` into wakes on the shared `Notify`
//! every worker selects on, dropping pickup latency from a poll interval to
//! sub-10ms. The poll loop in `job_worker` stays as a safety net for missed
//! notifications (reconnect window / pgBouncer transaction-mode).

use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgListener;
use sqlx::PgPool;
use tokio::sync::Notify;

use crate::services::jobs::JOBS_CHANNEL;
use crate::tasks::shutdown::ShutdownGuard;

const RECONNECT_BACKOFF: Duration = Duration::from_secs(5);

pub async fn run(pool: PgPool, notify: Arc<Notify>, mut shutdown: ShutdownGuard) {
    tracing::info!("Job listener starting");

    loop {
        if shutdown.is_triggered() {
            break;
        }

        let mut listener = match PgListener::connect_with(&pool).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("PgListener connect failed: {e}; retrying after backoff");
                tokio::select! {
                    _ = tokio::time::sleep(RECONNECT_BACKOFF) => continue,
                    _ = shutdown.wait() => break,
                }
            }
        };

        if let Err(e) = listener.listen(JOBS_CHANNEL).await {
            tracing::warn!("LISTEN {JOBS_CHANNEL} failed: {e}; retrying after backoff");
            tokio::select! {
                _ = tokio::time::sleep(RECONNECT_BACKOFF) => continue,
                _ = shutdown.wait() => break,
            }
        }

        tracing::info!(channel = JOBS_CHANNEL, "Job listener subscribed");

        loop {
            tokio::select! {
                recv = listener.recv() => match recv {
                    Ok(_) => notify.notify_waiters(),
                    Err(e) => {
                        tracing::warn!("PgListener recv failed: {e}; reconnecting");
                        break;
                    }
                },
                _ = shutdown.wait() => {
                    tracing::info!("Job listener stopping");
                    return;
                }
            }
        }
    }

    tracing::info!("Job listener exited");
}
