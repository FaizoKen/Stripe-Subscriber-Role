//! Shutdown plumbing shared by the HTTP server and background workers.
//!
//! Owning a single `Shutdown` lets every component subscribe to the same
//! cancellation signal. On SIGTERM/SIGINT, the listener fires `broadcast::send`,
//! which wakes:
//!   * the axum server (so it stops accepting new connections and drains)
//!   * every job-polling worker (Phase 7+)
//!   * the rate-limiter GC and any other long-running tasks
//!
//! After `wait()` resolves, callers should NOT start new work but MUST
//! finish what's already in flight. The main loop in `main.rs` joins all
//! worker handles before exiting so no in-flight job is silently dropped.

use tokio::sync::broadcast;

#[derive(Clone)]
pub struct Shutdown {
    tx: broadcast::Sender<()>,
}

impl Shutdown {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel::<()>(1);
        Self { tx }
    }

    /// Get a fresh receiver. Each component (worker, axum, etc.) should own
    /// its own receiver and `.await` on it.
    pub fn subscribe(&self) -> ShutdownGuard {
        ShutdownGuard {
            rx: self.tx.subscribe(),
        }
    }

    /// Fire the shutdown signal. Idempotent — calling more than once is fine.
    pub fn trigger(&self) {
        let _ = self.tx.send(());
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot wait handle. Most workers want exactly one of these and
/// `await` it inside a `tokio::select!` arm.
pub struct ShutdownGuard {
    rx: broadcast::Receiver<()>,
}

impl ShutdownGuard {
    /// Resolves when shutdown is triggered. Cancellation-safe under `select!`.
    pub async fn wait(&mut self) {
        let _ = self.rx.recv().await;
    }

    /// Non-blocking check.
    #[allow(dead_code)]
    pub fn is_triggered(&mut self) -> bool {
        matches!(
            self.rx.try_recv(),
            Ok(()) | Err(broadcast::error::TryRecvError::Closed)
        )
    }
}

/// Block until the OS sends us SIGTERM (orchestrator stop) or SIGINT
/// (Ctrl-C). On Windows only Ctrl-C is supported by tokio.
pub async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("Received SIGTERM"),
            _ = sigint.recv() => tracing::info!("Received SIGINT"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Received Ctrl-C");
    }
}
