//! Account import + reconcile worker.
//!
//! `import_account` pulls every subscription, customer and (best-effort) charge
//! for one connected Stripe account, upserts the local mirror, rebuilds member
//! facts, and fans a re-sync out to the account's role links. It's used both
//! for the initial backfill (the `account_backfill` job, queued on connect) and
//! by the periodic reconcile loop (the webhook-loss safety net, every 6h).
//!
//! Also GCs old webhook-delivery idempotency rows.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::error::AppError;
use crate::services::stripe::{self, StripeClient};
use crate::services::{crypto, ingest, jobs, sync};
use crate::tasks::shutdown::ShutdownGuard;
use crate::AppState;

const TICK: Duration = Duration::from_secs(6 * 60 * 60);
/// Run a first reconcile shortly after boot, then every TICK.
const INITIAL_DELAY: Duration = Duration::from_secs(120);

pub async fn run(state: Arc<AppState>, mut shutdown: ShutdownGuard) {
    tracing::info!("Reconcile worker started");

    tokio::select! {
        _ = tokio::time::sleep(INITIAL_DELAY) => {}
        _ = shutdown.wait() => return,
    }

    let mut interval = tokio::time::interval(TICK);
    loop {
        gc(&state).await;

        let accounts: Vec<i64> = sqlx::query_scalar("SELECT id FROM stripe_accounts")
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();

        for account_ref in accounts {
            if shutdown.is_triggered() {
                break;
            }
            if let Err(e) = import_account(&state, account_ref, false).await {
                tracing::warn!(account_ref, "reconcile failed: {e}");
            }
        }

        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown.wait() => break,
        }
    }

    tracing::info!("Reconcile worker stopped");
}

async fn gc(state: &Arc<AppState>) {
    let _ = sqlx::query(
        "DELETE FROM webhook_deliveries WHERE received_at < now() - interval '24 hours'",
    )
    .execute(&state.pool)
    .await;
}

/// Decrypt a connected account's restricted API key.
pub fn decrypt_key(state: &AppState, enc: &[u8]) -> Result<String, AppError> {
    let plain = crypto::decrypt(&state.config.session_secret, enc)
        .map_err(|_| AppError::Internal("failed to decrypt Stripe key".into()))?;
    String::from_utf8(plain).map_err(|_| AppError::Internal("Stripe key is not valid UTF-8".into()))
}

/// Full import of one account from Stripe. Idempotent — safe to re-run.
///
/// A failure is kept on the account (`last_import_error`, Stripe's own
/// message) so the settings page can say why — a missing permission, a
/// revoked key — instead of "Importing…" forever. The next import that
/// succeeds clears it.
pub async fn import_account(
    state: &Arc<AppState>,
    account_ref: i64,
    mark_backfill: bool,
) -> Result<(), AppError> {
    let result = import_inner(state, account_ref, mark_backfill).await;
    let error = result.as_ref().err().map(stripe::readable_error);
    let _ = sqlx::query(
        "UPDATE stripe_accounts SET last_import_error = $2, \
            last_import_error_at = CASE WHEN $2::text IS NULL THEN NULL ELSE now() END \
         WHERE id = $1",
    )
    .bind(account_ref)
    .bind(&error)
    .execute(&state.pool)
    .await;
    result
}

/// How far back a routine reconcile reads Checkout Sessions (the first
/// import reads them all): far enough to cover a webhook that never came.
const CHECKOUT_LOOKBACK_SECS: i64 = 7 * 24 * 60 * 60;

async fn import_inner(
    state: &Arc<AppState>,
    account_ref: i64,
    mark_backfill: bool,
) -> Result<(), AppError> {
    let row = sqlx::query_as::<_, (Vec<u8>, String)>(
        "SELECT api_key_enc, discord_metadata_key FROM stripe_accounts WHERE id = $1",
    )
    .bind(account_ref)
    .fetch_optional(&state.pool)
    .await?;
    let Some((api_key_enc, metadata_key)) = row else {
        // Account was disconnected mid-flight; nothing to import.
        return Ok(());
    };
    let key = decrypt_key(state, &api_key_enc)?;
    let client = StripeClient::new(state.config.stripe_api_base.clone());

    let mut touched: HashSet<String> = HashSet::new();

    // 1. Subscriptions (status=all, customer + price expanded).
    let subs = client.list_all_subscriptions(&key).await?;
    let sub_count = subs.len();
    for s in &subs {
        if let Some(did) =
            ingest::upsert_subscription(&state.pool, account_ref, s, &metadata_key, None).await?
        {
            touched.insert(did);
        }
    }

    // 2. Customers (covers one-time payers / customers with no subscription).
    let customers = client.list_all_customers(&key).await?;
    let cust_count = customers.len();
    for c in &customers {
        if let Some(did) =
            ingest::upsert_customer(&state.pool, account_ref, c, &metadata_key).await?
        {
            touched.insert(did);
        }
    }

    // 2b. Completed checkouts that carried the Discord ID only on the session
    //     (`client_reference_id` or session metadata): link the subscription
    //     and customer they created. Best-effort — the key may not grant
    //     Checkout Sessions read; subscription/customer metadata still link.
    let since = (!mark_backfill).then(|| chrono::Utc::now().timestamp() - CHECKOUT_LOOKBACK_SECS);
    match client.list_checkout_links(&key, since).await {
        Ok(links) => {
            for l in &links {
                let Some(did) = ingest::checkout_discord_id(
                    &l.metadata,
                    l.client_reference_id.as_deref(),
                    &metadata_key,
                ) else {
                    continue;
                };
                if let Some(d) = ingest::apply_checkout_link(
                    &state.pool,
                    account_ref,
                    &did,
                    l.customer_id.as_deref(),
                    l.subscription_id.as_deref(),
                )
                .await?
                {
                    touched.insert(d);
                }
            }
        }
        Err(e) => {
            tracing::info!(account_ref, "checkout-session links skipped: {e}");
        }
    }

    // 3. Charges → lifetime spend + payment count (best-effort; the restricted
    //    key may not grant charge read, in which case we keep whatever the
    //    charge.succeeded webhooks have accumulated).
    match client.aggregate_charges(&key).await {
        Ok((spend, count)) => {
            // Reset then set absolute values so refunds/voids converge correctly.
            sqlx::query(
                "UPDATE stripe_customers SET lifetime_spend_cents = 0, successful_payments = 0 \
                 WHERE account_ref = $1",
            )
            .bind(account_ref)
            .execute(&state.pool)
            .await?;
            for (customer_id, amount) in &spend {
                let n = *count.get(customer_id).unwrap_or(&0) as i32;
                let did =
                    ingest::set_customer_spend(&state.pool, account_ref, customer_id, *amount, n)
                        .await?;
                if let Some(d) = did {
                    touched.insert(d);
                }
            }
        }
        Err(e) => {
            tracing::info!(account_ref, "charge aggregation skipped: {e}");
        }
    }

    // 4. Rebuild member facts for everyone we touched.
    for did in &touched {
        if let Err(e) = sync::recompute_member_facts(&state.pool, account_ref, did).await {
            tracing::warn!(account_ref, discord_id = %did, "recompute facts failed: {e}");
        }
    }

    // 5. Stamp sync time + fan out a re-evaluation of bound role links.
    let stamp = if mark_backfill {
        "UPDATE stripe_accounts SET last_synced_at = now(), last_backfill_at = now(), updated_at = now() WHERE id = $1"
    } else {
        "UPDATE stripe_accounts SET last_synced_at = now(), updated_at = now() WHERE id = $1"
    };
    sqlx::query(stamp)
        .bind(account_ref)
        .execute(&state.pool)
        .await?;

    jobs::enqueue_account_sync(&state.pool, account_ref).await?;

    tracing::info!(
        account_ref,
        subscriptions = sub_count,
        customers = cust_count,
        members = touched.len(),
        backfill = mark_backfill,
        "Stripe account imported"
    );
    Ok(())
}
