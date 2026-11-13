//! Stripe webhook ingestor.
//!
//! URL is per-account: `/webhooks/stripe/{account_ref}` so we know which
//! account's signing secret to verify against (the secret is the security
//! boundary; the numeric account ref in the path is not sensitive). We:
//!   1. verify the Stripe-Signature HMAC,
//!   2. dedupe on the event id,
//!   3. apply the change to the local mirror (subscriptions / customers / spend),
//!   4. recompute the affected member's facts + enqueue a player_sync.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde_json::Value;

use crate::error::AppError;
use crate::services::stripe::{self, StripeClient};
use crate::services::{ingest, jobs, sync};
use crate::tasks::reconcile::decrypt_key;
use crate::AppState;

pub async fn stripe_webhook(
    State(state): State<Arc<AppState>>,
    Path(account_ref): Path<i64>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let account = sqlx::query_as::<_, (Vec<u8>, Option<Vec<u8>>, String)>(
        "SELECT api_key_enc, webhook_secret_enc, discord_metadata_key \
         FROM stripe_accounts WHERE id = $1",
    )
    .bind(account_ref)
    .fetch_optional(&state.pool)
    .await;

    let (api_key_enc, webhook_secret_enc, metadata_key) = match account {
        Ok(Some(row)) => row,
        // Unknown/disconnected account — ack so Stripe stops retrying.
        Ok(None) => return (StatusCode::OK, "unknown account"),
        Err(e) => {
            tracing::error!(account_ref, "webhook account lookup failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error");
        }
    };

    let Some(secret_enc) = webhook_secret_enc else {
        tracing::error!(
            account_ref,
            "webhook received but no signing secret configured"
        );
        note_refused(&state, account_ref, "no_secret").await;
        return (StatusCode::BAD_REQUEST, "no webhook secret configured");
    };
    let secret = match decrypt_key(&state, &secret_enc) {
        Ok(s) => s,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "secret decrypt failed"),
    };

    let signature = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if signature.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing signature");
    }
    if !stripe::verify_webhook_signature(&body, signature, &secret, stripe::WEBHOOK_TOLERANCE_SECS)
    {
        tracing::warn!(account_ref, "webhook signature verification failed");
        note_refused(&state, account_ref, "signature").await;
        return (StatusCode::UNAUTHORIZED, "bad signature");
    }

    // A Thin event verifies but carries nothing to read. Acknowledge it (a
    // retry would be just as thin) and tell the admin to use Snapshot.
    if stripe::is_thin_event(&body) {
        tracing::warn!(
            account_ref,
            "webhook destination sends Thin events; this plugin needs Snapshot"
        );
        note_refused(&state, account_ref, "thin").await;
        return (
            StatusCode::OK,
            "thin events are not supported; use snapshot",
        );
    }

    let Some((event_id, event_type, object)) = stripe::parse_event(&body) else {
        return (StatusCode::BAD_REQUEST, "bad event body");
    };

    // A delivery that verified and parsed: the webhook works.
    let _ = sqlx::query("UPDATE stripe_accounts SET webhook_last_ok_at = now() WHERE id = $1")
        .bind(account_ref)
        .execute(&state.pool)
        .await;

    // Idempotency per account: first writer wins; duplicates are acked
    // without reprocessing. Keyed by account too, because a Stripe account
    // connected to two servers gets the same event at both endpoints.
    let inserted = sqlx::query(
        "INSERT INTO webhook_deliveries (account_ref, event_id, event_type) VALUES ($1, $2, $3) \
         ON CONFLICT (account_ref, event_id) DO NOTHING",
    )
    .bind(account_ref)
    .bind(&event_id)
    .bind(&event_type)
    .execute(&state.pool)
    .await;
    match inserted {
        Ok(r) if r.rows_affected() == 0 => return (StatusCode::OK, "duplicate ignored"),
        Ok(_) => {}
        Err(e) => {
            tracing::error!(account_ref, "webhook_deliveries insert failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error");
        }
    }

    let api_key = match decrypt_key(&state, &api_key_enc) {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "key decrypt failed"),
    };

    match apply_event(
        &state,
        account_ref,
        &api_key,
        &metadata_key,
        &event_type,
        &object,
    )
    .await
    {
        Ok(affected) => {
            if let Some(did) = affected {
                if let Err(e) = sync::recompute_member_facts(&state.pool, account_ref, &did).await {
                    tracing::warn!(account_ref, "recompute after webhook failed: {e}");
                }
                let _ = jobs::enqueue_player_sync(&state.pool, &did).await;
                tracing::info!(
                    account_ref,
                    event_type,
                    discord_id = %did,
                    "Stripe webhook applied; member facts recomputed and re-sync queued"
                );
            } else {
                tracing::info!(
                    account_ref,
                    event_type,
                    "Stripe webhook applied; no linked Discord member affected"
                );
            }
            (StatusCode::OK, "ok")
        }
        Err(e) => {
            // Re-open the delivery so Stripe's retry re-processes it.
            let _ = sqlx::query(
                "DELETE FROM webhook_deliveries WHERE account_ref = $1 AND event_id = $2",
            )
            .bind(account_ref)
            .bind(&event_id)
            .execute(&state.pool)
            .await;
            tracing::error!(account_ref, event_type, "apply_event failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "apply failed")
        }
    }
}

/// Record why a delivery was refused, for the settings page ('signature',
/// 'thin', 'no_secret'). It only shows while newer than the last good one.
async fn note_refused(state: &AppState, account_ref: i64, reason: &str) {
    let _ = sqlx::query(
        "UPDATE stripe_accounts SET webhook_last_failed_at = now(), webhook_last_error = $2 \
         WHERE id = $1",
    )
    .bind(account_ref)
    .bind(reason)
    .execute(&state.pool)
    .await;
}

/// A charge was paid or refunded: recount that customer's totals from
/// Stripe (absolute, refund-aware). If the recount can't run — the key may
/// not grant Charges read — a new payment still counts once, as before;
/// a refund then waits for the next reconcile.
async fn recount_customer(
    state: &Arc<AppState>,
    account_ref: i64,
    api_key: &str,
    customer_id: &str,
    event_type: &str,
    object: &Value,
) -> Result<Option<String>, AppError> {
    let pool = &state.pool;
    let client = StripeClient::new(state.config.stripe_api_base.clone());
    match client.customer_charge_totals(api_key, customer_id).await {
        Ok((spend, n)) => {
            ingest::set_customer_totals(pool, account_ref, customer_id, spend, n as i32).await
        }
        Err(e) => {
            tracing::info!(account_ref, "charge recount skipped: {e}");
            let paid = object.get("paid").and_then(Value::as_bool).unwrap_or(false);
            let ok = object.get("status").and_then(Value::as_str) == Some("succeeded");
            if event_type == "charge.succeeded" && paid && ok {
                let amount = object.get("amount").and_then(Value::as_i64).unwrap_or(0);
                ingest::apply_successful_charge(pool, account_ref, customer_id, amount).await
            } else {
                Ok(None)
            }
        }
    }
}

/// Apply one event to the mirror. Returns the affected member's Discord ID (so
/// the caller can recompute facts + re-evaluate their roles).
async fn apply_event(
    state: &Arc<AppState>,
    account_ref: i64,
    api_key: &str,
    metadata_key: &str,
    event_type: &str,
    object: &Value,
) -> Result<Option<String>, AppError> {
    let pool = &state.pool;
    match event_type {
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted"
        | "customer.subscription.paused"
        | "customer.subscription.resumed" => {
            let Some(sub) = stripe::parse_subscription_object(object) else {
                return Ok(None);
            };
            ingest::upsert_subscription(pool, account_ref, &sub, metadata_key, None).await
        }
        "customer.created" | "customer.updated" => {
            let Some(cust) = stripe::parse_customer_object(object) else {
                return Ok(None);
            };
            ingest::upsert_customer(pool, account_ref, &cust, metadata_key).await
        }
        "customer.deleted" => {
            // Resolve the member BEFORE the row is removed so we can recompute
            // their facts afterwards (which then drops the now-empty facts row,
            // stripping the role). The deleted-customer event object often omits
            // `metadata`, so look the id up from our own row first, then fall
            // back to whatever metadata the event did carry.
            let customer_id = object.get("id").and_then(Value::as_str);
            let mut did: Option<String> = None;
            if let Some(cid) = customer_id {
                did = sqlx::query_scalar::<_, Option<String>>(
                    "SELECT discord_id FROM stripe_customers WHERE account_ref = $1 AND customer_id = $2",
                )
                .bind(account_ref)
                .bind(cid)
                .fetch_optional(pool)
                .await?
                .flatten();
            }
            if did.is_none() {
                if let Some(m) = object.get("metadata").and_then(|m| m.as_object()) {
                    let map: std::collections::HashMap<String, String> = m
                        .iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect();
                    did = ingest::resolve_from_meta(&map, metadata_key);
                }
            }
            if let Some(cust) = stripe::parse_customer_object(object) {
                // upsert_customer deletes the row when `deleted` is set.
                ingest::upsert_customer(pool, account_ref, &cust, metadata_key).await?;
            }
            Ok(did)
        }
        "charge.succeeded" | "charge.refunded" => {
            let Some(cid) = object.get("customer").and_then(Value::as_str) else {
                // A guest checkout: no customer, nobody to credit.
                return Ok(None);
            };
            recount_customer(state, account_ref, api_key, cid, event_type, object).await
        }
        "checkout.session.completed" => {
            // Capture the Discord<->customer link as early as possible, then
            // pull the freshly created subscription.
            let client_ref = object.get("client_reference_id").and_then(Value::as_str);
            let session_meta: std::collections::HashMap<String, String> = object
                .get("metadata")
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default();
            let sub_id = object.get("subscription").and_then(Value::as_str);
            let customer_id = object.get("customer").and_then(Value::as_str);
            match (sub_id, customer_id) {
                (Some(sid), _) => {
                    let client = StripeClient::new(state.config.stripe_api_base.clone());
                    let sub = client.retrieve_subscription(api_key, sid).await?;
                    let fallback =
                        ingest::checkout_discord_id(&session_meta, client_ref, metadata_key);
                    ingest::upsert_subscription(
                        pool,
                        account_ref,
                        &sub,
                        metadata_key,
                        fallback.as_deref(),
                    )
                    .await
                }
                // A one-time payment: no subscription, but Checkout saved a
                // customer. Link it from the session, pull its details, and
                // count its payments (the charge event may have come first,
                // before anyone knew whose it was).
                (None, Some(cid)) => {
                    let Some(did) =
                        ingest::checkout_discord_id(&session_meta, client_ref, metadata_key)
                    else {
                        return Ok(None);
                    };
                    ingest::link_customer(pool, account_ref, cid, &did).await?;
                    let client = StripeClient::new(state.config.stripe_api_base.clone());
                    if let Ok(cust) = client.retrieve_customer(api_key, cid).await {
                        ingest::upsert_customer(pool, account_ref, &cust, metadata_key).await?;
                    }
                    if let Ok((spend, n)) = client.customer_charge_totals(api_key, cid).await {
                        ingest::set_customer_totals(pool, account_ref, cid, spend, n as i32)
                            .await?;
                    }
                    sqlx::query_scalar::<_, Option<String>>(
                        "SELECT discord_id FROM stripe_customers WHERE account_ref = $1 AND customer_id = $2",
                    )
                    .bind(account_ref)
                    .bind(cid)
                    .fetch_optional(pool)
                    .await
                    .map(Option::flatten)
                    .map_err(AppError::from)
                }
                // A guest checkout (no customer object): nothing to link.
                (None, None) => Ok(None),
            }
        }
        "invoice.payment_failed" | "invoice.paid" => {
            // Refresh the subscription behind the invoice (status transitions).
            let sub_id = object
                .get("subscription")
                .and_then(Value::as_str)
                .or_else(|| {
                    object
                        .get("parent")
                        .and_then(|p| p.get("subscription_details"))
                        .and_then(|d| d.get("subscription"))
                        .and_then(Value::as_str)
                });
            match sub_id {
                Some(sid) => {
                    let client = StripeClient::new(state.config.stripe_api_base.clone());
                    let sub = client.retrieve_subscription(api_key, sid).await?;
                    ingest::upsert_subscription(pool, account_ref, &sub, metadata_key, None).await
                }
                None => Ok(None),
            }
        }
        other => {
            tracing::debug!(event_type = other, "unhandled Stripe event; recorded only");
            Ok(None)
        }
    }
}
