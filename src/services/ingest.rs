//! Shared Stripe-data ingestion: resolve a buyer's Discord ID from Stripe
//! metadata and upsert the raw `stripe_customers` / `stripe_subscriptions`
//! mirror rows. Used by both the webhook ingestor and the backfill/reconcile
//! passes.
//!
//! Discord linkage is read directly from Stripe — the convention RoleLogic's
//! own billing uses (`subscription.metadata.discord_user_id`,
//! `customer.metadata.discord_user_id`, `checkout.session.client_reference_id`).
//! The account's `discord_metadata_key` is tried first so other bot devs can
//! use their own key; common fallbacks are tried after.

use std::collections::HashMap;

use crate::error::AppError;
use crate::services::stripe::{CustomerFields, SubFields};

/// Extract a usable Discord user ID (snowflake) from a raw metadata value.
/// Accepts a bare numeric id, or pulls the digit run out of values like
/// `<@123…>` so a slightly-off convention still links.
fn normalize_discord_id(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    if t.bytes().all(|b| b.is_ascii_digit()) && (5..=25).contains(&t.len()) {
        return Some(t.to_string());
    }
    // Find the longest 15–25 digit run (Discord snowflakes are ~17–20 digits).
    let re = regex::Regex::new(r"\d{15,25}").ok()?;
    re.find(t).map(|m| m.as_str().to_string())
}

/// Resolve a Discord ID from a metadata map, trying the account's configured
/// key first, then common conventions.
pub fn resolve_from_meta(meta: &HashMap<String, String>, key: &str) -> Option<String> {
    let candidates = [key, "discord_user_id", "discord_id", "discordId", "discord"];
    for k in candidates {
        if let Some(v) = meta.get(k) {
            if let Some(id) = normalize_discord_id(v) {
                return Some(id);
            }
        }
    }
    None
}

/// Upsert a customer mirror row. Returns the effective Discord ID (resolved
/// from metadata or inherited from one of the customer's subscriptions).
///
/// Does NOT touch `lifetime_spend_cents` / `successful_payments` — those are
/// maintained separately (charge webhooks + the reconcile charge pass).
pub async fn upsert_customer(
    pool: &sqlx::PgPool,
    account_ref: i64,
    c: &CustomerFields,
    metadata_key: &str,
) -> Result<Option<String>, AppError> {
    if c.deleted {
        sqlx::query("DELETE FROM stripe_customers WHERE account_ref = $1 AND customer_id = $2")
            .bind(account_ref)
            .bind(&c.id)
            .execute(pool)
            .await?;
        return Ok(None);
    }

    let mut discord_id = resolve_from_meta(&c.metadata, metadata_key);

    // Inherit from a linked subscription if the customer carries no id of its own.
    if discord_id.is_none() {
        discord_id = sqlx::query_scalar::<_, Option<String>>(
            "SELECT discord_id FROM stripe_subscriptions \
             WHERE account_ref = $1 AND customer_id = $2 AND discord_id IS NOT NULL LIMIT 1",
        )
        .bind(account_ref)
        .bind(&c.id)
        .fetch_optional(pool)
        .await?
        .flatten();
    }

    sqlx::query(
        "INSERT INTO stripe_customers ( \
            account_ref, customer_id, discord_id, email, name, country, currency, \
            delinquent, stripe_created_at, last_synced_at \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now()) \
         ON CONFLICT (account_ref, customer_id) DO UPDATE SET \
            discord_id = COALESCE(EXCLUDED.discord_id, stripe_customers.discord_id), \
            email = EXCLUDED.email, \
            name = EXCLUDED.name, \
            country = EXCLUDED.country, \
            currency = EXCLUDED.currency, \
            delinquent = EXCLUDED.delinquent, \
            stripe_created_at = COALESCE(EXCLUDED.stripe_created_at, stripe_customers.stripe_created_at), \
            last_synced_at = now()",
    )
    .bind(account_ref)
    .bind(&c.id)
    .bind(&discord_id)
    .bind(&c.email)
    .bind(&c.name)
    .bind(&c.country)
    .bind(&c.currency)
    .bind(c.delinquent)
    .bind(c.created_at)
    .execute(pool)
    .await?;

    // Propagate a freshly-known id down to the customer's subscriptions.
    if let Some(did) = &discord_id {
        sqlx::query(
            "UPDATE stripe_subscriptions SET discord_id = $3 \
             WHERE account_ref = $1 AND customer_id = $2 AND discord_id IS NULL",
        )
        .bind(account_ref)
        .bind(&c.id)
        .bind(did)
        .execute(pool)
        .await?;
    }

    Ok(discord_id)
}

/// Upsert a subscription mirror row. If the subscription carried an expanded
/// customer object, that customer is upserted too. Returns the effective
/// Discord ID for the subscription.
///
/// `fallback_discord` is the checkout session's `client_reference_id`, used
/// when neither the subscription nor the customer metadata carries an id.
pub async fn upsert_subscription(
    pool: &sqlx::PgPool,
    account_ref: i64,
    s: &SubFields,
    metadata_key: &str,
    fallback_discord: Option<&str>,
) -> Result<Option<String>, AppError> {
    // Upsert the expanded customer first (captures email/country/currency).
    let mut customer_discord: Option<String> = None;
    if let Some(c) = &s.customer {
        customer_discord = upsert_customer(pool, account_ref, c, metadata_key).await?;
    }

    // Resolve discord id: subscription metadata → expanded-customer metadata →
    // checkout fallback → existing customer row → existing sub row.
    let mut discord_id = resolve_from_meta(&s.metadata, metadata_key);
    if discord_id.is_none() {
        if let Some(c) = &s.customer {
            discord_id = resolve_from_meta(&c.metadata, metadata_key);
        }
    }
    if discord_id.is_none() {
        discord_id = customer_discord;
    }
    if discord_id.is_none() {
        if let Some(fb) = fallback_discord {
            discord_id = normalize_discord_id(fb);
        }
    }
    if discord_id.is_none() {
        if let Some(cid) = &s.customer_id {
            discord_id = sqlx::query_scalar::<_, Option<String>>(
                "SELECT discord_id FROM stripe_customers \
                 WHERE account_ref = $1 AND customer_id = $2 AND discord_id IS NOT NULL LIMIT 1",
            )
            .bind(account_ref)
            .bind(cid)
            .fetch_optional(pool)
            .await?
            .flatten();
        }
    }

    sqlx::query(
        "INSERT INTO stripe_subscriptions ( \
            account_ref, subscription_id, customer_id, discord_id, status, price_id, product_id, \
            unit_amount_cents, currency, interval, interval_count, quantity, cancel_at_period_end, \
            current_period_end, trial_end, started_at, stripe_created_at, last_synced_at \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17, now()) \
         ON CONFLICT (account_ref, subscription_id) DO UPDATE SET \
            customer_id = EXCLUDED.customer_id, \
            discord_id = COALESCE(EXCLUDED.discord_id, stripe_subscriptions.discord_id), \
            status = EXCLUDED.status, \
            price_id = EXCLUDED.price_id, \
            product_id = EXCLUDED.product_id, \
            unit_amount_cents = EXCLUDED.unit_amount_cents, \
            currency = EXCLUDED.currency, \
            interval = EXCLUDED.interval, \
            interval_count = EXCLUDED.interval_count, \
            quantity = EXCLUDED.quantity, \
            cancel_at_period_end = EXCLUDED.cancel_at_period_end, \
            current_period_end = EXCLUDED.current_period_end, \
            trial_end = EXCLUDED.trial_end, \
            started_at = EXCLUDED.started_at, \
            stripe_created_at = COALESCE(EXCLUDED.stripe_created_at, stripe_subscriptions.stripe_created_at), \
            last_synced_at = now()",
    )
    .bind(account_ref)
    .bind(&s.id)
    .bind(&s.customer_id)
    .bind(&discord_id)
    .bind(&s.status)
    .bind(&s.price_id)
    .bind(&s.product_id)
    .bind(s.unit_amount_cents)
    .bind(&s.currency)
    .bind(&s.interval)
    .bind(s.interval_count)
    .bind(s.quantity)
    .bind(s.cancel_at_period_end)
    .bind(s.current_period_end)
    .bind(s.trial_end)
    .bind(s.started_at)
    .bind(s.created_at)
    .execute(pool)
    .await?;

    // Back-fill the customer row's discord id if we learned it from the sub.
    if let (Some(did), Some(cid)) = (&discord_id, &s.customer_id) {
        sqlx::query(
            "UPDATE stripe_customers SET discord_id = $3 \
             WHERE account_ref = $1 AND customer_id = $2 AND discord_id IS NULL",
        )
        .bind(account_ref)
        .bind(cid)
        .bind(did)
        .execute(pool)
        .await?;
    }

    Ok(discord_id)
}

/// Set absolute lifetime spend / payment count for a customer (reconcile
/// charge pass). Only updates an existing customer row — the customers list
/// pass has already created rows, so we never resurrect a deleted one here.
/// Returns the customer's Discord ID if known.
pub async fn set_customer_spend(
    pool: &sqlx::PgPool,
    account_ref: i64,
    customer_id: &str,
    amount_cents: i64,
    payments: i32,
) -> Result<Option<String>, AppError> {
    let did = sqlx::query_scalar::<_, Option<String>>(
        "UPDATE stripe_customers \
         SET lifetime_spend_cents = $3, successful_payments = $4, last_synced_at = now() \
         WHERE account_ref = $1 AND customer_id = $2 \
         RETURNING discord_id",
    )
    .bind(account_ref)
    .bind(customer_id)
    .bind(amount_cents)
    .bind(payments)
    .fetch_optional(pool)
    .await?
    .flatten();
    Ok(did)
}

/// Increment lifetime spend / payment count for a customer (charge.succeeded).
/// Returns the customer's Discord ID if known, so the caller can recompute
/// facts + re-evaluate roles.
pub async fn apply_successful_charge(
    pool: &sqlx::PgPool,
    account_ref: i64,
    customer_id: &str,
    amount_cents: i64,
) -> Result<Option<String>, AppError> {
    // Ensure a row exists so the increment lands even if we haven't seen the
    // customer object yet.
    sqlx::query(
        "INSERT INTO stripe_customers (account_ref, customer_id, lifetime_spend_cents, successful_payments) \
         VALUES ($1, $2, $3, 1) \
         ON CONFLICT (account_ref, customer_id) DO UPDATE SET \
            lifetime_spend_cents = stripe_customers.lifetime_spend_cents + EXCLUDED.lifetime_spend_cents, \
            successful_payments = stripe_customers.successful_payments + 1, \
            last_synced_at = now()",
    )
    .bind(account_ref)
    .bind(customer_id)
    .bind(amount_cents)
    .execute(pool)
    .await?;

    let discord_id = sqlx::query_scalar::<_, Option<String>>(
        "SELECT discord_id FROM stripe_customers WHERE account_ref = $1 AND customer_id = $2",
    )
    .bind(account_ref)
    .bind(customer_id)
    .fetch_optional(pool)
    .await?
    .flatten();
    Ok(discord_id)
}
