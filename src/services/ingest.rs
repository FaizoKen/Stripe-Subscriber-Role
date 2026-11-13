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
            current_period_end, trial_end, started_at, stripe_created_at, \
            price_ids, product_ids, period_amount_cents, last_synced_at \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20, now()) \
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
            price_ids = EXCLUDED.price_ids, \
            product_ids = EXCLUDED.product_ids, \
            period_amount_cents = EXCLUDED.period_amount_cents, \
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
    .bind(&s.price_ids)
    .bind(&s.product_ids)
    .bind(s.period_amount_cents)
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

/// Set a customer's totals from a fresh per-customer recount (the charge
/// webhooks). Unlike [set_customer_spend] it creates the row when the
/// customer hasn't been seen yet, so the first payment of a brand-new buyer
/// lands. Returns the customer's Discord ID if known.
pub async fn set_customer_totals(
    pool: &sqlx::PgPool,
    account_ref: i64,
    customer_id: &str,
    amount_cents: i64,
    payments: i32,
) -> Result<Option<String>, AppError> {
    let did = sqlx::query_scalar::<_, Option<String>>(
        "INSERT INTO stripe_customers (account_ref, customer_id, lifetime_spend_cents, successful_payments) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (account_ref, customer_id) DO UPDATE SET \
            lifetime_spend_cents = EXCLUDED.lifetime_spend_cents, \
            successful_payments = EXCLUDED.successful_payments, \
            last_synced_at = now() \
         RETURNING discord_id",
    )
    .bind(account_ref)
    .bind(customer_id)
    .bind(amount_cents)
    .bind(payments)
    .fetch_one(pool)
    .await?;
    Ok(did)
}

/// Link a customer to a Discord ID the buyer's checkout carried (its
/// `client_reference_id` or session metadata). An ID the customer already
/// has — from its own metadata — wins; this only fills a gap. Creates the
/// row if needed. Returns the customer's effective Discord ID.
pub async fn link_customer(
    pool: &sqlx::PgPool,
    account_ref: i64,
    customer_id: &str,
    discord_id: &str,
) -> Result<Option<String>, AppError> {
    let did = sqlx::query_scalar::<_, Option<String>>(
        "INSERT INTO stripe_customers (account_ref, customer_id, discord_id) VALUES ($1, $2, $3) \
         ON CONFLICT (account_ref, customer_id) DO UPDATE SET \
            discord_id = COALESCE(stripe_customers.discord_id, EXCLUDED.discord_id) \
         RETURNING discord_id",
    )
    .bind(account_ref)
    .bind(customer_id)
    .bind(discord_id)
    .fetch_one(pool)
    .await?;
    // Its subscriptions inherit the link, as they do from customer metadata.
    if let Some(d) = &did {
        sqlx::query(
            "UPDATE stripe_subscriptions SET discord_id = $3 \
             WHERE account_ref = $1 AND customer_id = $2 AND discord_id IS NULL",
        )
        .bind(account_ref)
        .bind(customer_id)
        .bind(d)
        .execute(pool)
        .await?;
    }
    Ok(did)
}

/// The Discord ID a completed Checkout Session carried: its metadata (the
/// account's key, then the usual names), else its `client_reference_id`.
pub fn checkout_discord_id(
    metadata: &HashMap<String, String>,
    client_reference_id: Option<&str>,
    key: &str,
) -> Option<String> {
    resolve_from_meta(metadata, key).or_else(|| client_reference_id.and_then(normalize_discord_id))
}

/// Apply a completed checkout's link to the mirror rows it created, during
/// an import (the webhook path does this live). Only fills rows that have no
/// Discord ID yet. Returns the Discord ID it linked, if any row changed.
pub async fn apply_checkout_link(
    pool: &sqlx::PgPool,
    account_ref: i64,
    discord_id: &str,
    customer_id: Option<&str>,
    subscription_id: Option<&str>,
) -> Result<Option<String>, AppError> {
    let mut changed = 0u64;
    if let Some(sid) = subscription_id {
        changed += sqlx::query(
            "UPDATE stripe_subscriptions SET discord_id = $3 \
             WHERE account_ref = $1 AND subscription_id = $2 AND discord_id IS NULL",
        )
        .bind(account_ref)
        .bind(sid)
        .bind(discord_id)
        .execute(pool)
        .await?
        .rows_affected();
    }
    if let Some(cid) = customer_id {
        changed += sqlx::query(
            "UPDATE stripe_customers SET discord_id = $3 \
             WHERE account_ref = $1 AND customer_id = $2 AND discord_id IS NULL",
        )
        .bind(account_ref)
        .bind(cid)
        .bind(discord_id)
        .execute(pool)
        .await?
        .rows_affected();
        changed += sqlx::query(
            "UPDATE stripe_subscriptions SET discord_id = $3 \
             WHERE account_ref = $1 AND customer_id = $2 AND discord_id IS NULL",
        )
        .bind(account_ref)
        .bind(cid)
        .bind(discord_id)
        .execute(pool)
        .await?
        .rows_affected();
    }
    Ok((changed > 0).then(|| discord_id.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn metadata_key_then_the_usual_names() {
        let m = meta(&[("discordId", "123456789012345678")]);
        assert_eq!(
            resolve_from_meta(&m, "discord_user_id").as_deref(),
            Some("123456789012345678")
        );
        let custom = meta(&[("member", "<@223456789012345678>")]);
        assert_eq!(
            resolve_from_meta(&custom, "member").as_deref(),
            Some("223456789012345678")
        );
        assert_eq!(
            resolve_from_meta(&meta(&[("discord", "not an id")]), "x"),
            None
        );
    }

    #[test]
    fn checkout_reads_metadata_before_client_reference_id() {
        let m = meta(&[("discord_user_id", "323456789012345678")]);
        assert_eq!(
            checkout_discord_id(&m, Some("423456789012345678"), "discord_user_id").as_deref(),
            Some("323456789012345678")
        );
        assert_eq!(
            checkout_discord_id(
                &HashMap::new(),
                Some("423456789012345678"),
                "discord_user_id"
            )
            .as_deref(),
            Some("423456789012345678")
        );
        assert_eq!(
            checkout_discord_id(&HashMap::new(), Some("order-17"), "discord_user_id"),
            None
        );
    }
}
