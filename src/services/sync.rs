//! Sync engine — recompute member facts, per-player sync, per-role-link bulk
//! sync, and per-account fan-out.
//!
//! Convention 38: guild membership comes from the Auth Gateway
//! `/auth/internal/*`, never a local JOIN. Convention 40: gateway HTTP failures
//! bubble up (the worker retries) — we never clear a role on a transient lookup
//! failure. Convention 47: a RoleLinkNotFound deletes the orphan local row
//! instead of retrying forever.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use futures_util::stream::{self, StreamExt};

use crate::error::AppError;
use crate::models::facts::Facts;
use crate::models::rule::RuleTree;
use crate::services::condition_eval;
use crate::services::rule_sql::{self, Bind};
use crate::services::{auth_gateway, jobs};
use crate::AppState;

// ---------------------------------------------------------------------------
// Member facts recompute
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct RawCustomerRow {
    email: Option<String>,
    country: Option<String>,
    currency: Option<String>,
    delinquent: bool,
    stripe_created_at: Option<DateTime<Utc>>,
    lifetime_spend_cents: i64,
    successful_payments: i32,
}

#[derive(sqlx::FromRow)]
struct RawSubRow {
    status: String,
    price_id: Option<String>,
    product_id: Option<String>,
    unit_amount_cents: i64,
    currency: Option<String>,
    interval: Option<String>,
    interval_count: i32,
    quantity: i32,
    cancel_at_period_end: bool,
    current_period_end: Option<DateTime<Utc>>,
    trial_end: Option<DateTime<Utc>>,
    started_at: Option<DateTime<Utc>>,
}

fn is_active_status(s: &str) -> bool {
    matches!(s, "active" | "trialing")
}

/// Favorability ranking for picking the member's headline `subscription_status`.
fn status_rank(s: &str) -> i32 {
    match s {
        "active" => 7,
        "trialing" => 6,
        "past_due" => 5,
        "unpaid" => 4,
        "paused" => 3,
        "incomplete" => 2,
        "canceled" => 1,
        _ => 0, // incomplete_expired and anything unknown
    }
}

/// Normalize a recurring amount to its approximate monthly value (cents).
fn monthly_value(amount_cents: i64, interval: Option<&str>, interval_count: i32) -> i64 {
    let n = interval_count.max(1) as f64;
    let amt = amount_cents as f64;
    let monthly = match interval.unwrap_or("month") {
        "year" => amt / (12.0 * n),
        "week" => amt * 52.0 / 12.0 / n,
        "day" => amt * 30.0 / n,
        _ => amt / n, // month (default)
    };
    monthly.round() as i64
}

fn email_domain(email: Option<&str>) -> Option<String> {
    email
        .and_then(|e| e.rsplit_once('@'))
        .map(|(_, dom)| dom.to_ascii_lowercase())
}

/// Rebuild the `stripe_member_facts` row for one (account, discord_id) by
/// aggregating that member's raw customer + subscription rows. Deletes the row
/// when the member has no relation left.
pub async fn recompute_member_facts(
    pool: &sqlx::PgPool,
    account_ref: i64,
    discord_id: &str,
) -> Result<(), AppError> {
    let customers: Vec<RawCustomerRow> = sqlx::query_as(
        "SELECT email, country, currency, delinquent, stripe_created_at, \
                lifetime_spend_cents, successful_payments \
         FROM stripe_customers WHERE account_ref = $1 AND discord_id = $2",
    )
    .bind(account_ref)
    .bind(discord_id)
    .fetch_all(pool)
    .await?;

    let subs: Vec<RawSubRow> = sqlx::query_as(
        "SELECT status, price_id, product_id, unit_amount_cents, currency, interval, \
                interval_count, quantity, cancel_at_period_end, current_period_end, \
                trial_end, started_at \
         FROM stripe_subscriptions WHERE account_ref = $1 AND discord_id = $2",
    )
    .bind(account_ref)
    .bind(discord_id)
    .fetch_all(pool)
    .await?;

    if customers.is_empty() && subs.is_empty() {
        sqlx::query("DELETE FROM stripe_member_facts WHERE account_ref = $1 AND discord_id = $2")
            .bind(account_ref)
            .bind(discord_id)
            .execute(pool)
            .await?;
        return Ok(());
    }

    // --- customer-level aggregates ---
    let lifetime_spend_cents: i64 = customers.iter().map(|c| c.lifetime_spend_cents).sum();
    let successful_payments: i32 = customers.iter().map(|c| c.successful_payments).sum();
    let is_delinquent = customers.iter().any(|c| c.delinquent);
    let email = customers.iter().find_map(|c| c.email.clone());
    let email_domain = email_domain(email.as_deref());
    let country_code = customers.iter().find_map(|c| c.country.clone());
    let customer_currency = customers.iter().find_map(|c| c.currency.clone());
    let customer_created_at = customers.iter().filter_map(|c| c.stripe_created_at).min();

    // --- subscription-level aggregates ---
    let active: Vec<&RawSubRow> = subs
        .iter()
        .filter(|s| is_active_status(&s.status))
        .collect();
    let has_active_subscription = !active.is_empty();
    let active_subscription_count = active.len() as i32;
    let is_trialing = subs.iter().any(|s| s.status == "trialing");
    let is_past_due = subs.iter().any(|s| s.status == "past_due");
    let cancels_at_period_end = active.iter().any(|s| s.cancel_at_period_end);

    let subscription_status = subs
        .iter()
        .max_by_key(|s| status_rank(&s.status))
        .map(|s| s.status.clone());

    // "Primary" active sub = highest per-period charge (unit_amount × quantity).
    let primary = active
        .iter()
        .max_by_key(|s| s.unit_amount_cents * s.quantity.max(1) as i64);
    let plan_amount_cents = primary
        .map(|s| s.unit_amount_cents * s.quantity.max(1) as i64)
        .unwrap_or(0);
    let billing_interval = primary.and_then(|s| s.interval.clone());
    let total_mrr_cents: i64 = active
        .iter()
        .map(|s| {
            monthly_value(
                s.unit_amount_cents * s.quantity.max(1) as i64,
                s.interval.as_deref(),
                s.interval_count,
            )
        })
        .sum();
    let subscription_started_at = active.iter().filter_map(|s| s.started_at).min();
    let current_period_end = active.iter().filter_map(|s| s.current_period_end).min();
    let trial_end = active.iter().filter_map(|s| s.trial_end).min();
    let sub_currency = active.iter().find_map(|s| s.currency.clone());

    let mut product_ids: Vec<String> = active.iter().filter_map(|s| s.product_id.clone()).collect();
    product_ids.sort();
    product_ids.dedup();
    let mut price_ids: Vec<String> = active.iter().filter_map(|s| s.price_id.clone()).collect();
    price_ids.sort();
    price_ids.dedup();

    // currency: prefer customer's, fall back to an active sub's.
    let currency = customer_currency.or(sub_currency);

    sqlx::query(
        "INSERT INTO stripe_member_facts ( \
            account_ref, discord_id, is_customer, customer_created_at, country_code, currency, \
            email, email_domain, is_delinquent, lifetime_spend_cents, successful_payments, \
            has_active_subscription, active_subscription_count, subscription_status, is_trialing, \
            is_past_due, cancels_at_period_end, plan_amount_cents, billing_interval, \
            subscription_started_at, current_period_end, trial_end, total_mrr_cents, \
            product_ids, price_ids, last_synced_at \
         ) VALUES ( \
            $1,$2, TRUE, $3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24, now() \
         ) \
         ON CONFLICT (account_ref, discord_id) DO UPDATE SET \
            is_customer = TRUE, \
            customer_created_at = EXCLUDED.customer_created_at, \
            country_code = EXCLUDED.country_code, \
            currency = EXCLUDED.currency, \
            email = EXCLUDED.email, \
            email_domain = EXCLUDED.email_domain, \
            is_delinquent = EXCLUDED.is_delinquent, \
            lifetime_spend_cents = EXCLUDED.lifetime_spend_cents, \
            successful_payments = EXCLUDED.successful_payments, \
            has_active_subscription = EXCLUDED.has_active_subscription, \
            active_subscription_count = EXCLUDED.active_subscription_count, \
            subscription_status = EXCLUDED.subscription_status, \
            is_trialing = EXCLUDED.is_trialing, \
            is_past_due = EXCLUDED.is_past_due, \
            cancels_at_period_end = EXCLUDED.cancels_at_period_end, \
            plan_amount_cents = EXCLUDED.plan_amount_cents, \
            billing_interval = EXCLUDED.billing_interval, \
            subscription_started_at = EXCLUDED.subscription_started_at, \
            current_period_end = EXCLUDED.current_period_end, \
            trial_end = EXCLUDED.trial_end, \
            total_mrr_cents = EXCLUDED.total_mrr_cents, \
            product_ids = EXCLUDED.product_ids, \
            price_ids = EXCLUDED.price_ids, \
            last_synced_at = now()",
    )
    .bind(account_ref)
    .bind(discord_id)
    .bind(customer_created_at)
    .bind(&country_code)
    .bind(&currency)
    .bind(&email)
    .bind(&email_domain)
    .bind(is_delinquent)
    .bind(lifetime_spend_cents)
    .bind(successful_payments)
    .bind(has_active_subscription)
    .bind(active_subscription_count)
    .bind(&subscription_status)
    .bind(is_trialing)
    .bind(is_past_due)
    .bind(cancels_at_period_end)
    .bind(plan_amount_cents)
    .bind(&billing_interval)
    .bind(subscription_started_at)
    .bind(current_period_end)
    .bind(trial_end)
    .bind(total_mrr_cents)
    .bind(&product_ids)
    .bind(&price_ids)
    .execute(pool)
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Facts row → Facts (for the single-member Rust evaluator)
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct FactsRow {
    is_customer: bool,
    customer_created_at: Option<DateTime<Utc>>,
    country_code: Option<String>,
    currency: Option<String>,
    email_domain: Option<String>,
    is_delinquent: bool,
    lifetime_spend_cents: i64,
    successful_payments: i32,
    has_active_subscription: bool,
    active_subscription_count: i32,
    subscription_status: Option<String>,
    is_trialing: bool,
    is_past_due: bool,
    cancels_at_period_end: bool,
    plan_amount_cents: i64,
    billing_interval: Option<String>,
    subscription_started_at: Option<DateTime<Utc>>,
    current_period_end: Option<DateTime<Utc>>,
    total_mrr_cents: i64,
    product_ids: Vec<String>,
    price_ids: Vec<String>,
}

impl From<FactsRow> for Facts {
    fn from(r: FactsRow) -> Self {
        Facts {
            has_active_subscription: r.has_active_subscription,
            subscription_status: r.subscription_status,
            is_trialing: r.is_trialing,
            is_past_due: r.is_past_due,
            cancels_at_period_end: r.cancels_at_period_end,
            active_subscription_count: r.active_subscription_count as i64,
            product_ids: r.product_ids,
            price_ids: r.price_ids,
            plan_amount_cents: r.plan_amount_cents,
            billing_interval: r.billing_interval,
            subscription_started_at: r.subscription_started_at,
            current_period_end: r.current_period_end,
            total_mrr_cents: r.total_mrr_cents,
            is_customer: r.is_customer,
            customer_created_at: r.customer_created_at,
            is_delinquent: r.is_delinquent,
            lifetime_spend_cents: r.lifetime_spend_cents,
            successful_payments: r.successful_payments as i64,
            country_code: r.country_code,
            currency: r.currency,
            email_domain: r.email_domain,
        }
    }
}

const FACTS_SELECT: &str = "SELECT \
    is_customer, customer_created_at, country_code, currency, email_domain, is_delinquent, \
    lifetime_spend_cents, successful_payments, has_active_subscription, active_subscription_count, \
    subscription_status, is_trialing, is_past_due, cancels_at_period_end, plan_amount_cents, \
    billing_interval, subscription_started_at, current_period_end, total_mrr_cents, \
    product_ids, price_ids \
  FROM stripe_member_facts WHERE account_ref = $1 AND discord_id = $2";

// ---------------------------------------------------------------------------
// Per-player sync
// ---------------------------------------------------------------------------

pub async fn sync_for_player(discord_id: &str, state: &AppState) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl_client = &state.rl_client;

    // Guilds the gateway already knows the user is in (opt-out filtered).
    let mut guild_ids = auth_gateway::fetch_user_guild_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        discord_id,
    )
    .await?;

    // Guilds where this user is a Stripe customer/subscriber, derived from the
    // guild each connected account belongs to. A brand-new subscriber who has
    // never signed into RoleLogic is absent from the gateway list above but
    // present here — this is what lets them get their role *without* opening
    // the verify page. RoleLogic's bot still enforces actual guild membership
    // when it applies the role.
    let subscriber_guilds: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT sa.guild_id \
         FROM stripe_member_facts mf \
         JOIN stripe_accounts sa ON sa.id = mf.account_ref \
         WHERE mf.discord_id = $1",
    )
    .bind(discord_id)
    .fetch_all(pool)
    .await?;

    // Add subscriber guilds the gateway didn't already return, but first vet
    // each for an opt-out: a user who logged in and opted this guild/plugin out
    // is missing from the gateway list *for that reason*, so we must not
    // re-add it. (A never-logged-in user can't have opted out.) Convention 40:
    // an opt-out lookup error bubbles up and the job retries.
    let extra: Vec<String> = {
        let known: HashSet<&str> = guild_ids.iter().map(String::as_str).collect();
        subscriber_guilds
            .into_iter()
            .filter(|g| !known.contains(g.as_str()))
            .collect()
    };
    for g in extra {
        let optouts = auth_gateway::fetch_guild_optout_ids(
            &state.http,
            &state.config.auth_gateway_url,
            &state.config.internal_api_key,
            &g,
        )
        .await?;
        if !optouts.iter().any(|o| o == discord_id) {
            guild_ids.push(g);
        }
    }

    if guild_ids.is_empty() {
        return Ok(());
    }

    let role_links = sqlx::query_as::<_, (String, String, String, Option<i64>, serde_json::Value)>(
        "SELECT guild_id, role_id, api_token, stripe_account_ref, rule_tree \
             FROM role_links WHERE guild_id = ANY($1)",
    )
    .bind(&guild_ids[..])
    .fetch_all(pool)
    .await?;
    if role_links.is_empty() {
        return Ok(());
    }

    let existing: HashSet<(String, String)> = sqlx::query_as::<_, (String, String)>(
        "SELECT guild_id, role_id FROM role_assignments WHERE discord_id = $1",
    )
    .bind(discord_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();

    enum Action {
        Add(String, String, String),
        Remove(String, String, String),
    }

    let mut actions: Vec<Action> = Vec::new();
    for (guild_id, role_id, api_token, account_ref, raw_tree) in &role_links {
        let tree: RuleTree = serde_json::from_value(raw_tree.clone()).unwrap_or_default();

        // No account bound ⇒ grant to nobody (Convention 42), even for the
        // grant-on-any preset (which needs an account to define "customer of").
        let qualifies = match account_ref {
            Some(acct) => {
                let facts_row: Option<FactsRow> = sqlx::query_as(FACTS_SELECT)
                    .bind(acct)
                    .bind(discord_id)
                    .fetch_optional(pool)
                    .await?;
                match facts_row {
                    Some(row) => condition_eval::evaluate(&tree, &Facts::from(row)),
                    None => false, // not a customer ⇒ qualifies for nothing
                }
            }
            None => false,
        };

        let assigned = existing.contains(&(guild_id.clone(), role_id.clone()));
        match (qualifies, assigned) {
            (true, false) => actions.push(Action::Add(
                guild_id.clone(),
                role_id.clone(),
                api_token.clone(),
            )),
            (false, true) => actions.push(Action::Remove(
                guild_id.clone(),
                role_id.clone(),
                api_token.clone(),
            )),
            _ => {}
        }
    }

    if actions.is_empty() {
        return Ok(());
    }

    let did = discord_id.to_string();
    stream::iter(actions)
        .for_each_concurrent(10, |action| {
            let pool = pool.clone();
            let rl = rl_client.clone();
            let did = did.clone();
            async move {
                match action {
                    Action::Add(g, r, tok) => {
                        match rl.add_user(&g, &r, &did, &tok).await {
                            Err(AppError::RoleLinkNotFound) => {
                                delete_orphan_role_link(&g, &r, &pool).await;
                                return;
                            }
                            Err(AppError::UserLimitReached { limit }) => {
                                tracing::warn!(g, r, did, limit, "user limit reached");
                                return;
                            }
                            Err(e) => {
                                tracing::error!(g, r, did, "add_user failed: {e}");
                                return;
                            }
                            Ok(_) => {}
                        }
                        let _ = sqlx::query(
                            "INSERT INTO role_assignments (guild_id, role_id, discord_id) \
                             VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                        )
                        .bind(&g)
                        .bind(&r)
                        .bind(&did)
                        .execute(&pool)
                        .await;
                    }
                    Action::Remove(g, r, tok) => {
                        match rl.remove_user(&g, &r, &did, &tok).await {
                            Err(AppError::RoleLinkNotFound) => {
                                delete_orphan_role_link(&g, &r, &pool).await;
                                return;
                            }
                            Err(e) => {
                                tracing::error!(g, r, did, "remove_user failed: {e}");
                                return;
                            }
                            Ok(_) => {}
                        }
                        let _ = sqlx::query(
                            "DELETE FROM role_assignments \
                             WHERE guild_id=$1 AND role_id=$2 AND discord_id=$3",
                        )
                        .bind(&g)
                        .bind(&r)
                        .bind(&did)
                        .execute(&pool)
                        .await;
                    }
                }
            }
        })
        .await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Per-role-link sync (bulk)
// ---------------------------------------------------------------------------

pub async fn sync_for_role_link(
    guild_id: &str,
    role_id: &str,
    state: &AppState,
) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl = &state.rl_client;

    let link = sqlx::query_as::<_, (String, Option<i64>, serde_json::Value)>(
        "SELECT api_token, stripe_account_ref, rule_tree \
         FROM role_links WHERE guild_id = $1 AND role_id = $2",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_optional(pool)
    .await?;

    let Some((api_token, account_ref, raw_tree)) = link else {
        return Ok(());
    };
    let tree: RuleTree = serde_json::from_value(raw_tree).unwrap_or_default();

    // No account bound, or a relation rule with no groups ⇒ grant to nobody.
    let nobody = account_ref.is_none() || (!tree.grant_on_any_relation && tree.groups.is_empty());
    if nobody {
        drain_to_empty(guild_id, role_id, &api_token, state).await?;
        return Ok(());
    }
    let account_ref = account_ref.expect("account bound checked above");

    // Candidate universe = everyone linked to this account (i.e. has a facts
    // row), minus anyone who opted this guild/plugin out. We deliberately do
    // NOT gate on the gateway's guild member list (`fetch_guild_member_ids`):
    // a subscriber who has never signed into RoleLogic is absent from it, yet
    // RoleLogic's bot is the real authority on who is actually in the guild
    // when it applies the role. Opt-outs are still honored centrally, so a
    // member who explicitly opted out is dropped from the next atomic PUT.
    // Convention 40: an opt-out lookup error bubbles up and the job retries —
    // we never treat a hiccup as "nobody opted out".
    let optout_ids = auth_gateway::fetch_guild_optout_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        guild_id,
    )
    .await?;

    let (_count, user_limit) = match rl.get_user_info(guild_id, role_id, &api_token).await {
        Ok(v) => v,
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, pool).await;
            return Ok(());
        }
        Err(_) => (0, 100),
    };

    // $1 = account_ref, $2 = optout_ids, rule binds from $3, limit last.
    // `<> ALL($2)` keeps everyone when the opt-out list is empty.
    let (rule_where, binds) = rule_sql::build_rule_where(&tree, 2);
    let limit_idx = 2 + binds.len() + 1;
    let query = format!(
        "SELECT mf.discord_id \
         FROM stripe_member_facts mf \
         WHERE mf.account_ref = $1 \
           AND mf.discord_id <> ALL($2::text[]) \
           AND ({rule_where}) \
         ORDER BY mf.discord_id \
         LIMIT ${limit_idx}"
    );
    let mut q = sqlx::query_scalar::<_, String>(&query)
        .bind(account_ref)
        .bind(&optout_ids);
    for b in &binds {
        q = match b {
            Bind::Bool(v) => q.bind(*v),
            Bind::Int(v) => q.bind(*v),
            Bind::Text(v) => q.bind(v.clone()),
            Bind::TextArray(v) => q.bind(v.clone()),
        };
    }
    q = q.bind(user_limit as i64);
    let qualifying: Vec<String> = q.fetch_all(pool).await?;

    // Skip the RoleLogic PUT when the computed set already equals what's
    // assigned (both ordered + de-duped, so `==` is an exact set comparison).
    let current: Vec<String> = sqlx::query_scalar(
        "SELECT discord_id FROM role_assignments \
         WHERE guild_id = $1 AND role_id = $2 ORDER BY discord_id",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_all(pool)
    .await?;
    if current == qualifying {
        return Ok(());
    }

    match rl
        .upload_users(guild_id, role_id, &qualifying, &api_token)
        .await
    {
        Ok(_) => {}
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, pool).await;
            return Ok(());
        }
        Err(e) => return Err(e),
    }

    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM role_assignments WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(&mut *tx)
        .await?;
    if !qualifying.is_empty() {
        sqlx::query(
            "INSERT INTO role_assignments (guild_id, role_id, discord_id) \
             SELECT $1, $2, UNNEST($3::text[])",
        )
        .bind(guild_id)
        .bind(role_id)
        .bind(&qualifying)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn drain_to_empty(
    guild_id: &str,
    role_id: &str,
    api_token: &str,
    state: &AppState,
) -> Result<(), AppError> {
    let any: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM role_assignments WHERE guild_id=$1 AND role_id=$2)",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_one(&state.pool)
    .await?;
    if !any {
        return Ok(());
    }

    match state
        .rl_client
        .upload_users(guild_id, role_id, &[], api_token)
        .await
    {
        Ok(_) => {}
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, &state.pool).await;
            return Ok(());
        }
        Err(e) => return Err(e),
    }
    sqlx::query("DELETE FROM role_assignments WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(&state.pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-account fan-out — re-evaluate all role links bound to an account.
// ---------------------------------------------------------------------------

pub async fn sync_for_account(account_ref: i64, state: &AppState) -> Result<(), AppError> {
    let links = sqlx::query_as::<_, (String, String)>(
        "SELECT guild_id, role_id FROM role_links WHERE stripe_account_ref = $1",
    )
    .bind(account_ref)
    .fetch_all(&state.pool)
    .await?;
    for (guild_id, role_id) in links {
        jobs::enqueue_config_sync(&state.pool, &guild_id, &role_id).await?;
    }
    Ok(())
}

/// Delete a role_link the RoleLogic API reports as gone (Convention 47).
/// CASCADE clears role_assignments. Best-effort: never propagates DB errors.
async fn delete_orphan_role_link(guild_id: &str, role_id: &str, pool: &sqlx::PgPool) {
    tracing::warn!(
        guild_id,
        role_id,
        "Role link not found on RoleLogic; removing orphaned local row"
    );
    if let Err(e) = sqlx::query("DELETE FROM role_links WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(pool)
        .await
    {
        tracing::error!(guild_id, role_id, "Failed to delete orphan role_link: {e}");
    }
}
