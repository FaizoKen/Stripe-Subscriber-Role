//! Stripe REST API client (read-only) + webhook signature verification.
//!
//! Each connected Stripe account supplies its own *restricted API key*, so the
//! client is stateless w.r.t. credentials: every method takes the key. Keys are
//! decrypted from the DB just-in-time at the call site (services/crypto.rs).
//!
//! We deliberately do NOT pin a Stripe-Version header — the account's default
//! API version is used, so a future Stripe upgrade can't break field shapes we
//! read defensively (every field is optional + `#[serde(default)]`).

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::AppError;
use crate::services::rl_token::constant_time_eq;

type HmacSha256 = Hmac<Sha256>;

pub const DEFAULT_API_BASE: &str = "https://api.stripe.com";
/// Page size for list endpoints (Stripe max).
const PAGE_LIMIT: usize = 100;
/// Hard cap on pages we'll walk in one pass — guards against a runaway loop on
/// a giant account. 2000 pages × 100 = 200k objects.
const MAX_PAGES: usize = 2000;
/// Default replay-attack tolerance for webhook timestamps.
pub const WEBHOOK_TOLERANCE_SECS: i64 = 300;

#[derive(Clone)]
pub struct StripeClient {
    http: reqwest::Client,
    base: String,
}

// ---------------------------------------------------------------------------
// Wire types (tolerant — every field optional, unknown fields ignored)
// ---------------------------------------------------------------------------

trait StripeId {
    fn stripe_id(&self) -> &str;
}

/// A Stripe "expandable" field: a bare id string, or the full object when the
/// request asked Stripe to expand it.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum Expandable<T> {
    Id(String),
    Obj(Box<T>),
}

impl<T: StripeId> Expandable<T> {
    fn id(&self) -> &str {
        match self {
            Expandable::Id(s) => s,
            Expandable::Obj(o) => o.stripe_id(),
        }
    }
    fn object(&self) -> Option<&T> {
        match self {
            Expandable::Obj(o) => Some(o),
            Expandable::Id(_) => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(bound(deserialize = "T: serde::Deserialize<'de>"))]
struct StripeList<T> {
    #[serde(default = "Vec::new")]
    data: Vec<T>,
    #[serde(default)]
    has_more: bool,
}

#[derive(Debug, Deserialize)]
struct RawAccount {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    business_profile: Option<BusinessProfile>,
    #[serde(default)]
    settings: Option<AccountSettings>,
}
#[derive(Debug, Deserialize)]
struct BusinessProfile {
    #[serde(default)]
    name: Option<String>,
}
#[derive(Debug, Deserialize)]
struct AccountSettings {
    #[serde(default)]
    dashboard: Option<DashboardSettings>,
}
#[derive(Debug, Deserialize)]
struct DashboardSettings {
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawCustomer {
    id: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    currency: Option<String>,
    #[serde(default)]
    delinquent: Option<bool>,
    #[serde(default)]
    created: Option<i64>,
    #[serde(default)]
    address: Option<Address>,
    #[serde(default)]
    metadata: HashMap<String, String>,
    #[serde(default)]
    deleted: Option<bool>,
}
impl StripeId for RawCustomer {
    fn stripe_id(&self) -> &str {
        &self.id
    }
}
#[derive(Debug, Deserialize)]
struct Address {
    #[serde(default)]
    country: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawProduct {
    id: String,
    #[serde(default)]
    name: Option<String>,
}
impl StripeId for RawProduct {
    fn stripe_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
struct RawPrice {
    id: String,
    #[serde(default)]
    unit_amount: Option<i64>,
    #[serde(default)]
    currency: Option<String>,
    #[serde(default)]
    nickname: Option<String>,
    #[serde(default)]
    recurring: Option<Recurring>,
    #[serde(default)]
    product: Option<Expandable<RawProduct>>,
}
impl StripeId for RawPrice {
    fn stripe_id(&self) -> &str {
        &self.id
    }
}
#[derive(Debug, Deserialize)]
struct Recurring {
    #[serde(default)]
    interval: Option<String>,
    #[serde(default)]
    interval_count: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RawSubItem {
    #[serde(default)]
    price: Option<RawPrice>,
    #[serde(default)]
    quantity: Option<i64>,
    #[serde(default)]
    current_period_end: Option<i64>,
}
#[derive(Debug, Deserialize, Default)]
struct RawSubItems {
    #[serde(default)]
    data: Vec<RawSubItem>,
}

#[derive(Debug, Deserialize)]
struct RawSubscription {
    id: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    customer: Option<Expandable<RawCustomer>>,
    #[serde(default)]
    cancel_at_period_end: Option<bool>,
    #[serde(default)]
    current_period_end: Option<i64>,
    #[serde(default)]
    trial_end: Option<i64>,
    #[serde(default)]
    start_date: Option<i64>,
    #[serde(default)]
    created: Option<i64>,
    #[serde(default)]
    metadata: HashMap<String, String>,
    #[serde(default)]
    items: RawSubItems,
}

#[derive(Debug, Deserialize)]
struct RawCharge {
    id: String,
    #[serde(default)]
    customer: Option<Expandable<RawCustomer>>,
    #[serde(default)]
    amount: Option<i64>,
    #[serde(default)]
    amount_refunded: Option<i64>,
    #[serde(default)]
    paid: Option<bool>,
    #[serde(default)]
    refunded: Option<bool>,
    #[serde(default)]
    status: Option<String>,
}

impl RawCharge {
    /// What a charge adds to its customer's totals: the amount kept (paid
    /// minus refunded) and whether it still counts as a payment. A fully
    /// refunded or failed charge adds nothing; a partly refunded one adds
    /// what was kept.
    fn kept(&self) -> Option<(String, i64)> {
        let paid = self.paid.unwrap_or(false) && self.status.as_deref() == Some("succeeded");
        if !paid || self.refunded.unwrap_or(false) {
            return None;
        }
        let kept = (self.amount.unwrap_or(0) - self.amount_refunded.unwrap_or(0)).max(0);
        let cid = self.customer.as_ref()?.id().to_string();
        Some((cid, kept))
    }
}

#[derive(Debug, Deserialize)]
struct RawCheckoutSession {
    id: String,
    #[serde(default)]
    client_reference_id: Option<String>,
    #[serde(default)]
    customer: Option<Expandable<RawCustomer>>,
    #[serde(default)]
    subscription: Option<Expandable<RawSubscription>>,
    #[serde(default)]
    metadata: HashMap<String, String>,
}
impl StripeId for RawSubscription {
    fn stripe_id(&self) -> &str {
        &self.id
    }
}

// ---------------------------------------------------------------------------
// Normalized output types consumed by sync / reconcile
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AccountInfo {
    pub account_id: String,
    pub display_name: String,
    pub country: Option<String>,
    pub livemode: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CustomerFields {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub country: Option<String>,
    pub currency: Option<String>,
    pub delinquent: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
    pub deleted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SubFields {
    pub id: String,
    pub customer_id: Option<String>,
    pub status: String,
    /// The first item's price / product (kept for older readers).
    pub price_id: Option<String>,
    pub product_id: Option<String>,
    /// Every item's price and product (an add-on is a product too).
    pub price_ids: Vec<String>,
    pub product_ids: Vec<String>,
    /// What one period charges: unit amount × quantity, summed over items.
    pub period_amount_cents: i64,
    pub unit_amount_cents: i64,
    pub currency: Option<String>,
    pub interval: Option<String>,
    pub interval_count: i32,
    pub quantity: i32,
    pub cancel_at_period_end: bool,
    pub current_period_end: Option<DateTime<Utc>>,
    pub trial_end: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
    /// Present only when the subscription's `customer` field was expanded.
    pub customer: Option<CustomerFields>,
}

/// A completed Checkout Session's link between a buyer and what they bought.
#[derive(Debug, Clone)]
pub struct CheckoutLink {
    pub client_reference_id: Option<String>,
    pub metadata: HashMap<String, String>,
    pub customer_id: Option<String>,
    pub subscription_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProductCatalogEntry {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct PriceCatalogEntry {
    pub id: String,
    pub product_id: Option<String>,
    pub nickname: Option<String>,
    pub unit_amount_cents: Option<i64>,
    pub currency: Option<String>,
    pub interval: Option<String>,
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

fn ts(unix: Option<i64>) -> Option<DateTime<Utc>> {
    unix.and_then(|s| Utc.timestamp_opt(s, 0).single())
}

impl RawCustomer {
    fn into_fields(self) -> CustomerFields {
        CustomerFields {
            country: self.address.as_ref().and_then(|a| a.country.clone()),
            id: self.id,
            email: self.email,
            name: self.name,
            currency: self.currency,
            delinquent: self.delinquent.unwrap_or(false),
            created_at: ts(self.created),
            metadata: self.metadata,
            deleted: self.deleted.unwrap_or(false),
        }
    }
}

impl RawSubscription {
    fn into_fields(self) -> SubFields {
        let customer_id = self.customer.as_ref().map(|c| c.id().to_string());
        let customer = self
            .customer
            .as_ref()
            .and_then(|c| c.object())
            .map(|c| CustomerFields {
                id: c.id.clone(),
                email: c.email.clone(),
                name: c.name.clone(),
                country: c.address.as_ref().and_then(|a| a.country.clone()),
                currency: c.currency.clone(),
                delinquent: c.delinquent.unwrap_or(false),
                created_at: ts(c.created),
                metadata: c.metadata.clone(),
                deleted: c.deleted.unwrap_or(false),
            });

        // Every item: its price, product and per-period charge. All items of
        // one subscription share its billing interval.
        let mut price_ids: Vec<String> = Vec::new();
        let mut product_ids: Vec<String> = Vec::new();
        let mut period_amount_cents: i64 = 0;
        for it in &self.items.data {
            if let Some(p) = it.price.as_ref() {
                if !price_ids.contains(&p.id) {
                    price_ids.push(p.id.clone());
                }
                if let Some(pr) = p.product.as_ref() {
                    let pid = pr.id().to_string();
                    if !product_ids.contains(&pid) {
                        product_ids.push(pid);
                    }
                }
                period_amount_cents += p.unit_amount.unwrap_or(0) * it.quantity.unwrap_or(1).max(1);
            }
        }

        let item = self.items.data.into_iter().next();
        let (
            price_id,
            product_id,
            unit_amount,
            currency,
            interval,
            interval_count,
            item_period_end,
        ) = match item.as_ref().and_then(|i| i.price.as_ref()) {
            Some(p) => (
                Some(p.id.clone()),
                p.product.as_ref().map(|pr| pr.id().to_string()),
                p.unit_amount.unwrap_or(0),
                p.currency.clone(),
                p.recurring.as_ref().and_then(|r| r.interval.clone()),
                p.recurring
                    .as_ref()
                    .and_then(|r| r.interval_count)
                    .unwrap_or(1) as i32,
                None,
            ),
            None => (None, None, 0, None, None, 1, None),
        };
        let item_period_end =
            item_period_end.or_else(|| item.as_ref().and_then(|i| i.current_period_end));
        let quantity = item.as_ref().and_then(|i| i.quantity).unwrap_or(1) as i32;

        SubFields {
            id: self.id,
            customer_id,
            status: self.status.unwrap_or_else(|| "incomplete".to_string()),
            price_id,
            product_id,
            price_ids,
            product_ids,
            period_amount_cents,
            unit_amount_cents: unit_amount,
            currency,
            interval,
            interval_count,
            quantity,
            cancel_at_period_end: self.cancel_at_period_end.unwrap_or(false),
            // Stripe moved current_period_end to the item level on newer API
            // versions; read the sub-level value first, then the item.
            current_period_end: ts(self.current_period_end.or(item_period_end)),
            trial_end: ts(self.trial_end),
            started_at: ts(self.start_date.or(self.created)),
            created_at: ts(self.created),
            metadata: self.metadata,
            customer,
        }
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

impl StripeClient {
    pub fn new(base: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to build Stripe HTTP client");
        Self {
            http,
            base: base.trim_end_matches('/').to_string(),
        }
    }

    async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T, AppError> {
        let url = format!("{}{}", self.base, path);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(key)
            .query(query)
            .send()
            .await
            .map_err(|e| AppError::StripeApi(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            // Keep the body short, but whole enough for `readable_error` to
            // parse Stripe's message out of it.
            let snippet: String = body.chars().take(1200).collect();
            return Err(AppError::StripeApi(format!("{status}: {snippet}")));
        }
        resp.json::<T>()
            .await
            .map_err(|e| AppError::StripeApi(format!("response parse: {e}")))
    }

    /// Validate a key and describe the account behind it. Tries `GET /v1/account`
    /// first; if the restricted key lacks the Account read permission, falls
    /// back to validating against `GET /v1/customers` and synthesizes a stable
    /// id from the key fingerprint.
    pub async fn validate_and_describe(&self, key: &str) -> Result<AccountInfo, AppError> {
        let livemode = key.contains("_live_");

        match self.get::<RawAccount>(key, "/v1/account", &[]).await {
            Ok(acct) => {
                let display_name = acct
                    .settings
                    .as_ref()
                    .and_then(|s| s.dashboard.as_ref())
                    .and_then(|d| d.display_name.clone())
                    .or_else(|| acct.business_profile.as_ref().and_then(|b| b.name.clone()))
                    .or_else(|| acct.email.clone())
                    .or_else(|| acct.id.clone())
                    .unwrap_or_else(|| "Stripe account".to_string());
                Ok(AccountInfo {
                    account_id: acct.id.unwrap_or_else(|| synth_account_id(key, livemode)),
                    display_name,
                    country: acct.country,
                    livemode,
                })
            }
            Err(_) => {
                // Account read not granted — confirm the key at least reads
                // customers (which is what we actually need for sync).
                self.get::<StripeList<RawCustomer>>(
                    key,
                    "/v1/customers",
                    &[("limit", "1".to_string())],
                )
                .await
                .map_err(|e| {
                    AppError::BadRequest(format!(
                        "Stripe rejected this key, or it can't read customers: {e}. \
                         Create a restricted key with read access to Customers, \
                         Subscriptions, Charges, Products and Prices."
                    ))
                })?;
                Ok(AccountInfo {
                    account_id: synth_account_id(key, livemode),
                    display_name: if livemode {
                        "Stripe account (live)".to_string()
                    } else {
                        "Stripe account (test)".to_string()
                    },
                    country: None,
                    livemode,
                })
            }
        }
    }

    /// Paginate every subscription (status=all), with customer + price expanded.
    pub async fn list_all_subscriptions(&self, key: &str) -> Result<Vec<SubFields>, AppError> {
        let mut out = Vec::new();
        let mut starting_after: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut q: Vec<(&str, String)> = vec![
                ("status", "all".to_string()),
                ("limit", PAGE_LIMIT.to_string()),
                ("expand[]", "data.customer".to_string()),
                ("expand[]", "data.items.data.price".to_string()),
            ];
            if let Some(sa) = &starting_after {
                q.push(("starting_after", sa.clone()));
            }
            let page: StripeList<RawSubscription> = self.get(key, "/v1/subscriptions", &q).await?;
            let has_more = page.has_more;
            let last_id = page.data.last().map(|s| s.id.clone());
            out.extend(page.data.into_iter().map(RawSubscription::into_fields));
            if !has_more {
                break;
            }
            match last_id {
                Some(id) => starting_after = Some(id),
                None => break,
            }
        }
        Ok(out)
    }

    /// Paginate every customer.
    pub async fn list_all_customers(&self, key: &str) -> Result<Vec<CustomerFields>, AppError> {
        let mut out = Vec::new();
        let mut starting_after: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut q: Vec<(&str, String)> = vec![("limit", PAGE_LIMIT.to_string())];
            if let Some(sa) = &starting_after {
                q.push(("starting_after", sa.clone()));
            }
            let page: StripeList<RawCustomer> = self.get(key, "/v1/customers", &q).await?;
            let has_more = page.has_more;
            let last_id = page.data.last().map(|c| c.id.clone());
            out.extend(page.data.into_iter().map(RawCustomer::into_fields));
            if !has_more {
                break;
            }
            match last_id {
                Some(id) => starting_after = Some(id),
                None => break,
            }
        }
        Ok(out)
    }

    /// Sum successful charge amounts per customer. Best-effort: callers should
    /// treat an error as "skip lifetime-spend enrichment this pass" rather than
    /// failing the whole sync (the restricted key may not grant charge read).
    pub async fn aggregate_charges(
        &self,
        key: &str,
    ) -> Result<(HashMap<String, i64>, HashMap<String, i64>), AppError> {
        let mut spend: HashMap<String, i64> = HashMap::new();
        let mut count: HashMap<String, i64> = HashMap::new();
        let mut starting_after: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut q: Vec<(&str, String)> = vec![("limit", PAGE_LIMIT.to_string())];
            if let Some(sa) = &starting_after {
                q.push(("starting_after", sa.clone()));
            }
            // We can't filter to paid on the server here cheaply across all
            // customers, so we list and filter client-side.
            let page: StripeList<RawCharge> = self.get(key, "/v1/charges", &q).await?;
            let has_more = page.has_more;
            let last_id = page.data.last().map(|c| c.id.clone());
            for ch in &page.data {
                if let Some((cid, kept)) = ch.kept() {
                    *spend.entry(cid.clone()).or_insert(0) += kept;
                    *count.entry(cid).or_insert(0) += 1;
                }
            }
            if !has_more {
                break;
            }
            match last_id {
                Some(id) => starting_after = Some(id),
                None => break,
            }
        }
        Ok((spend, count))
    }

    /// One customer's totals, recounted from Stripe (`charge.succeeded` /
    /// `charge.refunded`): the amount they kept paying and how many payments
    /// still count. Absolute, so a retried or out-of-order event can't count
    /// a charge twice, and a refund comes off as soon as Stripe reports it.
    pub async fn customer_charge_totals(
        &self,
        key: &str,
        customer_id: &str,
    ) -> Result<(i64, i64), AppError> {
        let (mut spend, mut count) = (0i64, 0i64);
        let mut starting_after: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut q: Vec<(&str, String)> = vec![
                ("customer", customer_id.to_string()),
                ("limit", PAGE_LIMIT.to_string()),
            ];
            if let Some(sa) = &starting_after {
                q.push(("starting_after", sa.clone()));
            }
            let page: StripeList<RawCharge> = self.get(key, "/v1/charges", &q).await?;
            for ch in &page.data {
                if let Some((_, kept)) = ch.kept() {
                    spend += kept;
                    count += 1;
                }
            }
            if !page.has_more {
                break;
            }
            match page.data.last() {
                Some(c) => starting_after = Some(c.id.clone()),
                None => break,
            }
        }
        Ok((spend, count))
    }

    /// One customer (the one-time Checkout path links a customer that has no
    /// subscription, and wants its email/country too).
    pub async fn retrieve_customer(
        &self,
        key: &str,
        customer_id: &str,
    ) -> Result<CustomerFields, AppError> {
        let raw: RawCustomer = self
            .get(key, &format!("/v1/customers/{customer_id}"), &[])
            .await?;
        Ok(raw.into_fields())
    }

    /// Completed Checkout Sessions that carry a buyer's Discord ID — in
    /// `client_reference_id` or the session's metadata — with the customer
    /// and subscription they created. The import reads these so a checkout
    /// that put the ID only on the session (not on the subscription or the
    /// customer) still links, even when its webhook was never received.
    /// `since` (unix seconds) bounds a routine reconcile to recent sessions;
    /// the first import reads them all. Best-effort: the key may not grant
    /// Checkout Sessions read.
    pub async fn list_checkout_links(
        &self,
        key: &str,
        since: Option<i64>,
    ) -> Result<Vec<CheckoutLink>, AppError> {
        let mut out = Vec::new();
        let mut starting_after: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut q: Vec<(&str, String)> = vec![
                ("status", "complete".to_string()),
                ("limit", PAGE_LIMIT.to_string()),
            ];
            if let Some(t) = since {
                q.push(("created[gte]", t.to_string()));
            }
            if let Some(sa) = &starting_after {
                q.push(("starting_after", sa.clone()));
            }
            let page: StripeList<RawCheckoutSession> =
                self.get(key, "/v1/checkout/sessions", &q).await?;
            let has_more = page.has_more;
            let last_id = page.data.last().map(|s| s.id.clone());
            for s in page.data {
                if s.client_reference_id.is_none() && s.metadata.is_empty() {
                    continue;
                }
                out.push(CheckoutLink {
                    client_reference_id: s.client_reference_id,
                    metadata: s.metadata,
                    customer_id: s.customer.as_ref().map(|c| c.id().to_string()),
                    subscription_id: s.subscription.as_ref().map(|x| x.id().to_string()),
                });
            }
            if !has_more {
                break;
            }
            match last_id {
                Some(id) => starting_after = Some(id),
                None => break,
            }
        }
        Ok(out)
    }

    /// Retrieve one subscription (used by the checkout.session.completed
    /// webhook to fetch the freshly created subscription).
    pub async fn retrieve_subscription(
        &self,
        key: &str,
        sub_id: &str,
    ) -> Result<SubFields, AppError> {
        let path = format!("/v1/subscriptions/{sub_id}");
        let q: Vec<(&str, String)> = vec![
            ("expand[]", "customer".to_string()),
            ("expand[]", "items.data.price".to_string()),
        ];
        let raw: RawSubscription = self.get(key, &path, &q).await?;
        Ok(raw.into_fields())
    }

    /// Active products for the rule-builder picker.
    pub async fn list_products(&self, key: &str) -> Result<Vec<ProductCatalogEntry>, AppError> {
        let q: Vec<(&str, String)> = vec![
            ("active", "true".to_string()),
            ("limit", PAGE_LIMIT.to_string()),
        ];
        let page: StripeList<RawProduct> = self.get(key, "/v1/products", &q).await?;
        Ok(page
            .data
            .into_iter()
            .map(|p| ProductCatalogEntry {
                name: p.name.clone().unwrap_or_else(|| p.id.clone()),
                id: p.id,
            })
            .collect())
    }

    /// Active prices for the rule-builder picker (product expanded for names).
    pub async fn list_prices(&self, key: &str) -> Result<Vec<PriceCatalogEntry>, AppError> {
        let q: Vec<(&str, String)> = vec![
            ("active", "true".to_string()),
            ("limit", PAGE_LIMIT.to_string()),
            ("expand[]", "data.product".to_string()),
        ];
        let page: StripeList<RawPrice> = self.get(key, "/v1/prices", &q).await?;
        Ok(page
            .data
            .into_iter()
            .map(|p| PriceCatalogEntry {
                product_id: p.product.as_ref().map(|pr| pr.id().to_string()),
                nickname: p.nickname.clone().or_else(|| {
                    p.product
                        .as_ref()
                        .and_then(|pr| pr.object())
                        .and_then(|o| o.name.clone())
                }),
                unit_amount_cents: p.unit_amount,
                currency: p.currency.clone(),
                interval: p.recurring.as_ref().and_then(|r| r.interval.clone()),
                id: p.id,
            })
            .collect())
    }
}

fn synth_account_id(key: &str, livemode: bool) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    let digest = hex::encode(h.finalize());
    let mode = if livemode { "live" } else { "test" };
    format!("acct_key_{mode}_{}", &digest[..16])
}

// ---------------------------------------------------------------------------
// Webhook signature verification (Stripe-Signature: t=…,v1=…)
// ---------------------------------------------------------------------------

/// Verify a Stripe webhook signature. Returns true iff the HMAC of
/// `"{t}.{payload}"` with `secret` matches a `v1` scheme value and the
/// timestamp is within `tolerance_secs` of now.
pub fn verify_webhook_signature(
    payload: &[u8],
    sig_header: &str,
    secret: &str,
    tolerance_secs: i64,
) -> bool {
    let mut timestamp: Option<i64> = None;
    let mut v1_sigs: Vec<&str> = Vec::new();
    for part in sig_header.split(',') {
        let mut kv = part.splitn(2, '=');
        match (kv.next(), kv.next()) {
            (Some("t"), Some(v)) => timestamp = v.trim().parse().ok(),
            (Some("v1"), Some(v)) => v1_sigs.push(v.trim()),
            _ => {}
        }
    }
    let Some(t) = timestamp else { return false };
    if v1_sigs.is_empty() {
        return false;
    }
    let now = Utc::now().timestamp();
    if (now - t).abs() > tolerance_secs {
        return false;
    }

    let mut signed = Vec::with_capacity(payload.len() + 16);
    signed.extend_from_slice(t.to_string().as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(payload);

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(&signed);
    let expected = hex::encode(mac.finalize().into_bytes());

    v1_sigs
        .iter()
        .any(|sig| constant_time_eq(sig.as_bytes(), expected.as_bytes()))
}

/// Parse a webhook event envelope into (event_id, event_type, data.object).
pub fn parse_event(payload: &[u8]) -> Option<(String, String, serde_json::Value)> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let id = v.get("id").and_then(|x| x.as_str())?.to_string();
    let typ = v.get("type").and_then(|x| x.as_str())?.to_string();
    let object = v.get("data").and_then(|d| d.get("object")).cloned()?;
    Some((id, typ, object))
}

/// A Thin event: Stripe's lighter payload ("Thin" is the format Stripe's
/// event-destination form recommends), carrying only `related_object` — no
/// `data.object` to read. This plugin needs Snapshot events; the settings
/// page says so when one of these arrives.
pub fn is_thin_event(payload: &[u8]) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return false;
    };
    let object = v.get("object").and_then(|x| x.as_str()).unwrap_or("");
    let has_snapshot = v.get("data").and_then(|d| d.get("object")).is_some();
    !has_snapshot && (object.starts_with("v2.") || v.get("related_object").is_some())
}

/// The readable part of a Stripe API error, for the settings page:
/// Stripe's own `error.message` (e.g. which permission the key lacks)
/// rather than the status line and raw JSON.
pub fn readable_error(e: &AppError) -> String {
    let raw = match e {
        AppError::StripeApi(s) => s.as_str(),
        other => return other.to_string().chars().take(300).collect(),
    };
    let message = raw
        .find('{')
        .and_then(|i| serde_json::from_str::<serde_json::Value>(&raw[i..]).ok())
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
        });
    message
        .unwrap_or_else(|| raw.to_string())
        .chars()
        .take(300)
        .collect()
}

/// Parse a subscription object (from a webhook `data.object`) into SubFields.
pub fn parse_subscription_object(object: &serde_json::Value) -> Option<SubFields> {
    let raw: RawSubscription = serde_json::from_value(object.clone()).ok()?;
    Some(raw.into_fields())
}

/// Parse a customer object (from a webhook `data.object`) into CustomerFields.
pub fn parse_customer_object(object: &serde_json::Value) -> Option<CustomerFields> {
    let raw: RawCustomer = serde_json::from_value(object.clone()).ok()?;
    Some(raw.into_fields())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(secret: &str, t: i64, payload: &[u8]) -> String {
        let mut signed = Vec::new();
        signed.extend_from_slice(t.to_string().as_bytes());
        signed.push(b'.');
        signed.extend_from_slice(payload);
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(&signed);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn webhook_sig_round_trip() {
        let secret = "whsec_test";
        let payload = br#"{"id":"evt_1","type":"customer.subscription.updated"}"#;
        let t = Utc::now().timestamp();
        let sig = sign(secret, t, payload);
        let header = format!("t={t},v1={sig}");
        assert!(verify_webhook_signature(
            payload,
            &header,
            secret,
            WEBHOOK_TOLERANCE_SECS
        ));
    }

    #[test]
    fn webhook_sig_rejects_wrong_secret() {
        let payload = br#"{}"#;
        let t = Utc::now().timestamp();
        let sig = sign("right", t, payload);
        let header = format!("t={t},v1={sig}");
        assert!(!verify_webhook_signature(
            payload,
            &header,
            "wrong",
            WEBHOOK_TOLERANCE_SECS
        ));
    }

    #[test]
    fn webhook_sig_rejects_old_timestamp() {
        let secret = "whsec_test";
        let payload = br#"{}"#;
        let t = Utc::now().timestamp() - 10_000;
        let sig = sign(secret, t, payload);
        let header = format!("t={t},v1={sig}");
        assert!(!verify_webhook_signature(
            payload,
            &header,
            secret,
            WEBHOOK_TOLERANCE_SECS
        ));
    }

    #[test]
    fn webhook_sig_accepts_multiple_v1() {
        let secret = "whsec_test";
        let payload = br#"{}"#;
        let t = Utc::now().timestamp();
        let good = sign(secret, t, payload);
        let header = format!("t={t},v1=deadbeef,v1={good}");
        assert!(verify_webhook_signature(
            payload,
            &header,
            secret,
            WEBHOOK_TOLERANCE_SECS
        ));
    }

    #[test]
    fn parse_subscription_reads_item_price() {
        let obj = serde_json::json!({
            "id": "sub_1",
            "status": "active",
            "customer": "cus_1",
            "cancel_at_period_end": false,
            "current_period_end": 1_700_000_000,
            "metadata": {"discord_user_id": "123"},
            "items": { "data": [ {
                "quantity": 1,
                "price": {
                    "id": "price_1",
                    "unit_amount": 1500,
                    "currency": "usd",
                    "recurring": { "interval": "month", "interval_count": 1 },
                    "product": "prod_1"
                }
            } ] }
        });
        let f = parse_subscription_object(&obj).unwrap();
        assert_eq!(f.id, "sub_1");
        assert_eq!(f.customer_id.as_deref(), Some("cus_1"));
        assert_eq!(f.price_id.as_deref(), Some("price_1"));
        assert_eq!(f.product_id.as_deref(), Some("prod_1"));
        assert_eq!(f.unit_amount_cents, 1500);
        assert_eq!(f.interval.as_deref(), Some("month"));
        assert_eq!(
            f.metadata.get("discord_user_id").map(String::as_str),
            Some("123")
        );
    }

    #[test]
    fn parse_subscription_reads_every_item() {
        let obj = serde_json::json!({
            "id": "sub_2",
            "status": "active",
            "customer": "cus_2",
            "items": { "data": [
                { "quantity": 1, "price": { "id": "price_base", "unit_amount": 900,
                  "currency": "usd", "recurring": { "interval": "month" }, "product": "prod_base" } },
                { "quantity": 3, "price": { "id": "price_seat", "unit_amount": 200,
                  "currency": "usd", "recurring": { "interval": "month" }, "product": "prod_addon" } }
            ] }
        });
        let f = parse_subscription_object(&obj).unwrap();
        assert_eq!(f.price_id.as_deref(), Some("price_base"));
        assert_eq!(f.price_ids, vec!["price_base", "price_seat"]);
        assert_eq!(f.product_ids, vec!["prod_base", "prod_addon"]);
        assert_eq!(f.period_amount_cents, 900 + 3 * 200);
    }

    #[test]
    fn charges_count_what_was_kept() {
        let ch = |v: serde_json::Value| serde_json::from_value::<RawCharge>(v).unwrap();
        let paid = ch(
            serde_json::json!({"id":"ch_1","customer":"cus_1","amount":5000,
            "amount_refunded":0,"paid":true,"refunded":false,"status":"succeeded"}),
        );
        assert_eq!(paid.kept(), Some(("cus_1".to_string(), 5000)));
        let partly = ch(
            serde_json::json!({"id":"ch_2","customer":"cus_1","amount":5000,
            "amount_refunded":2000,"paid":true,"refunded":false,"status":"succeeded"}),
        );
        assert_eq!(partly.kept(), Some(("cus_1".to_string(), 3000)));
        let fully = ch(
            serde_json::json!({"id":"ch_3","customer":"cus_1","amount":5000,
            "amount_refunded":5000,"paid":true,"refunded":true,"status":"succeeded"}),
        );
        assert_eq!(fully.kept(), None);
        let failed = ch(
            serde_json::json!({"id":"ch_4","customer":"cus_1","amount":5000,
            "paid":false,"status":"failed"}),
        );
        assert_eq!(failed.kept(), None);
        let guest =
            ch(serde_json::json!({"id":"ch_5","amount":5000,"paid":true,"status":"succeeded"}));
        assert_eq!(guest.kept(), None);
    }

    #[test]
    fn thin_events_are_recognised() {
        let thin = br#"{"id":"evt_1","object":"v2.core.event","type":"v1.customer.subscription.updated","related_object":{"id":"sub_1","type":"subscription","url":"/v1/subscriptions/sub_1"}}"#;
        assert!(is_thin_event(thin));
        let snapshot = br#"{"id":"evt_2","object":"event","type":"customer.subscription.updated","data":{"object":{"id":"sub_1"}}}"#;
        assert!(!is_thin_event(snapshot));
        assert!(!is_thin_event(b"not json"));
    }

    #[test]
    fn readable_error_keeps_stripes_message() {
        let e = AppError::StripeApi(
            r#"403 Forbidden: {"error":{"message":"The provided key 'rk_test_***1234' does not have the required permissions for this endpoint. Having the 'rak_subscription_read' permission would allow this request to continue.","type":"invalid_request_error"}}"#.into(),
        );
        let m = readable_error(&e);
        assert!(m.starts_with("The provided key"));
        assert!(m.contains("rak_subscription_read"));
        assert_eq!(
            readable_error(&AppError::StripeApi("timed out".into())),
            "timed out"
        );
    }

    #[test]
    fn synth_id_is_stable_and_mode_aware() {
        let a = synth_account_id("rk_live_abc", true);
        let b = synth_account_id("rk_live_abc", true);
        assert_eq!(a, b);
        assert!(a.contains("live"));
        assert!(synth_account_id("rk_test_abc", false).contains("test"));
    }
}
