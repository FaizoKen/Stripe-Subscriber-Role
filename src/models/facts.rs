//! Plain-data view of one member's Stripe facts (one `stripe_member_facts`
//! row) needed for condition evaluation.
//!
//! Kept POD (no methods, no I/O) so [services::condition_eval::evaluate] stays
//! sync and fast (Convention 5). Amounts are in the currency's smallest unit.

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Default)]
pub struct Facts {
    // -- subscription facts --
    pub has_active_subscription: bool,
    pub subscription_status: Option<String>,
    pub is_trialing: bool,
    pub is_past_due: bool,
    pub cancels_at_period_end: bool,
    pub active_subscription_count: i64,
    pub product_ids: Vec<String>,
    pub price_ids: Vec<String>,
    pub plan_amount_cents: i64,
    pub billing_interval: Option<String>,
    pub subscription_started_at: Option<DateTime<Utc>>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub total_mrr_cents: i64,

    // -- customer facts --
    pub is_customer: bool,
    pub customer_created_at: Option<DateTime<Utc>>,
    pub is_delinquent: bool,
    pub lifetime_spend_cents: i64,
    pub successful_payments: i64,
    pub country_code: Option<String>,
    pub currency: Option<String>,
    pub email_domain: Option<String>,
}
