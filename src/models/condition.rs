//! Condition target / operator types used in the rule tree.
//!
//! - `ConditionTarget` names a fact we can read about a (member, Stripe
//!   account) pair — i.e. one row of `stripe_member_facts`.
//! - `ConditionOperator` names a comparison.
//! - Validity of a (target, operator) combination is enforced at save time in
//!   [services::rule_validator] using each target's `kind()`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What kind of data this target produces. Drives which operators are valid and
/// how the rule_validator coerces literal values.
///
/// `StringList` targets are backed by a `text[]` column (the member's set of
/// active product / price ids). Their operators mean set membership:
///   * `Eq`    — the set includes this one value
///   * `In`    — the set overlaps any of the given values
///   * `NotIn` — the set overlaps none of the given values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Bool,
    Int,
    String,
    StringList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionTarget {
    // -- subscription facts --
    HasActiveSubscription,
    SubscriptionStatus,
    IsTrialing,
    IsPastDue,
    CancelsAtPeriodEnd,
    ActiveSubscriptionCount,
    SubscribedToProduct,
    SubscribedToPrice,
    PlanAmount,
    BillingInterval,
    SubscriptionAgeDays,
    DaysUntilRenewal,
    TotalMrr,

    // -- customer facts --
    IsCustomer,
    CustomerAgeDays,
    IsDelinquent,
    LifetimeSpend,
    SuccessfulPayments,
    CountryCode,
    Currency,
    EmailDomain,
}

impl ConditionTarget {
    pub fn kind(self) -> TargetKind {
        use ConditionTarget::*;
        match self {
            HasActiveSubscription
            | IsTrialing
            | IsPastDue
            | CancelsAtPeriodEnd
            | IsCustomer
            | IsDelinquent => TargetKind::Bool,

            ActiveSubscriptionCount
            | PlanAmount
            | SubscriptionAgeDays
            | DaysUntilRenewal
            | TotalMrr
            | CustomerAgeDays
            | LifetimeSpend
            | SuccessfulPayments => TargetKind::Int,

            SubscriptionStatus | BillingInterval | CountryCode | Currency | EmailDomain => {
                TargetKind::String
            }

            SubscribedToProduct | SubscribedToPrice => TargetKind::StringList,
        }
    }

    /// True when the integer value is a money amount in the currency's smallest
    /// unit (cents). The rule-builder UI shows a major-unit ($) input for these
    /// and multiplies by 100 before sending.
    pub fn is_money(self) -> bool {
        use ConditionTarget::*;
        matches!(self, PlanAmount | LifetimeSpend | TotalMrr)
    }

    pub fn as_str(self) -> &'static str {
        use ConditionTarget::*;
        match self {
            HasActiveSubscription => "has_active_subscription",
            SubscriptionStatus => "subscription_status",
            IsTrialing => "is_trialing",
            IsPastDue => "is_past_due",
            CancelsAtPeriodEnd => "cancels_at_period_end",
            ActiveSubscriptionCount => "active_subscription_count",
            SubscribedToProduct => "subscribed_to_product",
            SubscribedToPrice => "subscribed_to_price",
            PlanAmount => "plan_amount",
            BillingInterval => "billing_interval",
            SubscriptionAgeDays => "subscription_age_days",
            DaysUntilRenewal => "days_until_renewal",
            TotalMrr => "total_mrr",
            IsCustomer => "is_customer",
            CustomerAgeDays => "customer_age_days",
            IsDelinquent => "is_delinquent",
            LifetimeSpend => "lifetime_spend",
            SuccessfulPayments => "successful_payments",
            CountryCode => "country_code",
            Currency => "currency",
            EmailDomain => "email_domain",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        use ConditionTarget::*;
        Some(match s {
            "has_active_subscription" => HasActiveSubscription,
            "subscription_status" => SubscriptionStatus,
            "is_trialing" => IsTrialing,
            "is_past_due" => IsPastDue,
            "cancels_at_period_end" => CancelsAtPeriodEnd,
            "active_subscription_count" => ActiveSubscriptionCount,
            "subscribed_to_product" => SubscribedToProduct,
            "subscribed_to_price" => SubscribedToPrice,
            "plan_amount" => PlanAmount,
            "billing_interval" => BillingInterval,
            "subscription_age_days" => SubscriptionAgeDays,
            "days_until_renewal" => DaysUntilRenewal,
            "total_mrr" => TotalMrr,
            "is_customer" => IsCustomer,
            "customer_age_days" => CustomerAgeDays,
            "is_delinquent" => IsDelinquent,
            "lifetime_spend" => LifetimeSpend,
            "successful_payments" => SuccessfulPayments,
            "country_code" => CountryCode,
            "currency" => Currency,
            "email_domain" => EmailDomain,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    Between,
    Contains,
    Regex,
    In,
    NotIn,
}

impl ConditionOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Neq => "neq",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Between => "between",
            Self::Contains => "contains",
            Self::Regex => "regex",
            Self::In => "in",
            Self::NotIn => "not_in",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        Some(match s {
            "eq" => Self::Eq,
            "neq" => Self::Neq,
            "gt" => Self::Gt,
            "gte" => Self::Gte,
            "lt" => Self::Lt,
            "lte" => Self::Lte,
            "between" => Self::Between,
            "contains" => Self::Contains,
            "regex" => Self::Regex,
            "in" => Self::In,
            "not_in" => Self::NotIn,
            _ => return None,
        })
    }

    /// Operators that produce a meaningful predicate on each target kind.
    /// Save-time validation rejects mismatches.
    pub fn valid_for(self, kind: TargetKind) -> bool {
        use ConditionOperator::*;
        match kind {
            TargetKind::Bool => matches!(self, Eq),
            TargetKind::Int => matches!(self, Eq | Neq | Gt | Gte | Lt | Lte | Between),
            TargetKind::String => matches!(self, Eq | Neq | Contains | Regex | In | NotIn),
            TargetKind::StringList => matches!(self, Eq | In | NotIn),
        }
    }
}

/// A single condition row inside an AND-group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub target: ConditionTarget,
    pub operator: ConditionOperator,
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_end: Option<Value>,
}
