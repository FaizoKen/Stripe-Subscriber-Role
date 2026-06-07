//! Rust-side condition evaluation. Sync, fast, no I/O (Convention 5).
//!
//! Used by `services::sync::sync_for_player` to decide a single member's role
//! eligibility against the rule tree. The bulk per-role-link path uses
//! [services::rule_sql::build_rule_where] instead — it pushes the same
//! predicates down into Postgres.

use serde_json::Value;

use crate::models::condition::{Condition, ConditionOperator, ConditionTarget};
use crate::models::facts::Facts;
use crate::models::rule::RuleTree;

/// Evaluate the rule tree against a member's facts.
///
/// - `grant_on_any_relation = true` short-circuits to `true` (any customer of
///   the connected account).
/// - Otherwise an empty `groups` slice returns `false` (Convention 42).
/// - Otherwise: ANY group matches (OR) and each group requires ALL of its
///   conditions to match (AND).
pub fn evaluate(tree: &RuleTree, facts: &Facts) -> bool {
    if tree.grant_on_any_relation {
        return true;
    }
    if tree.groups.is_empty() {
        return false;
    }
    tree.groups
        .iter()
        .any(|g| !g.conditions.is_empty() && g.conditions.iter().all(|c| evaluate_single(c, facts)))
}

fn evaluate_single(c: &Condition, f: &Facts) -> bool {
    use ConditionTarget::*;
    match c.target {
        // -- booleans --
        HasActiveSubscription => bool_match(c, f.has_active_subscription),
        IsTrialing => bool_match(c, f.is_trialing),
        IsPastDue => bool_match(c, f.is_past_due),
        CancelsAtPeriodEnd => bool_match(c, f.cancels_at_period_end),
        IsCustomer => bool_match(c, f.is_customer),
        IsDelinquent => bool_match(c, f.is_delinquent),

        // -- integers --
        ActiveSubscriptionCount => int_match(c, Some(f.active_subscription_count)),
        PlanAmount => int_match(c, Some(f.plan_amount_cents)),
        SubscriptionAgeDays => int_match(c, days_since(f.subscription_started_at)),
        DaysUntilRenewal => int_match(c, days_until(f.current_period_end)),
        TotalMrr => int_match(c, Some(f.total_mrr_cents)),
        CustomerAgeDays => int_match(c, days_since(f.customer_created_at)),
        LifetimeSpend => int_match(c, Some(f.lifetime_spend_cents)),
        SuccessfulPayments => int_match(c, Some(f.successful_payments)),

        // -- strings (nullable) --
        SubscriptionStatus => string_match(c, f.subscription_status.as_deref()),
        BillingInterval => string_match(c, f.billing_interval.as_deref()),
        CountryCode => string_match(c, f.country_code.as_deref()),
        Currency => string_match(c, f.currency.as_deref()),
        EmailDomain => string_match(c, f.email_domain.as_deref()),

        // -- string sets --
        SubscribedToProduct => stringlist_match(c, &f.product_ids),
        SubscribedToPrice => stringlist_match(c, &f.price_ids),
    }
}

fn bool_match(c: &Condition, actual: bool) -> bool {
    if !matches!(c.operator, ConditionOperator::Eq) {
        return false;
    }
    c.value.as_bool().map(|v| v == actual).unwrap_or(false)
}

fn int_match(c: &Condition, actual: Option<i64>) -> bool {
    let Some(a) = actual else {
        return false; // missing data ⇒ fail-closed
    };
    let v = c.value.as_i64();
    match c.operator {
        ConditionOperator::Eq => v.map(|n| a == n).unwrap_or(false),
        ConditionOperator::Neq => v.map(|n| a != n).unwrap_or(false),
        ConditionOperator::Gt => v.map(|n| a > n).unwrap_or(false),
        ConditionOperator::Gte => v.map(|n| a >= n).unwrap_or(false),
        ConditionOperator::Lt => v.map(|n| a < n).unwrap_or(false),
        ConditionOperator::Lte => v.map(|n| a <= n).unwrap_or(false),
        ConditionOperator::Between => {
            let lo = v;
            let hi = c.value_end.as_ref().and_then(|x| x.as_i64());
            match (lo, hi) {
                (Some(lo), Some(hi)) => a >= lo && a <= hi,
                _ => false,
            }
        }
        _ => false,
    }
}

fn string_match(c: &Condition, actual: Option<&str>) -> bool {
    let Some(a) = actual else {
        // `neq` against missing is satisfied (mirrors the SQL IS DISTINCT FROM)
        // so "anyone NOT in country X" works against an unset country.
        return matches!(c.operator, ConditionOperator::Neq);
    };
    let v = c.value.as_str();
    match c.operator {
        ConditionOperator::Eq => v.map(|s| a == s).unwrap_or(false),
        ConditionOperator::Neq => v.map(|s| a != s).unwrap_or(false),
        ConditionOperator::Contains => v.map(|s| a.contains(s)).unwrap_or(false),
        ConditionOperator::Regex => {
            let Some(pattern) = v else { return false };
            let Ok(re) = regex::RegexBuilder::new(pattern)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .build()
            else {
                return false;
            };
            re.is_match(a)
        }
        ConditionOperator::In => list_contains(&c.value, a),
        ConditionOperator::NotIn => !list_contains(&c.value, a),
        _ => false,
    }
}

/// Set-membership match for `text[]`-backed targets (active product/price ids).
fn stringlist_match(c: &Condition, actual: &[String]) -> bool {
    match c.operator {
        // Eq: the set includes this one value.
        ConditionOperator::Eq => c
            .value
            .as_str()
            .map(|needle| actual.iter().any(|s| s == needle))
            .unwrap_or(false),
        // In: the set overlaps any of the listed values.
        ConditionOperator::In => any_overlap(&c.value, actual),
        // NotIn: the set overlaps none of the listed values.
        ConditionOperator::NotIn => !any_overlap(&c.value, actual),
        _ => false,
    }
}

fn any_overlap(value: &Value, actual: &[String]) -> bool {
    value
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .any(|needle| actual.iter().any(|s| s == needle))
        })
        .unwrap_or(false)
}

fn list_contains(value: &Value, needle: &str) -> bool {
    value
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).any(|s| s == needle))
        .unwrap_or(false)
}

fn days_since(ts: Option<chrono::DateTime<chrono::Utc>>) -> Option<i64> {
    ts.map(|t| (chrono::Utc::now() - t).num_days())
}

fn days_until(ts: Option<chrono::DateTime<chrono::Utc>>) -> Option<i64> {
    ts.map(|t| (t - chrono::Utc::now()).num_days())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::condition::ConditionTarget as T;
    use crate::models::rule::{ConditionGroup, RuleTree};
    use chrono::Duration;
    use serde_json::json;

    fn c(target: T, op: ConditionOperator, value: Value) -> Condition {
        Condition {
            target,
            operator: op,
            value,
            value_end: None,
        }
    }

    fn one_group(conds: Vec<Condition>) -> RuleTree {
        RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup { conditions: conds }],
        }
    }

    fn or_groups(g: Vec<Vec<Condition>>) -> RuleTree {
        RuleTree {
            grant_on_any_relation: false,
            groups: g
                .into_iter()
                .map(|cs| ConditionGroup { conditions: cs })
                .collect(),
        }
    }

    fn facts() -> Facts {
        Facts::default()
    }

    #[test]
    fn convention_42_no_groups_no_grant_means_nobody() {
        assert!(!evaluate(&RuleTree::default(), &facts()));
    }

    #[test]
    fn grant_on_any_short_circuits_true() {
        let t = RuleTree {
            grant_on_any_relation: true,
            groups: vec![],
        };
        assert!(evaluate(&t, &facts()));
    }

    #[test]
    fn active_subscriber_bool() {
        let t = one_group(vec![c(
            T::HasActiveSubscription,
            ConditionOperator::Eq,
            json!(true),
        )]);
        let mut f = facts();
        assert!(!evaluate(&t, &f));
        f.has_active_subscription = true;
        assert!(evaluate(&t, &f));
    }

    #[test]
    fn plan_amount_between() {
        let mut cond = c(T::PlanAmount, ConditionOperator::Between, json!(1000));
        cond.value_end = Some(json!(5000));
        let t = one_group(vec![cond]);
        let mut f = facts();
        f.plan_amount_cents = 2000;
        assert!(evaluate(&t, &f));
        f.plan_amount_cents = 9000;
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn subscription_age_from_timestamp() {
        let t = one_group(vec![c(
            T::SubscriptionAgeDays,
            ConditionOperator::Gte,
            json!(30),
        )]);
        let mut f = facts();
        f.subscription_started_at = Some(chrono::Utc::now() - Duration::days(45));
        assert!(evaluate(&t, &f));
        f.subscription_started_at = Some(chrono::Utc::now() - Duration::days(10));
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn days_until_renewal_future() {
        let t = one_group(vec![c(
            T::DaysUntilRenewal,
            ConditionOperator::Lte,
            json!(7),
        )]);
        let mut f = facts();
        f.current_period_end = Some(chrono::Utc::now() + Duration::days(3));
        assert!(evaluate(&t, &f));
        f.current_period_end = Some(chrono::Utc::now() + Duration::days(20));
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn missing_int_fails_closed() {
        let t = one_group(vec![c(
            T::CustomerAgeDays,
            ConditionOperator::Gte,
            json!(0),
        )]);
        let f = facts(); // customer_created_at = None
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn status_in_list() {
        let t = one_group(vec![c(
            T::SubscriptionStatus,
            ConditionOperator::In,
            json!(["active", "trialing"]),
        )]);
        let mut f = facts();
        f.subscription_status = Some("trialing".into());
        assert!(evaluate(&t, &f));
        f.subscription_status = Some("canceled".into());
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn null_status_neq_passes() {
        let t = one_group(vec![c(
            T::SubscriptionStatus,
            ConditionOperator::Neq,
            json!("canceled"),
        )]);
        let f = facts();
        assert!(evaluate(&t, &f));
    }

    #[test]
    fn email_domain_regex() {
        let t = one_group(vec![c(
            T::EmailDomain,
            ConditionOperator::Eq,
            json!("acme.com"),
        )]);
        let mut f = facts();
        f.email_domain = Some("acme.com".into());
        assert!(evaluate(&t, &f));
        f.email_domain = Some("gmail.com".into());
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn subscribed_to_product_eq() {
        let t = one_group(vec![c(
            T::SubscribedToProduct,
            ConditionOperator::Eq,
            json!("prod_pro"),
        )]);
        let mut f = facts();
        f.product_ids = vec!["prod_basic".into()];
        assert!(!evaluate(&t, &f));
        f.product_ids = vec!["prod_basic".into(), "prod_pro".into()];
        assert!(evaluate(&t, &f));
    }

    #[test]
    fn subscribed_to_price_in_any() {
        let t = one_group(vec![c(
            T::SubscribedToPrice,
            ConditionOperator::In,
            json!(["price_a", "price_b"]),
        )]);
        let mut f = facts();
        f.price_ids = vec!["price_b".into()];
        assert!(evaluate(&t, &f));
        f.price_ids = vec!["price_z".into()];
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn subscribed_to_product_not_in() {
        let t = one_group(vec![c(
            T::SubscribedToProduct,
            ConditionOperator::NotIn,
            json!(["prod_free"]),
        )]);
        let mut f = facts();
        f.product_ids = vec!["prod_pro".into()];
        assert!(evaluate(&t, &f));
        f.product_ids = vec!["prod_free".into()];
        assert!(!evaluate(&t, &f));
        // empty set ⇒ overlaps nothing ⇒ NotIn true
        f.product_ids = vec![];
        assert!(evaluate(&t, &f));
    }

    #[test]
    fn realistic_tier_rule() {
        // "@Pro" : (active sub to prod_pro) OR (lifetime spend ≥ $500)
        let t = or_groups(vec![
            vec![
                c(T::HasActiveSubscription, ConditionOperator::Eq, json!(true)),
                c(
                    T::SubscribedToProduct,
                    ConditionOperator::Eq,
                    json!("prod_pro"),
                ),
            ],
            vec![c(T::LifetimeSpend, ConditionOperator::Gte, json!(50000))],
        ]);

        let mut f = facts();
        f.has_active_subscription = true;
        f.product_ids = vec!["prod_pro".into()];
        assert!(evaluate(&t, &f));

        let mut f = facts();
        f.lifetime_spend_cents = 60000;
        assert!(evaluate(&t, &f));

        let mut f = facts();
        f.has_active_subscription = true;
        f.product_ids = vec!["prod_basic".into()];
        f.lifetime_spend_cents = 100;
        assert!(!evaluate(&t, &f));
    }
}
