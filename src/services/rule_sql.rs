//! SQL WHERE-clause builder for bulk per-role-link sync.
//!
//! Pushes the same DNF semantics as [services::condition_eval::evaluate] down
//! into Postgres so `sync_for_role_link` filters server-side instead of loading
//! every member's facts into memory (Convention 6 / 8).
//!
//! The clause references a single alias the caller must provide:
//!   * `mf` — stripe_member_facts (one row per (account, discord_id))
//!
//! NULL-handling matches the Rust evaluator's fail-closed behavior: a NULL
//! nullable column (e.g. an unset country, or a derived age over a NULL
//! timestamp) fails an int/scalar comparison and only satisfies string `neq`.

use crate::models::condition::{Condition, ConditionOperator, ConditionTarget, TargetKind};
use crate::models::rule::RuleTree;

#[derive(Debug, Clone)]
pub enum Bind {
    Bool(bool),
    Int(i64),
    Text(String),
    TextArray(Vec<String>),
}

/// Returns ("clause", binds). Binds use parameter indices starting at
/// `bind_offset + 1`. Convention 42: `grant_on_any_relation = false` AND no
/// groups ⇒ "FALSE" (match nobody). `grant_on_any_relation = true` ⇒ "TRUE".
pub fn build_rule_where(tree: &RuleTree, bind_offset: usize) -> (String, Vec<Bind>) {
    if tree.grant_on_any_relation {
        return ("TRUE".to_string(), vec![]);
    }
    if tree.groups.is_empty() {
        return ("FALSE".to_string(), vec![]);
    }

    let mut binds: Vec<Bind> = Vec::new();
    let mut group_clauses: Vec<String> = Vec::new();

    for group in &tree.groups {
        if group.conditions.is_empty() {
            group_clauses.push("FALSE".to_string());
            continue;
        }
        let mut cond_clauses: Vec<String> = Vec::new();
        for c in &group.conditions {
            cond_clauses.push(build_condition(c, bind_offset, &mut binds));
        }
        group_clauses.push(format!("({})", cond_clauses.join(" AND ")));
    }

    (format!("({})", group_clauses.join(" OR ")), binds)
}

/// SQL expression for a target, over the `mf` alias.
fn target_expr(target: ConditionTarget) -> &'static str {
    use ConditionTarget::*;
    match target {
        HasActiveSubscription => "mf.has_active_subscription",
        SubscriptionStatus => "mf.subscription_status",
        IsTrialing => "mf.is_trialing",
        IsPastDue => "mf.is_past_due",
        CancelsAtPeriodEnd => "mf.cancels_at_period_end",
        ActiveSubscriptionCount => "mf.active_subscription_count",
        SubscribedToProduct => "mf.product_ids",
        SubscribedToPrice => "mf.price_ids",
        PlanAmount => "mf.plan_amount_cents",
        BillingInterval => "mf.billing_interval",
        SubscriptionAgeDays => {
            "FLOOR(EXTRACT(EPOCH FROM (now() - mf.subscription_started_at)) / 86400)"
        }
        DaysUntilRenewal => "FLOOR(EXTRACT(EPOCH FROM (mf.current_period_end - now())) / 86400)",
        TotalMrr => "mf.total_mrr_cents",
        IsCustomer => "mf.is_customer",
        CustomerAgeDays => "FLOOR(EXTRACT(EPOCH FROM (now() - mf.customer_created_at)) / 86400)",
        IsDelinquent => "mf.is_delinquent",
        LifetimeSpend => "mf.lifetime_spend_cents",
        SuccessfulPayments => "mf.successful_payments",
        CountryCode => "mf.country_code",
        Currency => "mf.currency",
        EmailDomain => "mf.email_domain",
    }
}

fn build_condition(c: &Condition, bind_offset: usize, binds: &mut Vec<Bind>) -> String {
    let expr = target_expr(c.target);

    // StringList (text[]) targets use array set-membership operators.
    if c.target.kind() == TargetKind::StringList {
        return build_stringlist_condition(c, expr, bind_offset, binds);
    }

    use ConditionOperator::*;
    let next = |binds: &Vec<Bind>| bind_offset + binds.len() + 1;

    match c.operator {
        Eq => {
            if let Some(b) = c.value.as_bool() {
                let i = next(binds);
                binds.push(Bind::Bool(b));
                format!("{expr} = ${i}")
            } else if let Some(n) = c.value.as_i64() {
                let i = next(binds);
                binds.push(Bind::Int(n));
                format!("{expr} = ${i}")
            } else {
                let i = next(binds);
                binds.push(Bind::Text(c.value.as_str().unwrap_or("").to_string()));
                format!("{expr} = ${i}")
            }
        }
        Neq => {
            if let Some(n) = c.value.as_i64() {
                let i = next(binds);
                binds.push(Bind::Int(n));
                format!("{expr} <> ${i}")
            } else {
                let i = next(binds);
                binds.push(Bind::Text(c.value.as_str().unwrap_or("").to_string()));
                // IS DISTINCT FROM so NULL string (unset) DOES match `neq` —
                // matches the Rust evaluator's string behavior.
                format!("{expr} IS DISTINCT FROM ${i}")
            }
        }
        Gt | Gte | Lt | Lte => {
            let n = c.value.as_i64().unwrap_or(0);
            let i = next(binds);
            binds.push(Bind::Int(n));
            let op = match c.operator {
                Gt => ">",
                Gte => ">=",
                Lt => "<",
                Lte => "<=",
                _ => unreachable!(),
            };
            format!("({expr}) {op} ${i}")
        }
        Between => {
            let lo = c.value.as_i64().unwrap_or(0);
            let hi = c.value_end.as_ref().and_then(|v| v.as_i64()).unwrap_or(lo);
            let ia = next(binds);
            binds.push(Bind::Int(lo));
            let ib = next(binds);
            binds.push(Bind::Int(hi));
            format!("(({expr}) >= ${ia} AND ({expr}) <= ${ib})")
        }
        Contains => {
            let v = c.value.as_str().unwrap_or("");
            let i = next(binds);
            binds.push(Bind::Text(format!("%{}%", escape_like(v))));
            format!("{expr} LIKE ${i}")
        }
        Regex => {
            let v = c.value.as_str().unwrap_or("");
            let i = next(binds);
            binds.push(Bind::Text(v.to_string()));
            format!("{expr} ~ ${i}")
        }
        In => {
            let arr = str_array(c);
            if arr.is_empty() {
                return "FALSE".to_string();
            }
            let i = next(binds);
            binds.push(Bind::TextArray(arr));
            format!("{expr} = ANY(${i}::text[])")
        }
        NotIn => {
            let arr = str_array(c);
            if arr.is_empty() {
                return "TRUE".to_string();
            }
            let i = next(binds);
            binds.push(Bind::TextArray(arr));
            format!("({expr} IS NOT NULL AND {expr} <> ALL(${i}::text[]))")
        }
    }
}

/// Array set-membership predicates for `text[]` targets.
fn build_stringlist_condition(
    c: &Condition,
    expr: &str,
    bind_offset: usize,
    binds: &mut Vec<Bind>,
) -> String {
    let next = |binds: &Vec<Bind>| bind_offset + binds.len() + 1;
    match c.operator {
        ConditionOperator::Eq => {
            let v = c.value.as_str().unwrap_or("").to_string();
            let i = next(binds);
            binds.push(Bind::Text(v));
            // membership of one value in the set
            format!("${i} = ANY({expr})")
        }
        ConditionOperator::In => {
            let arr = str_array(c);
            if arr.is_empty() {
                return "FALSE".to_string();
            }
            let i = next(binds);
            binds.push(Bind::TextArray(arr));
            format!("({expr} && ${i}::text[])")
        }
        ConditionOperator::NotIn => {
            let arr = str_array(c);
            if arr.is_empty() {
                return "TRUE".to_string();
            }
            let i = next(binds);
            binds.push(Bind::TextArray(arr));
            format!("(NOT ({expr} && ${i}::text[]))")
        }
        // valid_for() rejects any other operator for StringList at save time.
        _ => "FALSE".to_string(),
    }
}

fn str_array(c: &Condition) -> Vec<String> {
    c.value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::condition::{Condition, ConditionOperator as Op, ConditionTarget as T};
    use crate::models::rule::{ConditionGroup, RuleTree};
    use serde_json::json;

    fn cond(t: T, op: Op, v: serde_json::Value) -> Condition {
        Condition {
            target: t,
            operator: op,
            value: v,
            value_end: None,
        }
    }

    fn one(c: Condition) -> RuleTree {
        RuleTree {
            grant_on_any_relation: false,
            groups: vec![ConditionGroup {
                conditions: vec![c],
            }],
        }
    }

    #[test]
    fn grant_on_any_is_true() {
        let t = RuleTree {
            grant_on_any_relation: true,
            groups: vec![],
        };
        let (sql, binds) = build_rule_where(&t, 2);
        assert_eq!(sql, "TRUE");
        assert!(binds.is_empty());
    }

    #[test]
    fn convention_42_empty_is_false() {
        let (sql, _) = build_rule_where(&RuleTree::default(), 2);
        assert_eq!(sql, "FALSE");
    }

    #[test]
    fn active_bool_eq() {
        let (sql, binds) =
            build_rule_where(&one(cond(T::HasActiveSubscription, Op::Eq, json!(true))), 2);
        assert!(sql.contains("mf.has_active_subscription = $3"));
        assert!(matches!(binds[0], Bind::Bool(true)));
    }

    #[test]
    fn plan_amount_gte() {
        let (sql, binds) = build_rule_where(&one(cond(T::PlanAmount, Op::Gte, json!(1000))), 0);
        assert!(sql.contains(">= $1"));
        assert!(matches!(binds[0], Bind::Int(1000)));
    }

    #[test]
    fn product_eq_uses_any() {
        let (sql, binds) = build_rule_where(
            &one(cond(T::SubscribedToProduct, Op::Eq, json!("prod_x"))),
            2,
        );
        assert!(sql.contains("$3 = ANY(mf.product_ids)"));
        assert!(matches!(&binds[0], Bind::Text(s) if s == "prod_x"));
    }

    #[test]
    fn price_in_uses_overlap() {
        let (sql, binds) = build_rule_where(
            &one(cond(
                T::SubscribedToPrice,
                Op::In,
                json!(["price_a", "price_b"]),
            )),
            2,
        );
        assert!(sql.contains("mf.price_ids && $3::text[]"));
        assert!(matches!(&binds[0], Bind::TextArray(v) if v.len() == 2));
    }

    #[test]
    fn product_not_in_negated_overlap() {
        let (sql, _) = build_rule_where(
            &one(cond(
                T::SubscribedToProduct,
                Op::NotIn,
                json!(["prod_free"]),
            )),
            2,
        );
        assert!(sql.contains("NOT (mf.product_ids && $3::text[])"));
    }

    #[test]
    fn status_neq_is_distinct_from() {
        let (sql, _) = build_rule_where(
            &one(cond(T::SubscriptionStatus, Op::Neq, json!("canceled"))),
            0,
        );
        assert!(sql.contains("IS DISTINCT FROM"));
    }

    #[test]
    fn sub_age_uses_epoch_expr() {
        let (sql, _) = build_rule_where(&one(cond(T::SubscriptionAgeDays, Op::Gte, json!(30))), 0);
        assert!(sql.contains("EXTRACT(EPOCH FROM (now() - mf.subscription_started_at))"));
    }

    #[test]
    fn between_two_binds() {
        let mut c = cond(T::LifetimeSpend, Op::Between, json!(1000));
        c.value_end = Some(json!(5000));
        let (sql, binds) = build_rule_where(&one(c), 0);
        assert!(sql.contains(">= $1") && sql.contains("<= $2"));
        assert_eq!(binds.len(), 2);
    }
}
