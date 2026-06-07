//! The rule tree: OR of AND-groups (DNF).
//!
//! Stored verbatim as the JSONB `rule_tree` column on `role_links`. Two-level
//! structure keeps validation, SQL translation, and the iframe rule-builder UI
//! simple while still expressing every boolean rule (any boolean expression has
//! a DNF form).
//!
//! Convention 42 invariant: an unconfigured role link grants the role to
//! nobody. `grant_on_any_relation = false` AND `groups.is_empty()` means "match
//! nobody" — both [services::condition_eval::evaluate] and the SQL builder
//! enforce this BEFORE inspecting groups.
//!
//! `grant_on_any_relation = true` means "grant to any customer of the connected
//! Stripe account" (anyone we have a member-facts row for), regardless of
//! subscription status.

use serde::{Deserialize, Serialize};

use crate::models::condition::Condition;

/// Maximum top-level OR-groups.
pub const MAX_GROUPS: usize = 8;
/// Maximum conditions per group.
pub const MAX_CONDITIONS_PER_GROUP: usize = 12;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleTree {
    #[serde(default)]
    pub grant_on_any_relation: bool,
    #[serde(default)]
    pub groups: Vec<ConditionGroup>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConditionGroup {
    #[serde(default)]
    pub conditions: Vec<Condition>,
}
