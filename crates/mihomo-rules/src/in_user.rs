//! IN-USER rule — matches on the authenticated inbound username (`Metadata.in_user`).
//!
//! `Metadata.in_user` is populated by the inbound auth layer (M1.F-3). Until
//! F-3 lands the field is always empty, so this rule never matches — consistent
//! with the "no auth configured → IN-USER is always absent" semantic.
//!
//! upstream: `rules/common/inbound.go`

use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};

pub struct InUserRule {
    username: String,
    adapter: String,
}

impl InUserRule {
    pub fn new(username: &str, adapter: &str) -> Result<Self, String> {
        Ok(Self {
            username: username.to_string(),
            adapter: adapter.to_string(),
        })
    }
}

impl Rule for InUserRule {
    fn rule_type(&self) -> RuleType {
        RuleType::InUser
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        !metadata.in_user.is_empty() && metadata.in_user == self.username
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.username
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mihomo_common::{Metadata, RuleMatchHelper};

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_with_user(in_user: &str) -> Metadata {
        Metadata {
            in_user: in_user.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn in_user_matches_when_populated() {
        let r = InUserRule::new("alice", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_with_user("alice"), &helper()));
    }

    #[test]
    fn in_user_no_match_different_user() {
        let r = InUserRule::new("alice", "DIRECT").unwrap();
        assert!(!r.match_metadata(&meta_with_user("bob"), &helper()));
    }

    #[test]
    fn in_user_empty_never_matches() {
        // F-3 not yet landed: in_user is always empty → IN-USER never matches.
        // upstream: rules/common/inbound.go (populated only after auth)
        let r = InUserRule::new("alice", "DIRECT").unwrap();
        assert!(!r.match_metadata(&meta_with_user(""), &helper()));
    }
}
