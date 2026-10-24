//! Resolving a category for one event, from an account's rules.
//!
//! [`Resolver::build`] indexes the caller's full rule list once;
//! [`Resolver::category_for`] is then one lookup per event. Built this
//! way rather than re-scanning the rule list for every event: an
//! account can hold up to [`super::store::MAX_RULES_PER_USER`] rules
//! and `GET /api/v1/events` can return up to
//! [`crate::events::query::MAX_ROWS`] rows, so the naive version would
//! do their *product* in string comparisons rather than their sum.

use std::cmp::Reverse;
use std::collections::HashMap;

use super::kind::RuleKind;
use super::store::CategoryRuleRecord;

/// An account's rules, indexed for repeated lookups against borrowed
/// data - nothing here is cloned out of the rule list it was built
/// from.
pub struct Resolver<'a> {
    by_app_id: HashMap<&'a str, &'a str>,
    /// Domain rules, longest pattern first. The `UNIQUE (user_id,
    /// kind, pattern)` constraint means no two rules share a pattern,
    /// so this order alone is enough to make the first match found in
    /// [`Resolver::category_for`] the most specific one - no need to
    /// keep walking after it.
    by_domain: Vec<(&'a str, &'a str)>,
}

impl<'a> Resolver<'a> {
    pub fn build(rules: &'a [CategoryRuleRecord]) -> Self {
        let mut by_app_id = HashMap::new();
        let mut by_domain = Vec::new();

        for rule in rules {
            match rule.kind {
                RuleKind::AppId => {
                    by_app_id.insert(rule.pattern.as_str(), rule.category.as_str());
                }
                RuleKind::Domain => {
                    by_domain.push((rule.pattern.as_str(), rule.category.as_str()));
                }
            }
        }
        by_domain.sort_unstable_by_key(|(pattern, _)| Reverse(pattern.len()));

        Self {
            by_app_id,
            by_domain,
        }
    }

    /// The category for one event, or `None` if no rule matches.
    ///
    /// An `app_id` match always wins over a `domain` match - see
    /// `crate::categories`'s module doc for why.
    pub fn category_for(&self, app_id: &str, domain: Option<&str>) -> Option<&'a str> {
        if let Some(category) = self.by_app_id.get(app_id).copied() {
            return Some(category);
        }

        let domain = domain?;
        self.by_domain
            .iter()
            .find(|(pattern, _)| matches_domain(domain, pattern))
            .map(|(_, category)| *category)
    }
}

/// Whether `domain` is `pattern` itself, or one of its subdomains.
///
/// The boundary checked is a literal `.`, not a bare
/// [`str::ends_with`] on `pattern`: without that boundary check, a
/// rule on `google.com` would also match `notgoogle.com`, which
/// shares no actual boundary with it.
fn matches_domain(domain: &str, pattern: &str) -> bool {
    domain == pattern
        || (domain.len() > pattern.len()
            && domain.ends_with(pattern)
            && domain.as_bytes()[domain.len() - pattern.len() - 1] == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::time::UnixTime;

    fn rule(kind: RuleKind, pattern: &str, category: &str) -> CategoryRuleRecord {
        CategoryRuleRecord {
            id: format!("r-{pattern}"),
            user_id: "u1".to_owned(),
            kind,
            pattern: pattern.to_owned(),
            category: category.to_owned(),
            created_at: UnixTime::from_secs(0),
        }
    }

    #[test]
    fn an_app_id_rule_matches_exactly() {
        let rules = vec![rule(RuleKind::AppId, "org.example.app", "Study")];
        let resolver = Resolver::build(&rules);

        assert_eq!(
            resolver.category_for("org.example.app", None),
            Some("Study")
        );
        assert_eq!(resolver.category_for("org.example.other", None), None);
    }

    #[test]
    fn an_app_id_rule_is_case_sensitive() {
        let rules = vec![rule(RuleKind::AppId, "org.example.app", "Study")];
        let resolver = Resolver::build(&rules);

        assert_eq!(resolver.category_for("ORG.EXAMPLE.APP", None), None);
    }

    #[test]
    fn a_domain_rule_matches_the_exact_domain() {
        let rules = vec![rule(RuleKind::Domain, "example.com", "Browsing")];
        let resolver = Resolver::build(&rules);

        assert_eq!(
            resolver.category_for("org.example.browser", Some("example.com")),
            Some("Browsing")
        );
    }

    #[test]
    fn a_domain_rule_matches_its_subdomains() {
        let rules = vec![rule(RuleKind::Domain, "google.com", "Search")];
        let resolver = Resolver::build(&rules);

        assert_eq!(
            resolver.category_for("app", Some("mail.google.com")),
            Some("Search")
        );
        assert_eq!(
            resolver.category_for("app", Some("deeply.nested.google.com")),
            Some("Search")
        );
    }

    /// The boundary has to be a `.`, or `notgoogle.com` would match a
    /// rule on `google.com` through a bare `ends_with`.
    #[test]
    fn a_domain_rule_does_not_match_an_unrelated_suffix() {
        let rules = vec![rule(RuleKind::Domain, "google.com", "Search")];
        let resolver = Resolver::build(&rules);

        assert_eq!(resolver.category_for("app", Some("notgoogle.com")), None);
        assert_eq!(resolver.category_for("app", Some("evilgoogle.com")), None);
    }

    #[test]
    fn the_longest_matching_domain_pattern_wins() {
        let rules = vec![
            rule(RuleKind::Domain, "google.com", "Search"),
            rule(RuleKind::Domain, "mail.google.com", "Email"),
        ];
        let resolver = Resolver::build(&rules);

        assert_eq!(
            resolver.category_for("app", Some("mail.google.com")),
            Some("Email"),
            "the more specific rule must win"
        );
        assert_eq!(
            resolver.category_for("app", Some("docs.google.com")),
            Some("Search"),
            "a sibling subdomain still falls back to the wider rule"
        );
    }

    #[test]
    fn an_app_id_match_beats_any_domain_match() {
        let rules = vec![
            rule(RuleKind::Domain, "example.com", "Browsing"),
            rule(RuleKind::AppId, "org.example.browser", "Study"),
        ];
        let resolver = Resolver::build(&rules);

        assert_eq!(
            resolver.category_for("org.example.browser", Some("example.com")),
            Some("Study"),
            "the app_id rule must win over the domain rule"
        );
    }

    #[test]
    fn no_match_is_none_not_a_sentinel() {
        let rules = vec![rule(RuleKind::AppId, "org.example.app", "Study")];
        let resolver = Resolver::build(&rules);

        assert_eq!(
            resolver.category_for("org.example.other", Some("unrelated.example")),
            None
        );
    }

    #[test]
    fn an_event_with_no_domain_can_still_match_by_app_id() {
        let rules = vec![rule(RuleKind::AppId, "org.example.app", "Study")];
        let resolver = Resolver::build(&rules);

        assert_eq!(
            resolver.category_for("org.example.app", None),
            Some("Study")
        );
    }
}
