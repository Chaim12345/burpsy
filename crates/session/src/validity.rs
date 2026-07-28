//! The operator-stated rule for what a valid session looks like.
//!
//! SESSION-02 hands this decision to the operator rather than to a heuristic here: a 200 with a
//! login form, a 302 to `/login`, and a 200 body `{"error":"unauthenticated"}` are all failed
//! sessions, and no fixed set of status-code checks recognises all three at once. So this crate
//! does not decide "valid" itself — it evaluates whatever [`ValidityRule`] tree the operator
//! supplies, using three-valued logic (Kleene's strong logic, the same one SQL's `NULL` follows)
//! so that "this rule's condition could not be checked" propagates as its own answer instead of
//! silently collapsing into "valid" or "invalid".

use crate::step::MacroResponse;

/// The result of evaluating a [`ValidityRule`] against a response.
///
/// `Indeterminate` is not `Invalid` wearing a different name: it is what a caller gets back when
/// the rule and the response disagree about what there is to check — e.g. a body-substring rule
/// against a response with no captured body. Treating it as `Valid` would be the fail-open
/// direction this crate exists to refuse; treating it as `Invalid` would silently discard the fact
/// that the rule was never actually able to render a verdict. A caller that needs a coarser yes/no
/// answer has to make that call deliberately, not have this type make it silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionValidity {
    Valid,
    Invalid,
    Indeterminate(String),
}

/// An operator-stated rule for recognising a valid session, composable with `All`/`Any`/`Not`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidityRule {
    /// Matches the response's status code exactly.
    StatusIs(u16),
    /// The response body contains this substring (checked over raw bytes).
    BodyContains(String),
    /// The response body does not contain this substring.
    BodyNotContains(String),
    /// A header with this name is present (case-insensitive), regardless of value.
    HeaderPresent(String),
    /// No header with this name is present (case-insensitive).
    HeaderAbsent(String),
    /// A `Location` header is present and its value contains this substring.
    RedirectsTo(String),
    /// Valid only if every child rule is valid — Kleene AND.
    All(Vec<ValidityRule>),
    /// Valid if any child rule is valid — Kleene OR.
    Any(Vec<ValidityRule>),
    /// Inverts a child rule. `Indeterminate` passes through unchanged: the opposite of "unknown"
    /// is still unknown, not a different kind of known.
    Not(Box<ValidityRule>),
}

impl ValidityRule {
    pub fn evaluate(&self, response: &MacroResponse) -> SessionValidity {
        use SessionValidity::{Indeterminate, Invalid, Valid};
        match self {
            ValidityRule::StatusIs(code) => {
                if response.status == *code {
                    Valid
                } else {
                    Invalid
                }
            }
            ValidityRule::BodyContains(needle) => match &response.body {
                None => Indeterminate(format!(
                    "cannot search for {needle:?}: response carries no captured body"
                )),
                Some(body) => {
                    if contains_subslice(body, needle.as_bytes()) {
                        Valid
                    } else {
                        Invalid
                    }
                }
            },
            ValidityRule::BodyNotContains(needle) => match &response.body {
                None => Indeterminate(format!(
                    "cannot search for {needle:?}: response carries no captured body"
                )),
                Some(body) => {
                    if contains_subslice(body, needle.as_bytes()) {
                        Invalid
                    } else {
                        Valid
                    }
                }
            },
            ValidityRule::HeaderPresent(name) => {
                if find_header(response, name).is_some() {
                    Valid
                } else {
                    Invalid
                }
            }
            ValidityRule::HeaderAbsent(name) => {
                if find_header(response, name).is_some() {
                    Invalid
                } else {
                    Valid
                }
            }
            // Absence of `Location` is a determinate "did not redirect there" — a header either
            // is or is not on the response, unlike a body that might simply not have been
            // captured — so this never returns `Indeterminate`.
            ValidityRule::RedirectsTo(target) => match find_header(response, "location") {
                Some(location) if location.contains(target.as_str()) => Valid,
                _ => Invalid,
            },
            ValidityRule::All(children) => {
                let mut indeterminate_reason = None;
                for child in children {
                    match child.evaluate(response) {
                        Invalid => return Invalid,
                        Indeterminate(reason) => {
                            indeterminate_reason.get_or_insert(reason);
                        }
                        Valid => {}
                    }
                }
                match indeterminate_reason {
                    Some(reason) => Indeterminate(reason),
                    None => Valid,
                }
            }
            ValidityRule::Any(children) => {
                let mut indeterminate_reason = None;
                for child in children {
                    match child.evaluate(response) {
                        Valid => return Valid,
                        Indeterminate(reason) => {
                            indeterminate_reason.get_or_insert(reason);
                        }
                        Invalid => {}
                    }
                }
                match indeterminate_reason {
                    Some(reason) => Indeterminate(reason),
                    None => Invalid,
                }
            }
            ValidityRule::Not(inner) => match inner.evaluate(response) {
                Valid => Invalid,
                Invalid => Valid,
                Indeterminate(reason) => Indeterminate(reason),
            },
        }
    }
}

fn find_header<'a>(response: &'a MacroResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn response(status: u16, headers: &[(&str, &str)], body: Option<&str>) -> MacroResponse {
        MacroResponse {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.map(|b| Bytes::from(b.to_string())),
        }
    }

    #[test]
    fn status_is_matches_only_the_exact_code() {
        let rule = ValidityRule::StatusIs(200);
        assert_eq!(
            rule.evaluate(&response(200, &[], Some(""))),
            SessionValidity::Valid
        );
        assert_eq!(
            rule.evaluate(&response(302, &[], Some(""))),
            SessionValidity::Invalid
        );
    }

    #[test]
    fn body_contains_is_valid_only_when_the_substring_is_present() {
        let rule = ValidityRule::BodyContains("Welcome back".into());
        assert_eq!(
            rule.evaluate(&response(200, &[], Some("Welcome back, alice"))),
            SessionValidity::Valid
        );
        assert_eq!(
            rule.evaluate(&response(200, &[], Some("Please log in"))),
            SessionValidity::Invalid
        );
    }

    #[test]
    fn body_not_contains_is_valid_only_when_the_substring_is_absent() {
        let rule = ValidityRule::BodyNotContains("Please log in".into());
        assert_eq!(
            rule.evaluate(&response(200, &[], Some("Welcome back"))),
            SessionValidity::Valid
        );
        assert_eq!(
            rule.evaluate(&response(200, &[], Some("Please log in"))),
            SessionValidity::Invalid
        );
    }

    #[test]
    fn a_body_rule_against_a_response_with_no_captured_body_is_indeterminate_not_valid() {
        let rule = ValidityRule::BodyContains("Welcome".into());
        let got = rule.evaluate(&response(200, &[], None));
        assert!(
            matches!(got, SessionValidity::Indeterminate(_)),
            "a rule that cannot be checked must not default to Valid (the fail-open direction): \
             got {got:?}"
        );
    }

    #[test]
    fn header_present_is_valid_only_when_the_header_exists_case_insensitively() {
        let rule = ValidityRule::HeaderPresent("X-Auth-Token".into());
        assert_eq!(
            rule.evaluate(&response(200, &[("x-auth-token", "abc")], Some(""))),
            SessionValidity::Valid
        );
        assert_eq!(
            rule.evaluate(&response(200, &[], Some(""))),
            SessionValidity::Invalid
        );
    }

    #[test]
    fn header_absent_is_valid_only_when_the_header_is_missing() {
        let rule = ValidityRule::HeaderAbsent("Set-Cookie".into());
        assert_eq!(
            rule.evaluate(&response(200, &[], Some(""))),
            SessionValidity::Valid
        );
        assert_eq!(
            rule.evaluate(&response(200, &[("Set-Cookie", "a=b")], Some(""))),
            SessionValidity::Invalid
        );
    }

    #[test]
    fn redirects_to_is_valid_only_when_location_contains_the_target() {
        let rule = ValidityRule::RedirectsTo("/login".into());
        assert_eq!(
            rule.evaluate(&response(
                302,
                &[("Location", "/login?reason=timeout")],
                Some("")
            )),
            SessionValidity::Valid
        );
        assert_eq!(
            rule.evaluate(&response(302, &[("Location", "/dashboard")], Some(""))),
            SessionValidity::Invalid
        );
        assert_eq!(
            rule.evaluate(&response(200, &[], Some(""))),
            SessionValidity::Invalid,
            "no Location header is a determinate 'did not redirect there', not Indeterminate"
        );
    }

    #[test]
    fn all_is_valid_only_when_every_child_is_valid() {
        let rule = ValidityRule::All(vec![
            ValidityRule::StatusIs(200),
            ValidityRule::BodyContains("ok".into()),
        ]);
        assert_eq!(
            rule.evaluate(&response(200, &[], Some("ok"))),
            SessionValidity::Valid
        );
        assert_eq!(
            rule.evaluate(&response(200, &[], Some("nope"))),
            SessionValidity::Invalid
        );
        assert_eq!(
            rule.evaluate(&response(500, &[], Some("ok"))),
            SessionValidity::Invalid
        );
    }

    #[test]
    fn all_short_circuits_to_invalid_even_when_another_child_is_indeterminate() {
        // A definite "no" from one child outweighs "could not check" from another: AND with a
        // known false is false in three-valued logic exactly as it is in two-valued logic.
        let rule = ValidityRule::All(vec![
            ValidityRule::StatusIs(500),
            ValidityRule::BodyContains("ok".into()),
        ]);
        assert_eq!(
            rule.evaluate(&response(200, &[], None)),
            SessionValidity::Invalid
        );
    }

    #[test]
    fn all_is_indeterminate_when_nothing_is_invalid_but_one_child_could_not_be_checked() {
        let rule = ValidityRule::All(vec![
            ValidityRule::StatusIs(200),
            ValidityRule::BodyContains("ok".into()),
        ]);
        let got = rule.evaluate(&response(200, &[], None));
        assert!(
            matches!(got, SessionValidity::Indeterminate(_)),
            "got {got:?}"
        );
    }

    #[test]
    fn any_is_valid_when_one_child_is_valid_even_if_another_is_indeterminate() {
        let rule = ValidityRule::Any(vec![
            ValidityRule::StatusIs(200),
            ValidityRule::BodyContains("ok".into()),
        ]);
        assert_eq!(
            rule.evaluate(&response(200, &[], None)),
            SessionValidity::Valid
        );
    }

    #[test]
    fn any_is_invalid_only_when_every_child_is_invalid() {
        let rule = ValidityRule::Any(vec![
            ValidityRule::StatusIs(500),
            ValidityRule::HeaderPresent("X".into()),
        ]);
        assert_eq!(
            rule.evaluate(&response(200, &[], Some(""))),
            SessionValidity::Invalid
        );
    }

    #[test]
    fn not_inverts_valid_and_invalid_but_leaves_indeterminate_unchanged() {
        let rule = ValidityRule::Not(Box::new(ValidityRule::StatusIs(200)));
        assert_eq!(
            rule.evaluate(&response(200, &[], Some(""))),
            SessionValidity::Invalid
        );
        assert_eq!(
            rule.evaluate(&response(500, &[], Some(""))),
            SessionValidity::Valid
        );

        let indeterminate_rule =
            ValidityRule::Not(Box::new(ValidityRule::BodyContains("x".into())));
        assert!(matches!(
            indeterminate_rule.evaluate(&response(200, &[], None)),
            SessionValidity::Indeterminate(_)
        ));
    }
}
