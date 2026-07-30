//! The rule model: a *list* of named, independently-scoped session-handling rules, each owning its
//! own macro, validity rule and retry bound.
//!
//! # Why a list, and why each rule carries its own scope
//!
//! One always-on macro is only correct for an engagement with one login. A real one has several —
//! an admin account and a user account on the same host, a staging host with a different form, an
//! API subdomain that authenticates with a bearer token instead of a cookie — and "which login
//! applies here" is a property of the *target*, not of the tool. Burp answers this with a list of
//! per-scope session-handling rules, and so does this: [`SessionRuleSpec::scope`] is an optional
//! [`Scope`], and the coordinator picks the first enabled rule whose scope covers the request in
//! question.
//!
//! That scope is a **selector, not an authorisation**. Nothing here decides what may be sent — that
//! stays with `burpsy_sender::AuthorisedSender` and the engagement-wide `Scope` behind it (HARD-03),
//! and a rule whose scope is wider than the engagement's still cannot send anything the chokepoint
//! refuses. What the per-rule scope decides is only *which recorded login* a target belongs to.
//!
//! # One matching rule, not every matching rule
//!
//! Burp runs the actions of *every* session-handling rule whose scope matches, in list order. That
//! composes because most of its actions are additive (add a cookie, add a header). The action this
//! crate implements is not: running two recorded logins because two rules both claim a host means two
//! logins against a live target for one observed session drop, which is exactly the "piling on"
//! [`crate::ReloginCoordinator`] exists to prevent — and the second macro would overwrite the session
//! the first one just established, so the answer would depend on list order anyway. So the first
//! enabled rule whose scope matches handles the request and the rest are not consulted. Two rules
//! that both claim a target is an ambiguity for the operator to settle by ordering them, and ordering
//! is preserved across edits for exactly that reason (see
//! [`crate::ReloginCoordinator::replace_rule`]).
//!
//! An empty scope is refused rather than accepted, the same way
//! `burpsy_tools::matchreplace::Rule::new` refuses one: a `Scope` with no rules matches nothing, so
//! the rule would silently never fire. Omitting `scope` is how a rule says "everywhere"; stating an
//! empty one is a mistake worth naming at configuration time.
//!
//! # Inert spec, validated rule
//!
//! [`SessionRuleSpec`] is the serialisable, inert form — holding one proves nothing has been
//! checked. [`SessionRule::new`] is the only way to a runnable rule, and it is where every operator
//! mistake this crate can catch without a network gets caught: an unnamed rule, an empty scope, a
//! `max_attempts` of zero, a macro with no steps, a step with no method or no host in its URL, an
//! extraction whose pattern does not compile, two extractions with the same name, and a step
//! referring to `{{a_value}}` that no earlier step produces. Every one of those would otherwise
//! surface mid-login as "the button did nothing".

use crate::extract::{CompiledExtraction, Extraction, placeholders};
use crate::step::MacroStep;
use crate::target::target_of;
use crate::validity::ValidityRule;
use burpsy_core::Scope;

/// Three total attempts: enough to absorb one transient failure (a redirect race, a target that
/// needed a moment to recover) without turning a genuinely dead credential into a long stall
/// against a live target. SESSION-04 asks the operator to state the limit, so a rule carries it
/// explicitly; this is offered as a sane default for a caller to pass, not a hidden ceiling this
/// crate falls back to on its own.
pub const DEFAULT_MAX_LOGIN_ATTEMPTS: u32 = 3;

/// One step of a macro: the request to send, and what to scrape out of its response.
///
/// The extractions live beside the step rather than inside [`MacroStep`] because `MacroStep` is also
/// the type of the request being *repaired* and of the probe a `/login` call hands in — neither of
/// which has anything to extract. Keeping the wire-shaped request free of macro-authoring concerns
/// means `MacroSender` implementations, and every caller that builds a plain request, are unaffected
/// by this feature existing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroItem {
    pub step: MacroStep,
    /// Values to lift out of this step's response, for `{{name}}` in a *later* step. Empty is the
    /// common case.
    pub extract: Vec<Extraction>,
}

impl MacroItem {
    pub fn new(step: MacroStep) -> Self {
        Self {
            step,
            extract: Vec::new(),
        }
    }

    pub fn extracting(mut self, e: Extraction) -> Self {
        self.extract.push(e);
        self
    }
}

/// A recorded sequence of steps that ends, if it works, with an authenticated session.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Macro {
    pub items: Vec<MacroItem>,
}

impl Macro {
    /// A macro that extracts nothing — the shape everything in this crate had before custom
    /// parameter extraction existed.
    pub fn of_steps(steps: Vec<MacroStep>) -> Self {
        Self {
            items: steps.into_iter().map(MacroItem::new).collect(),
        }
    }

    pub fn steps(&self) -> impl Iterator<Item = &MacroStep> {
        self.items.iter().map(|i| &i.step)
    }
}

/// The inert, serialisable form of a session-handling rule.
///
/// This type is *inert*: holding one proves nothing has been validated. Turn it into a
/// [`SessionRule`] to get something that can run.
#[derive(Debug, Clone)]
pub struct SessionRuleSpec {
    /// The operator's label for this rule. Required, because every error and every outcome this
    /// crate reports names the rule it came from, and "rule 3" is not a name.
    pub name: String,
    pub enabled: bool,
    /// Apply only to requests whose host, port, path and scheme match. `None` applies everywhere.
    pub scope: Option<Scope>,
    pub login_macro: Macro,
    /// What this rule considers a valid session — see [`ValidityRule`].
    pub validity: ValidityRule,
    /// How many times the macro itself may run before the rule gives up.
    pub max_attempts: u32,
}

impl SessionRuleSpec {
    /// A rule that applies everywhere, enabled, with the default retry bound.
    pub fn new(name: impl Into<String>, login_macro: Macro, validity: ValidityRule) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            scope: None,
            login_macro,
            validity,
            max_attempts: DEFAULT_MAX_LOGIN_ATTEMPTS,
        }
    }

    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.scope = Some(scope);
        self
    }

    pub fn with_max_attempts(mut self, n: u32) -> Self {
        self.max_attempts = n;
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// Why a rule was refused. Named after the rule so a rejected list says which entry to fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    /// The rule's name, or `"<unnamed>"` when that is what was wrong with it.
    pub rule: String,
    pub message: String,
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session rule {:?}: {}", self.rule, self.message)
    }
}

impl std::error::Error for RuleError {}

/// One validated macro step: the request, and its compiled extractions.
#[derive(Debug, Clone)]
pub(crate) struct CompiledItem {
    pub(crate) step: MacroStep,
    pub(crate) extract: Vec<CompiledExtraction>,
}

/// A validated, runnable session-handling rule. Construction is the only way in, and construction
/// validates.
#[derive(Debug, Clone)]
pub struct SessionRule {
    name: String,
    enabled: bool,
    scope: Option<Scope>,
    items: Vec<CompiledItem>,
    validity: ValidityRule,
    max_attempts: u32,
}

impl SessionRule {
    /// Validate a spec. Every mistake this crate can catch without a network is caught here — see
    /// the module docs for the list and why.
    pub fn new(spec: SessionRuleSpec) -> Result<Self, RuleError> {
        let label = if spec.name.trim().is_empty() {
            "<unnamed>".to_string()
        } else {
            spec.name.trim().to_string()
        };
        let err = |m: String| RuleError {
            rule: label.clone(),
            message: m,
        };

        if spec.name.trim().is_empty() {
            return Err(err(
                "a rule needs a name: every outcome and error this crate reports names its rule"
                    .to_string(),
            ));
        }
        // A scope with no rules matches nothing, so this rule would silently never fire. That is a
        // configuration mistake worth refusing rather than a rule that quietly does nothing — the
        // check `burpsy_tools::matchreplace::Rule::new` makes, for the same reason.
        if let Some(s) = &spec.scope
            && s.is_empty()
        {
            return Err(err(
                "the scope has no rules, so it matches nothing and this rule would never fire; \
                 omit `scope` to apply everywhere"
                    .to_string(),
            ));
        }
        if spec.max_attempts == 0 {
            return Err(err(format!(
                "max_attempts must be at least 1, or the macro can never run; \
                 {DEFAULT_MAX_LOGIN_ATTEMPTS} is the default"
            )));
        }
        if spec.login_macro.items.is_empty() {
            return Err(err(
                "the login macro has no steps, so there is nothing to run".to_string(),
            ));
        }

        let mut defined: Vec<String> = Vec::new();
        let mut items = Vec::with_capacity(spec.login_macro.items.len());
        for (index, item) in spec.login_macro.items.into_iter().enumerate() {
            if item.step.method.trim().is_empty() {
                return Err(err(format!("step {index} has an empty method")));
            }
            // Refused here rather than left to surface as a confusing send failure: a URL with no
            // readable host cannot be keyed in the cookie jar and cannot be matched against a scope,
            // so this rule could never do its job for it.
            if target_of(&item.step.url).is_none() {
                return Err(err(format!(
                    "step {index} has no host in its url {:?}; a macro step needs a full \
                     scheme://host[:port]/path",
                    item.step.url
                )));
            }
            // A reference must be produced by an *earlier* step: resolution happens immediately
            // before a step is sent, so a value extracted from this step's own response, or from a
            // later one, does not exist yet.
            for name in placeholders(&item.step) {
                if !defined.contains(&name) {
                    return Err(err(format!(
                        "step {index} refers to {{{{{name}}}}}, which no earlier step extracts"
                    )));
                }
            }
            let mut extract = Vec::with_capacity(item.extract.len());
            for extraction in item.extract {
                let compiled = CompiledExtraction::new(extraction)
                    .map_err(|m| err(format!("step {index}: {m}")))?;
                // Two extractions with the same name would mean the later one silently wins, and
                // which value a `{{name}}` carries would depend on step order nobody stated.
                if defined.iter().any(|d| d == compiled.name()) {
                    return Err(err(format!(
                        "step {index} extracts {:?}, which an earlier step already extracts",
                        compiled.name()
                    )));
                }
                defined.push(compiled.name().to_string());
                extract.push(compiled);
            }
            items.push(CompiledItem {
                step: item.step,
                extract,
            });
        }

        Ok(Self {
            name: label,
            enabled: spec.enabled,
            scope: spec.scope,
            items,
            validity: spec.validity,
            max_attempts: spec.max_attempts,
        })
    }

    /// The spec this rule was built from, rebuilt from what it actually holds rather than kept
    /// alongside it — so a reader of the spec can never see it disagree with what will run. This is
    /// what a caller reads a rule back through.
    pub fn spec(&self) -> SessionRuleSpec {
        SessionRuleSpec {
            name: self.name.clone(),
            enabled: self.enabled,
            scope: self.scope.clone(),
            login_macro: Macro {
                items: self
                    .items
                    .iter()
                    .map(|i| MacroItem {
                        step: i.step.clone(),
                        extract: i.extract.iter().map(|e| e.spec().clone()).collect(),
                    })
                    .collect(),
            },
            validity: self.validity.clone(),
            max_attempts: self.max_attempts,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn scope(&self) -> Option<&Scope> {
        self.scope.as_ref()
    }

    pub fn validity(&self) -> &ValidityRule {
        &self.validity
    }

    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Does this rule handle sessions for `url`?
    ///
    /// A disabled rule handles nothing. A rule with no scope handles everything, including a URL
    /// this crate cannot parse — that is what "applies everywhere" means. A *scoped* rule cannot
    /// match a URL whose host it cannot read: a scope decision about an unreadable target would be
    /// a guess, and guessing in the permissive direction is the one this crate refuses.
    pub fn applies_to(&self, url: &str) -> bool {
        if !self.enabled {
            return false;
        }
        match &self.scope {
            None => true,
            Some(scope) => {
                target_of(url).is_some_and(|t| scope.contains(t.host, t.port, t.path, t.tls))
            }
        }
    }

    pub(crate) fn items(&self) -> &[CompiledItem] {
        &self.items
    }

    /// The same rule with its macro's requests replaced, keeping each step's extractions.
    ///
    /// This is "update macro": everything about the rule except the recorded requests survives, and
    /// the replacement goes back through [`Self::new`] rather than being written in behind
    /// validation's back. Extractions are matched to steps by position, so a replacement with a
    /// different number of steps is refused — silently dropping the extractions of a step that no
    /// longer exists is how a macro comes back "working" and unable to log in.
    pub(crate) fn with_steps(&self, steps: Vec<MacroStep>) -> Result<Self, RuleError> {
        if steps.len() != self.items.len() {
            return Err(RuleError {
                rule: self.name.clone(),
                message: format!(
                    "cannot replace {} recorded step(s) with {}: extractions belong to a step by \
                     position",
                    self.items.len(),
                    steps.len()
                ),
            });
        }
        let mut spec = self.spec();
        for (item, step) in spec.login_macro.items.iter_mut().zip(steps) {
            item.step = step;
        }
        Self::new(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::ScopeRule;
    use bytes::Bytes;

    fn step(url: &str) -> MacroStep {
        MacroStep {
            method: "GET".to_string(),
            url: url.to_string(),
            headers: vec![],
            body: Bytes::new(),
        }
    }

    fn spec() -> SessionRuleSpec {
        SessionRuleSpec::new(
            "admin login",
            Macro::of_steps(vec![step("https://target.test/login")]),
            ValidityRule::StatusIs(200),
        )
    }

    #[test]
    fn a_rule_round_trips_through_its_spec() {
        let rule = SessionRule::new(spec()).expect("valid");
        let back = rule.spec();
        assert_eq!(back.name, "admin login");
        assert!(back.enabled);
        assert!(back.scope.is_none());
        assert_eq!(back.max_attempts, DEFAULT_MAX_LOGIN_ATTEMPTS);
        assert_eq!(back.login_macro.items.len(), 1);
        assert_eq!(back.login_macro.items[0].step.url, "https://target.test/login");
    }

    #[test]
    fn an_empty_scope_is_refused_because_it_would_silently_disable_the_rule() {
        let e = SessionRule::new(spec().with_scope(Scope::new())).unwrap_err();
        assert!(e.message.contains("matches nothing"), "{e}");
        assert_eq!(e.rule, "admin login", "the error must name the rule");
    }

    #[test]
    fn a_scope_limits_the_rule_to_the_targets_it_names() {
        let mut scope = Scope::new();
        scope.add(ScopeRule::include("staging.test"));
        let rule = SessionRule::new(spec().with_scope(scope)).expect("valid");
        assert!(rule.applies_to("https://staging.test/account"));
        assert!(!rule.applies_to("https://prod.test/account"));
        // A scoped rule cannot claim a URL it cannot read.
        assert!(!rule.applies_to("/just-a-path"));
    }

    #[test]
    fn a_rule_with_no_scope_applies_everywhere_including_to_an_unreadable_url() {
        let rule = SessionRule::new(spec()).expect("valid");
        assert!(rule.applies_to("https://anything.test/x"));
        assert!(rule.applies_to("/just-a-path"));
    }

    #[test]
    fn a_disabled_rule_applies_to_nothing() {
        let rule = SessionRule::new(spec().disabled()).expect("valid");
        assert!(!rule.applies_to("https://target.test/x"));
    }

    #[test]
    fn an_unnamed_rule_a_zero_attempt_bound_and_an_empty_macro_are_all_refused() {
        let mut unnamed = spec();
        unnamed.name = "   ".to_string();
        let e = SessionRule::new(unnamed).unwrap_err();
        assert!(e.message.contains("needs a name"), "{e}");
        assert_eq!(e.rule, "<unnamed>");

        let e = SessionRule::new(spec().with_max_attempts(0)).unwrap_err();
        assert!(e.message.contains("at least 1"), "{e}");

        let mut empty = spec();
        empty.login_macro = Macro::default();
        let e = SessionRule::new(empty).unwrap_err();
        assert!(e.message.contains("no steps"), "{e}");
    }

    #[test]
    fn a_step_with_no_method_or_no_host_is_refused_at_configuration_time() {
        let mut no_method = spec();
        no_method.login_macro.items[0].step.method = " ".to_string();
        assert!(
            SessionRule::new(no_method)
                .unwrap_err()
                .message
                .contains("empty method")
        );

        let mut no_host = spec();
        no_host.login_macro.items[0].step.url = "/login".to_string();
        let e = SessionRule::new(no_host).unwrap_err();
        assert!(e.message.contains("no host"), "{e}");
    }

    #[test]
    fn a_placeholder_no_earlier_step_extracts_is_refused() {
        let mut s = spec();
        s.login_macro = Macro::of_steps(vec![
            step("https://target.test/login"),
            step("https://target.test/act?csrf={{csrf}}"),
        ]);
        let e = SessionRule::new(s).unwrap_err();
        assert!(e.message.contains("{{csrf}}"), "{e}");
        assert!(e.message.contains("step 1"), "{e}");
    }

    #[test]
    fn a_placeholder_defined_by_an_earlier_step_is_accepted() {
        let mut s = spec();
        s.login_macro = Macro {
            items: vec![
                MacroItem::new(step("https://target.test/login"))
                    .extracting(Extraction::regex("csrf", "tok-([a-z0-9]+)", 1)),
                MacroItem::new(step("https://target.test/act?csrf={{csrf}}")),
            ],
        };
        SessionRule::new(s).expect("a value produced before it is used is fine");
    }

    #[test]
    fn a_step_cannot_refer_to_a_value_extracted_from_its_own_response() {
        // Resolution happens before the step is sent, so its own response does not exist yet.
        let mut s = spec();
        s.login_macro = Macro {
            items: vec![
                MacroItem::new(step("https://target.test/act?csrf={{csrf}}"))
                    .extracting(Extraction::regex("csrf", "tok-([a-z0-9]+)", 1)),
            ],
        };
        let e = SessionRule::new(s).unwrap_err();
        assert!(e.message.contains("no earlier step extracts"), "{e}");
    }

    #[test]
    fn two_extractions_with_the_same_name_are_refused() {
        let mut s = spec();
        s.login_macro = Macro {
            items: vec![
                MacroItem::new(step("https://target.test/a"))
                    .extracting(Extraction::regex("csrf", "a-(.+)", 1)),
                MacroItem::new(step("https://target.test/b"))
                    .extracting(Extraction::regex("csrf", "b-(.+)", 1)),
            ],
        };
        let e = SessionRule::new(s).unwrap_err();
        assert!(e.message.contains("already extracts"), "{e}");
    }

    #[test]
    fn an_unusable_extraction_pattern_fails_the_whole_rule_and_names_its_step() {
        let mut s = spec();
        s.login_macro = Macro {
            items: vec![
                MacroItem::new(step("https://target.test/a"))
                    .extracting(Extraction::regex("csrf", "([unclosed", 1)),
            ],
        };
        let e = SessionRule::new(s).unwrap_err();
        assert!(e.message.contains("step 0"), "{e}");
        assert!(e.message.contains("unusable pattern"), "{e}");
    }

    #[test]
    fn with_steps_keeps_the_extractions_and_refuses_a_different_step_count() {
        let rule = SessionRule::new(SessionRuleSpec::new(
            "r",
            Macro {
                items: vec![
                    MacroItem::new(step("https://target.test/login"))
                        .extracting(Extraction::regex("csrf", "tok-([a-z0-9]+)", 1)),
                ],
            },
            ValidityRule::StatusIs(200),
        ))
        .expect("valid");

        let updated = rule
            .with_steps(vec![step("https://target.test/login-v2")])
            .expect("same count");
        let spec = updated.spec();
        assert_eq!(spec.login_macro.items[0].step.url, "https://target.test/login-v2");
        assert_eq!(
            spec.login_macro.items[0].extract,
            vec![Extraction::regex("csrf", "tok-([a-z0-9]+)", 1)],
            "an update must not drop what the step extracts"
        );

        let e = rule.with_steps(vec![]).unwrap_err();
        assert!(e.message.contains("by position"), "{e}");
    }
}
