//! Bounded, collapsed re-login over a *list* of scoped rules: pick the rule that owns this target,
//! run its recorded macro when the session drops, never loop on it, and let concurrent observers of
//! the same failure share one login instead of piling on.
//!
//! # The three failure modes this exists to prevent
//!
//! **Looping.** [`crate::ValidityRule`] can say a response is invalid; nothing stops the *macro's own*
//! final response from being invalid too — wrong credentials, a target that started rejecting the
//! recorded flow, a CAPTCHA that appeared where it didn't before. Retrying such a macro forever is
//! both useless (the outcome will not change on its own) and actively harmful against a live
//! engagement target. Each rule's `max_attempts` bounds how many times its macro is run, and
//! [`RecoveryOutcome::GaveUp`] carries exactly how many that was — stopping with nothing to show for
//! it is the "partial result that looks complete" defect this project treats as a defect even when
//! the process technically terminates.
//!
//! **Piling on.** If N requests observe session loss at once — realistic under any concurrency —
//! reacting to each independently fires N logins against the target. [`ReloginCoordinator::ensure_logged_in`]
//! is a single-flight *per rule*: the first caller to notice invalidity runs that rule's macro; every
//! other caller for the same rule that arrives while it is in progress waits and shares the result.
//! Per rule rather than globally, because two rules are two different logins — collapsing an admin
//! login into a staging-host login would hand a caller a session for a target it never asked about.
//!
//! **Guessing which login applies.** With a rule list, a response can arrive for a target no rule
//! covers. That is [`RecoveryOutcome::NoRuleApplies`], stated plainly, and never treated as
//! `AlreadyValid` — the same fail-loud direction [`SessionValidity::Indeterminate`] takes. Picking
//! "the first rule" for an unmatched target would log into something the operator did not name.
//!
//! # One jar, several rules
//!
//! The cookie jar is coordinator-wide, not per rule: SESSION-03 asks for one jar shared across
//! tools, and it is keyed by host, so two rules for two hosts do not collide inside it and two rules
//! for the *same* host are deliberately sharing one session — which is what a rule list for one host
//! means. This is also why the rule list is mutable in place ([`ReloginCoordinator::add_rule`] and
//! friends) rather than the coordinator being rebuilt on every edit: rebuilding would silently throw
//! away every cookie the operator had, so editing one rule would log them out of everything.

use crate::cookie::{CookieJar, host_of};
use crate::extract::{resolve, untemplate};
use crate::rule::{RuleError, SessionRule, SessionRuleSpec};
use crate::step::{MacroResponse, MacroSender, MacroStep};
use crate::validity::SessionValidity;
use parking_lot::{Condvar, Mutex, RwLock};
use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// One macro step that did not produce a usable result — it could not be sent, or what came back
/// could not yield a value the macro needs. Carries which step, so "the macro failed" names a place
/// rather than just happening.
///
/// Both cases end the login attempt without retrying, and for the same reason: neither a refused
/// connection nor a response whose shape no longer matches the recorded extraction becomes true on
/// a second identical attempt. A stale extraction is exactly what "update macro" exists to repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroStepFailure {
    pub step_index: usize,
    pub error: String,
}

impl std::fmt::Display for MacroStepFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "login macro step {} failed: {}",
            self.step_index, self.error
        )
    }
}

impl std::error::Error for MacroStepFailure {}

/// What one login attempt — running the whole macro once, in order — produced.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LoginOutcome {
    /// The macro ran to completion and its own final response satisfied the validity rule.
    Succeeded { attempts: u32 },
    /// Every attempt ran to completion, but the final response never satisfied the validity rule.
    GaveUp { attempts: u32 },
    /// A step failed. Attempts stop immediately rather than retrying a target that is not answering
    /// at all, or a response that no longer has the value the macro needs — see
    /// [`MacroStepFailure`].
    MacroFailed {
        attempt: u32,
        failure: MacroStepFailure,
    },
}

/// What handling one observed response produced.
///
/// Every variant is reachable and distinct on purpose: a caller must be able to tell "this is
/// working" from "this has quietly stopped trying" without reading logs, which is the outcome
/// type the crate brief asks for directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// No enabled rule's scope covers this request, so no login was attempted. Distinct from
    /// `AlreadyValid`: nothing was checked, rather than checked and found fine.
    NoRuleApplies { url: String },
    /// The response handed in already satisfied the matching rule's validity rule; no re-login was
    /// attempted.
    AlreadyValid,
    /// Re-login succeeded and the retried original request now sees a valid session.
    Recovered {
        login_attempts: u32,
        response: MacroResponse,
    },
    /// Re-login completed (by its own account) but the retried original request is still not
    /// valid by the operator's rule — e.g. the macro authenticates a different account than the
    /// one the original request needed, or the rule is stricter than the macro's own check.
    StillInvalidAfterRelogin {
        login_attempts: u32,
        validity: SessionValidity,
        response: MacroResponse,
    },
    /// The macro ran `attempts` times and its own response never satisfied the validity rule.
    /// This is the "gave up" case SESSION-04 requires be stated, not silent.
    GaveUp { attempts: u32 },
    /// The login macro itself could not be run to completion.
    MacroFailed {
        attempt: u32,
        failure: MacroStepFailure,
    },
    /// Re-login succeeded, but resending the original request afterward failed to send.
    RetryFailed { login_attempts: u32, error: String },
}

/// What [`ReloginCoordinator::update_macro`] did.
///
/// An enum rather than a `Result<(), _>` because the three ways it can decline are three different
/// things for a caller to say to an operator, and "error" would flatten them into one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateMacroOutcome {
    /// The rule's recorded steps are now the ones the last successful login actually sent.
    Updated { steps: Vec<MacroStep> },
    /// No rule with that id — it was deleted, or the id was never one.
    NoSuchRule,
    /// This rule has never completed a login, so there is nothing observed to promote. Overwriting
    /// from a *failed* run would replace a stale macro with a broken one.
    NothingObserved,
    /// The observed steps did not survive validation. Reported rather than panicked: the recorded
    /// macro is left exactly as it was.
    Invalid(RuleError),
}

/// A single in-flight login attempt, shared by every caller that arrives while it is running.
///
/// Built on `parking_lot`'s `Mutex`/`Condvar` rather than `std::sync::Once`: `Once` looked like
/// the obvious fit (run exactly once, block concurrent callers), but a panic inside its closure
/// poisons it, and every future caller — including ones with nothing to do with the panicking
/// attempt — would then panic on `call_once` forever, since a poisoned `LoginRun` is never
/// replaced by a fresh one on the normal, non-panicking completion path. `parking_lot`'s
/// primitives carry no poisoning at all, and [`ReloginCoordinator::ensure_logged_in`] pairs that
/// with an explicit `catch_unwind` so a `MacroSender` that panics instead of returning `Err`
/// degrades to one honestly-reported failed attempt rather than wedging every later re-login.
#[derive(Debug)]
struct LoginRun {
    state: Mutex<Option<LoginOutcome>>,
    cv: Condvar,
}

impl LoginRun {
    fn new() -> Self {
        Self {
            state: Mutex::new(None),
            cv: Condvar::new(),
        }
    }

    /// Store the result and wake every caller blocked in [`Self::wait`].
    fn publish(&self, outcome: LoginOutcome) {
        *self.state.lock() = Some(outcome);
        self.cv.notify_all();
    }

    /// Block until [`Self::publish`] has been called, then return its outcome.
    fn wait(&self) -> LoginOutcome {
        let mut state = self.state.lock();
        while state.is_none() {
            self.cv.wait(&mut state);
        }
        state
            .clone()
            .expect("loop above only exits once state is Some")
    }
}

/// Runs the recorded login macro of whichever [`SessionRule`] owns a target, when a response fails
/// that rule's [`crate::ValidityRule`] — bounded, collapsed across concurrent callers, and honest
/// when no rule owns the target at all. See the module docs for why each of those matters.
#[derive(Debug)]
pub struct ReloginCoordinator {
    /// Ordered: the first enabled rule whose scope matches a request handles it. Ordering is the
    /// operator's, so a narrow rule can be placed ahead of a catch-all.
    rules: RwLock<Vec<(u64, Arc<SessionRule>)>>,
    /// Ids are never reused, so a stale id from a deleted rule reports [`UpdateMacroOutcome::NoSuchRule`]
    /// instead of addressing whatever now sits in that position.
    next_id: AtomicU64,
    jar: Arc<Mutex<CookieJar>>,
    /// `Some` entry while a login for that rule is in flight; removed once it has finished and its
    /// result observed. Cleared after each run — rather than cached forever — so a *later*,
    /// unrelated session drop starts a fresh attempt instead of replaying a stale result.
    runs: Mutex<HashMap<u64, Arc<LoginRun>>>,
    /// The requests the last *successful* login for each rule actually sent, with extracted values
    /// written back as `{{placeholders}}`. What "update macro" promotes.
    observed: Mutex<HashMap<u64, Vec<MacroStep>>>,
}

impl Default for ReloginCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ReloginCoordinator {
    /// A coordinator with no rules yet. Every response it is handed reports
    /// [`RecoveryOutcome::NoRuleApplies`] until one is added, which is the honest answer for a tool
    /// nobody has configured.
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            next_id: AtomicU64::new(1),
            jar: Arc::new(Mutex::new(CookieJar::new())),
            runs: Mutex::new(HashMap::new()),
            observed: Mutex::new(HashMap::new()),
        }
    }

    /// A coordinator holding a whole list. The first invalid rule stops the load and names itself,
    /// the way `burpsy_tools::matchreplace::RuleSet::compile` does.
    pub fn with_rules(specs: Vec<SessionRuleSpec>) -> Result<Self, RuleError> {
        let coordinator = Self::new();
        for spec in specs {
            coordinator.add_rule(spec)?;
        }
        Ok(coordinator)
    }

    /// Validate `spec` and append it. Returns the id to address it by later.
    pub fn add_rule(&self, spec: SessionRuleSpec) -> Result<u64, RuleError> {
        let rule = Arc::new(SessionRule::new(spec)?);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.rules.write().push((id, rule));
        Ok(id)
    }

    /// Replace one rule in place, keeping its position in the list — so an edit does not silently
    /// reorder which rule wins for a target. `Ok(false)` means there is no rule with that id.
    ///
    /// Validation happens before anything is replaced: a rejected edit leaves the running rule
    /// exactly as it was, rather than removing it and failing to put anything back.
    pub fn replace_rule(&self, id: u64, spec: SessionRuleSpec) -> Result<bool, RuleError> {
        let replacement = Arc::new(SessionRule::new(spec)?);
        let mut rules = self.rules.write();
        let Some(slot) = rules.iter_mut().find(|(existing, _)| *existing == id) else {
            return Ok(false);
        };
        slot.1 = replacement;
        drop(rules);
        // The replacement is a different macro, so what the old one was observed to send is no
        // longer a description of this rule.
        self.observed.lock().remove(&id);
        Ok(true)
    }

    /// Remove one rule. `false` means there was none with that id.
    pub fn remove_rule(&self, id: u64) -> bool {
        let mut rules = self.rules.write();
        let before = rules.len();
        rules.retain(|(existing, _)| *existing != id);
        let removed = rules.len() != before;
        drop(rules);
        if removed {
            self.observed.lock().remove(&id);
            self.runs.lock().remove(&id);
        }
        removed
    }

    /// Every rule, in the order they are consulted, with the id each is addressed by.
    pub fn rules(&self) -> Vec<(u64, SessionRuleSpec)> {
        self.rules
            .read()
            .iter()
            .map(|(id, rule)| (*id, rule.spec()))
            .collect()
    }

    /// The id and name of the rule that would handle `url`, or `None` when none would.
    ///
    /// Exposed so a caller can label an outcome with the rule that produced it without holding a
    /// second copy of the list.
    pub fn matching_rule(&self, url: &str) -> Option<(u64, String)> {
        self.matching(url)
            .map(|(id, rule)| (id, rule.name().to_string()))
    }

    fn matching(&self, url: &str) -> Option<(u64, Arc<SessionRule>)> {
        self.rules
            .read()
            .iter()
            .find(|(_, rule)| rule.applies_to(url))
            .map(|(id, rule)| (*id, rule.clone()))
    }

    /// The cookie jar this coordinator reads and writes. Cloning the `Arc` and handing it to
    /// another sender is how SESSION-03's "one jar shared across tools" gets wired up — this
    /// crate provides the jar and uses it faithfully, but does not itself know about Proxy,
    /// Repeater, or Intruder, so it cannot do that wiring; that happens where those tools do.
    pub fn shared_jar(&self) -> Arc<Mutex<CookieJar>> {
        self.jar.clone()
    }

    /// Evaluate `response` against the validity rule of whichever rule owns `original`'s URL and,
    /// if it is not valid, recover: run that rule's login macro (once, or share an already-running
    /// one) and retry `original`.
    ///
    /// Anything other than [`SessionValidity::Valid`] — including `Indeterminate` — takes the
    /// recovery path. Treating "the rule could not tell" as "leave it alone" would be the
    /// fail-open direction this crate exists to refuse.
    pub fn handle_response(
        &self,
        sender: &dyn MacroSender,
        original: &MacroStep,
        response: MacroResponse,
    ) -> RecoveryOutcome {
        let Some((id, rule)) = self.matching(&original.url) else {
            return RecoveryOutcome::NoRuleApplies {
                url: original.url.clone(),
            };
        };
        if rule.validity().evaluate(&response) == SessionValidity::Valid {
            return RecoveryOutcome::AlreadyValid;
        }
        self.recover(sender, id, &rule, original)
    }

    fn recover(
        &self,
        sender: &dyn MacroSender,
        id: u64,
        rule: &SessionRule,
        original: &MacroStep,
    ) -> RecoveryOutcome {
        match self.ensure_logged_in(sender, id, rule) {
            LoginOutcome::Succeeded { attempts } => match self.send_with_jar(sender, original) {
                Ok(response) => match rule.validity().evaluate(&response) {
                    SessionValidity::Valid => RecoveryOutcome::Recovered {
                        login_attempts: attempts,
                        response,
                    },
                    validity => RecoveryOutcome::StillInvalidAfterRelogin {
                        login_attempts: attempts,
                        validity,
                        response,
                    },
                },
                Err(error) => RecoveryOutcome::RetryFailed {
                    login_attempts: attempts,
                    error,
                },
            },
            LoginOutcome::GaveUp { attempts } => RecoveryOutcome::GaveUp { attempts },
            LoginOutcome::MacroFailed { attempt, failure } => {
                RecoveryOutcome::MacroFailed { attempt, failure }
            }
        }
    }

    /// Single-flight per rule: the first caller to arrive while no login for `id` is running
    /// installs a fresh [`LoginRun`] and becomes its leader, actually calling
    /// [`Self::run_with_retries`]. Everyone who arrives for the same rule while that run is still
    /// registered — before or after the leader's send calls start — gets the same `LoginRun` back
    /// and blocks in [`LoginRun::wait`] instead of starting one of its own, which is "N concurrent
    /// observers, one login" without any request beyond the first ever reaching `sender`.
    fn ensure_logged_in(
        &self,
        sender: &dyn MacroSender,
        id: u64,
        rule: &SessionRule,
    ) -> LoginOutcome {
        let (run, is_leader) = {
            let mut runs = self.runs.lock();
            match runs.get(&id) {
                Some(existing) => (existing.clone(), false),
                None => {
                    let fresh = Arc::new(LoginRun::new());
                    runs.insert(id, fresh.clone());
                    (fresh, true)
                }
            }
        };

        if !is_leader {
            return run.wait();
        }

        // Isolated so a `MacroSender` that panics instead of returning `Err` still produces one
        // honestly-reported failed attempt, rather than leaving every follower blocked forever
        // and every later caller joining a `LoginRun` that will never publish a result.
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
            self.run_with_retries(sender, id, rule)
        }))
        .unwrap_or_else(|_| LoginOutcome::MacroFailed {
            attempt: 0,
            failure: MacroStepFailure {
                step_index: 0,
                error: "login macro panicked instead of returning an error".to_string(),
            },
        });

        run.publish(outcome.clone());
        // Make room for the *next* session drop to start a fresh run instead of reusing this one
        // forever. Guarded by identity rather than removed unconditionally so a future change that
        // adds another mutator of `runs` fails loudly instead of clobbering a run it did not start.
        let mut runs = self.runs.lock();
        if matches!(runs.get(&id), Some(current) if Arc::ptr_eq(current, &run)) {
            runs.remove(&id);
        }
        drop(runs);

        outcome
    }

    fn run_with_retries(
        &self,
        sender: &dyn MacroSender,
        id: u64,
        rule: &SessionRule,
    ) -> LoginOutcome {
        for attempt in 1..=rule.max_attempts() {
            match self.run_macro_once(sender, rule) {
                Ok((response, sent)) => {
                    if rule.validity().evaluate(&response) == SessionValidity::Valid {
                        // Only a successful run is worth promoting: see `UpdateMacroOutcome`.
                        self.observed.lock().insert(id, sent);
                        return LoginOutcome::Succeeded { attempts: attempt };
                    }
                    // The macro completed, but its own response says we still are not
                    // authenticated. Loop again, bounded by `max_attempts` — this is the "a
                    // macro whose own response is invalid must not loop forever" case.
                }
                Err(failure) => return LoginOutcome::MacroFailed { attempt, failure },
            }
        }
        LoginOutcome::GaveUp {
            attempts: rule.max_attempts(),
        }
    }

    /// Run every step in order, threading extracted values forward, and return the final response
    /// together with the requests actually produced.
    ///
    /// The value map starts empty on every attempt: a CSRF token scraped during a login that did not
    /// work is stale by the time the next attempt sends it, and reusing it would make attempt 2 a
    /// replay of attempt 1's mistake rather than a fresh try.
    fn run_macro_once(
        &self,
        sender: &dyn MacroSender,
        rule: &SessionRule,
    ) -> Result<(MacroResponse, Vec<MacroStep>), MacroStepFailure> {
        let items = rule.items();
        if items.is_empty() {
            // `SessionRule::new` refuses an empty macro, so this is unreachable by construction; it
            // stays as a stated failure rather than an `expect`, because "the macro ran and did
            // nothing" must never be able to read as success.
            return Err(MacroStepFailure {
                step_index: 0,
                error: "login macro has no steps to run".to_string(),
            });
        }
        let mut values: HashMap<String, String> = HashMap::new();
        let mut sent = Vec::with_capacity(items.len());
        let mut last = None;
        for (step_index, item) in items.iter().enumerate() {
            // Resolved here, immediately before the send, so a step sees every value the steps
            // before it produced and none that do not exist yet.
            let resolved = resolve(&item.step, &values);
            let response = self
                .send_with_jar(sender, &resolved)
                .map_err(|error| MacroStepFailure { step_index, error })?;
            // Recorded *before* the jar's cookie is attached (`send_with_jar` does that on its own
            // copy) and with this run's extracted values turned back into their placeholders, so
            // promoting it later reinstates a template rather than a one-time secret.
            sent.push(untemplate(&resolved, &values));
            for extraction in &item.extract {
                let value = extraction
                    .value(&response)
                    .map_err(|error| MacroStepFailure { step_index, error })?;
                values.insert(extraction.name().to_string(), value);
            }
            last = Some(response);
        }
        Ok((
            last.expect("items is non-empty, checked above"),
            sent,
        ))
    }

    /// Overwrite a rule's recorded steps with the requests its last successful login actually sent.
    ///
    /// Burp's "update macro" action, and for its reason: a login flow drifts — a field is renamed, a
    /// step redirects somewhere new — and the recorded macro that still works is more trustworthy
    /// than the one an operator recorded weeks ago. What is promoted is the *last successful* run
    /// only, so this can never replace a working macro with the steps of one that failed.
    ///
    /// The replacement goes through [`SessionRule::new`] again, so an update cannot install anything
    /// the rule list would have refused in the first place.
    pub fn update_macro(&self, id: u64) -> UpdateMacroOutcome {
        let Some(rule) = self
            .rules
            .read()
            .iter()
            .find(|(existing, _)| *existing == id)
            .map(|(_, rule)| rule.clone())
        else {
            return UpdateMacroOutcome::NoSuchRule;
        };
        let Some(steps) = self.observed.lock().get(&id).cloned() else {
            return UpdateMacroOutcome::NothingObserved;
        };
        let updated = match rule.with_steps(steps.clone()) {
            Ok(r) => Arc::new(r),
            Err(e) => return UpdateMacroOutcome::Invalid(e),
        };
        let mut rules = self.rules.write();
        // Re-found under the write lock: the rule could have been deleted between the read above
        // and here, and reinstating a deleted rule would be worse than declining to update it.
        let Some(slot) = rules.iter_mut().find(|(existing, _)| *existing == id) else {
            return UpdateMacroOutcome::NoSuchRule;
        };
        slot.1 = updated;
        drop(rules);
        UpdateMacroOutcome::Updated { steps }
    }

    /// Send `step` with the jar's current cookie for its host attached, then absorb any
    /// `Set-Cookie` headers the response carries back into the jar. Used for both a macro's own
    /// steps and the retried original request, which is how a session cookie a login step sets
    /// reaches the request that needed it.
    ///
    /// Public so a caller driving [`Self::handle_response`] from outside this crate — e.g. a web
    /// handler sending the probe `handle_response` will evaluate — can send that probe through the
    /// same jar instead of bypassing it. Sending a probe without this would make it permanently
    /// look logged-out (no `Cookie` header ever attached) and leak a stale recorded `Cookie`
    /// header onto the wire, which [`Self::apply_jar`] exists to strip.
    pub fn send_with_jar(
        &self,
        sender: &dyn MacroSender,
        step: &MacroStep,
    ) -> Result<MacroResponse, String> {
        let effective = {
            let jar = self.jar.lock();
            Self::apply_jar(step, &jar)
        };
        let response = sender.send(&effective)?;
        if let Some(host) = host_of(&step.url) {
            let mut jar = self.jar.lock();
            for (name, value) in &response.headers {
                if name.eq_ignore_ascii_case("set-cookie") {
                    jar.absorb_set_cookie(host, value);
                }
            }
        }
        Ok(response)
    }

    /// A copy of `step` with any hardcoded `Cookie` header replaced by the jar's current one for
    /// its host. The jar is the single source of truth for session state across steps, so a
    /// recorded step's own `Cookie` header (stale the moment it was captured) never reaches the
    /// wire.
    fn apply_jar(step: &MacroStep, jar: &CookieJar) -> MacroStep {
        let mut headers: Vec<(String, String)> = step
            .headers
            .iter()
            .filter(|(k, _)| !k.eq_ignore_ascii_case("cookie"))
            .cloned()
            .collect();
        if let Some(cookie_header) = host_of(&step.url).and_then(|host| jar.cookie_header(host)) {
            headers.push(("Cookie".to_string(), cookie_header));
        }
        MacroStep {
            headers,
            ..step.clone()
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::step::{MacroResponse, MacroSender, MacroStep};
    use parking_lot::Mutex;
    use std::collections::{HashMap, VecDeque};

    /// A [`MacroSender`] double whose responses are scripted per URL and whose call order is
    /// recorded, so a test can assert both *what* was sent and *how many times*.
    ///
    /// Sending a URL with no script left panics rather than returning a made-up response: a test
    /// that under-scripts a scenario should fail loudly, not pass by accident on a default.
    pub(crate) struct FakeSender {
        scripts: Mutex<HashMap<String, VecDeque<Result<MacroResponse, String>>>>,
        calls: Mutex<Vec<MacroStep>>,
        /// An artificial delay to apply before answering a given URL, so a test can widen the
        /// window a "leader" send is in flight for and make a collapsing assertion deterministic
        /// instead of depending on how the OS happens to schedule threads that raced past a
        /// barrier.
        delays: Mutex<HashMap<String, std::time::Duration>>,
    }

    impl FakeSender {
        pub(crate) fn new() -> Self {
            Self {
                scripts: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                delays: Mutex::new(HashMap::new()),
            }
        }

        /// Queue one response (or transport error) to hand back the next time `url` is sent.
        pub(crate) fn script(&self, url: &str, result: Result<MacroResponse, String>) {
            self.scripts
                .lock()
                .entry(url.to_string())
                .or_default()
                .push_back(result);
        }

        /// Sleep for `d` before answering a send to `url`.
        pub(crate) fn delay(&self, url: &str, d: std::time::Duration) {
            self.delays.lock().insert(url.to_string(), d);
        }

        pub(crate) fn call_count(&self, url: &str) -> usize {
            self.calls.lock().iter().filter(|s| s.url == url).count()
        }

        pub(crate) fn total_calls(&self) -> usize {
            self.calls.lock().len()
        }

        pub(crate) fn sent_steps(&self, url: &str) -> Vec<MacroStep> {
            self.calls
                .lock()
                .iter()
                .filter(|s| s.url == url)
                .cloned()
                .collect()
        }

        /// Every URL sent, in order — for asserting that a substituted URL is what went out.
        pub(crate) fn sent_urls(&self) -> Vec<String> {
            self.calls.lock().iter().map(|s| s.url.clone()).collect()
        }
    }

    impl MacroSender for FakeSender {
        fn send(&self, step: &MacroStep) -> Result<MacroResponse, String> {
            self.calls.lock().push(step.clone());
            if let Some(d) = self.delays.lock().get(&step.url).copied() {
                std::thread::sleep(d);
            }
            let mut scripts = self.scripts.lock();
            let queue = scripts
                .get_mut(&step.url)
                .unwrap_or_else(|| panic!("FakeSender: no script queued for {}", step.url));
            queue
                .pop_front()
                .unwrap_or_else(|| panic!("FakeSender: script exhausted for {}", step.url))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::FakeSender;
    use super::*;
    use crate::extract::Extraction;
    use crate::rule::{DEFAULT_MAX_LOGIN_ATTEMPTS, Macro, MacroItem};
    use crate::validity::ValidityRule;
    use burpsy_core::{Scope, ScopeRule};
    use bytes::Bytes;
    use std::sync::Barrier;
    use std::thread;

    fn valid_response() -> MacroResponse {
        MacroResponse {
            status: 200,
            headers: vec![("X-Auth".into(), "1".into())],
            body: Some(Bytes::from_static(b"welcome")),
        }
    }

    fn invalid_response() -> MacroResponse {
        MacroResponse {
            status: 200,
            headers: vec![],
            body: Some(Bytes::from_static(b"please log in")),
        }
    }

    fn rule() -> ValidityRule {
        ValidityRule::HeaderPresent("X-Auth".into())
    }

    fn get_step(url: &str) -> MacroStep {
        MacroStep {
            method: "GET".into(),
            url: url.to_string(),
            headers: vec![],
            body: Bytes::new(),
        }
    }

    fn login_macro_of(urls: &[&str]) -> Macro {
        Macro::of_steps(urls.iter().map(|u| get_step(u)).collect())
    }

    /// One always-on rule over the given URLs — the shape every pre-rule-list test assumed.
    fn one_rule(urls: &[&str], max_attempts: u32) -> ReloginCoordinator {
        ReloginCoordinator::with_rules(vec![
            SessionRuleSpec::new("only", login_macro_of(urls), rule())
                .with_max_attempts(max_attempts),
        ])
        .expect("valid rule")
    }

    #[test]
    fn a_valid_response_does_not_trigger_a_login() {
        let fake = FakeSender::new();
        let coordinator = one_rule(&["https://target.test/login"], 3);
        let original = get_step("https://target.test/account");
        let outcome = coordinator.handle_response(&fake, &original, valid_response());
        assert_eq!(outcome, RecoveryOutcome::AlreadyValid);
        assert_eq!(
            fake.total_calls(),
            0,
            "no send should happen when the response handed in is already valid"
        );
    }

    #[test]
    fn an_invalid_response_triggers_exactly_one_macro_run_then_retries_the_original_request() {
        let fake = FakeSender::new();
        fake.script(
            "https://target.test/login",
            Ok(MacroResponse {
                status: 302,
                headers: vec![("Location".into(), "/dashboard".into())],
                body: Some(Bytes::new()),
            }),
        );
        fake.script("https://target.test/dashboard", Ok(valid_response()));
        fake.script("https://target.test/account", Ok(valid_response()));

        let coordinator = one_rule(
            &["https://target.test/login", "https://target.test/dashboard"],
            3,
        );
        let original = get_step("https://target.test/account");
        let outcome = coordinator.handle_response(&fake, &original, invalid_response());

        assert_eq!(
            fake.call_count("https://target.test/login"),
            1,
            "the login macro must run exactly once"
        );
        assert_eq!(fake.call_count("https://target.test/dashboard"), 1);
        assert_eq!(
            fake.call_count("https://target.test/account"),
            1,
            "the original request must be retried exactly once"
        );
        assert!(
            matches!(
                outcome,
                RecoveryOutcome::Recovered {
                    login_attempts: 1,
                    ..
                }
            ),
            "got {outcome:?}"
        );
    }

    #[test]
    fn a_login_macro_whose_own_response_stays_invalid_does_not_loop_forever() {
        let fake = FakeSender::new();
        for _ in 0..3 {
            fake.script("https://target.test/login", Ok(invalid_response()));
        }
        let coordinator = one_rule(&["https://target.test/login"], 3);
        let original = get_step("https://target.test/account");
        let outcome = coordinator.handle_response(&fake, &original, invalid_response());

        assert_eq!(
            fake.call_count("https://target.test/login"),
            3,
            "the macro must stop at the stated attempt limit, not run unboundedly"
        );
        assert_eq!(
            fake.call_count("https://target.test/account"),
            0,
            "the original request is never retried if login never succeeded"
        );
        assert_eq!(outcome, RecoveryOutcome::GaveUp { attempts: 3 });
    }

    #[test]
    fn giving_up_after_the_attempt_limit_is_reported_not_silently_swallowed() {
        let fake = FakeSender::new();
        for _ in 0..2 {
            fake.script("https://target.test/login", Ok(invalid_response()));
        }
        let coordinator = one_rule(&["https://target.test/login"], 2);
        let original = get_step("https://target.test/account");
        let outcome = coordinator.handle_response(&fake, &original, invalid_response());
        match outcome {
            RecoveryOutcome::GaveUp { attempts } => assert_eq!(
                attempts, 2,
                "the give-up outcome must carry how many attempts were actually made"
            ),
            other => panic!("expected GaveUp, got {other:?}"),
        }
    }

    #[test]
    fn a_transport_failure_during_the_macro_is_reported_distinctly_and_not_retried() {
        let fake = FakeSender::new();
        fake.script(
            "https://target.test/login",
            Err("connection reset".to_string()),
        );
        let coordinator = one_rule(&["https://target.test/login"], 3);
        let original = get_step("https://target.test/account");
        let outcome = coordinator.handle_response(&fake, &original, invalid_response());

        assert_eq!(
            fake.call_count("https://target.test/login"),
            1,
            "a transport failure must not be retried the way an invalid-session response is"
        );
        match outcome {
            RecoveryOutcome::MacroFailed { attempt, failure } => {
                assert_eq!(attempt, 1);
                assert_eq!(failure.step_index, 0);
                assert_eq!(failure.error, "connection reset");
            }
            other => panic!("expected MacroFailed, got {other:?}"),
        }
    }

    #[test]
    fn the_login_macros_session_cookie_is_attached_to_the_retried_original_request() {
        let fake = FakeSender::new();
        fake.script(
            "https://target.test/login",
            Ok(MacroResponse {
                status: 200,
                headers: vec![
                    ("Set-Cookie".into(), "session=abc123; Path=/".into()),
                    ("X-Auth".into(), "1".into()),
                ],
                body: Some(Bytes::new()),
            }),
        );
        fake.script("https://target.test/account", Ok(valid_response()));

        let coordinator = one_rule(&["https://target.test/login"], 3);
        let original = get_step("https://target.test/account");
        let outcome = coordinator.handle_response(&fake, &original, invalid_response());
        assert!(
            matches!(outcome, RecoveryOutcome::Recovered { .. }),
            "got {outcome:?}"
        );

        let sent = fake.sent_steps("https://target.test/account");
        assert_eq!(sent.len(), 1);
        let cookie = sent[0]
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .map(|(_, v)| v.clone());
        assert_eq!(
            cookie,
            Some("session=abc123".to_string()),
            "the cookie captured during login must be attached to the retried request"
        );
    }

    #[test]
    fn n_concurrent_invalid_observations_cause_one_login_not_n() {
        const N: usize = 8;
        let fake = Arc::new(FakeSender::new());
        fake.script("https://target.test/login", Ok(valid_response()));
        // The fake otherwise answers instantly, so without a deliberate delay a fast leader could
        // finish and clear its run before a slower-to-schedule thread ever checks it — a real send
        // has network latency to fill exactly this window; this stands in for that so the "one
        // login, not N" assertion below is deterministic rather than a race against the OS
        // scheduler.
        fake.delay(
            "https://target.test/login",
            std::time::Duration::from_millis(50),
        );
        for i in 0..N {
            fake.script(
                &format!("https://target.test/account{i}"),
                Ok(valid_response()),
            );
        }

        let coordinator = Arc::new(one_rule(&["https://target.test/login"], 3));
        let barrier = Arc::new(Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let coordinator = coordinator.clone();
                let fake = fake.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    let original = get_step(&format!("https://target.test/account{i}"));
                    barrier.wait();
                    coordinator.handle_response(&*fake, &original, invalid_response())
                })
            })
            .collect();

        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("thread panicked"))
            .collect();

        assert_eq!(
            fake.call_count("https://target.test/login"),
            1,
            "N concurrent session-invalid observations must collapse into one login, not N"
        );
        for outcome in outcomes {
            assert!(
                matches!(outcome, RecoveryOutcome::Recovered { .. }),
                "got {outcome:?}"
            );
        }
    }

    // ---- the rule list ---------------------------------------------------------------------

    fn scoped(name: &str, host: &str) -> SessionRuleSpec {
        let mut scope = Scope::new();
        scope.add(ScopeRule::include(host));
        SessionRuleSpec::new(
            name,
            login_macro_of(&[&format!("https://{host}/login")]),
            rule(),
        )
        .with_scope(scope)
    }

    #[test]
    fn a_response_for_a_target_no_rule_covers_is_reported_not_logged_into() {
        let fake = FakeSender::new();
        let coordinator =
            ReloginCoordinator::with_rules(vec![scoped("staging", "staging.test")]).expect("valid");
        let original = get_step("https://elsewhere.test/account");
        let outcome = coordinator.handle_response(&fake, &original, invalid_response());
        assert_eq!(
            outcome,
            RecoveryOutcome::NoRuleApplies {
                url: "https://elsewhere.test/account".to_string()
            },
            "an unmatched target must not be logged into with someone else's macro"
        );
        assert_eq!(fake.total_calls(), 0, "nothing may be sent");
    }

    #[test]
    fn an_empty_rule_list_applies_to_nothing_rather_than_to_everything() {
        let fake = FakeSender::new();
        let coordinator = ReloginCoordinator::new();
        let outcome = coordinator.handle_response(
            &fake,
            &get_step("https://target.test/account"),
            invalid_response(),
        );
        assert!(matches!(outcome, RecoveryOutcome::NoRuleApplies { .. }));
        assert_eq!(fake.total_calls(), 0);
    }

    #[test]
    fn each_scoped_rule_runs_its_own_macro_for_its_own_host() {
        let fake = FakeSender::new();
        fake.script("https://a.test/login", Ok(valid_response()));
        fake.script("https://a.test/account", Ok(valid_response()));
        fake.script("https://b.test/login", Ok(valid_response()));
        fake.script("https://b.test/account", Ok(valid_response()));

        let coordinator =
            ReloginCoordinator::with_rules(vec![scoped("a", "a.test"), scoped("b", "b.test")])
                .expect("valid");

        for host in ["a.test", "b.test"] {
            let outcome = coordinator.handle_response(
                &fake,
                &get_step(&format!("https://{host}/account")),
                invalid_response(),
            );
            assert!(
                matches!(outcome, RecoveryOutcome::Recovered { .. }),
                "{host}: got {outcome:?}"
            );
        }
        assert_eq!(fake.call_count("https://a.test/login"), 1);
        assert_eq!(
            fake.call_count("https://b.test/login"),
            1,
            "b's session drop must run b's macro, not a's"
        );
    }

    #[test]
    fn the_first_matching_enabled_rule_wins_and_a_disabled_one_is_skipped() {
        let fake = FakeSender::new();
        fake.script("https://a.test/login", Ok(valid_response()));
        fake.script("https://a.test/account", Ok(valid_response()));

        // A disabled narrow rule first, then a catch-all: the disabled one must not shadow it.
        let coordinator = ReloginCoordinator::with_rules(vec![
            scoped("disabled-narrow", "a.test").disabled(),
            SessionRuleSpec::new("catch-all", login_macro_of(&["https://a.test/login"]), rule()),
        ])
        .expect("valid");

        assert_eq!(
            coordinator.matching_rule("https://a.test/account"),
            Some((2, "catch-all".to_string()))
        );
        let outcome = coordinator.handle_response(
            &fake,
            &get_step("https://a.test/account"),
            invalid_response(),
        );
        assert!(matches!(outcome, RecoveryOutcome::Recovered { .. }));
    }

    #[test]
    fn rules_can_be_added_read_back_replaced_and_removed_by_id() {
        let coordinator = ReloginCoordinator::new();
        let first = coordinator.add_rule(scoped("a", "a.test")).expect("valid");
        let second = coordinator.add_rule(scoped("b", "b.test")).expect("valid");
        assert_ne!(first, second);

        let listed = coordinator.rules();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].0, first);
        assert_eq!(listed[0].1.name, "a");
        assert_eq!(listed[1].1.name, "b");

        // A replacement keeps its position, so which rule wins for a target does not silently move.
        assert!(
            coordinator
                .replace_rule(second, scoped("b-renamed", "b.test"))
                .expect("valid")
        );
        let listed = coordinator.rules();
        assert_eq!(listed[1].0, second);
        assert_eq!(listed[1].1.name, "b-renamed");

        assert!(!coordinator.replace_rule(999, scoped("x", "x.test")).unwrap());
        assert!(coordinator.remove_rule(first));
        assert!(!coordinator.remove_rule(first), "removing twice is not a lie");
        assert_eq!(coordinator.rules().len(), 1);
        // Ids are never reused, so the removed one cannot be addressed by accident.
        let third = coordinator.add_rule(scoped("c", "c.test")).expect("valid");
        assert!(third > second);
    }

    #[test]
    fn an_invalid_edit_leaves_the_running_rule_untouched() {
        let coordinator = ReloginCoordinator::new();
        let id = coordinator.add_rule(scoped("a", "a.test")).expect("valid");
        let mut broken = scoped("a", "a.test");
        broken.max_attempts = 0;
        let err = coordinator.replace_rule(id, broken).unwrap_err();
        assert!(err.message.contains("at least 1"), "{err}");
        assert_eq!(
            coordinator.rules()[0].1.max_attempts,
            DEFAULT_MAX_LOGIN_ATTEMPTS,
            "a rejected edit must not have replaced anything"
        );
    }

    #[test]
    fn an_invalid_rule_stops_a_whole_list_from_loading_and_names_itself() {
        let err = ReloginCoordinator::with_rules(vec![
            scoped("fine", "a.test"),
            scoped("broken", "b.test").with_scope(Scope::new()),
        ])
        .unwrap_err();
        assert_eq!(err.rule, "broken");
    }

    #[test]
    fn the_cookie_jar_survives_editing_the_rule_list() {
        // Rebuilding the coordinator per edit would log the operator out of everything; this is the
        // regression that would hide behind "the rules look right".
        let fake = FakeSender::new();
        fake.script(
            "https://a.test/login",
            Ok(MacroResponse {
                status: 200,
                headers: vec![
                    ("Set-Cookie".into(), "session=keep-me".into()),
                    ("X-Auth".into(), "1".into()),
                ],
                body: Some(Bytes::new()),
            }),
        );
        fake.script("https://a.test/account", Ok(valid_response()));

        let coordinator = ReloginCoordinator::new();
        let id = coordinator.add_rule(scoped("a", "a.test")).expect("valid");
        coordinator.handle_response(
            &fake,
            &get_step("https://a.test/account"),
            invalid_response(),
        );
        coordinator
            .replace_rule(id, scoped("a-edited", "a.test"))
            .expect("valid");
        assert_eq!(
            coordinator.shared_jar().lock().cookie_header("a.test"),
            Some("session=keep-me".to_string())
        );
    }

    // ---- custom parameter extraction -------------------------------------------------------

    /// A form page that hands out a CSRF token, then a login POST that has to echo it back.
    fn csrf_rule() -> SessionRuleSpec {
        SessionRuleSpec::new(
            "csrf login",
            Macro {
                items: vec![
                    MacroItem::new(get_step("https://target.test/login-form")).extracting(
                        Extraction::regex("csrf", r#"name="csrf" value="([^"]+)""#, 1),
                    ),
                    MacroItem::new(MacroStep {
                        method: "POST".into(),
                        url: "https://target.test/login?t={{csrf}}".into(),
                        headers: vec![("X-CSRF".into(), "{{csrf}}".into())],
                        body: Bytes::from_static(b"user=a&csrf={{csrf}}"),
                    }),
                ],
            },
            rule(),
        )
    }

    fn form_page(token: &str) -> MacroResponse {
        MacroResponse {
            status: 200,
            headers: vec![],
            body: Some(Bytes::from(format!(
                r#"<form><input name="csrf" value="{token}"></form>"#
            ))),
        }
    }

    #[test]
    fn a_value_extracted_from_one_step_is_substituted_into_the_next_steps_url_headers_and_body() {
        let fake = FakeSender::new();
        fake.script("https://target.test/login-form", Ok(form_page("tok-9f3a")));
        fake.script("https://target.test/login?t=tok-9f3a", Ok(valid_response()));
        fake.script("https://target.test/account", Ok(valid_response()));

        let coordinator = ReloginCoordinator::with_rules(vec![csrf_rule()]).expect("valid");
        let outcome = coordinator.handle_response(
            &fake,
            &get_step("https://target.test/account"),
            invalid_response(),
        );
        assert!(
            matches!(outcome, RecoveryOutcome::Recovered { .. }),
            "got {outcome:?}"
        );

        let sent = fake.sent_steps("https://target.test/login?t=tok-9f3a");
        assert_eq!(sent.len(), 1, "the substituted URL is what went out");
        assert_eq!(
            sent[0]
                .headers
                .iter()
                .find(|(k, _)| k == "X-CSRF")
                .map(|(_, v)| v.as_str()),
            Some("tok-9f3a")
        );
        assert_eq!(sent[0].body, Bytes::from_static(b"user=a&csrf=tok-9f3a"));
    }

    #[test]
    fn a_second_attempt_re_extracts_rather_than_replaying_the_first_attempts_token() {
        // A one-time token from a failed attempt is stale; reusing it would make attempt 2 a replay
        // of attempt 1's mistake.
        let fake = FakeSender::new();
        fake.script("https://target.test/login-form", Ok(form_page("tok-first")));
        fake.script("https://target.test/login?t=tok-first", Ok(invalid_response()));
        fake.script("https://target.test/login-form", Ok(form_page("tok-second")));
        fake.script("https://target.test/login?t=tok-second", Ok(valid_response()));
        fake.script("https://target.test/account", Ok(valid_response()));

        let coordinator = ReloginCoordinator::with_rules(vec![csrf_rule()]).expect("valid");
        let outcome = coordinator.handle_response(
            &fake,
            &get_step("https://target.test/account"),
            invalid_response(),
        );
        assert!(
            matches!(
                outcome,
                RecoveryOutcome::Recovered {
                    login_attempts: 2,
                    ..
                }
            ),
            "got {outcome:?}"
        );
        assert_eq!(fake.call_count("https://target.test/login?t=tok-second"), 1);
    }

    #[test]
    fn an_extraction_that_finds_nothing_fails_the_login_and_is_not_retried() {
        // A response whose shape no longer matches the recorded extraction will not match on a
        // second identical attempt either — and this is the stale-macro case "update macro" exists
        // for, so the outcome has to say which step and why.
        let fake = FakeSender::new();
        fake.script(
            "https://target.test/login-form",
            Ok(MacroResponse {
                status: 200,
                headers: vec![],
                body: Some(Bytes::from_static(b"<form>the field was renamed</form>")),
            }),
        );
        let coordinator = ReloginCoordinator::with_rules(vec![csrf_rule()]).expect("valid");
        let outcome = coordinator.handle_response(
            &fake,
            &get_step("https://target.test/account"),
            invalid_response(),
        );
        match outcome {
            RecoveryOutcome::MacroFailed { attempt, failure } => {
                assert_eq!(attempt, 1, "a stale extraction is not retried");
                assert_eq!(failure.step_index, 0);
                assert!(failure.error.contains("csrf"), "{}", failure.error);
                assert!(failure.error.contains("matched nothing"), "{}", failure.error);
            }
            other => panic!("expected MacroFailed, got {other:?}"),
        }
        assert_eq!(fake.call_count("https://target.test/login-form"), 1);
        assert_eq!(
            fake.total_calls(),
            1,
            "the step that needed the value must not be sent with a hole in it"
        );
    }

    // ---- update macro ----------------------------------------------------------------------

    #[test]
    fn update_macro_promotes_the_last_successful_run_and_keeps_the_placeholders() {
        let fake = FakeSender::new();
        fake.script("https://target.test/login-form", Ok(form_page("tok-9f3a")));
        fake.script("https://target.test/login?t=tok-9f3a", Ok(valid_response()));
        fake.script("https://target.test/account", Ok(valid_response()));

        let coordinator = ReloginCoordinator::new();
        let id = coordinator.add_rule(csrf_rule()).expect("valid");
        assert_eq!(
            coordinator.update_macro(id),
            UpdateMacroOutcome::NothingObserved,
            "there is nothing to promote before a login has worked"
        );

        coordinator.handle_response(
            &fake,
            &get_step("https://target.test/account"),
            invalid_response(),
        );
        let outcome = coordinator.update_macro(id);
        let UpdateMacroOutcome::Updated { steps } = outcome else {
            panic!("expected Updated, got {outcome:?}");
        };
        assert_eq!(steps.len(), 2);
        // This run's one-time token must not have been baked into the stored macro.
        let stored = coordinator.rules()[0].1.login_macro.clone();
        assert_eq!(stored.items[1].step.url, "https://target.test/login?t={{csrf}}");
        assert_eq!(
            stored.items[1].step.body,
            Bytes::from_static(b"user=a&csrf={{csrf}}")
        );
        assert_eq!(
            stored.items[0].extract.len(),
            1,
            "the extraction survives the update"
        );
    }

    #[test]
    fn update_macro_records_what_the_run_actually_sent_including_a_url_that_moved() {
        // The point of the feature: the stored step is stale, the run followed the target's current
        // flow, and promoting it captures that rather than the recording.
        let fake = FakeSender::new();
        fake.script(
            "https://target.test/login",
            Ok(MacroResponse {
                status: 200,
                headers: vec![
                    ("Set-Cookie".into(), "session=s1".into()),
                    ("X-Auth".into(), "1".into()),
                ],
                body: Some(Bytes::new()),
            }),
        );
        fake.script("https://target.test/account", Ok(valid_response()));

        let coordinator = ReloginCoordinator::new();
        let id = coordinator
            .add_rule(SessionRuleSpec::new(
                "plain",
                Macro::of_steps(vec![MacroStep {
                    method: "POST".into(),
                    url: "https://target.test/login".into(),
                    // A recorded `Cookie` header the jar owns: it is stripped before the send, so it
                    // must not come back as part of what was observed either.
                    headers: vec![("Cookie".into(), "session=stale".into())],
                    body: Bytes::from_static(b"user=a"),
                }]),
                rule(),
            ))
            .expect("valid");
        coordinator.handle_response(
            &fake,
            &get_step("https://target.test/account"),
            invalid_response(),
        );

        let UpdateMacroOutcome::Updated { steps } = coordinator.update_macro(id) else {
            panic!("a successful login should be promotable");
        };
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].url, "https://target.test/login");
        assert_eq!(steps[0].body, Bytes::from_static(b"user=a"));
        assert!(
            steps[0]
                .headers
                .iter()
                .any(|(k, v)| k == "Cookie" && v == "session=stale"),
            "the step is recorded as the macro produced it, before the jar's cookie replaces this \
             one: {:?}",
            steps[0].headers
        );
    }

    #[test]
    fn update_macro_on_an_unknown_or_deleted_rule_says_so() {
        let coordinator = ReloginCoordinator::new();
        assert_eq!(coordinator.update_macro(42), UpdateMacroOutcome::NoSuchRule);
        let id = coordinator.add_rule(scoped("a", "a.test")).expect("valid");
        assert!(coordinator.remove_rule(id));
        assert_eq!(coordinator.update_macro(id), UpdateMacroOutcome::NoSuchRule);
    }

    #[test]
    fn only_a_successful_run_is_observed_for_promotion() {
        let fake = FakeSender::new();
        for _ in 0..3 {
            fake.script("https://target.test/login", Ok(invalid_response()));
        }
        let coordinator = ReloginCoordinator::new();
        let id = coordinator
            .add_rule(SessionRuleSpec::new(
                "never works",
                login_macro_of(&["https://target.test/login"]),
                rule(),
            ))
            .expect("valid");
        let outcome = coordinator.handle_response(
            &fake,
            &get_step("https://target.test/account"),
            invalid_response(),
        );
        assert_eq!(outcome, RecoveryOutcome::GaveUp { attempts: 3 });
        assert_eq!(
            coordinator.update_macro(id),
            UpdateMacroOutcome::NothingObserved,
            "promoting the steps of a run that never logged in would replace a stale macro with a \
             broken one"
        );
    }

    #[test]
    fn what_a_run_sent_is_forgotten_when_the_rule_is_replaced() {
        let fake = FakeSender::new();
        fake.script("https://a.test/login", Ok(valid_response()));
        fake.script("https://a.test/account", Ok(valid_response()));
        let coordinator = ReloginCoordinator::new();
        let id = coordinator.add_rule(scoped("a", "a.test")).expect("valid");
        coordinator.handle_response(
            &fake,
            &get_step("https://a.test/account"),
            invalid_response(),
        );
        coordinator
            .replace_rule(id, scoped("a-edited", "a.test"))
            .expect("valid");
        assert_eq!(
            coordinator.update_macro(id),
            UpdateMacroOutcome::NothingObserved,
            "what the previous macro sent does not describe the one that replaced it"
        );
    }

    #[test]
    fn sent_urls_are_recorded_in_order_so_a_substitution_is_visible_end_to_end() {
        // Guards the ordering the whole extraction feature depends on: the form page is fetched
        // before the login that needs its token.
        let fake = FakeSender::new();
        fake.script("https://target.test/login-form", Ok(form_page("t1")));
        fake.script("https://target.test/login?t=t1", Ok(valid_response()));
        fake.script("https://target.test/account", Ok(valid_response()));
        let coordinator = ReloginCoordinator::with_rules(vec![csrf_rule()]).expect("valid");
        coordinator.handle_response(
            &fake,
            &get_step("https://target.test/account"),
            invalid_response(),
        );
        assert_eq!(
            fake.sent_urls(),
            vec![
                "https://target.test/login-form",
                "https://target.test/login?t=t1",
                "https://target.test/account",
            ]
        );
    }
}
