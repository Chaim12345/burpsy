//! Bounded, collapsed re-login: run the recorded macro when the session drops, never loop on it,
//! and let concurrent observers of the same failure share one login instead of piling on.
//!
//! # The two failure modes this exists to prevent
//!
//! **Looping.** [`ValidityRule`] can say a response is invalid; nothing stops the *macro's own*
//! final response from being invalid too — wrong credentials, a target that started rejecting the
//! recorded flow, a CAPTCHA that appeared where it didn't before. Retrying such a macro forever is
//! both useless (the outcome will not change on its own) and actively harmful against a live
//! engagement target. [`ReloginCoordinator::new`]'s `max_attempts` bounds how many times the macro
//! itself is run, and [`RecoveryOutcome::GaveUp`] carries exactly how many that was — stopping
//! with nothing to show for it is the "partial result that looks complete" defect this project
//! treats as a defect even when the process technically terminates.
//!
//! **Piling on.** If N requests observe session loss at once — realistic under any concurrency —
//! reacting to each independently fires N logins against the target. [`ReloginCoordinator::ensure_logged_in`]
//! is a single-flight: the first caller to notice invalidity runs the macro; every other caller
//! that arrives while that is in progress waits for the same attempt and shares its result, rather
//! than starting one of its own. See that method's doc comment for how.

use crate::cookie::{CookieJar, host_of};
use crate::step::{MacroResponse, MacroSender, MacroStep};
use crate::validity::{SessionValidity, ValidityRule};
use parking_lot::{Condvar, Mutex};
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;

/// A recorded sequence of steps that ends, if it works, with an authenticated session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Macro {
    pub steps: Vec<MacroStep>,
}

/// Three total attempts: enough to absorb one transient failure (a redirect race, a target that
/// needed a moment to recover) without turning a genuinely dead credential into a long stall
/// against a live target. SESSION-04 asks the operator to state the limit, so [`ReloginCoordinator::new`]
/// takes it explicitly; this is offered as a sane default for a caller to pass, not a hidden
/// ceiling this module falls back to on its own.
pub const DEFAULT_MAX_LOGIN_ATTEMPTS: u32 = 3;

/// One macro step that could not be sent at all — a transport failure, not a session-invalid
/// response. Carries which step, so "the macro failed" names a place rather than just happening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroStepFailure {
    pub step_index: usize,
    pub error: String,
}

impl std::fmt::Display for MacroStepFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "login macro step {} could not be sent: {}",
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
    /// A step failed to send. Attempts stop immediately rather than retrying a target that is not
    /// answering at all — see the module docs on why a transport failure is not treated as "try
    /// again", the way an invalid response is.
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
    /// The response handed in already satisfied the validity rule; no re-login was attempted.
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
    /// The login macro itself could not be sent.
    MacroFailed {
        attempt: u32,
        failure: MacroStepFailure,
    },
    /// Re-login succeeded, but resending the original request afterward failed to send.
    RetryFailed { login_attempts: u32, error: String },
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

/// Runs a recorded login [`Macro`] when a response fails the operator's [`ValidityRule`], bounded
/// and collapsed across concurrent callers. See the module docs for why both of those matter.
pub struct ReloginCoordinator {
    login_macro: Macro,
    rule: ValidityRule,
    max_attempts: u32,
    jar: Arc<Mutex<CookieJar>>,
    /// `Some` while a login is in flight; `None` once it has finished and its result observed.
    /// Cleared after each run — rather than cached forever — so a *later*, unrelated session drop
    /// starts a fresh attempt instead of replaying a stale result.
    current: Mutex<Option<Arc<LoginRun>>>,
}

impl ReloginCoordinator {
    pub fn new(login_macro: Macro, rule: ValidityRule, max_attempts: u32) -> Self {
        Self {
            login_macro,
            rule,
            max_attempts,
            jar: Arc::new(Mutex::new(CookieJar::new())),
            current: Mutex::new(None),
        }
    }

    /// The cookie jar this coordinator reads and writes. Cloning the `Arc` and handing it to
    /// another sender is how SESSION-03's "one jar shared across tools" gets wired up — this
    /// crate provides the jar and uses it faithfully, but does not itself know about Proxy,
    /// Repeater, or Intruder, so it cannot do that wiring; that happens where those tools do.
    pub fn shared_jar(&self) -> Arc<Mutex<CookieJar>> {
        self.jar.clone()
    }

    /// Evaluate `response` against the validity rule and, if it is not valid, recover: run the
    /// login macro (once, or share an already-running one) and retry `original`.
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
        if self.rule.evaluate(&response) == SessionValidity::Valid {
            return RecoveryOutcome::AlreadyValid;
        }
        self.recover(sender, original)
    }

    fn recover(&self, sender: &dyn MacroSender, original: &MacroStep) -> RecoveryOutcome {
        match self.ensure_logged_in(sender) {
            LoginOutcome::Succeeded { attempts } => match self.send_with_jar(sender, original) {
                Ok(response) => match self.rule.evaluate(&response) {
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

    /// Single-flight: the first caller to arrive while no login is running installs a fresh
    /// [`LoginRun`] and becomes its leader, actually calling [`Self::run_with_retries`]. Everyone
    /// who arrives while that run is still in `current` — before or after the leader's send calls
    /// start — gets the same `LoginRun` back and blocks in [`LoginRun::wait`] instead of starting
    /// one of its own, which is "N concurrent observers, one login" without any request beyond the
    /// first ever reaching `sender`.
    fn ensure_logged_in(&self, sender: &dyn MacroSender) -> LoginOutcome {
        let (run, is_leader) = {
            let mut current = self.current.lock();
            match current.as_ref() {
                Some(existing) => (existing.clone(), false),
                None => {
                    let fresh = Arc::new(LoginRun::new());
                    *current = Some(fresh.clone());
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
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| self.run_with_retries(sender)))
            .unwrap_or_else(|_| LoginOutcome::MacroFailed {
                attempt: 0,
                failure: MacroStepFailure {
                    step_index: 0,
                    error: "login macro panicked instead of returning an error".to_string(),
                },
            });

        run.publish(outcome.clone());
        // Make room for the *next* session drop to start a fresh run instead of reusing this one
        // forever. Guarded by identity rather than done unconditionally so a future change that
        // adds another mutator of `current` fails loudly instead of clobbering a run it did not
        // start.
        let mut current = self.current.lock();
        if matches!(current.as_ref(), Some(c) if Arc::ptr_eq(c, &run)) {
            *current = None;
        }
        drop(current);

        outcome
    }

    fn run_with_retries(&self, sender: &dyn MacroSender) -> LoginOutcome {
        for attempt in 1..=self.max_attempts {
            match self.run_macro_once(sender) {
                Ok(response) => {
                    if self.rule.evaluate(&response) == SessionValidity::Valid {
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
            attempts: self.max_attempts,
        }
    }

    fn run_macro_once(&self, sender: &dyn MacroSender) -> Result<MacroResponse, MacroStepFailure> {
        if self.login_macro.steps.is_empty() {
            return Err(MacroStepFailure {
                step_index: 0,
                error: "login macro has no steps to run".to_string(),
            });
        }
        let mut last = None;
        for (step_index, step) in self.login_macro.steps.iter().enumerate() {
            match self.send_with_jar(sender, step) {
                Ok(response) => last = Some(response),
                Err(error) => return Err(MacroStepFailure { step_index, error }),
            }
        }
        Ok(last.expect("steps is non-empty, checked above"))
    }

    /// Send `step` with the jar's current cookie for its host attached, then absorb any
    /// `Set-Cookie` headers the response carries back into the jar. Used for both the macro's own
    /// steps and the retried original request, which is how a session cookie a login step sets
    /// reaches the request that needed it.
    fn send_with_jar(
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
        Macro {
            steps: urls.iter().map(|u| get_step(u)).collect(),
        }
    }

    #[test]
    fn a_valid_response_does_not_trigger_a_login() {
        let fake = FakeSender::new();
        let coordinator =
            ReloginCoordinator::new(login_macro_of(&["https://target.test/login"]), rule(), 3);
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

        let coordinator = ReloginCoordinator::new(
            login_macro_of(&["https://target.test/login", "https://target.test/dashboard"]),
            rule(),
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
        let coordinator =
            ReloginCoordinator::new(login_macro_of(&["https://target.test/login"]), rule(), 3);
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
        let coordinator =
            ReloginCoordinator::new(login_macro_of(&["https://target.test/login"]), rule(), 2);
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
        let coordinator =
            ReloginCoordinator::new(login_macro_of(&["https://target.test/login"]), rule(), 3);
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

        let coordinator =
            ReloginCoordinator::new(login_macro_of(&["https://target.test/login"]), rule(), 3);
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
        // finish and clear `current` before a slower-to-schedule thread ever checks it — a real
        // send has network latency to fill exactly this window; this stands in for that so the
        // "one login, not N" assertion below is deterministic rather than a race against the OS
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

        let coordinator = Arc::new(ReloginCoordinator::new(
            login_macro_of(&["https://target.test/login"]),
            rule(),
            3,
        ));
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
}
