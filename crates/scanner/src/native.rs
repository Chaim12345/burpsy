//! The two native passive checks, and where they hook into [`crate::PassiveScanner`].
//!
//! # Why these are not in `PassiveScanner::passive`
//!
//! That field is a `Vec<Check>` — parsed BChecks, dispatched through
//! [`burpsy_bcheck::run_passive`]. SCAN-01 and SCAN-02 are not expressible in the DSL: one needs
//! version arithmetic against a 683-entry dataset, the other needs HMAC computation against a
//! wordlist. They cannot be parsed into a `Check`, so they cannot live in that vector, and a test
//! in `lib.rs` additionally asserts no *loaded check* shares a name with one of Burp's catalogued
//! issues — while these two deliberately use Burp's exact issue names so `enrich` attaches Burp's
//! own remediation.
//!
//! So they are a separate collection, dispatched from the same place in
//! [`crate::PassiveScanner::scan_message`], recorded through the same
//! [`crate::PassiveScanner::record`], and deduplicated by the same `FindingStore`. The registration
//! path is shared; only the evaluation is different.
//!
//! # Why "off by default"
//!
//! [`NativeChecks::none`] is the default, so an existing caller's behaviour does not change until it
//! asks for these. A check that appeared silently would make every existing coverage figure in the
//! project wrong by one, and this crate's whole argument is that its coverage figures are exact.
//!
//! # Why the coverage is reported per check, not merged into one number
//!
//! SCAN-01 can be *unavailable* (no dataset) and SCAN-02 can be *truncated* (budget spent
//! mid-wordlist). Those are different failures with different remedies, and collapsing them into a
//! shared "ran / did not run" flag would throw away exactly the information that keeps a zero-finding
//! report honest. Both live under [`NativeCoverage`], which hangs off
//! [`crate::CoverageReport`] so anything serialising coverage gets them without being changed.

use burpsy_bcheck::Finding;
use burpsy_core::StoredMessage;

use crate::js_vulns::{JsCoverage, JsLibraryCheck};
use crate::jwt_weak::{JwtCoverage, JwtWeakSecretCheck};

/// The native check set held by a [`crate::PassiveScanner`].
#[derive(Default)]
pub struct NativeChecks {
    js: Option<JsLibraryCheck>,
    jwt: Option<JwtWeakSecretCheck>,
}

/// Runtime coverage for whichever native checks are enabled.
///
/// `Option` rather than a flag plus zeroed counters: "SCAN-01 is not enabled" and "SCAN-01 ran and
/// found nothing" must not render the same way, and a zeroed struct would let them.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct NativeCoverage {
    /// SCAN-01, when enabled.
    pub js_libraries: Option<JsCoverage>,
    /// SCAN-02, when enabled.
    pub jwt_weak_secret: Option<JwtCoverage>,
}

impl NativeCoverage {
    /// True when an enabled native check cannot back a clean result — no dataset, an unidentifiable
    /// asset, a token never attacked, a wordlist cut short. A reporting caller that shows zero
    /// findings must consult this first.
    pub fn inconclusive(&self) -> bool {
        self.js_libraries.as_ref().is_some_and(|c| c.inconclusive())
            || self
                .jwt_weak_secret
                .as_ref()
                .is_some_and(|c| c.inconclusive())
    }

    /// One line per enabled check, for an operator-facing summary.
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(js) = &self.js_libraries {
            out.push(format!("{}: {}", JsLibraryCheck::NAME, js.dataset.summary()));
        }
        if let Some(jwt) = &self.jwt_weak_secret {
            out.push(format!("{}: {}", JwtWeakSecretCheck::NAME, jwt.summary()));
        }
        out
    }
}

impl NativeChecks {
    /// No native checks. The default, so wiring these in is always an explicit decision.
    pub fn none() -> Self {
        NativeChecks::default()
    }

    /// Both checks with their vendored data: the retire.js corpus compiled into this binary and the
    /// 51-entry bundled JWT wordlist.
    pub fn vendored() -> Self {
        NativeChecks {
            js: Some(JsLibraryCheck::vendored()),
            jwt: Some(JwtWeakSecretCheck::bundled()),
        }
    }

    pub fn with_js(mut self, c: JsLibraryCheck) -> Self {
        self.js = Some(c);
        self
    }

    pub fn with_jwt(mut self, c: JwtWeakSecretCheck) -> Self {
        self.jwt = Some(c);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.js.is_none() && self.jwt.is_none()
    }

    /// How many native checks are enabled — the figure a load report adds to its check count.
    pub fn len(&self) -> usize {
        usize::from(self.js.is_some()) + usize::from(self.jwt.is_some())
    }

    /// Run every enabled check over one response.
    ///
    /// `request` is the request that produced `resp` when the caller has it. SCAN-02 needs it for
    /// `Authorization` headers and counts its absence rather than passing over it silently.
    pub(crate) fn scan(
        &self,
        resp: &StoredMessage,
        request: Option<&StoredMessage>,
        path: &str,
    ) -> Vec<Finding> {
        let mut out = Vec::new();
        if let Some(js) = &self.js {
            let ct = resp
                .header("Content-Type")
                .map(|v| String::from_utf8_lossy(&v).into_owned());
            let body = resp.body();
            out.extend(js.scan(path, ct.as_deref(), &body));
        }
        if let Some(jwt) = &self.jwt {
            out.extend(jwt.scan(resp, request));
        }
        out
    }

    pub(crate) fn coverage(&self) -> NativeCoverage {
        NativeCoverage {
            js_libraries: self.js.as_ref().map(|c| c.coverage()),
            jwt_weak_secret: self.jwt.as_ref().map(|c| c.coverage()),
        }
    }
}
