//! SCAN-02 — JWTs signed with a weak HMAC secret, proved by verifying the signature.
//!
//! # The only finding this check will make
//!
//! A candidate secret from the wordlist recomputes the token's signature exactly. Nothing else
//! counts. A short secret, a suspicious `kid`, a token that "looks" weak — none of those are
//! findings here, because none of them is evidence that anyone can forge a token. That is why the
//! confidence is always `Certain`: the check has either reproduced the signature or it has not.
//!
//! # Scope: HMAC only, and the rest is counted
//!
//! `HS256`/`HS384`/`HS512` are the algorithms whose signing key is a shared secret, so a wordlist
//! attack is the relevant attack at all. `RS*`/`ES*`/`PS*` are asymmetric and `alg: none` is a
//! different vulnerability with its own catalogued definition. Those tokens are **counted as
//! skipped**, per algorithm, in [`JwtCoverage::out_of_scope_algorithms`]. Leaving them out of the
//! report would let "no weak secrets found" cover tokens this check never attacked.
//!
//! # The bound, and why a truncated attack is not a clean result
//!
//! This is brute force, so the work is `distinct tokens × wordlist entries` HMAC computations.
//! [`JwtWeakSecretCheck::with_budget`] caps that at `max_hmac_attempts` per response. When the cap
//! stops a token part-way, the token is [`TokenOutcome::Abandoned`]: `tokens_abandoned` goes up,
//! [`JwtCoverage::truncated`] becomes true, and the token is **not** counted as exhausted. Only a
//! token tested against every entry in the wordlist is `tokens_exhausted`, and even that is a claim
//! about the wordlist rather than about the secret — which is why
//! [`JwtCoverage::wordlist`] names the list and its exact size in every report. "No weak secrets
//! found against 51 entries" and "…against 10 million entries" are different claims, and stating
//! only the conclusion is how a truncated brute force gets read as a clean bill of health.
//!
//! # Deduplication
//!
//! Keyed on the signing input, so a session token seen on 200 pages is cracked once. Same insight
//! as `FindingStore`'s insertion-time dedup and the audit ledger's `AlreadyCovered`. The table is
//! capped at [`MAX_TRACKED_TOKENS`]: past that, tokens are still tested (never skipped) but no
//! longer remembered, and [`JwtCoverage::dedup_capacity_reached`] says so — the honest failure
//! direction is repeated work, not unexamined tokens.
//!
//! # Where the wordlist comes from
//!
//! [`Wordlist::bundled`] is 51 entries, each one verified present in Burp Suite 2026.7.1's shipped
//! `resources/Scanner/jwt_secrets.txt` (sha256
//! `0e451733b80f7cf722f6e33b82e4e6c7ca4b66c8407da0a7e92badd445d52fb2`, 103,975 entries) on
//! 2026-07-28. Burp's whole list is deliberately *not* vendored: a megabyte of password dump for a
//! check whose real hit rate comes from a few dozen framework defaults is a poor trade, and
//! [`Wordlist::load`] takes the full file — or any other — from an operator who wants it.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use burpsy_bcheck::{Confidence, Finding, Severity};
use burpsy_core::StoredMessage;
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use sha2::{Sha256, Sha384, Sha512};

/// The issue name, an exact match for Burp's catalogued issue (`catalog_data.rs`, declared type
/// index 2099459) so [`crate::enrich`] attaches Burp's own remediation.
const ISSUE: &str = "JWT weak HMAC secret";

/// HMAC computations one response may cost. 200,000 short-input HMAC-SHA256 computations measured
/// at roughly 0.15 s on the development machine, which is affordable off the proxy hot path and
/// nowhere near affordable on it — which is the other reason scanning does not run there.
pub const DEFAULT_MAX_HMAC_ATTEMPTS: u64 = 200_000;

/// Distinct signing inputs remembered for deduplication. A cap rather than an unbounded map because
/// this crate's whole thesis is that nothing may grow without limit with traffic volume.
pub const MAX_TRACKED_TOKENS: usize = 65_536;

/// Longest token this check will hash. A token above this is refused *before* any HMAC work and
/// counted: a multi-megabyte "token" is a denial of service against the scanner, not a credential.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;

/// Secrets that are documented framework defaults, canonical documentation examples, or the
/// perennial placeholders. Every entry was verified present in Burp's shipped `jwt_secrets.txt` —
/// see the module docs — so this list is a stated subset of a known corpus rather than a guess at
/// what a weak secret looks like.
const BUNDLED: &[&str] = &[
    "secret",
    "Secret",
    "SECRET",
    "secretkey",
    "secret_key",
    "secretKey",
    "mysecret",
    "my-secret",
    "supersecret",
    "super-secret",
    "topsecret",
    "changeme",
    "changeit",
    "password",
    "Password",
    "passw0rd",
    "123456",
    "qwerty",
    "admin",
    "test",
    "jwt",
    "jwtsecret",
    "jwt_secret",
    "jwtSecret",
    "jwt-secret",
    "your-256-bit-secret",
    "your_secret_key",
    "keyboard cat",
    "default",
    "dev",
    "development",
    "token",
    "shhhh",
    "s3cr3t",
    "letmein",
    "abc123",
    "1234567890",
    "null",
    "undefined",
    "example",
    "hello",
    "iloveyou",
    "root",
    "JWT_SECRET",
    "asdf",
    "foo",
    "bar",
    "secretsecret",
    "mySuperSecretKey",
    "your-secret-key",
    "thisisasecret",
];

/// The HMAC algorithms a wordlist attack applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HmacAlg {
    Hs256,
    Hs384,
    Hs512,
}

impl HmacAlg {
    fn parse(alg: &str) -> Option<Self> {
        match alg {
            "HS256" => Some(HmacAlg::Hs256),
            "HS384" => Some(HmacAlg::Hs384),
            "HS512" => Some(HmacAlg::Hs512),
            _ => None,
        }
    }

    /// Recompute and compare in constant time. `new_from_slice` accepts any key length, which is
    /// what makes short weak secrets testable at all.
    ///
    /// Written out per algorithm rather than generically: the generic form needs `digest`'s
    /// associated-type bounds spelled out in the signature, which is a dependency and four lines of
    /// where-clause to save nine lines of body.
    fn verifies(self, key: &[u8], signing_input: &[u8], signature: &[u8]) -> bool {
        macro_rules! check {
            ($d:ty) => {{
                match Hmac::<$d>::new_from_slice(key) {
                    Ok(mut mac) => {
                        mac.update(signing_input);
                        mac.verify_slice(signature).is_ok()
                    }
                    Err(_) => false,
                }
            }};
        }
        match self {
            HmacAlg::Hs256 => check!(Sha256),
            HmacAlg::Hs384 => check!(Sha384),
            HmacAlg::Hs512 => check!(Sha512),
        }
    }
}

/// A candidate-secret list, with the identity that has to appear beside any negative result.
#[derive(Debug, Clone)]
pub struct Wordlist {
    name: String,
    source: String,
    entries: Vec<String>,
}

/// How a report names the wordlist. Without this, "no weak secrets found" is an unqualified claim.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct WordlistId {
    pub name: String,
    pub source: String,
    pub entries: usize,
}

impl Wordlist {
    /// The compiled-in default. See the module docs for its provenance.
    pub fn bundled() -> Self {
        Wordlist {
            name: "burpsy bundled JWT secrets".into(),
            source: "subset of Burp Suite 2026.7.1 resources/Scanner/jwt_secrets.txt, verified 2026-07-28"
                .into(),
            entries: BUNDLED.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// One secret per line, blank lines dropped. Duplicates are dropped too, so the reported entry
    /// count is the number of *distinct* secrets actually tried rather than the file's line count —
    /// the budget is spent on distinct work and the number beside a negative result should describe
    /// the same thing.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut seen = HashSet::new();
        let entries: Vec<String> = raw
            .lines()
            .map(|l| l.trim_end_matches('\r'))
            .filter(|l| !l.is_empty())
            .filter(|l| seen.insert(l.to_string()))
            .map(str::to_string)
            .collect();
        if entries.is_empty() {
            return Err(format!("{} contains no candidate secrets", path.display()));
        }
        Ok(Wordlist {
            name: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string()),
            source: path.display().to_string(),
            entries,
        })
    }

    /// Build from explicit entries, for tests and for a caller assembling a list in memory.
    pub fn from_entries(name: &str, source: &str, entries: &[&str]) -> Self {
        Wordlist {
            name: name.into(),
            source: source.into(),
            entries: entries.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn id(&self) -> WordlistId {
        WordlistId {
            name: self.name.clone(),
            source: self.source.clone(),
            entries: self.entries.len(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Where a token was found. Part of the finding detail because a token in a `Set-Cookie` and a
/// token pasted into a response body are different mistakes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Location {
    ResponseBody,
    ResponseHeader(String),
    RequestHeader(String),
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Location::ResponseBody => write!(f, "the response body"),
            Location::ResponseHeader(n) => write!(f, "response header {n}"),
            Location::RequestHeader(n) => write!(f, "request header {n}"),
        }
    }
}

/// A JWS-shaped string found in traffic, before its header has been looked at.
#[derive(Debug, Clone)]
struct RawToken {
    signing_input: String,
    signature_b64: String,
    header_b64: String,
    where_found: Location,
}

/// What happened to one distinct token. Every token lands in exactly one of these, which is what
/// makes the counters in [`JwtCoverage`] sum to `tokens_distinct`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenOutcome {
    /// A wordlist entry reproduced the signature.
    Cracked,
    /// Tested against every wordlist entry, no match. Evidence, bounded by the wordlist.
    Exhausted,
    /// The attempt hit the HMAC budget before the wordlist ran out. **Not** a clean result.
    Abandoned,
    /// Not an HMAC algorithm: nothing here to attack with a wordlist.
    OutOfScope,
    /// Header would not decode, or the token was too large to hash. Refused, not guessed at.
    Refused,
}

/// SCAN-02's record of what it attacked and what it declined to.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct JwtCoverage {
    /// Which list the negative results are relative to.
    pub wordlist: WordlistId,
    /// The per-response HMAC cap in force.
    pub max_hmac_attempts: u64,
    pub responses: u64,
    /// Token-shaped strings seen, including repeats.
    pub tokens_seen: u64,
    /// Distinct signing inputs actually considered.
    pub tokens_distinct: u64,
    /// Repeats collapsed by the dedup table.
    pub tokens_already_covered: u64,
    pub tokens_cracked: u64,
    /// Tested against the whole wordlist with no match.
    pub tokens_exhausted: u64,
    /// Gave up part-way through the wordlist. These are the tokens a clean report must not cover.
    pub tokens_abandoned: u64,
    /// Not HMAC-signed, so out of this check's scope entirely.
    pub tokens_out_of_scope: u64,
    /// Header undecodable, or larger than [`MAX_TOKEN_BYTES`].
    pub tokens_refused: u64,
    /// HMAC computations performed.
    pub hmac_attempts: u64,
    /// True once any token was abandoned mid-wordlist.
    pub truncated: bool,
    /// The dedup table stopped remembering tokens, so some work may have been repeated. Counted
    /// because the alternative reading — that tokens were skipped — would be much worse and a
    /// reader cannot tell the two apart without being told.
    pub dedup_capacity_reached: bool,
    /// Responses scanned with no matching request message available, so request-side tokens
    /// (`Authorization: Bearer …`) were not seen for them.
    pub requests_unavailable: u64,
    /// Algorithms seen and skipped, with counts — `RS256`, `none`, and anything else asymmetric.
    pub out_of_scope_algorithms: Vec<(String, u64)>,
}

impl JwtCoverage {
    /// Every distinct token lands in exactly one outcome, so this must equal `tokens_distinct`.
    /// A tested invariant: a future outcome added without being counted here would otherwise
    /// silently shrink the denominator behind every claim this check makes.
    pub fn accounted(&self) -> u64 {
        self.tokens_cracked
            + self.tokens_exhausted
            + self.tokens_abandoned
            + self.tokens_out_of_scope
            + self.tokens_refused
    }

    /// True when a zero-finding result does not mean "no weak secrets".
    pub fn inconclusive(&self) -> bool {
        self.truncated || self.tokens_refused > 0 || self.tokens_out_of_scope > 0
    }

    /// One line an operator can act on, naming the wordlist and every give-up.
    pub fn summary(&self) -> String {
        format!(
            "{} distinct JWTs against {} ({} entries): {} cracked, {} exhausted, {} abandoned mid-wordlist, \
             {} out of scope (non-HMAC), {} refused; {} HMAC attempts",
            self.tokens_distinct,
            self.wordlist.name,
            self.wordlist.entries,
            self.tokens_cracked,
            self.tokens_exhausted,
            self.tokens_abandoned,
            self.tokens_out_of_scope,
            self.tokens_refused,
            self.hmac_attempts,
        )
    }
}

/// SCAN-02 as a passive check.
pub struct JwtWeakSecretCheck {
    wordlist: Wordlist,
    max_attempts: u64,
    /// Signing inputs already resolved, so a token seen again is not re-attacked.
    seen: RwLock<HashSet<String>>,
    dedup_full: AtomicBool,
    truncated: AtomicBool,
    responses: AtomicU64,
    tokens_seen: AtomicU64,
    tokens_distinct: AtomicU64,
    already_covered: AtomicU64,
    cracked: AtomicU64,
    exhausted: AtomicU64,
    abandoned: AtomicU64,
    out_of_scope: AtomicU64,
    refused: AtomicU64,
    attempts: AtomicU64,
    requests_unavailable: AtomicU64,
    algs: RwLock<BTreeMap<String, u64>>,
}

impl JwtWeakSecretCheck {
    pub const NAME: &'static str = "JWT weak HMAC secret (SCAN-02)";

    /// The bundled wordlist at the default budget.
    pub fn bundled() -> Self {
        Self::with_budget(Wordlist::bundled(), DEFAULT_MAX_HMAC_ATTEMPTS)
    }

    pub fn new(wordlist: Wordlist) -> Self {
        Self::with_budget(wordlist, DEFAULT_MAX_HMAC_ATTEMPTS)
    }

    /// An explicit HMAC budget per response. Zero means no token can be tested at all, and every
    /// token is then reported abandoned rather than clean.
    pub fn with_budget(wordlist: Wordlist, max_hmac_attempts: u64) -> Self {
        JwtWeakSecretCheck {
            wordlist,
            max_attempts: max_hmac_attempts,
            seen: RwLock::new(HashSet::new()),
            dedup_full: AtomicBool::new(false),
            truncated: AtomicBool::new(false),
            responses: AtomicU64::new(0),
            tokens_seen: AtomicU64::new(0),
            tokens_distinct: AtomicU64::new(0),
            already_covered: AtomicU64::new(0),
            cracked: AtomicU64::new(0),
            exhausted: AtomicU64::new(0),
            abandoned: AtomicU64::new(0),
            out_of_scope: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            attempts: AtomicU64::new(0),
            requests_unavailable: AtomicU64::new(0),
            algs: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn coverage(&self) -> JwtCoverage {
        JwtCoverage {
            wordlist: self.wordlist.id(),
            max_hmac_attempts: self.max_attempts,
            responses: self.responses.load(Ordering::Relaxed),
            tokens_seen: self.tokens_seen.load(Ordering::Relaxed),
            tokens_distinct: self.tokens_distinct.load(Ordering::Relaxed),
            tokens_already_covered: self.already_covered.load(Ordering::Relaxed),
            tokens_cracked: self.cracked.load(Ordering::Relaxed),
            tokens_exhausted: self.exhausted.load(Ordering::Relaxed),
            tokens_abandoned: self.abandoned.load(Ordering::Relaxed),
            tokens_out_of_scope: self.out_of_scope.load(Ordering::Relaxed),
            tokens_refused: self.refused.load(Ordering::Relaxed),
            hmac_attempts: self.attempts.load(Ordering::Relaxed),
            truncated: self.truncated.load(Ordering::Relaxed),
            dedup_capacity_reached: self.dedup_full.load(Ordering::Relaxed),
            requests_unavailable: self.requests_unavailable.load(Ordering::Relaxed),
            out_of_scope_algorithms: self
                .algs
                .read()
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
        }
    }

    /// Scan one response, plus the request that produced it when the caller has it.
    ///
    /// `request` is `Option` because [`crate::PassiveScanner::scan_message`] is handed a response
    /// alone. Passing `None` is legitimate, but it means `Authorization` headers were never looked
    /// at, so it increments [`JwtCoverage::requests_unavailable`] instead of passing silently.
    pub fn scan(&self, resp: &StoredMessage, request: Option<&StoredMessage>) -> Vec<Finding> {
        self.responses.fetch_add(1, Ordering::Relaxed);
        if request.is_none() {
            self.requests_unavailable.fetch_add(1, Ordering::Relaxed);
        }

        let mut raw = Vec::new();
        collect(resp, false, &mut raw);
        if let Some(req) = request {
            collect(req, true, &mut raw);
        }
        self.tokens_seen
            .fetch_add(raw.len() as u64, Ordering::Relaxed);

        let mut budget = self.max_attempts;
        let mut out = Vec::new();
        for t in raw {
            if !self.claim(&t.signing_input) {
                self.already_covered.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            self.tokens_distinct.fetch_add(1, Ordering::Relaxed);
            match self.attack(&t, &mut budget) {
                (TokenOutcome::Cracked, Some(secret)) => {
                    self.cracked.fetch_add(1, Ordering::Relaxed);
                    out.push(self.finding(&t, &secret));
                }
                (TokenOutcome::Exhausted, _) => {
                    self.exhausted.fetch_add(1, Ordering::Relaxed);
                }
                (TokenOutcome::Abandoned, _) => {
                    self.abandoned.fetch_add(1, Ordering::Relaxed);
                    self.truncated.store(true, Ordering::Relaxed);
                }
                (TokenOutcome::OutOfScope, _) => {
                    self.out_of_scope.fetch_add(1, Ordering::Relaxed);
                }
                (TokenOutcome::Refused, _) | (TokenOutcome::Cracked, None) => {
                    self.refused.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        out
    }

    /// Claim a signing input for attack, returning false when it was already resolved.
    ///
    /// Past [`MAX_TRACKED_TOKENS`] the table stops growing and every token is claimed — repeating
    /// work rather than skipping tokens, which is the failure direction that cannot produce a false
    /// negative.
    fn claim(&self, signing_input: &str) -> bool {
        let mut seen = self.seen.write();
        if seen.contains(signing_input) {
            return false;
        }
        if seen.len() >= MAX_TRACKED_TOKENS {
            self.dedup_full.store(true, Ordering::Relaxed);
            return true;
        }
        seen.insert(signing_input.to_string());
        true
    }

    /// Run the wordlist against one token, spending from `budget`.
    fn attack(&self, t: &RawToken, budget: &mut u64) -> (TokenOutcome, Option<String>) {
        if t.signing_input.len() + t.signature_b64.len() + 1 > MAX_TOKEN_BYTES {
            return (TokenOutcome::Refused, None);
        }
        let Some(header) = b64url_decode(&t.header_b64) else {
            return (TokenOutcome::Refused, None);
        };
        let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header) else {
            return (TokenOutcome::Refused, None);
        };
        let Some(alg) = header.get("alg").and_then(|a| a.as_str()) else {
            return (TokenOutcome::Refused, None);
        };
        let Some(alg) = HmacAlg::parse(alg) else {
            *self.algs.write().entry(alg.to_string()).or_insert(0) += 1;
            return (TokenOutcome::OutOfScope, None);
        };
        let Some(signature) = b64url_decode(&t.signature_b64) else {
            return (TokenOutcome::Refused, None);
        };

        for candidate in &self.wordlist.entries {
            if *budget == 0 {
                return (TokenOutcome::Abandoned, None);
            }
            *budget -= 1;
            self.attempts.fetch_add(1, Ordering::Relaxed);
            if alg.verifies(candidate.as_bytes(), t.signing_input.as_bytes(), &signature) {
                return (TokenOutcome::Cracked, Some(candidate.clone()));
            }
        }
        (TokenOutcome::Exhausted, None)
    }

    fn finding(&self, t: &RawToken, secret: &str) -> Finding {
        Finding {
            check_name: Self::NAME.to_string(),
            issue_name: Some(ISSUE.to_string()),
            severity: Severity::High,
            confidence: Confidence::Certain,
            detail: Some(format!(
                "A JWT found in {} is signed with the secret {secret:?}, taken from {} ({} entries). \
                 The signature was recomputed with that secret and matched, so anyone holding the \
                 wordlist can mint tokens for this application. Signing input: {}.",
                t.where_found,
                self.wordlist.name,
                self.wordlist.entries.len(),
                elide(&t.signing_input),
            )),
            // Left to `enrich`: Burp's catalogued definition for this exact issue name carries the
            // real remediation text.
            remediation: None,
        }
    }
}

/// Shorten a signing input for a finding detail. A finding is a report, not a copy of the traffic —
/// the store already holds the bytes and the finding carries the message id.
fn elide(s: &str) -> String {
    if s.len() <= 96 {
        return s.to_string();
    }
    format!("{}…{} ({} bytes)", &s[..48], &s[s.len() - 16..], s.len())
}

/// Pull every JWS-shaped string out of one message's headers and body.
fn collect(msg: &StoredMessage, is_request: bool, out: &mut Vec<RawToken>) {
    for h in &msg.shape.headers {
        let name = msg.text(h.name);
        let value = msg.text(h.value);
        let at = if is_request {
            Location::RequestHeader(name)
        } else {
            Location::ResponseHeader(name)
        };
        scan_text(&value, &at, out);
    }
    if !is_request {
        let body = msg.body();
        if let Ok(text) = std::str::from_utf8(&body) {
            scan_text(text, &Location::ResponseBody, out);
        }
    }
}

/// Find `header.payload.signature` triples.
///
/// Anchored on `eyJ` — the base64url of `{"` — rather than on a general three-segment pattern,
/// because "three dot-separated base64url runs" also describes plenty of filenames and version
/// strings, and every one of those would cost a base64 decode and a JSON parse to reject.
///
/// A candidate is refused rather than trimmed if its run does not have exactly three segments: a
/// five-segment JWE is a different thing, and silently taking its first three parts would produce a
/// signature check against bytes that are not a signature.
fn scan_text(hay: &str, at: &Location, out: &mut Vec<RawToken>) {
    let bytes = hay.as_bytes();
    let mut i = 0usize;
    while let Some(rel) = hay[i..].find("eyJ") {
        let start = i + rel;
        // Mid-token match: the byte before is part of the same base64url run, so this "eyJ" is not
        // the start of a header segment.
        if start > 0 && is_segment_body(bytes[start - 1]) {
            i = start + 3;
            continue;
        }
        let mut end = start;
        while end < bytes.len() && (is_segment_body(bytes[end]) || bytes[end] == b'.' || bytes[end] == b'=')
        {
            end += 1;
        }
        let run = hay[start..end].trim_end_matches('.');
        let parts: Vec<&str> = run.split('.').collect();
        if parts.len() == 3 && !parts.iter().any(|p| p.is_empty()) {
            out.push(RawToken {
                signing_input: format!("{}.{}", parts[0], parts[1]),
                signature_b64: parts[2].to_string(),
                header_b64: parts[0].to_string(),
                where_found: at.clone(),
            });
        }
        i = end.max(start + 3);
    }
}

/// The base64url alphabet proper.
///
/// `=` is deliberately excluded: it is tolerated *inside* a segment as padding, but a `=` before
/// `eyJ` is `cookie=eyJ…` or `token=eyJ…` — the most common way a token appears in real traffic —
/// and treating it as part of a preceding token skipped every one of them.
fn is_segment_body(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Decode unpadded base64url, refusing anything that is not.
///
/// Padding is tolerated because real deployments emit it despite RFC 7515 forbidding it, but a
/// character outside the alphabet, or a length that cannot be a base64 encoding at all, is a
/// refusal: a partial decode would hand a truncated signature to the comparison.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    if s.is_empty() || s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::{Direction, TrafficStore};
    use bytes::Bytes;

    fn b64url(bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            let take = chunk.len() + 1;
            for i in 0..take {
                out.push(A[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            }
        }
        out
    }

    /// A real HS256/384/512 token signed with `secret`.
    fn token(alg: &str, secret: &str) -> String {
        let header = b64url(format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#).as_bytes());
        let payload = b64url(br#"{"sub":"1234567890","name":"burpsy"}"#);
        let signing_input = format!("{header}.{payload}");
        let sig = match alg {
            "HS384" => {
                let mut m = Hmac::<Sha384>::new_from_slice(secret.as_bytes()).unwrap();
                m.update(signing_input.as_bytes());
                m.finalize().into_bytes().to_vec()
            }
            "HS512" => {
                let mut m = Hmac::<Sha512>::new_from_slice(secret.as_bytes()).unwrap();
                m.update(signing_input.as_bytes());
                m.finalize().into_bytes().to_vec()
            }
            _ => {
                let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
                m.update(signing_input.as_bytes());
                m.finalize().into_bytes().to_vec()
            }
        };
        format!("{signing_input}.{}", b64url(&sig))
    }

    /// An `alg` this check cannot attack, with a signature that is merely well-formed base64url.
    fn non_hmac_token(alg: &str) -> String {
        let header = b64url(format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#).as_bytes());
        let payload = b64url(br#"{"sub":"1234567890"}"#);
        format!("{header}.{payload}.{}", b64url(&[7u8; 32]))
    }

    fn response(body: &str) -> StoredMessage {
        let store = TrafficStore::new();
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let id = store.put(Bytes::from(raw), Direction::Response);
        store.get(id).unwrap()
    }

    fn response_with_header(header_line: &str) -> StoredMessage {
        let store = TrafficStore::new();
        let raw = format!("HTTP/1.1 200 OK\r\n{header_line}\r\nContent-Length: 0\r\n\r\n");
        let id = store.put(Bytes::from(raw), Direction::Response);
        store.get(id).unwrap()
    }

    #[test]
    fn a_token_signed_with_a_wordlist_secret_is_found_and_names_the_secret() {
        let c = JwtWeakSecretCheck::bundled();
        let body = format!(r#"{{"access_token":"{}"}}"#, token("HS256", "secret"));
        let f = c.scan(&response(&body), None);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].issue_name.as_deref(), Some(ISSUE));
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].confidence, Confidence::Certain);
        let detail = f[0].detail.as_deref().unwrap();
        assert!(detail.contains(r#""secret""#), "{detail}");
        assert!(detail.contains("the response body"), "{detail}");
        let cov = c.coverage();
        assert_eq!(cov.tokens_cracked, 1);
        assert_eq!(cov.tokens_distinct, 1);
        assert!(!cov.truncated);
        assert_eq!(cov.accounted(), cov.tokens_distinct);
    }

    #[test]
    fn hs384_and_hs512_are_attacked_with_their_own_digest() {
        for alg in ["HS384", "HS512"] {
            let c = JwtWeakSecretCheck::bundled();
            let body = format!(r#"{{"t":"{}"}}"#, token(alg, "changeme"));
            let f = c.scan(&response(&body), None);
            assert_eq!(f.len(), 1, "{alg}: {f:#?}");
            assert!(f[0].detail.as_deref().unwrap().contains(r#""changeme""#));
        }
    }

    #[test]
    fn a_token_signed_with_a_strong_secret_produces_no_finding_and_is_counted_exhausted() {
        let c = JwtWeakSecretCheck::bundled();
        let body = format!(
            r#"{{"t":"{}"}}"#,
            token("HS256", "8f2c1e5b-4d7a-4c9e-b3f1-6a0d92e77c14/entropy")
        );
        let f = c.scan(&response(&body), None);
        assert!(f.is_empty(), "{f:#?}");
        let cov = c.coverage();
        assert_eq!(cov.tokens_exhausted, 1);
        assert_eq!(cov.tokens_abandoned, 0);
        assert!(!cov.truncated);
        assert_eq!(cov.hmac_attempts, cov.wordlist.entries as u64);
        // The negative result is real, but only relative to the list — which the report names.
        assert!(cov.summary().contains("burpsy bundled JWT secrets"), "{}", cov.summary());
        assert!(!cov.inconclusive());
    }

    #[test]
    fn a_non_hmac_token_is_counted_as_skipped_not_as_clean() {
        let c = JwtWeakSecretCheck::bundled();
        let body = format!(
            r#"{{"a":"{}","b":"{}","c":"{}"}}"#,
            non_hmac_token("RS256"),
            non_hmac_token("ES256"),
            non_hmac_token("none")
        );
        let f = c.scan(&response(&body), None);
        assert!(f.is_empty(), "{f:#?}");
        let cov = c.coverage();
        assert_eq!(cov.tokens_out_of_scope, 3);
        assert_eq!(cov.tokens_exhausted, 0);
        assert_eq!(cov.hmac_attempts, 0, "no HMAC work is possible on an asymmetric token");
        assert_eq!(
            cov.out_of_scope_algorithms,
            vec![
                ("ES256".to_string(), 1),
                ("RS256".to_string(), 1),
                ("none".to_string(), 1)
            ]
        );
        assert!(
            cov.inconclusive(),
            "three tokens were never attacked, so this is not a clean result for them"
        );
        assert_eq!(cov.accounted(), cov.tokens_distinct);
    }

    #[test]
    fn a_run_that_hits_the_hmac_budget_reports_the_truncation_instead_of_a_clean_result() {
        // The real secret sits at the end of the list, and the budget stops three entries in.
        let list = Wordlist::from_entries(
            "tiny",
            "unit test",
            &["a", "b", "c", "d", "e", "keyboard cat"],
        );
        let c = JwtWeakSecretCheck::with_budget(list, 3);
        let body = format!(r#"{{"t":"{}"}}"#, token("HS256", "keyboard cat"));
        let f = c.scan(&response(&body), None);
        assert!(
            f.is_empty(),
            "the secret was never reached, so there is no evidence to report"
        );
        let cov = c.coverage();
        assert_eq!(cov.tokens_abandoned, 1);
        assert_eq!(cov.tokens_exhausted, 0, "an abandoned token is never exhausted");
        assert_eq!(cov.hmac_attempts, 3);
        assert!(cov.truncated, "the bound must be visible, not silent");
        assert!(cov.inconclusive());
        assert!(cov.summary().contains("1 abandoned mid-wordlist"), "{}", cov.summary());
        assert_eq!(cov.accounted(), cov.tokens_distinct);
    }

    #[test]
    fn a_zero_budget_abandons_every_token_rather_than_clearing_it() {
        let c = JwtWeakSecretCheck::with_budget(Wordlist::bundled(), 0);
        let body = format!(r#"{{"t":"{}"}}"#, token("HS256", "secret"));
        assert!(c.scan(&response(&body), None).is_empty());
        let cov = c.coverage();
        assert_eq!(cov.tokens_abandoned, 1);
        assert_eq!(cov.hmac_attempts, 0);
        assert!(cov.truncated);
    }

    #[test]
    fn the_same_token_on_a_second_response_is_deduplicated_by_signing_input() {
        let c = JwtWeakSecretCheck::bundled();
        let body = format!(r#"{{"t":"{}"}}"#, token("HS256", "secret"));
        assert_eq!(c.scan(&response(&body), None).len(), 1);
        assert!(
            c.scan(&response(&body), None).is_empty(),
            "cracked once, not once per page"
        );
        let cov = c.coverage();
        assert_eq!(cov.tokens_seen, 2);
        assert_eq!(cov.tokens_distinct, 1);
        assert_eq!(cov.tokens_already_covered, 1);
        assert_eq!(cov.hmac_attempts, 1, "the wordlist runs once for one signing input");
    }

    #[test]
    fn a_token_in_a_set_cookie_header_is_found_and_the_location_named() {
        let c = JwtWeakSecretCheck::bundled();
        let msg = response_with_header(&format!(
            "Set-Cookie: session={}; Path=/; HttpOnly",
            token("HS256", "jwt")
        ));
        let f = c.scan(&msg, None);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(
            f[0].detail.as_deref().unwrap().contains("response header Set-Cookie"),
            "{:?}",
            f[0].detail
        );
    }

    #[test]
    fn a_token_in_a_request_authorization_header_is_found_when_the_request_is_supplied() {
        let store = TrafficStore::new();
        let req = store.put(
            Bytes::from(format!(
                "GET /api HTTP/1.1\r\nHost: h.test\r\nAuthorization: Bearer {}\r\n\r\n",
                token("HS256", "admin")
            )),
            Direction::Request,
        );
        let req = store.get(req).unwrap();
        let c = JwtWeakSecretCheck::bundled();
        let f = c.scan(&response("{}"), Some(&req));
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(
            f[0].detail.as_deref().unwrap().contains("request header Authorization"),
            "{:?}",
            f[0].detail
        );
        assert_eq!(c.coverage().requests_unavailable, 0);
    }

    #[test]
    fn scanning_without_a_request_message_records_that_the_request_side_was_not_examined() {
        let c = JwtWeakSecretCheck::bundled();
        c.scan(&response("{}"), None);
        assert_eq!(c.coverage().requests_unavailable, 1);
    }

    #[test]
    fn a_five_segment_jwe_is_refused_rather_than_treated_as_a_jws() {
        let c = JwtWeakSecretCheck::bundled();
        let header = b64url(br#"{"alg":"dir","enc":"A128GCM"}"#);
        let body = format!(r#"{{"t":"{header}.aaaa.bbbb.cccc.dddd"}}"#);
        assert!(c.scan(&response(&body), None).is_empty());
        let cov = c.coverage();
        assert_eq!(cov.tokens_seen, 0, "a five-segment token is not JWS-shaped");
        assert_eq!(cov.tokens_distinct, 0);
    }

    #[test]
    fn a_token_whose_header_is_not_decodable_json_is_refused_not_guessed_at() {
        let c = JwtWeakSecretCheck::bundled();
        // `eyJ`-prefixed, three segments, but the header decodes to bytes that are not JSON.
        let body = r#"{"t":"eyJxxxxxx.eyJzdWIiOiJhIn0.QUJDREVG"}"#;
        assert!(c.scan(&response(body), None).is_empty());
        let cov = c.coverage();
        assert_eq!(cov.tokens_seen, 1);
        assert_eq!(cov.tokens_refused, 1);
        assert_eq!(cov.tokens_exhausted, 0);
        assert!(cov.inconclusive());
        assert_eq!(cov.accounted(), cov.tokens_distinct);
    }

    #[test]
    fn base64url_decoding_refuses_a_character_outside_the_alphabet() {
        assert!(b64url_decode("eyJhbGciOiJIUzI1NiJ9").is_some());
        assert!(b64url_decode("ab+cd").is_none(), "standard base64 '+' is not base64url");
        assert!(b64url_decode("ab/cd").is_none());
        assert!(b64url_decode("").is_none());
        assert!(b64url_decode("a").is_none(), "one base64 character cannot encode a byte");
        // Padding is tolerated, since deployments emit it despite the JWS spec.
        assert_eq!(b64url_decode("QQ==").unwrap(), b"A");
    }

    #[test]
    fn the_bundled_wordlist_states_its_size_and_provenance() {
        let w = Wordlist::bundled();
        assert_eq!(w.len(), 51);
        assert_eq!(w.id().entries, 51);
        assert!(w.id().source.contains("jwt_secrets.txt"), "{}", w.id().source);
    }

    #[test]
    fn a_wordlist_file_reports_distinct_entries_rather_than_line_count() {
        let dir = std::env::temp_dir().join(format!("burpsy-jwt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("list.txt");
        std::fs::write(&p, "secret\n\nsecret\nchangeme\n").unwrap();
        let w = Wordlist::load(&p).unwrap();
        assert_eq!(w.len(), 2, "the duplicate and the blank line are not entries");
        assert_eq!(w.id().name, "list.txt");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_wordlist_file_is_an_error_rather_than_an_empty_attack() {
        assert!(Wordlist::load(std::path::Path::new("/nonexistent/list.txt")).is_err());
    }
}
