//! SCAN-01 — known-vulnerable JavaScript libraries, matched by **version range**.
//!
//! # Why this is not a BCheck
//!
//! The BCheck DSL can say "this body matches that regex". It cannot say "the version this regex
//! captured is at or above 3.0.0 and below 3.4.1", and a check that cannot do version arithmetic
//! cannot answer the only question that matters here. Writing 683 BChecks — one per known
//! vulnerability, each with a hand-expanded set of literal version strings — is the shape this
//! module exists to avoid: it would be wrong the day upstream publishes 3.4.2.
//!
//! So the range comparison is real arithmetic on parsed [`Version`]s. It is deliberately **not** a
//! string prefix test: `"1.4"` is a prefix of `"1.40.0"`, and a prefix test would clear a
//! vulnerable 1.4.2 while flagging an unaffected 1.40.0. It is also not semver, because the
//! versions real libraries ship are not semver — `2.0`, `1.11.0b1`, `3.0.0-rc1`, `2.2.4-lite` all
//! occur in the dataset's own bounds, and a strict semver parser rejects most of them.
//!
//! # The dataset
//!
//! Retire.js's `jsrepository` corpus, as shipped inside Burp Suite 2026.7.1 at
//! `resources/RetireJS/retirejs_repository.json` (sha256
//! `5fdf3cc5707264de891f3844becea5fbc17377e8a684aecf8d2fca7936afb6da`, 514,644 bytes, extracted
//! 2026-07-28). Retire.js is Apache-2.0; the vendored copy lives at
//! `crates/scanner/data/retirejs_repository.json` and is compiled in by [`JsVulnDb::vendored`].
//!
//! Compiled in rather than looked up on disk at runtime because a scanner that guesses at an
//! install path has a new failure mode — "it found nothing because the file was somewhere else" —
//! which is precisely the kind of silent non-result this crate is built to refuse. An operator who
//! wants a fresher snapshot passes it to [`JsVulnDb::load`], and the file's identity, size and
//! entry counts are then reported instead of the vendored one's.
//!
//! **Currency is reported, not implied.** [`DatasetSummary`] carries the source and every count, so
//! "no vulnerable libraries" is always qualified by which corpus said so and how much of it this
//! engine could actually evaluate.
//!
//! # What is deliberately not implemented, and counted
//!
//! Retire.js has five extractor kinds. This module uses three (`uri`, `filename`, `filecontent`)
//! and refuses two:
//!
//! * `func` extractors evaluate JavaScript in the page (`window.jQuery.fn.jquery`). That needs a JS
//!   engine, which this crate does not have and should not grow.
//! * `hashes` map a SHA-1 of the whole file to a version. Cheap to add later; not here yet.
//!
//! Both are **counted** in [`DatasetSummary`] rather than quietly skipped, because they are the
//! difference between "we checked every way retire.js knows how" and "we checked three of five".
//! Three of the corpus's own regexes use backreferences or lookbehind, which the Rust engine does
//! not support; those are counted too.
//!
//! # The three verdicts, and why "clean" is the rarest
//!
//! A response either identifies a library at a comparable version (then it is vulnerable or it is
//! not), or it identifies one whose version cannot be compared. That last case is
//! [`Verdict::Undetermined`] and it is *reported*: an unknown version is not evidence of safety.
//! Guessing "probably vulnerable" invents a finding; guessing "probably fine" hides one. Both are
//! refusals to answer, and only one of them is honest about it.

use std::sync::atomic::{AtomicU64, Ordering};

use burpsy_bcheck::{Confidence, Finding, Severity};
use regex::{Regex, RegexSet};

/// The vendored corpus, compiled in. See the module docs for provenance.
const VENDORED: &str = include_str!("../data/retirejs_repository.json");

/// The name of the vendored corpus as it appears in every report.
const VENDORED_NAME: &str = "retirejs_repository.json (Burp Suite 2026.7.1, extracted 2026-07-28)";

/// The issue name, an exact match for Burp's catalogued issue (`catalog_data.rs`, type index
/// 5243008) so [`crate::enrich`] attaches Burp's own remediation instead of invented advice.
const ISSUE: &str = "Vulnerable JavaScript dependency";

/// The issue name for a library whose version could not be compared. Deliberately *not* a
/// catalogued name: Burp has no definition for this, and inventing one that looks catalogued would
/// put authoritative-sounding prose behind a non-conclusion.
const UNDETERMINED_ISSUE: &str = "JavaScript library version not comparable";

/// What retire.js substitutes for `§§version§§`: a version must start with a digit. Copied from
/// retire.js's own `versionPattern` so a match here means the same thing it means upstream.
const STRICT_VERSION: &str = r"[0-9][0-9.a-z_\-]+";

/// The same slot, widened to "whatever token is in that position". Used only after the strict
/// pattern has already failed, and only on a URL, and its matches can only ever produce
/// [`Verdict::Undetermined`] — never a vulnerability claim. This is what turns `jquery-latest.js`
/// from a silent miss into a reported non-conclusion: something jQuery-shaped was served and this
/// engine cannot say which version it was.
///
/// No `.`, unlike the strict pattern: a dotted loose match is greedy across the rest of the
/// filename, so `jquery-latest.min.js` would report its version as `"latest.min"`. The point of
/// this pattern is to name the token that should have been a version, and naming it wrongly in the
/// report defeats that.
const LOOSE_VERSION: &str = r"[0-9A-Za-z][0-9A-Za-z_+\-]*";

/// A version as libraries actually spell it: dotted numeric components plus an optional
/// non-numeric tail.
///
/// `parts` is the numeric prefix, `tail` everything after it with one leading separator stripped —
/// so `3.0.0-rc1` is `([3,0,0], "rc1")` and `1.11.0b1` is `([1,11,0], "b1")`.
#[derive(Debug, Clone)]
pub struct Version {
    parts: Vec<u32>,
    tail: String,
}

impl Version {
    /// Parse, or refuse. `None` means "this is not a version I can compare", which callers must
    /// propagate as [`Verdict::Undetermined`] rather than treating as either verdict.
    ///
    /// Refuses anything whose first dotted component has no leading digit — `latest`, `x`, the
    /// empty string. A numeric component wider than [`u32`] is refused for the same reason: an
    /// overflow that silently wrapped would compare wrongly, which is worse than not comparing.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let mut parts = Vec::new();
        let mut rest = s;
        // Assigned on every path out of the loop; declared without an initialiser so a future path
        // that forgets to set it fails to compile rather than silently meaning "no tail".
        let tail: &str;
        loop {
            let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
            if digits == 0 {
                tail = rest;
                break;
            }
            parts.push(rest[..digits].parse::<u32>().ok()?);
            rest = &rest[digits..];
            match rest.strip_prefix('.') {
                Some(next) => rest = next,
                None => {
                    tail = rest;
                    break;
                }
            }
        }
        if parts.is_empty() {
            return None;
        }
        let tail = tail
            .trim_start_matches(['-', '_', '+'])
            .trim_end_matches('.')
            .to_string();
        Some(Version { parts, tail })
    }

    /// The numeric components, shortest-zero-padded on comparison. Exposed for tests.
    pub fn parts(&self) -> &[u32] {
        &self.parts
    }
}

impl Ord for Version {
    /// Element-wise on the numeric parts with the shorter side zero-padded, so `2.0 == 2.0.0`.
    /// Then: an empty tail sorts **after** a non-empty one, so `3.0.0-rc1 < 3.0.0` — a release
    /// candidate is not the release, and a `below: 3.0.0` range must catch it.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let n = self.parts.len().max(other.parts.len());
        for i in 0..n {
            let a = self.parts.get(i).copied().unwrap_or(0);
            let b = other.parts.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                std::cmp::Ordering::Equal => {}
                other => return other,
            }
        }
        match (self.tail.is_empty(), other.tail.is_empty()) {
            (true, true) => std::cmp::Ordering::Equal,
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            (false, false) => self.tail.cmp(&other.tail),
        }
    }
}

/// Equality is [`Ord`], not the derived field-by-field comparison.
///
/// The derive would make `2.0` and `2.0.0` unequal while [`Version::cmp`] calls them equal, and two
/// notions of "same version" inside one type is exactly the kind of near-miss that produces a
/// range check that agrees with itself and disagrees with reality.
impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let joined: Vec<String> = self.parts.iter().map(|p| p.to_string()).collect();
        write!(f, "{}", joined.join("."))?;
        if !self.tail.is_empty() {
            write!(f, "-{}", self.tail)?;
        }
        Ok(())
    }
}

/// One end of a version range.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Edge {
    at: Version,
    inclusive: bool,
}

/// An affected-version range: retire.js's `atOrAbove`/`above`/`below`/`atOrBelow` predicates.
///
/// A range with no bounds at all would match every version, so it is refused at load time rather
/// than loaded and allowed to flag everything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRange {
    lower: Option<Edge>,
    upper: Option<Edge>,
    /// The predicate as the corpus spelled it, for the finding detail.
    text: String,
}

impl VersionRange {
    fn contains(&self, v: &Version) -> bool {
        if let Some(l) = &self.lower {
            let ok = if l.inclusive { *v >= l.at } else { *v > l.at };
            if !ok {
                return false;
            }
        }
        if let Some(u) = &self.upper {
            let ok = if u.inclusive { *v <= u.at } else { *v < u.at };
            if !ok {
                return false;
            }
        }
        true
    }

    pub fn text(&self) -> &str {
        &self.text
    }
}

/// One known vulnerability in one component.
#[derive(Debug, Clone)]
pub struct Vuln {
    pub range: VersionRange,
    pub severity: Severity,
    pub summary: Option<String>,
    pub identifiers: Vec<String>,
}

/// A `uri`/`filename` pattern in both its strict and loose forms. See [`LOOSE_VERSION`].
struct UrlPattern {
    strict: Regex,
    loose: Regex,
}

/// One library the corpus knows about.
struct Component {
    name: String,
    url: Vec<UrlPattern>,
    vulns: Vec<Vuln>,
    /// Vulnerability entries this engine refused to load, so "no range matched" can say whether it
    /// evaluated the whole component or only part of it.
    dropped_vulns: usize,
}

/// Whether the corpus is usable at all, and if not, why.
///
/// `Unavailable` exists because the alternative — an empty component list that finds nothing — is
/// indistinguishable from a clean scan. A caller must be able to tell "checked 76 libraries" from
/// "never had a corpus to check against".
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum DatasetState {
    Loaded,
    Unavailable(String),
}

impl DatasetState {
    pub fn is_available(&self) -> bool {
        matches!(self, DatasetState::Loaded)
    }
}

/// What loading the corpus produced. Every number here appears in the coverage report, because a
/// negative result is only as good as the corpus and the fraction of it this engine can evaluate.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct DatasetSummary {
    /// Where the corpus came from — the vendored name or the operator's path.
    pub source: String,
    pub components: usize,
    /// Vulnerability entries loaded with an evaluable range.
    pub vulnerabilities: usize,
    pub url_patterns: usize,
    pub content_patterns: usize,
    /// `func` extractors skipped: they need a JavaScript engine.
    pub unsupported_func_extractors: usize,
    /// `hashes` extractors skipped: content-hash identification is not implemented yet.
    pub unsupported_hash_extractors: usize,
    /// `filecontentreplace` extractors skipped: a sed-style rewrite, not a match.
    pub unsupported_replace_extractors: usize,
    /// Corpus regexes the Rust engine rejected, with the reason.
    pub unusable_patterns: Vec<String>,
    /// Vulnerability entries dropped because their range was not evaluable.
    pub unusable_ranges: Vec<String>,
    pub state: DatasetState,
}

impl DatasetSummary {
    fn unavailable(source: String, why: String) -> Self {
        DatasetSummary {
            source,
            state: DatasetState::Unavailable(why),
            ..Default::default()
        }
    }

    /// One line an operator can act on. Names the source and the refusals, never just the totals.
    pub fn summary(&self) -> String {
        match &self.state {
            DatasetState::Unavailable(why) => {
                format!("js vulnerability dataset UNAVAILABLE ({}): {why}", self.source)
            }
            DatasetState::Loaded => format!(
                "{} components, {} vulnerabilities, {} url + {} content patterns from {}; \
                 skipped {} func / {} hash / {} replace extractors, {} unusable patterns, {} unusable ranges",
                self.components,
                self.vulnerabilities,
                self.url_patterns,
                self.content_patterns,
                self.source,
                self.unsupported_func_extractors,
                self.unsupported_hash_extractors,
                self.unsupported_replace_extractors,
                self.unusable_patterns.len(),
                self.unusable_ranges.len(),
            ),
        }
    }
}

impl Default for DatasetState {
    fn default() -> Self {
        DatasetState::Unavailable("not loaded".into())
    }
}

/// One multi-pattern prefilter over a slice of the `filecontent` corpus, plus the flat indices its
/// member patterns occupy in [`JsVulnDb::content`].
struct ContentSet {
    set: RegexSet,
    ix: Vec<usize>,
}

/// How many `filecontent` patterns go into one [`ContentSet`].
///
/// All 336 in a single set overruns the regex crate's compiled-size limit: several corpus patterns
/// use bounded repeats like `.{50,300}`, which expand to hundreds of states each, and one set of
/// everything exceeds 10 MB. Raising the limit instead would buy a single multi-megabyte automaton;
/// chunking keeps each prefilter small while still turning 336 passes over a body into 14.
const CONTENT_CHUNK: usize = 24;

/// The parsed corpus.
pub struct JsVulnDb {
    components: Vec<Component>,
    /// Every `filecontent` regex, flat, for the capture pass.
    content: Vec<Regex>,
    /// Prefilters over `content`. A body is scanned once per set and only the patterns that hit are
    /// then run for their capture group, instead of 336 separate scans of the same bytes.
    content_sets: Vec<ContentSet>,
    /// Parallel to `content`: which component each flat pattern belongs to.
    content_owner: Vec<usize>,
    summary: DatasetSummary,
}

impl JsVulnDb {
    /// The corpus compiled into the binary. Always available.
    pub fn vendored() -> Self {
        Self::parse(VENDORED, VENDORED_NAME.to_string())
    }

    /// A refreshed corpus from disk, in the same `jsrepository.json` shape.
    ///
    /// A missing or unreadable file yields a [`DatasetState::Unavailable`] database, not an error
    /// the caller can drop on the floor: the check must still appear in the coverage report, saying
    /// it had nothing to check against.
    pub fn load(path: &std::path::Path) -> Self {
        let source = path.display().to_string();
        match std::fs::read_to_string(path) {
            Ok(src) => Self::parse(&src, source),
            Err(e) => Self::empty(DatasetSummary::unavailable(source, e.to_string())),
        }
    }

    /// An explicitly unavailable database, for a caller that has decided not to load one.
    pub fn unavailable(why: &str) -> Self {
        Self::empty(DatasetSummary::unavailable("<none>".into(), why.to_string()))
    }

    fn empty(summary: DatasetSummary) -> Self {
        JsVulnDb {
            components: Vec::new(),
            content: Vec::new(),
            content_sets: Vec::new(),
            content_owner: Vec::new(),
            summary,
        }
    }

    pub fn summary(&self) -> &DatasetSummary {
        &self.summary
    }

    fn parse(src: &str, source: String) -> Self {
        let root: serde_json::Value = match serde_json::from_str(src) {
            Ok(v) => v,
            Err(e) => {
                return Self::empty(DatasetSummary::unavailable(
                    source,
                    format!("not parsable as jsrepository JSON: {e}"),
                ));
            }
        };
        let Some(obj) = root.as_object() else {
            return Self::empty(DatasetSummary::unavailable(
                source,
                "top level is not a JSON object of component names".into(),
            ));
        };

        let mut summary = DatasetSummary {
            source,
            state: DatasetState::Loaded,
            ..Default::default()
        };
        let mut components = Vec::new();
        let mut content = Vec::new();
        let mut content_owner = Vec::new();

        for (name, comp) in obj {
            let ci = components.len();
            let ex = comp.get("extractors");
            let mut url = Vec::new();
            for kind in ["uri", "filename"] {
                for p in ex.and_then(|e| e.get(kind)).and_then(|v| v.as_array()).into_iter().flatten() {
                    let Some(raw) = p.as_str() else { continue };
                    match url_pattern(raw) {
                        Ok(up) => url.push(up),
                        Err(e) => summary.unusable_patterns.push(format!("{name} {kind}: {e}")),
                    }
                }
            }
            let mut own_content = 0usize;
            for p in ex
                .and_then(|e| e.get("filecontent"))
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
            {
                let Some(raw) = p.as_str() else { continue };
                match Regex::new(&substitute(raw, STRICT_VERSION)) {
                    Ok(re) => {
                        own_content += 1;
                        content.push(re);
                        content_owner.push(ci);
                    }
                    Err(e) => summary
                        .unusable_patterns
                        .push(format!("{name} filecontent: {e}")),
                }
            }
            summary.unsupported_func_extractors += count_of(ex, "func");
            summary.unsupported_hash_extractors += hash_entries(ex);
            summary.unsupported_replace_extractors += count_of(ex, "filecontentreplace");

            let mut vulns = Vec::new();
            let mut dropped = 0usize;
            for v in comp
                .get("vulnerabilities")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
            {
                match range_of(v) {
                    Some(range) => vulns.push(Vuln {
                        range,
                        severity: severity_of(v),
                        summary: v
                            .get("identifiers")
                            .and_then(|i| i.get("summary"))
                            .and_then(|s| s.as_str())
                            .map(str::to_string),
                        identifiers: identifiers_of(v),
                    }),
                    None => {
                        dropped += 1;
                        summary
                            .unusable_ranges
                            .push(format!("{name}: {}", range_text(v)));
                    }
                }
            }

            summary.url_patterns += url.len();
            summary.content_patterns += own_content;
            summary.vulnerabilities += vulns.len();
            components.push(Component {
                name: name.clone(),
                url,
                vulns,
                dropped_vulns: dropped,
            });
        }
        summary.components = components.len();

        // Each pattern already compiled individually above, so a chunk of one always builds; a
        // chunk that overruns the size limit is therefore split rather than dropped. Nothing here
        // can silently lose a pattern — losing one would make this check blind to a library while
        // still reporting its pattern count.
        let content_sets = build_content_sets(&content);
        JsVulnDb {
            components,
            content,
            content_sets,
            content_owner,
            summary,
        }
    }

    /// Identify libraries in one asset: `url` is the request path, `body` the response body.
    ///
    /// URL signals are [`Signal::Url`] and content signals [`Signal::Content`], which the caller
    /// maps onto confidence — a filename is a claim about naming, a version marker inside the file
    /// is a claim about the file.
    ///
    /// One `(library, version)` appears once. The corpus has several `filecontent` patterns per
    /// library that overlap by design — jQuery has eleven, and a real jQuery banner matches two of
    /// them — so without collapsing them the same library at the same version would be reported
    /// twice and counted twice. `FindingStore` would merge the findings later, but the coverage
    /// counters here would already be wrong, and they are the numbers a report leans on.
    fn detect(&self, url: &str, body: &[u8]) -> Vec<Detection> {
        let mut out: Vec<Detection> = Vec::new();
        let filename = url.rsplit('/').next().unwrap_or(url);
        for (ci, c) in self.components.iter().enumerate() {
            let mut hit = None;
            for p in &c.url {
                if let Some(v) = capture(&p.strict, url).or_else(|| capture(&p.strict, filename)) {
                    hit = Some(v);
                    break;
                }
            }
            if hit.is_none() {
                for p in &c.url {
                    if let Some(v) = capture(&p.loose, url).or_else(|| capture(&p.loose, filename)) {
                        hit = Some(v);
                        break;
                    }
                }
            }
            if let Some(raw) = hit {
                push(&mut out, Detection::new(ci, c, raw, Signal::Url));
            }
        }
        // A prefilter pass per chunk, then a capture run only for the patterns that actually hit.
        if let Ok(text) = std::str::from_utf8(body) {
            for cs in &self.content_sets {
                for local in cs.set.matches(text).into_iter() {
                    let i = cs.ix[local];
                    let ci = self.content_owner[i];
                    if let Some(raw) = capture(&self.content[i], text) {
                        push(
                            &mut out,
                            Detection::new(ci, &self.components[ci], raw, Signal::Content),
                        );
                    }
                }
            }
        }
        out
    }

    /// Decide one detection against the component's known vulnerabilities.
    fn judge(&self, d: &Detection) -> Verdict<'_> {
        let c = &self.components[d.component_ix];
        let Some(v) = &d.version else {
            return Verdict::Undetermined(format!(
                "version string {:?} is not comparable",
                d.raw_version
            ));
        };
        let hits: Vec<&Vuln> = c.vulns.iter().filter(|x| x.range.contains(v)).collect();
        if !hits.is_empty() {
            return Verdict::Vulnerable(hits);
        }
        if c.dropped_vulns > 0 {
            return Verdict::Undetermined(format!(
                "{} of {} known vulnerabilities for {} have ranges this engine cannot evaluate, \
                 so {v} is not cleared",
                c.dropped_vulns,
                c.dropped_vulns + c.vulns.len(),
                c.name
            ));
        }
        Verdict::NotVulnerable
    }
}

/// Which evidence identified a library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signal {
    /// A `uri`/`filename` pattern matched the request path. A claim about how the file is named.
    Url,
    /// A `filecontent` version marker matched inside the body. A claim about the file itself.
    Content,
}

impl Signal {
    /// The confidence ladder from the phase design: naming is `Tentative`, an in-content marker is
    /// `Firm`. Nothing here is `Certain` — that tier is reserved for a content-hash match, which
    /// this module does not implement and says so in [`DatasetSummary`].
    fn confidence(self) -> Confidence {
        match self {
            Signal::Url => Confidence::Tentative,
            Signal::Content => Confidence::Firm,
        }
    }
}

/// One library identified in one asset.
#[derive(Debug, Clone)]
struct Detection {
    component_ix: usize,
    component: String,
    raw_version: String,
    version: Option<Version>,
    signal: Signal,
}

impl Detection {
    fn new(ix: usize, c: &Component, raw: String, signal: Signal) -> Self {
        Detection {
            component_ix: ix,
            component: c.name.clone(),
            version: Version::parse(&raw),
            raw_version: raw,
            signal,
        }
    }
}

/// Add a detection unless the same `(library, version)` is already there, keeping the stronger
/// signal when it is.
///
/// A linear scan: one asset yields a handful of detections, so a hash map would cost more to build
/// than the scan costs to run.
fn push(out: &mut Vec<Detection>, d: Detection) {
    if let Some(existing) = out
        .iter_mut()
        .find(|e| e.component_ix == d.component_ix && e.raw_version == d.raw_version)
    {
        if d.signal == Signal::Content {
            existing.signal = Signal::Content;
        }
        return;
    }
    out.push(d);
}

/// The three possible answers. There is no fourth, and `NotVulnerable` is the only one that
/// justifies saying nothing.
enum Verdict<'a> {
    Vulnerable(Vec<&'a Vuln>),
    NotVulnerable,
    Undetermined(String),
}

/// SCAN-01 as a passive check: dataset plus the running record of what it looked at.
///
/// Counters are atomics rather than a lock because each is independent and this runs from several
/// off-hot-path scan tasks at once — the same reasoning as
/// [`crate::coverage::CoverageTracker`]'s skip counters.
pub struct JsLibraryCheck {
    db: JsVulnDb,
    responses: AtomicU64,
    not_js: AtomicU64,
    assets: AtomicU64,
    identified: AtomicU64,
    unidentified: AtomicU64,
    undetermined: AtomicU64,
    vulnerable: AtomicU64,
    cleared: AtomicU64,
    dataset_unavailable: AtomicU64,
}

/// What SCAN-01 actually looked at. `dataset` first, because every other number here is worthless
/// without knowing which corpus produced it.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct JsCoverage {
    pub dataset: DatasetSummary,
    /// Responses handed to the check.
    pub responses: u64,
    /// Responses that did not look like a JavaScript asset, so were not examined.
    pub not_javascript: u64,
    /// JavaScript assets examined.
    pub assets_seen: u64,
    /// Assets where a library *and* a comparable version were identified.
    pub assets_identified: u64,
    /// Assets where no corpus pattern matched at all. **Not** clean: a concatenated bundle with
    /// jQuery inlined usually matches nothing, and "0 vulnerable libraries" must be
    /// distinguishable from "we could not identify any of the assets we saw".
    pub assets_unidentified: u64,
    /// Detections whose version could not be compared, or whose component has ranges this engine
    /// cannot evaluate. Reported as undetermined, never as clean.
    pub detections_undetermined: u64,
    /// Detections that landed inside a known-vulnerable range.
    pub detections_vulnerable: u64,
    /// Detections compared against the whole of their component's range set with no hit — the only
    /// evidence-backed "not vulnerable" this check can produce.
    pub detections_cleared: u64,
    /// Responses not examined at all because the corpus was unavailable.
    pub skipped_dataset_unavailable: u64,
}

impl JsCoverage {
    /// True when this check produced no evidence either way, for whatever reason. A report that
    /// shows zero findings must consult this before calling the result clean.
    pub fn inconclusive(&self) -> bool {
        !self.dataset.state.is_available()
            || self.detections_undetermined > 0
            || self.assets_unidentified > 0
    }
}

impl JsLibraryCheck {
    pub const NAME: &'static str = "Vulnerable JavaScript dependency (SCAN-01)";

    pub fn new(db: JsVulnDb) -> Self {
        JsLibraryCheck {
            db,
            responses: AtomicU64::new(0),
            not_js: AtomicU64::new(0),
            assets: AtomicU64::new(0),
            identified: AtomicU64::new(0),
            unidentified: AtomicU64::new(0),
            undetermined: AtomicU64::new(0),
            vulnerable: AtomicU64::new(0),
            cleared: AtomicU64::new(0),
            dataset_unavailable: AtomicU64::new(0),
        }
    }

    /// The vendored corpus, which is what a caller wants unless an operator supplied a fresher one.
    pub fn vendored() -> Self {
        Self::new(JsVulnDb::vendored())
    }

    pub fn coverage(&self) -> JsCoverage {
        JsCoverage {
            dataset: self.db.summary.clone(),
            responses: self.responses.load(Ordering::Relaxed),
            not_javascript: self.not_js.load(Ordering::Relaxed),
            assets_seen: self.assets.load(Ordering::Relaxed),
            assets_identified: self.identified.load(Ordering::Relaxed),
            assets_unidentified: self.unidentified.load(Ordering::Relaxed),
            detections_undetermined: self.undetermined.load(Ordering::Relaxed),
            detections_vulnerable: self.vulnerable.load(Ordering::Relaxed),
            detections_cleared: self.cleared.load(Ordering::Relaxed),
            skipped_dataset_unavailable: self.dataset_unavailable.load(Ordering::Relaxed),
        }
    }

    /// Scan one response. `path` is the request path the response answered, which is where a
    /// `filename`/`uri` extractor looks.
    pub fn scan(&self, path: &str, content_type: Option<&str>, body: &[u8]) -> Vec<Finding> {
        self.responses.fetch_add(1, Ordering::Relaxed);
        if !self.db.summary.state.is_available() {
            self.dataset_unavailable.fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        }
        if !looks_like_javascript(path, content_type) {
            self.not_js.fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        }
        self.assets.fetch_add(1, Ordering::Relaxed);

        let detections = self.db.detect(path, body);
        if detections.is_empty() {
            self.unidentified.fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        }

        let mut out = Vec::new();
        let mut any_comparable = false;
        for d in &detections {
            match self.db.judge(d) {
                Verdict::Vulnerable(hits) => {
                    any_comparable = true;
                    self.vulnerable.fetch_add(1, Ordering::Relaxed);
                    out.push(vulnerable_finding(d, &hits, &self.db.summary));
                }
                Verdict::NotVulnerable => {
                    any_comparable = true;
                    self.cleared.fetch_add(1, Ordering::Relaxed);
                }
                Verdict::Undetermined(why) => {
                    self.undetermined.fetch_add(1, Ordering::Relaxed);
                    out.push(undetermined_finding(d, &why, &self.db.summary));
                }
            }
        }
        if any_comparable {
            self.identified.fetch_add(1, Ordering::Relaxed);
        }
        out
    }
}

/// A vulnerability finding. Severity comes from the corpus entry, confidence from the signal that
/// identified the library — never promoted past what the evidence supports.
fn vulnerable_finding(d: &Detection, hits: &[&Vuln], ds: &DatasetSummary) -> Finding {
    let worst = hits.iter().map(|h| sev_rank(h.severity)).max().unwrap_or(0);
    let mut detail = format!(
        "{} {} matched {} known {} ({} signal). Corpus: {}.",
        d.component,
        d.version.as_ref().map(|v| v.to_string()).unwrap_or_default(),
        hits.len(),
        if hits.len() == 1 {
            "vulnerability"
        } else {
            "vulnerabilities"
        },
        match d.signal {
            Signal::Url => "URL",
            Signal::Content => "in-content version marker",
        },
        ds.source,
    );
    for h in hits {
        detail.push_str(&format!(
            "\n  {} [{}]{}{}",
            h.range.text(),
            severity_word(h.severity),
            h.summary
                .as_deref()
                .map(|s| format!(" {s}"))
                .unwrap_or_default(),
            if h.identifiers.is_empty() {
                String::new()
            } else {
                format!(" ({})", h.identifiers.join(", "))
            }
        ));
    }
    Finding {
        check_name: JsLibraryCheck::NAME.to_string(),
        issue_name: Some(ISSUE.to_string()),
        severity: rank_sev(worst),
        confidence: d.signal.confidence(),
        detail: Some(detail),
        // Left empty on purpose: `enrich` fills it from Burp's catalogued definition for this exact
        // issue name, which is real remediation text rather than something written here.
        remediation: None,
    }
}

/// A non-conclusion, reported as one. `Info`/`Tentative` because that is exactly what it is worth:
/// evidence that something was served which this engine could not evaluate.
fn undetermined_finding(d: &Detection, why: &str, ds: &DatasetSummary) -> Finding {
    Finding {
        check_name: JsLibraryCheck::NAME.to_string(),
        issue_name: Some(UNDETERMINED_ISSUE.to_string()),
        severity: Severity::Info,
        confidence: Confidence::Tentative,
        detail: Some(format!(
            "{} was identified but not assessed: {why}. This is not a clean result — the library \
             may or may not be vulnerable. Corpus: {}.",
            d.component, ds.source,
        )),
        remediation: Some(
            "Determine the exact library version served at this path and re-check it against the \
             advisory data by hand."
                .into(),
        ),
    }
}

/// Is this response worth looking at as a JavaScript asset?
///
/// Path suffix or `Content-Type`, either alone. Servers get `Content-Type` wrong on static assets
/// often enough that requiring both would silently skip real scripts, and requiring only the type
/// would skip the `.js` files served as `text/plain`.
fn looks_like_javascript(path: &str, content_type: Option<&str>) -> bool {
    let stem = path.split(['?', '#']).next().unwrap_or(path);
    if stem.to_ascii_lowercase().ends_with(".js") || stem.to_ascii_lowercase().ends_with(".mjs") {
        return true;
    }
    content_type.is_some_and(|ct| {
        let ct = ct.to_ascii_lowercase();
        ct.contains("javascript") || ct.contains("ecmascript")
    })
}

/// Run one pattern and return its version capture group.
///
/// Group 1 by convention: every corpus pattern wraps `§§version§§` in its own parentheses. A
/// pattern that matched but captured nothing is treated as no match — a "match" with no version is
/// not something this check can do anything with.
fn capture(re: &Regex, hay: &str) -> Option<String> {
    re.captures(hay)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn substitute(pattern: &str, version: &str) -> String {
    pattern.replace("\u{a7}\u{a7}version\u{a7}\u{a7}", version)
}

fn url_pattern(raw: &str) -> Result<UrlPattern, regex::Error> {
    Ok(UrlPattern {
        strict: Regex::new(&substitute(raw, STRICT_VERSION))?,
        loose: Regex::new(&substitute(raw, LOOSE_VERSION))?,
    })
}

/// Group the `filecontent` patterns into prefilter sets of at most [`CONTENT_CHUNK`].
///
/// A chunk the regex crate refuses — the compiled-size limit, hit by the corpus's bounded-repeat
/// patterns — is split into single-pattern sets rather than dropped. Every pattern compiled on its
/// own during parsing, so a set of one always builds and no pattern can go missing. The alternative
/// (drop the chunk) would leave the check blind to those libraries while its reported pattern count
/// still claimed otherwise.
fn build_content_sets(content: &[Regex]) -> Vec<ContentSet> {
    let mut out = Vec::new();
    for chunk in (0..content.len()).collect::<Vec<_>>().chunks(CONTENT_CHUNK) {
        let pats: Vec<&str> = chunk.iter().map(|&i| content[i].as_str()).collect();
        match RegexSet::new(&pats) {
            Ok(set) => out.push(ContentSet {
                set,
                ix: chunk.to_vec(),
            }),
            Err(_) => {
                for &i in chunk {
                    if let Ok(set) = RegexSet::new([content[i].as_str()]) {
                        out.push(ContentSet { set, ix: vec![i] });
                    }
                }
            }
        }
    }
    out
}

fn count_of(ex: Option<&serde_json::Value>, key: &str) -> usize {
    ex.and_then(|e| e.get(key))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

fn hash_entries(ex: Option<&serde_json::Value>) -> usize {
    ex.and_then(|e| e.get("hashes"))
        .and_then(|v| v.as_object())
        .map(|o| o.len())
        .unwrap_or(0)
}

/// Build a range from one corpus vulnerability entry, or refuse it.
///
/// Refuses an entry with no evaluable bound at all: a bound-free range matches every version, so
/// loading one would flag every sighting of the library as vulnerable. A bound that does not parse
/// is a refusal for the same reason it is elsewhere in this module — the comparison would be a
/// guess.
fn range_of(v: &serde_json::Value) -> Option<VersionRange> {
    let get = |k: &str| v.get(k).and_then(|x| x.as_str());
    let mut lower = None;
    let mut upper = None;
    let mut parts: Vec<String> = Vec::new();
    for (key, inclusive) in [("atOrAbove", true), ("above", false)] {
        if let Some(s) = get(key) {
            let at = Version::parse(s)?;
            parts.push(format!("{key} {s}"));
            lower = Some(Edge { at, inclusive });
        }
    }
    for (key, inclusive) in [("atOrBelow", true), ("below", false)] {
        if let Some(s) = get(key) {
            let at = Version::parse(s)?;
            parts.push(format!("{key} {s}"));
            upper = Some(Edge { at, inclusive });
        }
    }
    if lower.is_none() && upper.is_none() {
        return None;
    }
    Some(VersionRange {
        lower,
        upper,
        text: parts.join(", "),
    })
}

fn range_text(v: &serde_json::Value) -> String {
    ["atOrAbove", "above", "atOrBelow", "below"]
        .iter()
        .filter_map(|k| v.get(*k).and_then(|x| x.as_str()).map(|s| format!("{k} {s}")))
        .collect::<Vec<_>>()
        .join(", ")
}

fn identifiers_of(v: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(ids) = v.get("identifiers") else {
        return out;
    };
    for key in ["CVE", "githubID", "bug", "issue", "retid", "osvdb"] {
        match ids.get(key) {
            Some(serde_json::Value::Array(a)) => {
                out.extend(a.iter().filter_map(|x| x.as_str()).map(str::to_string));
            }
            Some(serde_json::Value::String(s)) => out.push(s.clone()),
            _ => {}
        }
    }
    out
}

/// The corpus's severity words. `critical` folds onto `High`: this project's [`Severity`] has four
/// levels and inventing a fifth to carry one corpus's vocabulary would change a type every check
/// shares. An unrecognised word becomes `Medium` — the corpus said it was a vulnerability, so
/// dropping to `Info` would understate it.
fn severity_of(v: &serde_json::Value) -> Severity {
    match v.get("severity").and_then(|s| s.as_str()) {
        Some("critical") | Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        _ => Severity::Medium,
    }
}

fn severity_word(s: Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn sev_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
    }
}

fn rank_sev(r: u8) -> Severity {
    match r {
        3 => Severity::High,
        2 => Severity::Medium,
        1 => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> JsVulnDb {
        JsVulnDb::vendored()
    }

    #[test]
    fn the_vendored_corpus_loads_and_reports_what_it_could_not_use() {
        let d = db();
        assert!(d.summary().state.is_available(), "{}", d.summary().summary());
        assert_eq!(d.summary().components, 76);
        assert_eq!(d.summary().vulnerabilities, 683);
        // Every one of the corpus's 1,182 version bounds parses, so no vulnerability entry is
        // dropped. If a refreshed corpus introduces an unparsable bound this fails loudly rather
        // than quietly narrowing what gets compared.
        assert!(
            d.summary().unusable_ranges.is_empty(),
            "unusable ranges: {:?}",
            d.summary().unusable_ranges
        );
        // Two corpus regexes this engine cannot compile: jQuery's minified-banner pattern uses a
        // backreference and lodash's uses a lookbehind. Pinned so the number cannot grow unnoticed —
        // each one is a library this check is partly blind to by content.
        assert_eq!(
            d.summary().unusable_patterns.len(),
            2,
            "{:?}",
            d.summary().unusable_patterns
        );
        // The two extractor kinds this module refuses are counted, not silently skipped.
        assert!(d.summary().unsupported_func_extractors > 0);
        assert!(d.summary().unsupported_hash_extractors > 0);
    }

    #[test]
    fn a_known_vulnerable_version_in_the_filename_is_flagged_at_the_corpus_severity() {
        let c = JsLibraryCheck::vendored();
        let f = c.scan("/static/jquery-1.4.2.min.js", None, b"");
        let vulns: Vec<_> = f.iter().filter(|f| f.issue_name.as_deref() == Some(ISSUE)).collect();
        assert_eq!(vulns.len(), 1, "{f:#?}");
        assert_eq!(vulns[0].confidence, Confidence::Tentative);
        let detail = vulns[0].detail.as_deref().unwrap();
        assert!(detail.contains("jquery 1.4.2"), "{detail}");
        assert!(detail.contains("CVE-2011-4969"), "{detail}");
        assert_eq!(c.coverage().detections_vulnerable, 1);
        assert_eq!(c.coverage().detections_cleared, 0);
    }

    #[test]
    fn a_patched_version_of_the_same_library_produces_no_finding_but_is_counted_as_cleared() {
        let c = JsLibraryCheck::vendored();
        let f = c.scan("/static/jquery-3.7.1.min.js", None, b"");
        assert!(f.is_empty(), "{f:#?}");
        let cov = c.coverage();
        assert_eq!(cov.detections_cleared, 1);
        assert_eq!(cov.detections_vulnerable, 0);
        assert_eq!(cov.assets_identified, 1);
        assert!(
            !cov.inconclusive(),
            "a comparable, cleared version is the one case that really is clean"
        );
    }

    #[test]
    fn an_unknown_version_is_reported_as_undetermined_rather_than_clean() {
        let c = JsLibraryCheck::vendored();
        let f = c.scan("/js/jquery-latest.min.js", None, b"");
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].issue_name.as_deref(), Some(UNDETERMINED_ISSUE));
        assert_eq!(f[0].severity, Severity::Info);
        let detail = f[0].detail.as_deref().unwrap();
        assert!(detail.contains("not a clean result"), "{detail}");
        assert!(detail.contains("\"latest\""), "{detail}");
        let cov = c.coverage();
        assert_eq!(cov.detections_undetermined, 1);
        assert_eq!(cov.detections_cleared, 0);
        assert_eq!(cov.detections_vulnerable, 0);
        assert!(cov.inconclusive());
    }

    #[test]
    fn an_in_content_version_marker_is_firm_where_a_filename_is_only_tentative() {
        let c = JsLibraryCheck::vendored();
        let body = b"/*! jQuery v1.7.1 | (c) jQuery Foundation */ var x = 1;";
        let f = c.scan("/bundle.js", Some("application/javascript"), body);
        let vulns: Vec<_> = f.iter().filter(|f| f.issue_name.as_deref() == Some(ISSUE)).collect();
        assert_eq!(vulns.len(), 1, "{f:#?}");
        assert_eq!(vulns[0].confidence, Confidence::Firm);
        assert!(vulns[0].detail.as_deref().unwrap().contains("jquery 1.7.1"));
    }

    #[test]
    fn a_script_no_pattern_recognises_is_counted_unidentified_not_clean() {
        let c = JsLibraryCheck::vendored();
        let f = c.scan("/app.bundle.js", None, b"console.log('hand written');");
        assert!(f.is_empty());
        let cov = c.coverage();
        assert_eq!(cov.assets_seen, 1);
        assert_eq!(cov.assets_unidentified, 1);
        assert_eq!(cov.assets_identified, 0);
        assert!(
            cov.inconclusive(),
            "an unidentified asset is not evidence that the page ships no vulnerable library"
        );
    }

    #[test]
    fn a_non_javascript_response_is_counted_separately_from_a_clean_script() {
        let c = JsLibraryCheck::vendored();
        assert!(c.scan("/index.html", Some("text/html"), b"<html>").is_empty());
        let cov = c.coverage();
        assert_eq!(cov.not_javascript, 1);
        assert_eq!(cov.assets_seen, 0);
    }

    #[test]
    fn an_absent_dataset_reports_the_check_unavailable_rather_than_finding_nothing() {
        let c = JsLibraryCheck::new(JsVulnDb::load(std::path::Path::new(
            "/nonexistent/retirejs_repository.json",
        )));
        let f = c.scan("/static/jquery-1.4.2.min.js", None, b"");
        assert!(f.is_empty());
        let cov = c.coverage();
        assert!(matches!(cov.dataset.state, DatasetState::Unavailable(_)));
        assert!(cov.dataset.summary().contains("UNAVAILABLE"), "{}", cov.dataset.summary());
        assert_eq!(cov.skipped_dataset_unavailable, 1);
        assert_eq!(cov.assets_seen, 0, "nothing was examined, so nothing is clean");
        assert!(cov.inconclusive());
    }

    #[test]
    fn a_dataset_that_is_not_jsrepository_json_is_unavailable_with_the_parse_reason() {
        let db = JsVulnDb::parse("[1,2,3]", "unit test".into());
        match &db.summary().state {
            DatasetState::Unavailable(why) => assert!(why.contains("not a JSON object"), "{why}"),
            s => panic!("expected refusal, got {s:?}"),
        }
    }

    #[test]
    fn version_comparison_is_arithmetic_not_a_string_prefix() {
        let v = |s: &str| Version::parse(s).unwrap();
        // The exact trap a prefix test falls into: "1.4" is a textual prefix of "1.40.0".
        assert!(v("1.4.2") < v("1.9.0"));
        assert!(v("1.40.0") > v("1.9.0"));
        assert!(v("1.9.0") < v("1.10.0"), "9 < 10 numerically, but '9' > '1' textually");
        assert_eq!(v("2.0"), v("2.0.0"), "the shorter side is zero-padded");
        assert!(v("3.0.0-rc1") < v("3.0.0"), "a release candidate is not the release");
        assert!(v("1.11.0b1") < v("1.11.0"));
        assert!(v("2.2.4-lite") < v("2.2.4"));
        assert_eq!(v("1.11.0b1").parts(), &[1, 11, 0]);
    }

    #[test]
    fn a_version_string_with_no_leading_digit_is_refused_rather_than_guessed_at() {
        assert!(Version::parse("latest").is_none());
        assert!(Version::parse("").is_none());
        assert!(Version::parse("  ").is_none());
        assert!(Version::parse("v").is_none());
        // Wider than u32: refused, because a wrapped comparison is worse than no comparison.
        assert!(Version::parse("99999999999.0").is_none());
    }

    #[test]
    fn a_range_boundary_is_exclusive_below_and_inclusive_at_or_above() {
        let json: serde_json::Value =
            serde_json::from_str(r#"{"atOrAbove":"1.2.0","below":"1.4.0"}"#).unwrap();
        let r = range_of(&json).unwrap();
        let v = |s: &str| Version::parse(s).unwrap();
        assert!(!r.contains(&v("1.1.9")));
        assert!(r.contains(&v("1.2.0")), "atOrAbove includes its bound");
        assert!(r.contains(&v("1.3.9")));
        assert!(!r.contains(&v("1.4.0")), "below excludes its bound");
        assert_eq!(r.text(), "atOrAbove 1.2.0, below 1.4.0");
    }

    #[test]
    fn a_vulnerability_entry_with_no_bounds_is_refused_rather_than_matching_every_version() {
        let json: serde_json::Value = serde_json::from_str(r#"{"severity":"high"}"#).unwrap();
        assert!(range_of(&json).is_none());
    }
}
