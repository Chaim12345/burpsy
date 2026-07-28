//! REPORT-03 — SARIF 2.1.0, for a code-scanning consumer.
//!
//! # The subset emitted, and why nothing outside it
//!
//! SARIF is a large format and most of it does not apply to a tool that reports on HTTP endpoints
//! rather than source lines. Only these are emitted:
//!
//! * `$schema`, `version` — `"2.1.0"`, the OASIS-standardised version.
//! * `runs[].tool.driver.{name, version, rules[], notifications[]}`.
//! * `runs[].results[].{ruleId, level, message.text, locations[], partialFingerprints,
//!   occurrenceCount, properties}`.
//! * `runs[].invocations[0].{executionSuccessful, startTimeUtc, toolExecutionNotifications[]}`.
//! * `runs[].automationDetails.id`, `runs[].properties.coverage`.
//!
//! Everything else is omitted rather than filled in. In particular **`region` is omitted**: burpsy
//! findings have no line numbers, and emitting `startLine: 1` to make a consumer's UI happier would
//! be an invented location pointing at a line nobody claimed anything about.
//!
//! # Severity, and what the mapping loses
//!
//! burpsy has four severities; SARIF `level` has `none | note | warning | error`.
//!
//! | burpsy | `level` | `properties["security-severity"]` |
//! |---|---|---|
//! | High | `error` | `7.0` |
//! | Medium | `warning` | `5.0` |
//! | Low | `note` | `3.0` |
//! | Info | `note` | `0.0` |
//!
//! **Lost:** `Low` and `Info` both collapse onto `note`. Consequence, and it is a deliberate choice
//! rather than an oversight: **`Info` findings are excluded by default**, with the excluded count
//! stated in a coverage notification and an opt-in [`SarifOptions::include_info`] to keep them. An
//! informational finding rendered in a consumer's UI as a low-severity *security alert* is a
//! misrepresentation; dropping it silently is worse than that; dropping it with a stated count is the
//! only one of the three that is honest.
//!
//! **Also lost:** confidence. There is no SARIF equivalent — `reportingDescriptor.properties.precision`
//! is a property of a *rule* and burpsy's confidence is per finding, and `result.rank` means priority,
//! not confidence, so using it as one would be a misuse of the field. Confidence is therefore carried
//! verbatim in `result.properties.confidence`, which no mainstream consumer surfaces. A `Tentative`
//! and a `Certain` finding look identical in a code-scanning UI, and a coverage notification says so
//! in one sentence, because a reader who does not know that will treat every alert as firm.
//!
//! # `rules[]` lists only rules that produced a result
//!
//! Declaring all 264 loaded checks as rules with zero results would present *capability* as a clean
//! bill of health for each one — exactly the ambiguity REPORT-04 removes. The not-run set goes in
//! notifications, where it cannot be read as a rule that came back clean.
//!
//! # Where REPORT-04 lives in a SARIF document
//!
//! SARIF has no standard "this rule did not run" marker, so there are three candidate places and only
//! one of them is honest:
//!
//! | Option | Verdict |
//! |---|---|
//! | `invocations[].toolExecutionNotifications[]` plus `runs[].properties.coverage` | **Used.** Standard, round-trippable, and cannot be mistaken for a finding. |
//! | `invocations[].executionSuccessful = false` | Rejected. The tool did not fail. Reporting a successful bounded scan as a failed invocation is a different lie from the one being avoided. |
//! | A synthetic `note` result against a `coverage-incomplete` rule | Opt-in only ([`SarifOptions::coverage_alert`]). Visible in a consumer's alert list, which some CI gates read exclusively — but a fabricated result *about the scan* is the one thing this project's reporting must never emit by default. |
//!
//! # What could not be verified from here
//!
//! Whether a given consumer ingests results whose `artifactLocation.uri` is an absolute `https:` URL
//! absent from the repository. burpsy findings are about endpoints, and code-scanning products
//! annotate files relative to a repository root; DAST tools publish SARIF this way, but that is a
//! claim about someone else's service and this crate's tests cannot back it. What the tests *do* back
//! is that the document has the required 2.1.0 shape — see
//! [`tests::the_document_carries_every_required_sarif_2_1_0_key`].

use serde::Serialize;

use super::{NotChecked, Report, TOOL_NAME, TOOL_VERSION, Unit, Verdict};
use burpsy_core::{Finding, Severity};

/// The 2.1.0 schema URL. A constant rather than a literal at the use site so the version in
/// [`SARIF_VERSION`] and the schema it points at cannot drift apart.
pub const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

/// The only SARIF version emitted.
pub const SARIF_VERSION: &str = "2.1.0";

/// Notification descriptor ids. Stable: a consumer may suppress or key on them.
const NOTE_COVERAGE: &str = "burpsy/coverage/not-checked";
const NOTE_VERDICT: &str = "burpsy/coverage/verdict";
const NOTE_UNKNOWN: &str = "burpsy/coverage/unknown";
const NOTE_INFO_EXCLUDED: &str = "burpsy/coverage/info-findings-excluded";
const NOTE_CONFIDENCE: &str = "burpsy/coverage/confidence-not-surfaced";
const RULE_COVERAGE_ALERT: &str = "burpsy/coverage-incomplete";

/// Choices a caller has to make explicitly, because both defaults lose something and the operator
/// should know which loss they are choosing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SarifOptions {
    /// Emit `Info` findings as `note`-level results. Off by default — see the module docs.
    pub include_info: bool,
    /// Additionally emit one synthetic `note` result naming the incomplete coverage, for a CI gate
    /// that reads only the alert list. Off by default: a fabricated result about the scan itself is
    /// not something to produce unasked.
    pub coverage_alert: bool,
}

// `Default` is derived: both options are `false`, and the doc comments above state why each one
// defaults to off. A hand-written impl would be a second place for that to drift.

/// Serialise a report as SARIF 2.1.0 with the default options.
pub fn to_sarif(r: &Report) -> String {
    to_sarif_with(r, SarifOptions::default())
}

/// As [`to_sarif`], with explicit options.
pub fn to_sarif_with(r: &Report, opts: SarifOptions) -> String {
    let doc = SarifLog::build(r, opts);
    serde_json::to_string_pretty(&doc)
        .unwrap_or_else(|e| format!("{{\"error\":\"burpsy SARIF serialisation failed: {e}\"}}"))
}

#[derive(Debug, Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Run>,
}

impl SarifLog {
    fn build(r: &Report, opts: SarifOptions) -> Self {
        let included: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|f| opts.include_info || f.severity != Severity::Info)
            .collect();
        let excluded_info = r.findings.len() - included.len();

        let mut rules: Vec<Rule> = Vec::new();
        let mut results: Vec<SarifResult> = Vec::new();
        for f in &included {
            let id = rule_id(f);
            if !rules.iter().any(|r| r.id == id) {
                rules.push(Rule {
                    id: id.clone(),
                    name: Some(f.check_name.clone()),
                    short_description: Some(Message {
                        text: f
                            .issue_name
                            .clone()
                            .unwrap_or_else(|| f.check_name.clone()),
                    }),
                    // No `fullDescription` and no `help`: the shipped check corpus carries neither,
                    // and writing plausible security prose to fill the gap is precisely the failure
                    // `crate::catalog` exists to prevent. The absence stays visible.
                    properties: RuleProperties {
                        tags: vec!["security"],
                    },
                });
            }
            results.push(SarifResult::build(f, id));
        }

        let verdict = r.verdict();
        if opts.coverage_alert && !verdict.coverage_is_complete() {
            rules.push(Rule {
                id: RULE_COVERAGE_ALERT.to_owned(),
                name: Some("Scan coverage incomplete".to_owned()),
                short_description: Some(Message {
                    text: "Work was declined or never reached, so a clean result is not a clean \
                           bill of health."
                        .to_owned(),
                }),
                properties: RuleProperties {
                    tags: vec!["security"],
                },
            });
            results.push(SarifResult::coverage_alert(r, &verdict));
        }

        let notifications = notifications(r, &verdict, excluded_info, !included.is_empty());

        Self {
            schema: SARIF_SCHEMA,
            version: SARIF_VERSION,
            runs: vec![Run {
                tool: Tool {
                    driver: Driver {
                        name: TOOL_NAME,
                        version: TOOL_VERSION,
                        rules,
                        notifications: notification_descriptors(),
                    },
                },
                automation_details: AutomationDetails {
                    id: format!("{TOOL_NAME}/scan/{}", r.generated_unix_ms),
                },
                invocations: vec![Invocation {
                    // True, and deliberately so. The scan ran; it was *bounded*. Reporting a
                    // successful bounded scan as a failed invocation would trade one
                    // misrepresentation for another — see the module docs.
                    execution_successful: true,
                    start_time_utc: r.generated_at(),
                    tool_execution_notifications: notifications,
                }],
                results,
                properties: RunProperties {
                    coverage: CoverageProperties::build(r, &verdict, excluded_info),
                },
            }],
        }
    }
}

#[derive(Debug, Serialize)]
struct Run {
    tool: Tool,
    #[serde(rename = "automationDetails")]
    automation_details: AutomationDetails,
    invocations: Vec<Invocation>,
    results: Vec<SarifResult>,
    properties: RunProperties,
}

#[derive(Debug, Serialize)]
struct Tool {
    driver: Driver,
}

/// `informationUri` is **absent on purpose**: this project publishes no canonical URL, and SARIF
/// marks the field optional. Emitting a plausible-looking repository link would be inventing a fact
/// about where the tool lives.
#[derive(Debug, Serialize)]
struct Driver {
    name: &'static str,
    version: &'static str,
    rules: Vec<Rule>,
    notifications: Vec<NotificationDescriptor>,
}

#[derive(Debug, Serialize)]
struct Rule {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "shortDescription", skip_serializing_if = "Option::is_none")]
    short_description: Option<Message>,
    properties: RuleProperties,
}

#[derive(Debug, Serialize)]
struct RuleProperties {
    tags: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct NotificationDescriptor {
    id: &'static str,
    #[serde(rename = "shortDescription")]
    short_description: Message,
}

fn notification_descriptors() -> Vec<NotificationDescriptor> {
    vec![
        NotificationDescriptor {
            id: NOTE_VERDICT,
            short_description: Message {
                text: "Whether this run's coverage was complete.".to_owned(),
            },
        },
        NotificationDescriptor {
            id: NOTE_COVERAGE,
            short_description: Message {
                text: "Work that was not done, and why.".to_owned(),
            },
        },
        NotificationDescriptor {
            id: NOTE_UNKNOWN,
            short_description: Message {
                text: "Something this run structurally cannot know.".to_owned(),
            },
        },
        NotificationDescriptor {
            id: NOTE_INFO_EXCLUDED,
            short_description: Message {
                text: "Informational findings withheld from this document.".to_owned(),
            },
        },
        NotificationDescriptor {
            id: NOTE_CONFIDENCE,
            short_description: Message {
                text: "Per-finding confidence is carried but not surfaced by consumers.".to_owned(),
            },
        },
    ]
}

#[derive(Debug, Serialize)]
struct AutomationDetails {
    id: String,
}

#[derive(Debug, Serialize)]
struct Invocation {
    #[serde(rename = "executionSuccessful")]
    execution_successful: bool,
    #[serde(rename = "startTimeUtc")]
    start_time_utc: String,
    #[serde(rename = "toolExecutionNotifications")]
    tool_execution_notifications: Vec<Notification>,
}

#[derive(Debug, Serialize)]
struct Notification {
    descriptor: DescriptorRef,
    level: &'static str,
    message: Message,
}

#[derive(Debug, Serialize)]
struct DescriptorRef {
    id: &'static str,
}

#[derive(Debug, Serialize)]
struct Message {
    text: String,
}

/// REPORT-04 in SARIF's own vocabulary: one notification per statement, at a level that reflects what
/// it means.
///
/// Order matters — the verdict first, so a consumer that shows only the first notification shows the
/// one sentence that qualifies the whole run.
fn notifications(
    r: &Report,
    verdict: &Verdict,
    excluded_info: usize,
    any_results: bool,
) -> Vec<Notification> {
    let mut v = vec![Notification {
        descriptor: DescriptorRef { id: NOTE_VERDICT },
        level: if verdict.coverage_is_complete() {
            "note"
        } else {
            // `warning`, not `note`: incomplete coverage is a caveat on every conclusion in the
            // document, and a consumer filtering notes would drop exactly the wrong one.
            "warning"
        },
        message: Message {
            text: verdict.headline(),
        },
    }];

    for row in r.coverage.not_checked() {
        v.push(Notification {
            descriptor: DescriptorRef { id: NOTE_COVERAGE },
            level: "warning",
            message: Message {
                text: not_checked_sentence(&row),
            },
        });
    }

    for u in &r.coverage.unknowns {
        v.push(Notification {
            descriptor: DescriptorRef { id: NOTE_UNKNOWN },
            level: "note",
            message: Message {
                text: format!("Not knowable from this run: {} — {}", u.subject, u.because),
            },
        });
    }

    if excluded_info > 0 {
        v.push(Notification {
            descriptor: DescriptorRef {
                id: NOTE_INFO_EXCLUDED,
            },
            level: "warning",
            message: Message {
                text: format!(
                    "{excluded_info} informational findings are not in this document. SARIF's \
                     `level` has no band below `note`, so an informational finding would appear as \
                     a low-severity security alert. They are in the JSON export."
                ),
            },
        });
    }

    if any_results {
        v.push(Notification {
            descriptor: DescriptorRef {
                id: NOTE_CONFIDENCE,
            },
            level: "note",
            message: Message {
                text: "Per-finding confidence is carried in `result.properties.confidence`. No \
                       mainstream consumer surfaces it, so a tentative finding and a certain one \
                       look identical here."
                    .to_owned(),
            },
        });
    }

    v
}

fn not_checked_sentence(row: &NotChecked) -> String {
    let unit = match (row.reason.unit(), row.count) {
        (Unit::Checks, 1) => "check",
        (Unit::Checks, _) => "checks",
        (Unit::Dispatches, 1) => "check dispatch",
        (Unit::Dispatches, _) => "check dispatches",
        (Unit::Responses, 1) => "captured response",
        (Unit::Responses, _) => "captured responses",
        (Unit::Items, 1) => "audit item",
        (Unit::Items, _) => "audit items",
    };
    let mut s = format!(
        "Not checked: {} {unit} — {} [{}]",
        row.count,
        row.reason.explanation(),
        row.reason.id()
    );
    if !row.identities.is_empty() {
        // Bounded: a SARIF notification is a message for a human reading a CI log, and the full list
        // is in the JSON export. Truncated with the count stated, never silently.
        const MAX: usize = 10;
        let shown = row.identities.len().min(MAX);
        s.push_str(". ");
        s.push_str(&row.identities[..shown].join("; "));
        if shown < row.identities.len() {
            s.push_str(&format!(
                " (… {} of {} listed; the JSON export has all of them)",
                shown,
                row.identities.len()
            ));
        }
    }
    s
}

#[derive(Debug, Serialize)]
struct RunProperties {
    coverage: CoverageProperties,
}

/// The machine-readable half of REPORT-04, for a consumer that reads `runs[].properties` rather than
/// notification prose.
#[derive(Debug, Serialize)]
struct CoverageProperties {
    verdict: &'static str,
    #[serde(rename = "coverageIsComplete")]
    coverage_is_complete: bool,
    checked: usize,
    #[serde(rename = "notChecked")]
    not_checked: usize,
    #[serde(rename = "notCheckedByReason")]
    not_checked_by_reason: Vec<ReasonCount>,
    #[serde(rename = "auditRequested")]
    audit_requested: bool,
    #[serde(rename = "infoFindingsExcluded")]
    info_findings_excluded: usize,
    unknowns: Vec<String>,
}

impl CoverageProperties {
    fn build(r: &Report, verdict: &Verdict, excluded_info: usize) -> Self {
        Self {
            verdict: verdict.id(),
            coverage_is_complete: verdict.coverage_is_complete(),
            checked: r.coverage.checked_total(),
            not_checked: r.coverage.not_checked_total(),
            not_checked_by_reason: r
                .coverage
                .not_checked()
                .iter()
                .map(|row| ReasonCount {
                    reason: row.reason.id(),
                    unit: row.reason.unit().id(),
                    count: row.count,
                })
                .collect(),
            audit_requested: r.coverage.active.audit_requested,
            info_findings_excluded: excluded_info,
            unknowns: r
                .coverage
                .unknowns
                .iter()
                .map(|u| format!("{}: {}", u.subject, u.because))
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ReasonCount {
    reason: &'static str,
    unit: &'static str,
    count: usize,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: Message,
    locations: Vec<Location>,
    #[serde(rename = "partialFingerprints")]
    partial_fingerprints: Fingerprints,
    #[serde(rename = "occurrenceCount", skip_serializing_if = "Option::is_none")]
    occurrence_count: Option<u64>,
    properties: ResultProperties,
}

impl SarifResult {
    fn build(f: &Finding, rule_id: String) -> Self {
        Self {
            rule_id,
            level: level_for(f.severity),
            message: Message {
                // `detail` where the check supplied one, the issue or check name otherwise. Never an
                // empty string: `message.text` is required and a blank alert body is useless.
                text: f
                    .detail
                    .clone()
                    .filter(|d| !d.trim().is_empty())
                    .unwrap_or_else(|| {
                        f.issue_name.clone().unwrap_or_else(|| f.check_name.clone())
                    }),
            },
            locations: locations_for(f),
            partial_fingerprints: Fingerprints {
                dedup_key_v1: format!("{:016x}", fnv1a(f.dedup_key().as_bytes())),
            },
            occurrence_count: Some(f.times_seen),
            properties: ResultProperties {
                security_severity: security_severity(f.severity),
                confidence: f.confidence.as_str(),
                host: f.host.clone(),
                check_name: f.check_name.clone(),
                burpsy_severity: f.severity.as_str(),
            },
        }
    }

    /// The opt-in synthetic result from option C in the module docs.
    fn coverage_alert(r: &Report, verdict: &Verdict) -> Self {
        Self {
            rule_id: RULE_COVERAGE_ALERT.to_owned(),
            level: "note",
            message: Message {
                text: verdict.headline(),
            },
            locations: Vec::new(),
            partial_fingerprints: Fingerprints {
                dedup_key_v1: format!("{:016x}", fnv1a(RULE_COVERAGE_ALERT.as_bytes())),
            },
            occurrence_count: None,
            properties: ResultProperties {
                security_severity: "0.0",
                confidence: "certain",
                host: r.scope.summary(),
                check_name: "coverage".to_owned(),
                burpsy_severity: "info",
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct Fingerprints {
    /// Versioned key: changing how the fingerprint is computed means a new key, not a silent change
    /// that reopens every alert a consumer has already triaged.
    #[serde(rename = "burpsyDedupKey/v1")]
    dedup_key_v1: String,
}

#[derive(Debug, Serialize)]
struct ResultProperties {
    #[serde(rename = "security-severity")]
    security_severity: &'static str,
    /// Carried because dropping it would lose information; see the module docs for why no consumer
    /// shows it.
    confidence: &'static str,
    host: String,
    #[serde(rename = "checkName")]
    check_name: String,
    /// The original four-level severity, since `level` collapses `Low` and `Info`.
    #[serde(rename = "burpsySeverity")]
    burpsy_severity: &'static str,
}

#[derive(Debug, Serialize)]
struct Location {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Debug, Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
}

#[derive(Debug, Serialize)]
struct ArtifactLocation {
    uri: String,
}

/// One location per retained occurrence, capped by storage at
/// [`burpsy_core::MAX_OCCURRENCES`]. `occurrenceCount` carries the true total, so a consumer showing
/// three locations for a finding seen 1,204 times can still see the 1,204.
fn locations_for(f: &Finding) -> Vec<Location> {
    f.occurrences
        .iter()
        .map(|o| Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    // Host and path, not a repository-relative file: burpsy findings are about
                    // endpoints and there is no source file to point at. Scheme is unknown here —
                    // `Occurrence` carries no TLS flag — so the URI is host-relative rather than
                    // asserting `https:` for traffic that may have been plain HTTP.
                    uri: format!("{}{}", f.host, o.path),
                },
            },
        })
        .collect()
}

/// `burpsy/bcheck/<slug>`.
///
/// A check name is the only stable identifier a BCheck has, so **an upstream rename reopens that
/// check's alerts** in a consumer that tracks alerts by rule id. Unavoidable, and stated here rather
/// than discovered by an operator wondering why their triage was undone.
fn rule_id(f: &Finding) -> String {
    format!("{TOOL_NAME}/bcheck/{}", slug(&f.check_name))
}

fn slug(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_dash = true;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        // A rule id is required and must be non-empty. An unnameable check gets a stated placeholder
        // rather than an empty id that a consumer would silently discard.
        out.push_str("unnamed");
    }
    out
}

fn level_for(s: Severity) -> &'static str {
    match s {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn security_severity(s: Severity) -> &'static str {
    match s {
        Severity::High => "7.0",
        Severity::Medium => "5.0",
        Severity::Low => "3.0",
        Severity::Info => "0.0",
    }
}

/// FNV-1a, matching the implementation already in `burpsy-tools`' comparer.
///
/// Deliberately not `std::hash::DefaultHasher`: its algorithm is explicitly unspecified and may
/// change between compiler releases, which for a `partialFingerprints` value would silently reopen
/// every alert a consumer had triaged after a routine toolchain bump.
fn fnv1a(b: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &x in b {
        h ^= x as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests::{bounded_session, passive_all_ran, shipped_load};
    use crate::report::RunFacts;
    use burpsy_core::{Confidence, MsgId, Occurrence, Scope};
    use serde_json::Value;

    fn finding(severity: Severity, check: &str) -> Finding {
        Finding {
            id: 0,
            check_name: check.to_owned(),
            issue_name: Some("SQL injection".into()),
            severity,
            confidence: Confidence::Firm,
            host: "app.test".into(),
            detail: Some("payload reflected in an error message".into()),
            remediation: None,
            occurrences: vec![Occurrence {
                exchange_id: 12,
                response: MsgId(9),
                path: "/search?q=1".into(),
            }],
            times_seen: 3,
        }
    }

    fn doc_with(
        findings: &[Finding],
        audits: &[crate::SessionOutcome],
        opts: SarifOptions,
    ) -> Value {
        let scope = Scope::allow_everything();
        let load = shipped_load();
        let passive = passive_all_ran(105);
        let r = Report::from_facts(RunFacts {
            scope: &scope,
            load: &load,
            passive: &passive,
            audits,
            findings,
            generated_unix_ms: 1_753_660_800_000,
        });
        serde_json::from_str(&to_sarif_with(&r, opts)).expect("SARIF must be valid JSON")
    }

    fn doc(findings: &[Finding], audits: &[crate::SessionOutcome]) -> Value {
        doc_with(findings, audits, SarifOptions::default())
    }

    #[test]
    fn the_document_carries_every_required_sarif_2_1_0_key() {
        let v = doc(&[finding(Severity::High, "SQLi error based")], &[]);

        assert_eq!(v["$schema"], SARIF_SCHEMA);
        assert_eq!(v["version"], "2.1.0");

        let runs = v["runs"].as_array().expect("runs[] must be an array");
        assert_eq!(runs.len(), 1);
        let run = &runs[0];

        let driver = &run["tool"]["driver"];
        assert_eq!(driver["name"], TOOL_NAME);
        assert_eq!(driver["version"], TOOL_VERSION);
        assert!(driver["rules"].is_array());

        let results = run["results"].as_array().expect("results[] must be present");
        assert_eq!(results.len(), 1);
        let res = &results[0];
        assert_eq!(res["ruleId"], "burpsy/bcheck/sqli-error-based");
        assert_eq!(res["level"], "error");
        assert!(
            res["message"]["text"].as_str().is_some_and(|t| !t.is_empty()),
            "message.text is required and must not be blank"
        );
        let uri = &res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"];
        assert_eq!(uri, "app.test/search?q=1");
        assert!(
            res["locations"][0]["physicalLocation"].get("region").is_none(),
            "no line numbers exist, so no region may be fabricated"
        );

        // Every emitted ruleId must resolve to a declared rule, or a consumer drops the result.
        let declared: Vec<&str> = driver["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert!(declared.contains(&res["ruleId"].as_str().unwrap()));
    }

    #[test]
    fn rules_declare_only_checks_that_produced_a_result() {
        let v = doc(&[finding(Severity::High, "One check")], &[]);
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            1,
            "declaring all 264 loaded checks would present capability as a clean bill of health"
        );
    }

    #[test]
    fn a_run_with_refused_dispatches_does_not_serialise_as_a_clean_sarif_document() {
        let v = doc(&[], &[bounded_session()]);
        assert!(
            v["runs"][0]["results"].as_array().unwrap().is_empty(),
            "the run reported no findings, which is exactly the case that must not look clean"
        );

        let cov = &v["runs"][0]["properties"]["coverage"];
        assert_eq!(cov["verdict"], "partially_checked");
        assert_eq!(cov["coverageIsComplete"], false);
        assert!(cov["notChecked"].as_u64().unwrap() > 0);
        let reasons = cov["notCheckedByReason"].as_array().unwrap();
        assert!(
            reasons
                .iter()
                .any(|r| r["reason"] == "not_dispatched/request_budget_spent"
                    && r["count"] == 6),
            "the refused dispatches must appear in runs[].properties.coverage: {reasons:?}"
        );

        let notes = v["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .unwrap();
        assert!(
            notes.iter().any(|n| n["message"]["text"]
                .as_str()
                .unwrap()
                .contains("not_dispatched/request_budget_spent")),
            "and in toolExecutionNotifications, where a CI log will show them: {notes:?}"
        );
        assert!(
            notes
                .iter()
                .any(|n| n["descriptor"]["id"] == NOTE_VERDICT && n["level"] == "warning"),
            "the verdict notification must be a warning when coverage is incomplete"
        );
    }

    #[test]
    fn the_invocation_is_reported_as_successful_even_when_coverage_is_partial() {
        let v = doc(&[], &[bounded_session()]);
        assert_eq!(
            v["runs"][0]["invocations"][0]["executionSuccessful"], true,
            "the tool did not fail; it was bounded. Claiming a failed invocation is a different lie."
        );
    }

    #[test]
    fn every_notification_descriptor_id_is_declared_on_the_driver() {
        let v = doc(&[finding(Severity::Info, "Info only")], &[bounded_session()]);
        let declared: Vec<String> = v["runs"][0]["tool"]["driver"]["notifications"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap().to_owned())
            .collect();
        for n in v["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .unwrap()
        {
            let id = n["descriptor"]["id"].as_str().unwrap().to_owned();
            assert!(
                declared.contains(&id),
                "notification {id} references an undeclared descriptor"
            );
        }
    }

    #[test]
    fn info_findings_are_withheld_by_default_and_the_count_is_stated() {
        let v = doc(&[finding(Severity::Info, "Info only")], &[]);
        assert!(
            v["runs"][0]["results"].as_array().unwrap().is_empty(),
            "an informational finding must not appear as a low-severity security alert"
        );
        assert_eq!(v["runs"][0]["properties"]["coverage"]["infoFindingsExcluded"], 1);
        let notes = v["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .unwrap();
        assert!(
            notes.iter().any(|n| n["descriptor"]["id"] == NOTE_INFO_EXCLUDED),
            "dropping them silently would be worse than emitting them"
        );
    }

    #[test]
    fn info_findings_are_emitted_when_the_caller_opts_in() {
        let opts = SarifOptions {
            include_info: true,
            ..Default::default()
        };
        let v = doc_with(&[finding(Severity::Info, "Info only")], &[], opts);
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["level"], "note");
        assert_eq!(results[0]["properties"]["burpsySeverity"], "info");
    }

    #[test]
    fn the_coverage_alert_result_is_opt_in_and_absent_by_default() {
        let by_default = doc(&[], &[bounded_session()]);
        assert!(
            by_default["runs"][0]["results"]
                .as_array()
                .unwrap()
                .is_empty(),
            "a fabricated result about the scan must never be the default"
        );

        let opts = SarifOptions {
            coverage_alert: true,
            ..Default::default()
        };
        let opted_in = doc_with(&[], &[bounded_session()], opts);
        let results = opted_in["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], RULE_COVERAGE_ALERT);
        assert_eq!(results[0]["level"], "note");
    }

    #[test]
    fn the_severity_mapping_is_pinned_including_what_it_collapses() {
        assert_eq!(
            [
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Info
            ]
            .map(level_for),
            ["error", "warning", "note", "note"]
        );
        assert_eq!(
            [
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Info
            ]
            .map(security_severity),
            ["7.0", "5.0", "3.0", "0.0"]
        );
    }

    #[test]
    fn a_fingerprint_is_stable_for_the_same_dedup_key_and_differs_across_hosts() {
        let a = finding(Severity::High, "Check");
        let mut b = finding(Severity::High, "Check");
        b.host = "other.test".into();
        let fa = fnv1a(a.dedup_key().as_bytes());
        assert_eq!(fa, fnv1a(a.dedup_key().as_bytes()));
        assert_ne!(fa, fnv1a(b.dedup_key().as_bytes()));
    }

    #[test]
    fn a_check_name_with_no_alphanumerics_still_yields_a_usable_rule_id() {
        assert_eq!(slug("SQLi (error based)!"), "sqli-error-based");
        assert_eq!(slug("---"), "unnamed");
    }
}
