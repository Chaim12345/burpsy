//! REPORT-02 — the JSON export, for a machine reader.
//!
//! # This is an API surface, not a debug dump
//!
//! The shape here is declared explicitly and versioned. It is deliberately **not**
//! [`burpsy_core::Finding`]'s own `serde` representation, even though that already derives
//! `Serialize` and is already what `GET /api/issues` returns, for three reasons:
//!
//! * `Occurrence::response` is a [`burpsy_core::MsgId`] — an index into *this process's* traffic
//!   store. It is meaningless outside the run that produced it and different between two captures of
//!   the same traffic. Publishing it as if it were an identifier invites a consumer to key on it.
//! * `core`'s `#[serde(default)]` convention exists so an old capture still deserialises. That is
//!   backward compatibility on the *read* side; a published export needs it on the *write* side, and
//!   the two constraints pull in opposite directions.
//! * An accidentally-stable internal shape means every field rename inside `Finding` breaks
//!   somebody's downstream script, and we find out when they tell us.
//!
//! **The cost, stated:** the field list is now written twice, so a new `Finding` field can silently
//! fail to reach the export. Two mitigations, both tests rather than intentions:
//! [`tests::the_top_level_key_set_is_pinned`] pins the document's top-level keys, and
//! [`tests::every_finding_field_is_either_exported_or_listed_as_excluded`] pins the exported finding
//! keys against the exclusion list below.
//!
//! # `Finding` fields deliberately not exported
//!
//! | Field | Why |
//! |---|---|
//! | `Occurrence::response` | A process-local [`burpsy_core::MsgId`]; see above. `exchange_id` is exported in its place because it is the id the operator sees in the UI. |
//!
//! Every other field of `Finding` and `Occurrence` is exported.
//!
//! # Why the coverage block is the full model
//!
//! HTML and SARIF are renderings of [`super::RunCoverage`]; this is the model itself, so it carries
//! every population rather than a summary. It is therefore the format REPORT-04 is tested against,
//! and the one an operator diffs between two runs to see coverage change.

use serde::Serialize;

use super::{NotChecked, Report, TOOL_NAME, TOOL_VERSION, Verdict};
use burpsy_core::Finding;

/// Bumped deliberately, never implicitly. A consumer may branch on it.
pub const SCHEMA_VERSION: u32 = 1;

/// Serialise a report as pretty-printed JSON.
///
/// Pretty rather than compact: the file is read by humans at least as often as by scripts, and a
/// single-line 200 kB document is unreviewable in a diff.
pub fn to_json(r: &Report) -> String {
    let doc = Document::build(r);
    // `Document` is a plain tree of owned types and `Serialize` impls that cannot fail, so a failure
    // here would be a bug in this module rather than bad input. Reported as text in the document
    // rather than panicking in a report writer, and never silently as an empty file.
    serde_json::to_string_pretty(&doc)
        .unwrap_or_else(|e| format!("{{\"error\":\"burpsy report serialisation failed: {e}\"}}"))
}

#[derive(Debug, Serialize)]
struct Document {
    schema_version: u32,
    generated_at: String,
    generated_unix_ms: u64,
    tool: Tool,
    scope: ScopeOut,
    coverage: CoverageOut,
    findings: Vec<FindingOut>,
}

impl Document {
    fn build(r: &Report) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            generated_at: r.generated_at(),
            generated_unix_ms: r.generated_unix_ms,
            tool: Tool {
                name: TOOL_NAME,
                version: TOOL_VERSION,
            },
            scope: ScopeOut {
                allow_all: r.scope.allow_all,
                rules: r.scope.rules.clone(),
                summary: r.scope.summary(),
            },
            coverage: CoverageOut::build(r),
            findings: r.findings.iter().map(FindingOut::build).collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct Tool {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct ScopeOut {
    allow_all: bool,
    rules: Vec<String>,
    summary: String,
}

/// REPORT-04 as structured counts.
///
/// `not_checked` is the load-bearing field: a consumer that reads `findings` and ignores it is
/// reading a bound as a clean result, which is why `verdict` sits beside it and says so in one word.
#[derive(Debug, Serialize)]
struct CoverageOut {
    verdict: VerdictOut,
    /// Every reason work was not done, with a count and its unit. Empty **only** when nothing was
    /// left undone.
    not_checked: Vec<NotCheckedOut>,
    corpus: CorpusOut,
    passive: PassiveOut,
    active: ActiveOut,
    /// Things the tool structurally cannot know. Present so they are not read as zeroes.
    unknowns: Vec<UnknownOut>,
}

impl CoverageOut {
    fn build(r: &Report) -> Self {
        let c = &r.coverage;
        Self {
            verdict: VerdictOut::build(r.verdict()),
            not_checked: c.not_checked().iter().map(NotCheckedOut::build).collect(),
            corpus: CorpusOut {
                files: c.corpus.files,
                passive_loaded: c.corpus.passive_loaded,
                active_loaded: c.corpus.active_loaded,
                collaborator: c.corpus.collaborator,
                needs_insertion_point: c.corpus.needs_insertion_point,
                unparsable: c
                    .corpus
                    .unparsable
                    .iter()
                    .map(|(file, error)| UnparsableOut {
                        file: file.clone(),
                        error: error.clone(),
                    })
                    .collect(),
                accounted: c.corpus.accounted(),
            },
            passive: PassiveOut {
                loaded: c.corpus.passive_loaded,
                checked: c.passive.checked(),
                responses_scanned: c.passive.responses_scanned,
                states: c
                    .passive
                    .states
                    .iter()
                    .map(|(st, n)| CountOut {
                        id: coverage_state_id(*st),
                        count: *n,
                    })
                    .collect(),
                never_dispatched: c.passive.never_dispatched.clone(),
                errored: c
                    .passive
                    .errored
                    .iter()
                    .map(|(check, error)| ErroredOut {
                        check: check.clone(),
                        error: error.clone(),
                    })
                    .collect(),
                skips: c
                    .passive
                    .skips
                    .iter()
                    .map(|(s, n)| CountOut {
                        id: super::scan_skip_id(*s),
                        count: *n as usize,
                    })
                    .collect(),
            },
            active: ActiveOut {
                loaded: c.active.loaded,
                audit_requested: c.active.audit_requested,
                considered: c.active.considered(),
                ran: c.active.ran(),
                covered_elsewhere: c.active.covered_elsewhere(),
                dispositions: c
                    .active
                    .dispositions
                    .iter()
                    .map(|(d, n)| CountOut {
                        id: super::disposition_id(*d),
                        count: *n,
                    })
                    .collect(),
                items: c
                    .active
                    .items
                    .iter()
                    .map(|(st, n)| CountOut {
                        id: super::item_state_id(*st),
                        count: *n,
                    })
                    .collect(),
                requests_sent: c.active.requests_sent,
                requests_refused: c.active.requests_refused,
                timed_out: c.active.timed_out,
                paused: c.active.paused,
                errors: c.active.errors.clone(),
            },
            unknowns: c
                .unknowns
                .iter()
                .map(|u| UnknownOut {
                    subject: u.subject.clone(),
                    because: u.because.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct VerdictOut {
    id: &'static str,
    headline: String,
    coverage_is_complete: bool,
    checked: usize,
    not_checked: usize,
}

impl VerdictOut {
    fn build(v: Verdict) -> Self {
        // Flattened to a fixed field set rather than serialising the enum's variants: a consumer
        // reading `not_checked` must not have to know which variant it is looking at to find out
        // whether anything was skipped.
        let (checked, not_checked) = match v {
            Verdict::FullyChecked { checked, .. } => (checked, 0),
            Verdict::PartiallyChecked {
                checked,
                not_checked,
                ..
            } => (checked, not_checked),
            Verdict::NothingChecked => (0, 0),
        };
        Self {
            id: v.id(),
            headline: v.headline(),
            coverage_is_complete: v.coverage_is_complete(),
            checked,
            not_checked,
        }
    }
}

#[derive(Debug, Serialize)]
struct NotCheckedOut {
    reason: &'static str,
    unit: &'static str,
    count: usize,
    explanation: &'static str,
    /// Concrete identities where the engine retains them. An empty array is not a claim that there
    /// are none — `coverage.unknowns` names the buckets whose identities the loader drops.
    identities: Vec<String>,
}

impl NotCheckedOut {
    fn build(row: &NotChecked) -> Self {
        Self {
            reason: row.reason.id(),
            unit: row.reason.unit().id(),
            count: row.count,
            explanation: row.reason.explanation(),
            identities: row.identities.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct CountOut {
    id: &'static str,
    count: usize,
}

#[derive(Debug, Serialize)]
struct UnparsableOut {
    file: String,
    error: String,
}

#[derive(Debug, Serialize)]
struct ErroredOut {
    check: String,
    error: String,
}

#[derive(Debug, Serialize)]
struct CorpusOut {
    files: usize,
    passive_loaded: usize,
    active_loaded: usize,
    collaborator: usize,
    needs_insertion_point: usize,
    unparsable: Vec<UnparsableOut>,
    /// The buckets summed. Equal to `files` — exported so a consumer can check the report's
    /// arithmetic rather than trust it.
    accounted: usize,
}

#[derive(Debug, Serialize)]
struct PassiveOut {
    loaded: usize,
    checked: usize,
    responses_scanned: u64,
    states: Vec<CountOut>,
    never_dispatched: Vec<String>,
    errored: Vec<ErroredOut>,
    skips: Vec<CountOut>,
}

#[derive(Debug, Serialize)]
struct ActiveOut {
    loaded: usize,
    /// False when no audit ran. With `loaded > 0` that is the difference between "the active set
    /// found nothing" and "the active set was never started".
    audit_requested: bool,
    considered: usize,
    ran: usize,
    covered_elsewhere: usize,
    dispositions: Vec<CountOut>,
    items: Vec<CountOut>,
    requests_sent: u32,
    requests_refused: u32,
    timed_out: bool,
    paused: bool,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UnknownOut {
    subject: String,
    because: String,
}

#[derive(Debug, Serialize)]
struct FindingOut {
    id: u64,
    check_name: String,
    issue_name: Option<String>,
    severity: &'static str,
    confidence: &'static str,
    host: String,
    detail: Option<String>,
    remediation: Option<String>,
    /// Stable across runs, unlike `id`: it is the `(check, issue name, host)` grouping key the store
    /// deduplicates on.
    dedup_key: String,
    /// Total times seen, including occurrences beyond the retained cap.
    times_seen: u64,
    /// Retained occurrences, capped at [`burpsy_core::MAX_OCCURRENCES`]. Compare with `times_seen`
    /// to see whether the list is complete.
    occurrences: Vec<OccurrenceOut>,
}

impl FindingOut {
    fn build(f: &Finding) -> Self {
        Self {
            id: f.id,
            check_name: f.check_name.clone(),
            issue_name: f.issue_name.clone(),
            severity: f.severity.as_str(),
            confidence: f.confidence.as_str(),
            host: f.host.clone(),
            detail: f.detail.clone(),
            remediation: f.remediation.clone(),
            dedup_key: f.dedup_key(),
            times_seen: f.times_seen,
            occurrences: f
                .occurrences
                .iter()
                .map(|o| OccurrenceOut {
                    exchange_id: o.exchange_id,
                    path: o.path.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct OccurrenceOut {
    exchange_id: u64,
    path: String,
}

fn coverage_state_id(s: crate::CoverageState) -> &'static str {
    match s {
        crate::CoverageState::NeverDispatched => "never_dispatched",
        crate::CoverageState::RanClean => "ran_clean",
        crate::CoverageState::RanAndFound => "ran_and_found",
        crate::CoverageState::Errored => "errored",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests::{bounded_session, passive_all_ran, shipped_load};
    use crate::report::{RunFacts, now_unix_ms};
    use burpsy_core::{Confidence, MsgId, Occurrence, Scope, Severity};
    use serde_json::Value;

    fn finding() -> Finding {
        Finding {
            id: 0,
            check_name: "Cloud storage bucket".into(),
            issue_name: Some("Cloud storage URL disclosed".into()),
            severity: Severity::Medium,
            confidence: Confidence::Firm,
            host: "app.test".into(),
            detail: Some("s3://secrets".into()),
            remediation: None,
            occurrences: vec![Occurrence {
                exchange_id: 7,
                response: MsgId(3),
                path: "/assets/app.js".into(),
            }],
            times_seen: 4,
        }
    }

    fn doc(findings: &[Finding], audits: &[crate::SessionOutcome]) -> Value {
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
        serde_json::from_str(&to_json(&r)).expect("the export must be valid JSON")
    }

    #[test]
    fn the_top_level_key_set_is_pinned() {
        let v = doc(&[], &[]);
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "coverage",
                "findings",
                "generated_at",
                "generated_unix_ms",
                "schema_version",
                "scope",
                "tool",
            ],
            "the top-level shape is a published contract: adding or renaming a key here is a \
             schema_version bump, not an edit"
        );
    }

    #[test]
    fn every_finding_field_is_either_exported_or_listed_as_excluded() {
        let v = doc(&[finding()], &[]);
        let f = &v["findings"][0];
        let mut keys: Vec<&str> = f.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "check_name",
                "confidence",
                "dedup_key",
                "detail",
                "host",
                "id",
                "issue_name",
                "occurrences",
                "remediation",
                "severity",
                "times_seen",
            ],
            "a new `Finding` field must be exported or added to this module's exclusion table"
        );
        let mut occ: Vec<&str> = f["occurrences"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        occ.sort_unstable();
        assert_eq!(
            occ,
            ["exchange_id", "path"],
            "`response` is excluded on purpose: it is a process-local MsgId"
        );
    }

    #[test]
    fn a_run_with_refused_dispatches_does_not_serialise_as_a_clean_report() {
        let v = doc(&[], &[bounded_session()]);
        assert!(v["findings"].as_array().unwrap().is_empty());

        let verdict = &v["coverage"]["verdict"];
        assert_eq!(verdict["id"], "partially_checked");
        assert_eq!(verdict["coverage_is_complete"], false);
        assert!(
            verdict["not_checked"].as_u64().unwrap() > 0,
            "a run that refused work must report a non-zero not-checked count"
        );

        let rows = v["coverage"]["not_checked"].as_array().unwrap();
        let refused = rows
            .iter()
            .find(|r| r["reason"] == "not_dispatched/request_budget_spent")
            .expect("the refused dispatches must be in the not_checked array");
        assert_eq!(refused["count"], 6);
        assert_eq!(refused["unit"], "dispatches");
        assert!(
            refused["explanation"].as_str().unwrap().contains("budget"),
            "each row carries the engine's own explanation, not just a count"
        );
    }

    #[test]
    fn a_zero_finding_report_still_enumerates_the_collaborator_gated_checks() {
        let v = doc(&[], &[]);
        let rows = v["coverage"]["not_checked"].as_array().unwrap();
        let collab = rows
            .iter()
            .find(|r| r["reason"] == "not_loaded/collaborator")
            .expect("26 Collaborator-gated checks are always unchecked and must always be stated");
        assert_eq!(collab["count"], 26);
        assert_eq!(collab["unit"], "checks");
    }

    #[test]
    fn the_coverage_section_is_never_absent_or_zeroed_when_work_was_skipped() {
        // The defect REPORT-04 exists to prevent, asserted directly: for a run with skipped work,
        // no path through the writer may produce a document whose coverage block is missing or
        // whose not-checked rows all read zero.
        let v = doc(&[], &[bounded_session()]);
        let rows = v["coverage"]["not_checked"].as_array().unwrap();
        assert!(!rows.is_empty(), "the not_checked array must not be empty");
        assert!(
            rows.iter().all(|r| r["count"].as_u64().unwrap() > 0),
            "a zero row would let a reader conclude nothing was skipped: {rows:?}"
        );
        assert!(
            !v["coverage"]["unknowns"].as_array().unwrap().is_empty(),
            "the structural unknowns are unconditional and must always be present"
        );
    }

    #[test]
    fn the_corpus_arithmetic_is_exported_so_a_consumer_can_check_it() {
        let v = doc(&[], &[]);
        let c = &v["coverage"]["corpus"];
        assert_eq!(c["accounted"], c["files"]);
        assert_eq!(c["files"], 264);
    }

    #[test]
    fn a_generated_timestamp_read_from_the_clock_is_a_valid_rfc_3339_instant() {
        let scope = Scope::allow_everything();
        let load = shipped_load();
        let passive = passive_all_ran(1);
        let r = Report::from_facts(RunFacts {
            scope: &scope,
            load: &load,
            passive: &passive,
            audits: &[],
            findings: &[],
            generated_unix_ms: now_unix_ms(),
        });
        let at = r.generated_at();
        assert!(
            at.ends_with('Z') && at.len() == 24 && at.as_bytes()[10] == b'T',
            "generated_at must be an RFC 3339 UTC instant: {at}"
        );
    }
}
