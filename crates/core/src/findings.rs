//! Finding storage and deduplication.
//!
//! # Why dedup is part of storage, not display
//!
//! One secret-regex matching on 200 pages produces 200 identical findings. Burp treats this as a
//! first-class concern — `burp.Zbvp` is a chain-of-responsibility consolidator with
//! `findIssuesOfSameType` / `shouldMergeIssues`, and `burp.Zby4` computes a CRC over the issue-type
//! set for cheap "same shape" matching.
//!
//! Deduplicating at insertion rather than at render time matters for the memory thesis: an
//! un-deduplicated finding set grows with traffic volume, which is exactly the unbounded growth this
//! crate exists to avoid.
//!
//! The grouping key here is `(check identity, issue name, host)` — deliberately **not** the URL.
//! A leaked key found on 200 pages of one host is one finding with 200 occurrences, not 200
//! findings; but the same key on a different host is a separate finding, because the blast radius
//! differs.

use crate::MsgId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

/// Declaration order encodes the ranking: Tentative < Firm < Certain, so a derived `Ord` lets a
/// merge keep the strongest confidence seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Tentative,
    Firm,
    Certain,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Tentative => "tentative",
            Confidence::Firm => "firm",
            Confidence::Certain => "certain",
        }
    }
}

/// One place a finding was observed. Holds ids, never bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Occurrence {
    pub exchange_id: u64,
    pub response: MsgId,
    pub path: String,
}

/// A deduplicated finding with every place it was seen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: u64,
    /// Which check produced it.
    pub check_name: String,
    /// Issue title, if the check supplied one.
    pub issue_name: Option<String>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub host: String,
    pub detail: Option<String>,
    pub remediation: Option<String>,
    /// Every exchange this fired on. Capped — see [`MAX_OCCURRENCES`].
    pub occurrences: Vec<Occurrence>,
    /// Total times seen, including any beyond the retained cap.
    pub times_seen: u64,
}

/// Retained occurrences per finding.
///
/// Unbounded occurrence lists reintroduce exactly the growth-with-traffic problem the store avoids:
/// a header-misconfiguration check fires on every response, so 100k requests would mean 100k
/// occurrence records for one finding. `times_seen` keeps the true count, so capping loses evidence
/// breadth but never the fact of how often it fired.
pub const MAX_OCCURRENCES: usize = 50;

impl Finding {
    /// Grouping key: check + issue name + host, deliberately not the URL.
    ///
    /// A materialised key for callers that need one thing to hash or print. Insertion does **not**
    /// use it — see [`Finding::same_issue_as`].
    pub fn dedup_key(&self) -> String {
        format!(
            "{}\u{1}{}\u{1}{}",
            self.check_name,
            self.issue_name.as_deref().unwrap_or(""),
            self.host
        )
    }

    /// Does an incoming finding belong to this one? The same rule as [`Finding::dedup_key`],
    /// decided by comparing fields.
    ///
    /// Building a key string here instead cost 4.2 s per 100k inserts across 200 distinct findings
    /// (measured, release): every insert formatted a fresh `String` for *every* finding it walked
    /// past, so a passive scan of ordinary proxy traffic spent its time in the allocator. Comparing
    /// fields is the same decision with no allocation — 50–100 ms for the same workload, ~50×
    /// faster. A store whose whole purpose is to not allocate per message must not allocate per
    /// comparison.
    pub fn same_issue_as(&self, f: &NewFinding) -> bool {
        self.check_name == f.check_name
            && self.issue_name.as_deref() == f.issue_name.as_deref()
            && self.host == f.host
    }
}

/// A finding awaiting insertion.
#[derive(Debug, Clone)]
pub struct NewFinding {
    pub check_name: String,
    pub issue_name: Option<String>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub host: String,
    pub detail: Option<String>,
    pub remediation: Option<String>,
    pub exchange_id: u64,
    pub response: MsgId,
    pub path: String,
}

/// Outcome of an insertion, so callers can tell new findings from repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inserted {
    /// A finding not previously seen for this (check, name, host).
    New(u64),
    /// Merged into an existing finding.
    Merged(u64),
}

#[derive(Debug, Default)]
pub struct FindingStore {
    findings: Vec<Finding>,
    next_id: u64,
}

impl FindingStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert, merging into an existing finding when the dedup key matches.
    pub fn insert(&mut self, f: NewFinding) -> Inserted {
        if let Some(existing) = self.findings.iter_mut().find(|e| e.same_issue_as(&f)) {
            existing.times_seen += 1;
            if existing.occurrences.len() < MAX_OCCURRENCES {
                existing.occurrences.push(Occurrence {
                    exchange_id: f.exchange_id,
                    response: f.response,
                    path: f.path,
                });
            }
            // Keep the strongest severity/confidence seen — a check may report the same issue with
            // higher confidence on a later, better piece of evidence.
            if f.severity > existing.severity {
                existing.severity = f.severity;
            }
            if f.confidence > existing.confidence {
                existing.confidence = f.confidence;
            }
            return Inserted::Merged(existing.id);
        }

        let id = self.next_id;
        self.next_id += 1;
        self.findings.push(Finding {
            id,
            check_name: f.check_name,
            issue_name: f.issue_name,
            severity: f.severity,
            confidence: f.confidence,
            host: f.host,
            detail: f.detail,
            remediation: f.remediation,
            occurrences: vec![Occurrence {
                exchange_id: f.exchange_id,
                response: f.response,
                path: f.path,
            }],
            times_seen: 1,
        });
        Inserted::New(id)
    }

    /// All findings, most severe first, then most frequent.
    pub fn all(&self) -> Vec<Finding> {
        let mut v = self.findings.clone();
        v.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.confidence.cmp(&a.confidence))
                .then(b.times_seen.cmp(&a.times_seen))
        });
        v
    }

    pub fn get(&self, id: u64) -> Option<&Finding> {
        self.findings.iter().find(|f| f.id == id)
    }

    pub fn len(&self) -> usize {
        self.findings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Counts by severity, for the UI summary.
    pub fn severity_counts(&self) -> [usize; 4] {
        let mut c = [0usize; 4];
        for f in &self.findings {
            let i = match f.severity {
                Severity::High => 0,
                Severity::Medium => 1,
                Severity::Low => 2,
                Severity::Info => 3,
            };
            c[i] += 1;
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nf(check: &str, host: &str, path: &str, ex: u64) -> NewFinding {
        NewFinding {
            check_name: check.into(),
            issue_name: None,
            severity: Severity::Low,
            confidence: Confidence::Firm,
            host: host.into(),
            detail: None,
            remediation: None,
            exchange_id: ex,
            response: MsgId(ex),
            path: path.into(),
        }
    }

    #[test]
    fn the_field_comparison_and_the_key_string_agree_on_every_axis() {
        // `insert` matches on fields for speed while `dedup_key` still builds a string; if the two
        // ever disagreed, dedup would silently change meaning. Vary each part of the key in turn.
        let base = nf("Check", "a.test", "/", 1);
        let mut stored = FindingStore::new();
        stored.insert(base.clone());
        let f = &stored.all()[0];

        let mut differs_by_check = base.clone();
        differs_by_check.check_name = "Other".into();
        let mut differs_by_host = base.clone();
        differs_by_host.host = "b.test".into();
        let mut differs_by_name = base.clone();
        differs_by_name.issue_name = Some("AWS key".into());

        for candidate in [&base, &differs_by_check, &differs_by_host, &differs_by_name] {
            let by_field = f.same_issue_as(candidate);
            let by_key = f.dedup_key()
                == format!(
                    "{}\u{1}{}\u{1}{}",
                    candidate.check_name,
                    candidate.issue_name.as_deref().unwrap_or(""),
                    candidate.host
                );
            assert_eq!(
                by_field, by_key,
                "disagreement on {:?}",
                candidate.check_name
            );
        }
        assert!(f.same_issue_as(&base));
        assert!(!f.same_issue_as(&differs_by_check));
        assert!(!f.same_issue_as(&differs_by_host));
        assert!(!f.same_issue_as(&differs_by_name));
    }

    #[test]
    fn same_check_same_host_different_paths_is_one_finding() {
        // The case that matters: a secret regex firing across many pages of one host.
        let mut s = FindingStore::new();
        assert!(matches!(
            s.insert(nf("Leaked key", "a.test", "/1", 1)),
            Inserted::New(_)
        ));
        assert!(matches!(
            s.insert(nf("Leaked key", "a.test", "/2", 2)),
            Inserted::Merged(_)
        ));
        assert!(matches!(
            s.insert(nf("Leaked key", "a.test", "/3", 3)),
            Inserted::Merged(_)
        ));
        assert_eq!(s.len(), 1);
        let f = &s.all()[0];
        assert_eq!(f.times_seen, 3);
        assert_eq!(f.occurrences.len(), 3);
    }

    #[test]
    fn different_host_is_a_separate_finding() {
        // Blast radius differs per host, so these must not merge.
        let mut s = FindingStore::new();
        s.insert(nf("Leaked key", "a.test", "/1", 1));
        s.insert(nf("Leaked key", "b.test", "/1", 2));
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn occurrences_are_capped_but_the_count_is_not() {
        let mut s = FindingStore::new();
        for i in 0..(MAX_OCCURRENCES as u64 + 25) {
            s.insert(nf("Header missing", "a.test", "/x", i));
        }
        let f = &s.all()[0];
        assert_eq!(
            f.occurrences.len(),
            MAX_OCCURRENCES,
            "occurrences must be capped"
        );
        assert_eq!(
            f.times_seen,
            MAX_OCCURRENCES as u64 + 25,
            "true count must be kept"
        );
    }

    #[test]
    fn merging_keeps_the_strongest_severity_and_confidence() {
        let mut s = FindingStore::new();
        s.insert(nf("X", "a.test", "/1", 1));
        let mut stronger = nf("X", "a.test", "/2", 2);
        stronger.severity = Severity::High;
        stronger.confidence = Confidence::Certain;
        s.insert(stronger);
        let f = &s.all()[0];
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::Certain);
    }

    #[test]
    fn sorted_most_severe_first() {
        let mut s = FindingStore::new();
        let mut info = nf("info", "a.test", "/", 1);
        info.severity = Severity::Info;
        let mut high = nf("high", "a.test", "/", 2);
        high.severity = Severity::High;
        let mut med = nf("med", "a.test", "/", 3);
        med.severity = Severity::Medium;
        s.insert(info);
        s.insert(high);
        s.insert(med);
        let all = s.all();
        assert_eq!(all[0].severity, Severity::High);
        assert_eq!(all[1].severity, Severity::Medium);
        assert_eq!(all[2].severity, Severity::Info);
        assert_eq!(s.severity_counts(), [1, 1, 0, 1]);
    }

    #[test]
    fn issue_name_distinguishes_findings_from_one_check() {
        // One check can report several distinct issues (e.g. a multi-pattern scanner).
        let mut s = FindingStore::new();
        let mut a = nf("Scanner", "a.test", "/", 1);
        a.issue_name = Some("AWS key".into());
        let mut b = nf("Scanner", "a.test", "/", 2);
        b.issue_name = Some("Slack token".into());
        s.insert(a);
        s.insert(b);
        assert_eq!(s.len(), 2);
    }
}
