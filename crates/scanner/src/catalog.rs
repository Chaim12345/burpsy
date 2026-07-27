//! Burp's issue catalog — the 183 definitions behind `burp.Zcot`.
//!
//! # Why this exists
//!
//! A finding that says only "check `Springboot env actuator` fired" tells an operator nothing they
//! can act on. Burp's value here is not its detection logic, it is the 183 hand-written issue
//! definitions shipped in `resources/KnowledgeBase/Issues/` — background, remediation, typical
//! severity, and CWE/CAPEC classifications. That data is recoverable from the teardown, so a
//! finding can carry it.
//!
//! # Provenance
//!
//! Every string in [`catalog_data`](super::catalog_data) is a mechanical transcription of the
//! shipped JSON. Nothing is reworded, summarised, or filled in. This matters more here than
//! anywhere else in the crate: invented remediation text is invented security advice, presented to
//! an operator with the authority of a scanner. A field that is null in the source is `None` here.
//!
//! # What is *not* in the source
//!
//! * **No CVSS.** 433 classifications across the catalog: 306 CWE, 126 CAPEC, 1 OWASP Top Ten.
//!   Not one CVSS vector or base score. There is therefore no CVSS field on
//!   [`IssueDefinition`] — an empty one would imply the data merely had not been wired up.
//! * **No `permanentIndex` for the audit states.** `burp.Zq5`'s per-state byte index is assigned in
//!   a static initialiser that the obfuscator stripped, so [`crate::audit::AuditStatus`] does not
//!   claim one.
//!
//! # The two IDs
//!
//! The filename encodes the ID in hex (`00100200_SqlInjection.json` ⇒ `0x00100200`) and that
//! encoding is unique across all 183 files, so it is the search key. The `typeIndex` field *inside*
//! the JSON disagrees for two issues, where a stale value duplicates another issue's ID — a defect
//! in the shipped data. Both values are kept ([`IssueDefinition::type_index`] and
//! [`IssueDefinition::declared_type_index`]) rather than reconciled, because silently picking one
//! would hide a discrepancy that a future reader needs to know about. `disagreeing_ids` pins it.

use burpsy_core::Severity;

use crate::catalog_data::ISSUES;

/// One of Burp's 183 issue definitions, verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssueDefinition {
    /// The ID encoded in the source filename. Unique across the catalog; the lookup key.
    pub type_index: u32,
    /// The `typeIndex` field inside the JSON body. Differs from [`Self::type_index`] for exactly
    /// two issues — see the module docs.
    pub declared_type_index: u32,
    pub name: &'static str,
    /// Burp's `typicalSeverity`. Reference metadata for the issue *class* — never a substitute for
    /// the severity a check reported from actual evidence.
    pub typical_severity: Severity,
    /// Background, as an HTML fragment. [`Self::description_text`] renders it as plain text.
    pub description: &'static str,
    /// Remediation, as an HTML fragment. `None` for the 14 issues where the source has no
    /// remediation — an absent one must not read as "nothing to do".
    pub remediation: Option<&'static str>,
    pub references: &'static [Reference],
    /// CWE / CAPEC / OWASP entries. See [`Classification::cwe`].
    pub classifications: &'static [Classification],
}

/// A further-reading link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reference {
    pub title: &'static str,
    pub url: &'static str,
}

/// A weakness-taxonomy entry, e.g. `CWE-89: Improper Neutralization of …`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classification {
    pub title: &'static str,
    pub url: &'static str,
}

impl Classification {
    /// The CWE number, when this is a CWE entry.
    pub fn cwe(&self) -> Option<u32> {
        numbered_prefix(self.title, "CWE-")
    }

    /// The CAPEC number, when this is a CAPEC entry.
    pub fn capec(&self) -> Option<u32> {
        numbered_prefix(self.title, "CAPEC-")
    }
}

/// `CWE-89: …` ⇒ `89`. Returns `None` unless the prefix matches *and* digits follow it, so a
/// title the catalog format did not anticipate yields nothing rather than a wrong number.
fn numbered_prefix(title: &str, prefix: &str) -> Option<u32> {
    let rest = title.strip_prefix(prefix)?;
    let digits: &str = rest.split(|c: char| !c.is_ascii_digit()).next()?;
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

impl IssueDefinition {
    /// Every CWE number attached to this issue, in catalog order.
    pub fn cwe_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.classifications.iter().filter_map(Classification::cwe)
    }

    /// Every CAPEC number attached to this issue, in catalog order.
    pub fn capec_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.classifications.iter().filter_map(Classification::capec)
    }

    /// [`Self::description`] rendered as plain text.
    pub fn description_text(&self) -> String {
        html_to_text(self.description)
    }

    /// [`Self::remediation`] rendered as plain text, or `None` when the source has none.
    pub fn remediation_text(&self) -> Option<String> {
        self.remediation.map(html_to_text)
    }
}

/// The whole catalog, ordered by [`IssueDefinition::type_index`].
pub fn all() -> &'static [IssueDefinition] {
    ISSUES
}

/// Look up by the filename-encoded type index.
pub fn by_type_index(type_index: u32) -> Option<&'static IssueDefinition> {
    ISSUES
        .binary_search_by_key(&type_index, |i| i.type_index)
        .ok()
        .map(|i| &ISSUES[i])
}

/// Look up by issue name, comparing case-insensitively with runs of whitespace collapsed.
///
/// Deliberately an exact match on the normalised name — no substring, prefix, or fuzzy fallback.
/// A looser matcher would raise the hit rate by attaching one issue's remediation to a different
/// issue's finding, which is the failure this whole module exists to avoid.
pub fn by_name(name: &str) -> Option<&'static IssueDefinition> {
    ISSUES.iter().find(|i| names_match(i.name, name))
}

/// Case-insensitive comparison with whitespace runs collapsed and the ends trimmed. Allocation
/// free, because it runs once per candidate over the whole 183-entry catalog.
fn names_match(a: &str, b: &str) -> bool {
    let (mut x, mut y) = (Normalised::of(a), Normalised::of(b));
    loop {
        match (x.next(), y.next()) {
            (None, None) => return true,
            (p, q) if p != q => return false,
            _ => {}
        }
    }
}

/// A name's characters, ASCII-lowercased, with whitespace runs collapsed to one space and the
/// ends trimmed.
struct Normalised<'a> {
    inner: std::str::Chars<'a>,
    /// The character held back while the collapsed space it followed is emitted.
    pending: Option<char>,
    started: bool,
}

impl<'a> Normalised<'a> {
    fn of(s: &'a str) -> Self {
        Self { inner: s.chars(), pending: None, started: false }
    }
}

impl Iterator for Normalised<'_> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        if let Some(c) = self.pending.take() {
            return Some(c);
        }
        let mut after_space = false;
        loop {
            // Trailing whitespace ends the iterator here, which is what trims it.
            let c = self.inner.next()?;
            if c.is_whitespace() {
                after_space = true;
                continue;
            }
            let c = c.to_ascii_lowercase();
            // Leading whitespace emits nothing, because `started` is still false.
            if after_space && self.started {
                self.pending = Some(c);
                return Some(' ');
            }
            self.started = true;
            return Some(c);
        }
    }
}

/// Render the catalog's HTML fragments as plain text.
///
/// The catalog uses exactly six tags (`p ul ol li b i`) and five entities (`&quot; &lt; &gt;
/// &nbsp; &amp;`), so this handles that closed set rather than pretending to be an HTML parser.
/// Anything else passes through as literal text — visible, rather than silently dropped.
fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(lt) = rest.find('<') {
        push_decoded(&mut out, &rest[..lt]);
        let Some(gt) = rest[lt..].find('>') else {
            // An unterminated '<' is literal text, not a tag.
            push_decoded(&mut out, &rest[lt..]);
            return reflow(out);
        };
        let tag = &rest[lt + 1..lt + gt];
        let closing = tag.starts_with('/');
        let name = tag.trim_start_matches('/').split_whitespace().next().unwrap_or("");
        if name.eq_ignore_ascii_case("li") && !closing {
            out.push_str("\n- ");
        } else if ["p", "ul", "ol", "li"].iter().any(|t| name.eq_ignore_ascii_case(t)) {
            out.push('\n');
        }
        rest = &rest[lt + gt + 1..];
    }
    push_decoded(&mut out, rest);
    reflow(out)
}

/// The five entities the catalog uses, and nothing else.
const ENTITIES: [(&str, char); 5] =
    [("&quot;", '"'), ("&lt;", '<'), ("&gt;", '>'), ("&nbsp;", ' '), ("&amp;", '&')];

fn push_decoded(out: &mut String, s: &str) {
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        match ENTITIES.iter().find(|(e, _)| tail.starts_with(e)) {
            Some((entity, ch)) => {
                out.push(*ch);
                rest = &tail[entity.len()..];
            }
            // Not one of the five — keep the '&' as written rather than guessing.
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
}

/// Drop the blank lines that tag boundaries leave behind: one line per paragraph or bullet.
fn reflow(s: String) -> String {
    let mut out = String::with_capacity(s.len());
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalog_holds_all_one_hundred_and_eighty_three_definitions() {
        assert_eq!(all().len(), 183, "one per KnowledgeBase/Issues JSON file");
    }

    #[test]
    fn severities_match_the_distribution_measured_in_the_shipped_catalog() {
        let count = |s: Severity| all().iter().filter(|i| i.typical_severity == s).count();
        // Independently measured over resources/KnowledgeBase/Issues/*.json, and quoted in
        // SCAN_ENGINE.md §1.1. If a transcription bug dropped or mangled entries this moves.
        assert_eq!(count(Severity::Info), 68);
        assert_eq!(count(Severity::High), 57);
        assert_eq!(count(Severity::Low), 36);
        assert_eq!(count(Severity::Medium), 22);
        assert_eq!(68 + 57 + 36 + 22, all().len());
    }

    #[test]
    fn type_indices_are_unique_and_sorted_so_lookup_is_sound() {
        for pair in all().windows(2) {
            assert!(
                pair[0].type_index < pair[1].type_index,
                "{} then {} breaks the binary-search order",
                pair[0].name,
                pair[1].name
            );
        }
    }

    #[test]
    fn sql_injection_carries_its_real_metadata() {
        let d = by_type_index(0x0010_0200).expect("00100200_SqlInjection.json");
        assert_eq!(d.name, "SQL injection");
        assert_eq!(d.typical_severity, Severity::High);
        assert_eq!(d.cwe_ids().collect::<Vec<_>>(), vec![89, 94, 116]);
        assert_eq!(d.capec_ids().collect::<Vec<_>>(), vec![66]);
        assert!(
            d.description_text()
                .starts_with("SQL injection vulnerabilities arise when user-controllable data"),
            "background must be the shipped text: {}",
            &d.description_text()[..80]
        );
        let rem = d.remediation_text().expect("SQL injection ships a remediation");
        assert!(
            rem.starts_with("The most effective way to prevent SQL injection attacks is to use"),
            "remediation must be the shipped text, not a paraphrase: {}",
            &rem[..rem.len().min(120)]
        );
        assert!(!rem.contains('<'), "plain text must not retain tags");
    }

    #[test]
    fn the_two_issues_whose_declared_id_contradicts_their_filename_are_pinned() {
        // A defect in Burp's own data: these two JSON bodies carry a stale `typeIndex` that
        // duplicates another issue's ID. Recorded rather than reconciled, so nobody later
        // "fixes" the transcription to match a value that was never in the source.
        let odd: Vec<_> = all()
            .iter()
            .filter(|i| i.type_index != i.declared_type_index)
            .map(|i| (i.name, i.type_index, i.declared_type_index))
            .collect();
        assert_eq!(
            odd,
            vec![
                (
                    "React Server Components remote code execution (React2Shell)",
                    0x0010_1200,
                    0x0010_0e00
                ),
                ("Bambda generated issue", 0x0900_8000, 0x0900_0000),
            ]
        );
        // The stale values each collide with a real, different issue.
        assert_eq!(by_type_index(0x0010_0e00).unwrap().name, "Perl code injection");
        assert_eq!(by_type_index(0x0900_0000).unwrap().name, "BCheck generated issue");
    }

    #[test]
    fn exactly_fourteen_definitions_have_no_remediation_and_report_none() {
        let missing = all().iter().filter(|i| i.remediation.is_none()).count();
        assert_eq!(missing, 14, "an absent remediation must stay absent, not become \"\"");
        assert!(all().iter().all(|i| !i.description.is_empty()), "every issue has background");
    }

    #[test]
    fn no_definition_claims_a_cvss_score_because_the_source_has_none() {
        // The shipped catalog carries CWE, CAPEC and one OWASP entry — no CVSS anywhere. If a
        // future edit invents one, it will show up as a classification prefix nobody extracted.
        let cwe: usize = all().iter().map(|i| i.cwe_ids().count()).sum();
        let capec: usize = all().iter().map(|i| i.capec_ids().count()).sum();
        let total: usize = all().iter().map(|i| i.classifications.len()).sum();
        assert_eq!((cwe, capec, total), (306, 126, 433));
        assert_eq!(total - cwe - capec, 1, "the single OWASP Top Ten entry");
        assert!(
            all()
                .iter()
                .flat_map(|i| i.classifications)
                .all(|c| !c.title.to_ascii_uppercase().contains("CVSS")),
            "no CVSS data exists in the source"
        );
    }

    #[test]
    fn name_lookup_is_case_and_whitespace_insensitive_but_never_fuzzy() {
        assert_eq!(by_name("SQL injection").unwrap().type_index, 0x0010_0200);
        assert_eq!(by_name("  sql   INJECTION ").unwrap().type_index, 0x0010_0200);
        // A near miss must miss. Attaching SQL injection's remediation to a finding about
        // second-order SQL injection would be wrong advice, confidently delivered.
        assert!(by_name("SQL injection!").is_none());
        assert!(by_name("SQL").is_none());
        assert!(by_name("injection").is_none());
        assert_eq!(
            by_name("SQL injection (second order)").unwrap().name,
            "SQL injection (second order)"
        );
    }

    #[test]
    fn every_name_resolves_back_to_its_own_definition() {
        for d in all() {
            let found = by_name(d.name).unwrap_or_else(|| panic!("{} did not resolve", d.name));
            assert_eq!(found.type_index, d.type_index, "duplicate name: {}", d.name);
        }
    }

    #[test]
    fn html_renders_to_readable_text_with_entities_decoded() {
        assert_eq!(html_to_text("<p>one</p>\n<p>two</p>"), "one\ntwo");
        assert_eq!(html_to_text("<p>a <b>bold</b> word</p>"), "a bold word");
        assert_eq!(html_to_text("<ul>\n<li>first</li>\n<li>second</li>\n</ul>"), "- first\n- second");
        assert_eq!(html_to_text("5 &lt; 6 &amp;&amp; &quot;x&quot; &gt; y"), "5 < 6 && \"x\" > y");
        // An entity outside the five the catalog uses is left visible rather than swallowed.
        assert_eq!(html_to_text("A&copy;B"), "A&copy;B");
        assert_eq!(html_to_text("1 < 2"), "1 < 2");
    }
}
