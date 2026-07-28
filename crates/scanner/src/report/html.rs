//! REPORT-01 — a single self-contained HTML page, for a human reader.
//!
//! # One file, no external assets, no JavaScript
//!
//! A report that fetches a stylesheet from a CDN is useless in the engagement it was written for: the
//! network it describes is frequently the network it cannot reach. So the CSS is inline, there are no
//! images, and there is no script. The page renders identically from a `file://` URL on a laptop with
//! its interface down.
//!
//! No templating dependency either. That is not asceticism — it is that a template engine's
//! auto-escaping is exactly the control that must not be taken on trust for this data, and pulling in
//! a dependency to get a guarantee you then have to audit anyway is the worse trade. This crate
//! already declines to pretend a hand-rolled tag walker is a parser ([`crate::catalog`]); the same
//! honesty applies here in the other direction.
//!
//! # Escaping is a security control here, not formatting
//!
//! [`burpsy_core::Finding::detail`] is interpolated from response bytes by the check that reported
//! it, and `Occurrence::path` is a request target. Both are attacker-controlled. Rendering either
//! unescaped is stored XSS in the operator's own browser, usually from a `file://` origin — the most
//! privileged context they have. Two controls, structural first:
//!
//! 1. **No finding-derived byte ever reaches a dangerous context.** All of it is emitted as element
//!    text: never into an attribute value, a `<script>`, a `<style>`, a URL position or a comment.
//!    Enforced by shape — [`push_text`] is the only function in this module that emits
//!    finding-derived bytes, and it always escapes. Every attribute value in the output is built from
//!    a tool-controlled constant or an integer.
//! 2. **[`escape_text`] escapes five characters: `& < > " '`.** The web UI's own `esc` escapes three,
//!    which is safe there *only* because its output never lands in an attribute. A report writer that
//!    inherited the three-character version and later put a finding string in a `title=` attribute
//!    would have an XSS. Five costs nothing and decouples the escape set from the emission site, so
//!    control 1 failing is not immediately exploitable.
//!
//! Defence in depth, not the primary control: a `Content-Security-Policy` meta element with
//! `default-src 'none'`. It is free and it fails closed if control 1 is ever violated. Having zero
//! JavaScript is what makes control 2 sufficient by construction: with no script context there is no
//! context the five-character escape can be escaped from.
//!
//! **Lost:** client-side sort, filter and search. Mostly recovered, because
//! [`burpsy_core::FindingStore::all`] already returns findings most-severe-first and the writer
//! preserves that order, and `<details>` gives per-finding collapse. An operator who needs real
//! filtering uses the JSON export, which is what it is for.
//!
//! # Layout order is deliberate
//!
//! Coverage verdict, then what was not checked, then the severity counts, then the findings. A reader
//! who stops after the first screen has seen the coverage statement. Putting the findings table first
//! would mean the most common reading of the document — scroll, see an empty table, close it — is the
//! one misreading REPORT-04 exists to prevent.

use super::{Report, TOOL_NAME, TOOL_VERSION, Unit};
use burpsy_core::findings::MAX_OCCURRENCES;
use burpsy_core::{Finding, Severity};

/// Bytes of `detail` rendered per finding before truncation.
///
/// A check can interpolate a whole response body into `detail`. The bytes are not dropped silently:
/// the marker states how many of how many are shown, so a reader knows to go to the JSON export for
/// the rest.
pub const DEFAULT_DETAIL_BYTES: usize = 4096;

/// Render a report as one self-contained HTML page.
pub fn to_html(r: &Report) -> String {
    to_html_with(r, DEFAULT_DETAIL_BYTES)
}

/// As [`to_html`], with an explicit per-finding detail budget.
pub fn to_html_with(r: &Report, detail_bytes: usize) -> String {
    let mut out = String::with_capacity(16 * 1024 + r.findings.len() * 512);
    let verdict = r.verdict();

    out.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    // Defence in depth: no script, no style sheet, no image, no connection. `style-src` is opened
    // only for the inline block below.
    out.push_str(
        "<meta http-equiv=\"Content-Security-Policy\" \
         content=\"default-src 'none'; style-src 'unsafe-inline'\">\n",
    );
    out.push_str("<title>");
    push_text(&mut out, &format!("{TOOL_NAME} scan report"));
    out.push_str("</title>\n<style>\n");
    out.push_str(CSS);
    out.push_str("</style>\n</head>\n<body>\n");

    out.push_str("<h1>");
    push_text(&mut out, &format!("{TOOL_NAME} scan report"));
    out.push_str("</h1>\n<p class=\"meta\">");
    push_text(
        &mut out,
        &format!("{TOOL_NAME} {TOOL_VERSION} — generated {}", r.generated_at()),
    );
    out.push_str("</p>\n<p class=\"meta\">Scope: ");
    push_text(&mut out, &r.scope.summary());
    out.push_str("</p>\n");

    // 1. The verdict. First, and styled by how bad it is, because it qualifies everything below.
    let cls = match verdict {
        super::Verdict::FullyChecked { findings: 0, .. } => "verdict clean",
        super::Verdict::FullyChecked { .. } => "verdict found",
        super::Verdict::PartiallyChecked { .. } => "verdict partial",
        super::Verdict::NothingChecked => "verdict nothing",
    };
    out.push_str("<p class=\"");
    out.push_str(cls);
    out.push_str("\">");
    push_text(&mut out, &verdict.headline());
    out.push_str("</p>\n");

    // 2. What was not checked. Above the findings, for the reason in the module docs.
    push_not_checked(&mut out, r);

    // 3. Severity counts.
    push_severity_counts(&mut out, r);

    // 4. Coverage detail, collapsed: an operator who wants the per-population numbers can open it,
    // and the summary above never depends on their doing so.
    push_coverage_detail(&mut out, r);

    // 5. The findings.
    push_findings(&mut out, r, detail_bytes);

    out.push_str("</body>\n</html>\n");
    out
}

fn push_not_checked(out: &mut String, r: &Report) {
    let rows = r.coverage.not_checked();
    out.push_str("<h2>What was not checked</h2>\n");
    if rows.is_empty() {
        out.push_str(
            "<p class=\"note\">Every check and dispatch in this run reached a conclusion. The \
             unknowns below still apply.</p>\n",
        );
    } else {
        out.push_str(
            "<table><thead><tr><th>Count</th><th>Unit</th><th>Reason</th><th>Detail</th></tr>\
             </thead>\n<tbody>\n",
        );
        for row in &rows {
            out.push_str("<tr><td class=\"num\">");
            push_text(out, &commas(row.count as u64));
            out.push_str("</td><td>");
            push_text(out, unit_word(row.reason.unit(), row.count));
            out.push_str("</td><td>");
            push_text(out, row.reason.explanation());
            out.push_str("</td><td>");
            if row.identities.is_empty() {
                out.push_str("<span class=\"none\">identities not retained</span>");
            } else {
                out.push_str("<details><summary>");
                push_text(out, &format!("{} listed", commas(row.identities.len() as u64)));
                out.push_str("</summary><ul>");
                for id in &row.identities {
                    out.push_str("<li>");
                    push_text(out, id);
                    out.push_str("</li>");
                }
                out.push_str("</ul></details>");
            }
            out.push_str("</td></tr>\n");
        }
        out.push_str("</tbody></table>\n");
        out.push_str("<p class=\"note\">");
        push_text(
            out,
            "Counts in different units are listed separately and never summed: a loaded check, an \
             audit dispatch and a captured response are three different things.",
        );
        out.push_str("</p>\n");
    }

    if !r.coverage.unknowns.is_empty() {
        out.push_str("<h3>Not knowable from this run</h3>\n<ul class=\"unknowns\">\n");
        for u in &r.coverage.unknowns {
            out.push_str("<li><b>");
            push_text(out, &u.subject);
            out.push_str("</b> — ");
            push_text(out, &u.because);
            out.push_str("</li>\n");
        }
        out.push_str("</ul>\n");
    }
}

fn push_severity_counts(out: &mut String, r: &Report) {
    let [high, medium, low, info] = r.severity_counts();
    out.push_str("<h2>Findings by severity</h2>\n<ul class=\"sev\">\n");
    for (label, n, cls) in [
        ("High", high, "high"),
        ("Medium", medium, "medium"),
        ("Low", low, "low"),
        ("Info", info, "info"),
    ] {
        out.push_str("<li class=\"");
        out.push_str(cls);
        out.push_str("\">");
        push_text(out, &format!("{label}: {}", commas(n as u64)));
        out.push_str("</li>\n");
    }
    out.push_str("</ul>\n");
}

fn push_coverage_detail(out: &mut String, r: &Report) {
    let c = &r.coverage;
    out.push_str("<details class=\"cov\"><summary>Coverage detail</summary>\n");

    out.push_str("<h3>Check corpus, as loaded</h3>\n<table><tbody>\n");
    for (label, n) in [
        ("Check files found", c.corpus.files),
        ("Loaded, passive", c.corpus.passive_loaded),
        ("Loaded, active", c.corpus.active_loaded),
        ("Not loaded: needs an interaction server", c.corpus.collaborator),
        (
            "Not loaded: needs an insertion point",
            c.corpus.needs_insertion_point,
        ),
        ("Not loaded: would not parse", c.corpus.unparsable.len()),
    ] {
        push_kv(out, label, &commas(n as u64));
    }
    out.push_str("</tbody></table>\n");

    out.push_str("<h3>Passive path</h3>\n<table><tbody>\n");
    push_kv(
        out,
        "Checks whose silence is evidence",
        &format!(
            "{} of {} loaded",
            commas(c.passive.checked() as u64),
            commas(c.corpus.passive_loaded as u64)
        ),
    );
    push_kv(
        out,
        "Responses scanned",
        &commas(c.passive.responses_scanned),
    );
    out.push_str("</tbody></table>\n");

    out.push_str("<h3>Active audit</h3>\n<table><tbody>\n");
    push_kv(
        out,
        "An audit was run",
        if c.active.audit_requested { "yes" } else { "no" },
    );
    push_kv(
        out,
        "Check dispatches that completed",
        &format!(
            "{} of {} considered",
            commas(c.active.ran() as u64),
            commas(c.active.considered() as u64)
        ),
    );
    push_kv(
        out,
        "Refused as already covered in this run",
        &commas(c.active.covered_elsewhere() as u64),
    );
    push_kv(out, "Probe requests sent", &commas(c.active.requests_sent as u64));
    push_kv(
        out,
        "Probes refused as out of scope",
        &commas(c.active.requests_refused as u64),
    );
    push_kv(
        out,
        "Stopped by the time budget",
        if c.active.timed_out { "yes" } else { "no" },
    );
    push_kv(
        out,
        "Stopped by the failure breaker",
        if c.active.paused { "yes" } else { "no" },
    );
    out.push_str("</tbody></table>\n");

    if !c.active.errors.is_empty() {
        out.push_str("<h3>Audit item errors</h3>\n<ul>\n");
        for e in &c.active.errors {
            out.push_str("<li>");
            push_text(out, e);
            out.push_str("</li>\n");
        }
        out.push_str("</ul>\n");
    }

    out.push_str("</details>\n");
}

fn push_findings(out: &mut String, r: &Report, detail_bytes: usize) {
    out.push_str("<h2>Findings</h2>\n");
    if r.findings.is_empty() {
        out.push_str("<p class=\"note\">");
        push_text(
            out,
            "No findings were reported. Read that together with the coverage statement above: it \
             means the checks that ran did not fire, not that the target is clean.",
        );
        out.push_str("</p>\n");
        return;
    }
    // Above this many findings the detail blocks start collapsed. The bytes are still in the file;
    // only the initial rendering changes, because a hundred expanded response excerpts is a document
    // nobody scrolls through.
    let collapse = r.findings.len() > 20;
    for f in &r.findings {
        push_finding(out, f, detail_bytes, collapse);
    }
}

fn push_finding(out: &mut String, f: &Finding, detail_bytes: usize, collapse: bool) {
    out.push_str("<section class=\"finding ");
    out.push_str(sev_class(f.severity));
    out.push_str("\">\n<h3>");
    push_text(out, f.issue_name.as_deref().unwrap_or(&f.check_name));
    out.push_str("</h3>\n<p class=\"tags\">");
    push_text(
        out,
        &format!(
            "{} severity, {} confidence — {} — seen {}",
            f.severity.as_str(),
            f.confidence.as_str(),
            f.host,
            plural(f.times_seen, "time"),
        ),
    );
    out.push_str("</p>\n<p class=\"meta\">Check: ");
    push_text(out, &f.check_name);
    out.push_str("</p>\n");

    if let Some(d) = &f.detail {
        let (shown, total) = truncate_at_char_boundary(d, detail_bytes);
        out.push_str("<details");
        if !collapse {
            out.push_str(" open");
        }
        out.push_str("><summary>Detail</summary>\n<pre>");
        push_text(out, shown);
        out.push_str("</pre>\n");
        if shown.len() < total {
            out.push_str("<p class=\"note\">");
            push_text(
                out,
                &format!(
                    "{} of {} bytes shown; the JSON export carries the rest.",
                    commas(shown.len() as u64),
                    commas(total as u64)
                ),
            );
            out.push_str("</p>\n");
        }
        out.push_str("</details>\n");
    }

    if let Some(rem) = &f.remediation {
        out.push_str("<details><summary>Remediation</summary>\n<pre>");
        push_text(out, rem);
        out.push_str("</pre>\n</details>\n");
    }

    out.push_str("<details><summary>");
    // `times_seen` is the true count and `occurrences` is capped, so the two are stated together
    // rather than letting the shorter list read as the whole story.
    let shown = f.occurrences.len();
    if (f.times_seen as usize) > shown {
        push_text(
            out,
            &format!(
                "{} of {} occurrences shown (retained cap is {MAX_OCCURRENCES})",
                commas(shown as u64),
                commas(f.times_seen)
            ),
        );
    } else {
        push_text(out, &format!("{} occurrences", commas(shown as u64)));
    }
    out.push_str("</summary>\n<ul class=\"occ\">\n");
    for o in &f.occurrences {
        out.push_str("<li>");
        push_text(out, &format!("#{} {}", o.exchange_id, o.path));
        out.push_str("</li>\n");
    }
    out.push_str("</ul>\n</details>\n</section>\n");
}

fn push_kv(out: &mut String, label: &str, value: &str) {
    out.push_str("<tr><th>");
    push_text(out, label);
    out.push_str("</th><td class=\"num\">");
    push_text(out, value);
    out.push_str("</td></tr>\n");
}

/// The only function in this module permitted to put non-constant bytes into the document.
///
/// Everything an attacker can influence goes through here, and it escapes unconditionally. Keeping it
/// as one narrow function is control 1 from the module docs: a reviewer checks that no other write of
/// finding-derived data exists, which is a grep, rather than checking that every one of forty call
/// sites remembered to escape.
pub fn push_text(out: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
}

/// [`push_text`] into a fresh `String`. For callers that need the escaped form as a value.
pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    push_text(&mut out, s);
    out
}

/// `(shown, total_bytes)`, cut at a UTF-8 boundary at or below `limit`.
///
/// Slicing a `&str` at an arbitrary byte index panics, and a report writer that panics on a finding
/// containing a multi-byte character would take out the whole export for one detail string.
fn truncate_at_char_boundary(s: &str, limit: usize) -> (&str, usize) {
    let total = s.len();
    if total <= limit {
        return (s, total);
    }
    let mut end = limit;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (&s[..end], total)
}

fn unit_word(u: Unit, n: usize) -> &'static str {
    match (u, n) {
        (Unit::Checks, 1) => "check",
        (Unit::Checks, _) => "checks",
        (Unit::Dispatches, 1) => "dispatch",
        (Unit::Dispatches, _) => "dispatches",
        (Unit::Responses, 1) => "response",
        (Unit::Responses, _) => "responses",
        (Unit::Items, 1) => "item",
        (Unit::Items, _) => "items",
    }
}

fn plural(n: u64, word: &str) -> String {
    if n == 1 {
        format!("{n} {word}")
    } else {
        format!("{} {word}s", commas(n))
    }
}

fn sev_class(s: Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// Thousands separators, so a six-figure occurrence count is readable at a glance.
fn commas(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    let lead = digits.len() % 3;
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && i % 3 == lead {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Inline stylesheet. Tool-controlled constant: no finding-derived byte reaches it, which is why
/// `style-src 'unsafe-inline'` above is not a hole.
const CSS: &str = r#"
:root { color-scheme: light dark; }
body { font: 15px/1.5 system-ui, sans-serif; margin: 0 auto; max-width: 60rem; padding: 2rem 1rem; }
h1 { margin-bottom: 0.2rem; }
h2 { margin-top: 2rem; border-bottom: 1px solid #8884; padding-bottom: 0.2rem; }
p.meta { color: #6b7280; margin: 0.2rem 0; }
p.note { color: #6b7280; font-size: 0.9em; }
span.none { color: #9ca3af; font-style: italic; }
p.verdict { border-left: 4px solid; padding: 0.7rem 1rem; margin: 1.2rem 0; font-weight: 600; }
p.verdict.clean { border-color: #16a34a; background: #16a34a1a; }
p.verdict.found { border-color: #2563eb; background: #2563eb1a; }
p.verdict.partial { border-color: #d97706; background: #d977061a; }
p.verdict.nothing { border-color: #dc2626; background: #dc26261a; }
table { border-collapse: collapse; width: 100%; margin: 0.6rem 0; }
th, td { border: 1px solid #8884; padding: 0.35rem 0.55rem; text-align: left; vertical-align: top; }
td.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
ul.sev { list-style: none; display: flex; gap: 0.5rem; flex-wrap: wrap; padding: 0; }
ul.sev li { border: 1px solid #8884; border-radius: 4px; padding: 0.3rem 0.7rem; }
ul.sev li.high { border-color: #dc2626; }
ul.sev li.medium { border-color: #d97706; }
ul.sev li.low { border-color: #2563eb; }
ul.unknowns li { margin-bottom: 0.4rem; }
section.finding { border: 1px solid #8884; border-left-width: 4px; border-radius: 4px;
  padding: 0.6rem 1rem; margin: 0.8rem 0; }
section.finding.high { border-left-color: #dc2626; }
section.finding.medium { border-left-color: #d97706; }
section.finding.low { border-left-color: #2563eb; }
section.finding.info { border-left-color: #6b7280; }
section.finding h3 { margin: 0.2rem 0; }
p.tags { color: #374151; margin: 0.2rem 0; }
pre { background: #8881; padding: 0.6rem; overflow-x: auto; white-space: pre-wrap;
  word-break: break-word; }
ul.occ { font-family: ui-monospace, monospace; font-size: 0.9em; }
details.cov { margin: 1rem 0; }
summary { cursor: pointer; }
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests::{bounded_session, passive_all_ran, shipped_load};
    use crate::report::{Report, RunFacts};
    use burpsy_core::{Confidence, MsgId, Occurrence, Scope};

    fn render(findings: &[Finding], audits: &[crate::SessionOutcome]) -> String {
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
        to_html(&r)
    }

    fn finding_with_detail(detail: &str) -> Finding {
        Finding {
            id: 0,
            check_name: "Reflected input".into(),
            issue_name: None,
            severity: Severity::High,
            confidence: Confidence::Certain,
            host: "app.test".into(),
            detail: Some(detail.to_owned()),
            remediation: None,
            occurrences: vec![Occurrence {
                exchange_id: 1,
                response: MsgId(1),
                path: "/search".into(),
            }],
            times_seen: 1,
        }
    }

    #[test]
    fn the_page_is_self_contained_with_no_external_asset_and_no_script() {
        let html = render(&[finding_with_detail("x")], &[bounded_session()]);
        for forbidden in ["<script", "src=", "href=", "http://", "https://", "@import"] {
            assert!(
                !html.contains(forbidden),
                "an air-gapped report must not contain {forbidden:?}"
            );
        }
        assert!(html.contains("Content-Security-Policy"));
        assert!(html.starts_with("<!doctype html>"));
    }

    #[test]
    fn a_finding_detail_that_is_a_script_tag_renders_as_visible_literal_text() {
        let html = render(&[finding_with_detail(r#""><script>alert(1)</script>"#)], &[]);
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "the payload must not survive as markup"
        );
        assert!(
            html.contains("&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"),
            "the payload must be visible to the reader as text: {html}"
        );
    }

    #[test]
    fn escaping_covers_the_two_characters_the_web_uis_own_escape_misses() {
        // Not a redundant test of `escape_text`: the UI's `esc` handles `& < >` only, and this is the
        // regression that would reappear if this writer were ever "simplified" to match it.
        assert_eq!(escape_text("a\"b'c"), "a&quot;b&#39;c");
    }

    #[test]
    fn a_run_with_refused_dispatches_does_not_render_as_a_clean_report() {
        let html = render(&[], &[bounded_session()]);
        assert!(
            html.contains("verdict partial"),
            "the verdict must be styled and worded as partial coverage"
        );
        assert!(html.contains("Partial coverage:"));
        assert!(
            html.contains("the outbound request budget was already spent"),
            "the engine's own explanation for the refusal must be on the page: {html}"
        );
        assert!(
            html.contains("What was not checked"),
            "the not-checked section is mandatory"
        );
    }

    #[test]
    fn a_zero_finding_page_says_the_collaborator_gated_checks_were_never_loaded() {
        let html = render(&[], &[]);
        assert!(html.contains("needs an out-of-band interaction server"));
        assert!(
            html.contains("no audit was run"),
            "the most important sentence in a browse-only report: {html}"
        );
        assert!(
            !html.contains("Checked and clean"),
            "a report with 26 unloaded checks must never claim to be clean"
        );
    }

    #[test]
    fn the_coverage_statement_appears_before_the_findings_table() {
        let html = render(&[finding_with_detail("x")], &[bounded_session()]);
        let coverage = html.find("What was not checked").expect("section present");
        let findings = html.find("<h2>Findings</h2>").expect("section present");
        assert!(
            coverage < findings,
            "a reader who stops after the first screen must have seen the coverage statement"
        );
    }

    #[test]
    fn an_oversized_detail_is_truncated_with_both_counts_stated() {
        let big = "A".repeat(10_000);
        let scope = Scope::allow_everything();
        let load = shipped_load();
        let passive = passive_all_ran(1);
        let r = Report::from_facts(RunFacts {
            scope: &scope,
            load: &load,
            passive: &passive,
            audits: &[],
            findings: &[finding_with_detail(&big)],
            generated_unix_ms: 0,
        });
        let html = to_html_with(&r, 100);
        assert!(
            html.contains("100 of 10,000 bytes shown"),
            "a silent trim would let a reader think they had seen the whole detail"
        );
    }

    #[test]
    fn a_detail_truncated_mid_character_does_not_panic_and_cuts_at_a_boundary() {
        // Cutting a 3-byte character at byte 2 is the panic a naive `&s[..limit]` would take.
        let d = "aa\u{2603}bbbb";
        let (shown, total) = truncate_at_char_boundary(d, 3);
        assert_eq!(shown, "aa");
        assert_eq!(total, d.len());
    }

    #[test]
    fn an_occurrence_list_capped_by_storage_states_the_true_count() {
        let mut f = finding_with_detail("x");
        f.times_seen = 1204;
        f.occurrences = (0..MAX_OCCURRENCES)
            .map(|i| Occurrence {
                exchange_id: i as u64,
                response: MsgId(i as u64),
                path: "/p".into(),
            })
            .collect();
        let html = render(&[f], &[]);
        assert!(
            html.contains("50 of 1,204 occurrences shown"),
            "the retained list is capped and the report must say so: {html}"
        );
    }

    #[test]
    fn thousands_separators_are_placed_correctly() {
        assert_eq!(commas(0), "0");
        assert_eq!(commas(999), "999");
        assert_eq!(commas(1_000), "1,000");
        assert_eq!(commas(12_345), "12,345");
        assert_eq!(commas(1_234_567), "1,234,567");
    }
}
