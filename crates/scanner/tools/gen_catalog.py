#!/usr/bin/env python3
"""Generate crates/scanner/src/catalog_data.rs from Burp's shipped KnowledgeBase.

    python3 crates/scanner/tools/gen_catalog.py crates/scanner/src/catalog_data.rs

Source: the 183 `resources/KnowledgeBase/Issues/*.json` files from the Burp Suite 2026.7.1
jar, as extracted by the teardown to /root/burp-re/out/scanner_spec/issues/. Point SRC at
another extraction of the same resource directory if that tree is not present.

Mechanical transcription only — no field is synthesised, reworded, or defaulted, and a field
absent in the source stays absent in the output. The generator exits non-zero rather than
emit anything if the source stops matching its assumptions (183 files, unique
filename-encoded IDs, IDs that fit in u32), because the alternative is a catalog that quietly
disagrees with the data it claims to transcribe.
"""
import glob
import json
import os
import sys

SRC = "/root/burp-re/out/scanner_spec/issues"
OUT = sys.argv[1]

SEV = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}


def lit(s):
    """A Rust string literal holding exactly `s`.

    Prefers a raw string so embedded HTML stays readable in the generated file; falls back to
    an escaped literal when the text contains something a raw string cannot hold verbatim.
    """
    if "\r" in s or "\x00" in s:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace(
            "\r", "\\r"
        ).replace("\n", "\\n") + '"'
    n = 1
    while ('"' + "#" * n) in s:
        n += 1
    h = "#" * n
    return f'r{h}"{s}"{h}'


def main():
    files = sorted(glob.glob(os.path.join(SRC, "*.json")))
    if len(files) != 183:
        sys.exit(f"expected 183 issue definitions, found {len(files)}")

    issues = []
    for f in files:
        d = json.load(open(f, encoding="utf-8"))
        # The filename encodes the ID in hex (00100200_SqlInjection.json => 0x00100200). That
        # encoding is unique across all 183 files; the JSON `typeIndex` field is not — two files
        # carry a stale value that duplicates another issue's ID. Both are kept verbatim.
        # webIntro is dropped: null in 179 of 183 and duplicative of `description` in the rest.
        issues.append(
            {
                "type_index": int(os.path.basename(f).split("_")[0], 16),
                "declared_type_index": d["typeIndex"],
                "name": d["name"],
                "severity": SEV[d["typicalSeverity"]],
                "description": d["description"],
                "remediation": d["remediation"],
                "references": d["references"] or [],
                "classifications": d["vulnerabilityClassifications"] or [],
            }
        )
    issues.sort(key=lambda i: i["type_index"])
    idx = [i["type_index"] for i in issues]
    if len(set(idx)) != len(idx):
        sys.exit("filename-encoded type index is not unique — binary search would be unsound")
    if max(idx) > 0xFFFFFFFF:
        sys.exit("a type index does not fit in u32")

    n_dis = sum(1 for i in issues if i["type_index"] != i["declared_type_index"])
    n_rem = sum(1 for i in issues if i["remediation"] is not None)
    n_ref = sum(len(i["references"]) for i in issues)
    n_cls = sum(len(i["classifications"]) for i in issues)

    w = []
    p = w.append
    p("//! Burp's shipped issue catalog, transcribed. **Generated — do not edit by hand.**")
    p("//!")
    p("//! Source: `resources/KnowledgeBase/Issues/*.json` from the Burp Suite 2026.7.1 jar,")
    p("//! extracted to `/root/burp-re/out/scanner_spec/issues/` by the teardown. Regenerate with")
    p("//! `python3 crates/scanner/tools/gen_catalog.py crates/scanner/src/catalog_data.rs`.")
    p("//!")
    p(f"//! {len(issues)} definitions; {n_rem} carry a remediation ({len(issues) - n_rem} are null in")
    p(f"//! the source and stay `None`); {n_ref} references; {n_cls} vulnerability classifications.")
    p("//! There is no CVSS data anywhere in the shipped catalog, so no CVSS field exists here.")
    p("//!")
    p("//! `type_index` is the ID encoded in the filename, which is unique across all 183 files.")
    p(f"//! `declared_type_index` is the `typeIndex` field inside the JSON body; it disagrees in")
    p(f"//! {n_dis} of {len(issues)} cases, where the stale value duplicates another issue's ID. Both are")
    p("//! kept verbatim rather than reconciled — see `catalog::tests`.")
    p("//!")
    p("//! Sorted by `type_index` so [`crate::catalog::by_type_index`] can binary-search it.")
    p("")
    p("use crate::catalog::{Classification, IssueDefinition, Reference};")
    p("use burpsy_core::Severity;")
    p("")
    p("pub(crate) static ISSUES: &[IssueDefinition] = &[")
    for i in issues:
        p("    IssueDefinition {")
        p(f"        type_index: {i['type_index']},")
        p(f"        declared_type_index: {i['declared_type_index']},")
        p(f"        name: {lit(i['name'])},")
        p(f"        typical_severity: Severity::{i['severity']},")
        p(f"        description: {lit(i['description'])},")
        if i["remediation"] is None:
            p("        remediation: None,")
        else:
            p(f"        remediation: Some({lit(i['remediation'])}),")
        if not i["references"]:
            p("        references: &[],")
        else:
            p("        references: &[")
            for r in i["references"]:
                p(f"            Reference {{ title: {lit(r['title'])}, url: {lit(r['url'])} }},")
            p("        ],")
        if not i["classifications"]:
            p("        classifications: &[],")
        else:
            p("        classifications: &[")
            for c in i["classifications"]:
                p(
                    f"            Classification {{ title: {lit(c['title'])}, url: {lit(c['url'])} }},"
                )
            p("        ],")
        p("    },")
    p("];")
    p("")

    open(OUT, "w", encoding="utf-8").write("\n".join(w))
    print(
        f"wrote {OUT}: {len(issues)} issues, {n_rem} with remediation, "
        f"{n_ref} refs, {n_cls} classifications, {os.path.getsize(OUT)} bytes"
    )


main()
