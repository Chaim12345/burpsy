//! Conformance runner: parse a tree of .bcheck files and report what we accept.
//!
//! Paired with PortSwigger's own `BCheckChecker-1.9.jar` as an oracle — running both over the same
//! tree and diffing accept/reject is the cheapest possible validation of the grammar.
use std::path::PathBuf;

fn main() {
    let root = std::env::args().nth(1).unwrap_or_else(|| "/tmp/BChecks".into());
    let mut files: Vec<PathBuf> = Vec::new();
    walk(PathBuf::from(&root), &mut files);
    files.sort();

    let (mut ok, mut fail) = (0usize, 0usize);
    let (mut passive, mut collab, mut by_freq) = (0usize, 0usize, std::collections::BTreeMap::new());
    let mut failures = Vec::new();
    // Modifier tally, cross-checked against a grep of the same tree. If the parser silently drops a
    // clause these counts fall below the grep and the discrepancy is visible.
    let mut mods: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut sends = 0usize;
    let mut raw_sends = 0usize;

    for f in &files {
        let src = match std::fs::read_to_string(f) {
            Ok(s) => s,
            Err(_) => continue,
        };
        match burpsy_bcheck::parse(&src) {
            Ok(c) => {
                ok += 1;
                let key = format!("{:?}", c.frequency);
                *by_freq.entry(key).or_insert(0usize) += 1;
                if c.is_passive() && !c.needs_collaborator() {
                    passive += 1;
                }
                if c.needs_collaborator() {
                    collab += 1;
                }
                count_mods(&c.body, &mut mods, &mut sends, &mut raw_sends);
                if std::env::var("PER_FILE").is_ok() {
                    let mut m = std::collections::BTreeMap::new();
                    let (mut a, mut b) = (0, 0);
                    count_mods(&c.body, &mut m, &mut a, &mut b);
                    println!("PERFILE\t{}\t{}", f.display(), m.get("method").copied().unwrap_or(0));
                }
            }
            Err(e) => {
                fail += 1;
                failures.push(format!("{}: {e}", f.display()));
            }
        }
    }

    println!("files          : {}", files.len());
    println!("parsed OK      : {ok}");
    println!("failed         : {fail}");
    if !files.is_empty() {
        println!("accept rate    : {:.1}%", ok as f64 * 100.0 / files.len() as f64);
        println!("M1 runnable    : {passive} ({:.1}%)", passive as f64 * 100.0 / files.len() as f64);
        println!("needs collab   : {collab} ({:.1}%)", collab as f64 * 100.0 / files.len() as f64);
    }
    println!("\nby given-frequency:");
    for (k, v) in &by_freq {
        println!("  {k:<28} {v}");
    }
    println!("\nsend request   : {sends} ({raw_sends} raw-string form)");
    println!("request modifiers captured:");
    let total: usize = mods.values().sum();
    for (k, v) in &mods {
        println!("  {k:<28} {v}");
    }
    println!("  {:<28} {total}", "TOTAL");
    if !failures.is_empty() {
        println!("\nfirst failures:");
        for f in failures.iter().take(15) {
            println!("  {f}");
        }
    }
}

/// Walk statements counting `send request` modifier clauses by target and operation.
fn count_mods(
    ss: &[burpsy_bcheck::ast::Statement],
    out: &mut std::collections::BTreeMap<String, usize>,
    sends: &mut usize,
    raw_sends: &mut usize,
) {
    use burpsy_bcheck::ast::{ModOp, RequestMod, Statement};
    for s in ss {
        match s {
            Statement::If { then, otherwise, .. } => {
                count_mods(then, out, sends, raw_sends);
                count_mods(otherwise, out, sends, raw_sends);
            }
            Statement::SendRequest { raw, mods, .. } => {
                *sends += 1;
                if raw.is_some() {
                    *raw_sends += 1;
                }
                for m in mods {
                    let key = match m {
                        RequestMod::Method(_) => "method".to_string(),
                        RequestMod::QueryString(_) => "query_string".to_string(),
                        RequestMod::Queries(v) => format!("appending queries ({} entries)", v.len()),
                        RequestMod::Path { op, .. } => format!("{} path", opname(*op)),
                        RequestMod::Body { op, .. } => format!("{} body", opname(*op)),
                        RequestMod::Headers { op, pairs } => {
                            format!("{} headers ({} pairs)", opname(*op), pairs.len())
                        }
                    };
                    // Collapse the per-clause entry counts into one bucket per target+op.
                    let bucket = key.split(" (").next().unwrap().to_string();
                    *out.entry(bucket).or_insert(0) += 1;
                }
            }
            _ => {}
        }
    }
    fn opname(o: ModOp) -> &'static str {
        match o {
            ModOp::Replace => "replacing",
            ModOp::Append => "appending",
        }
    }
}

fn walk(p: PathBuf, out: &mut Vec<PathBuf>) {
    if p.is_dir() {
        if let Ok(rd) = std::fs::read_dir(&p) {
            for e in rd.flatten() {
                walk(e.path(), out);
            }
        }
    } else if p.extension().map(|e| e == "bcheck").unwrap_or(false) {
        out.push(p);
    }
}
