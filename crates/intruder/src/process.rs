//! The payload-processing rule chain: an ordered list of transformations applied to each payload.
//!
//! # Where in the attack this runs, and why not later
//!
//! Burp applies processing rules at send time, once per request, inside the attack loop. Here the
//! chain runs at **resolve time**, over the [`PayloadSet`] a [`crate::PayloadSource`] produced,
//! before an [`crate::AttackPlan`] is built over it. The engine is not told that processing exists.
//!
//! That is not a shortcut, it is the only placement that keeps the two properties this crate is built
//! on:
//!
//! * **A result row holds an ordinal and nothing else.** That works because the payload behind
//!   ordinal `i` is recoverable after the attack. If processing ran per-send, recovering a payload
//!   would mean re-running the chain — and a chain containing a random-seeded or clock-dependent step
//!   would recover a *different* payload than the one that was sent.
//! * **A skipped payload is a shorter set, not a hole in the plan.** `skip-if-matches` drops a
//!   payload here, so the plan is built over what will actually be sent and `plan.len()` is the
//!   number of requests. Applying the skip inside the engine would leave gaps in the ordinal space,
//!   and every count in [`crate::AttackReport`] would need a "and also N ordinals that were never
//!   requests" caveat.
//!
//! The cost is real and worth naming: a rule cannot depend on anything that only exists at send time.
//! Nothing in Burp's rule set does — every rule is a pure function of the payload — but a
//! hypothetical "add current timestamp" rule would produce one timestamp for the whole attack rather
//! than one per request, and would belong in the engine instead.
//!
//! # Refuse rather than mangle
//!
//! A rule that cannot be applied — base64-decoding a payload that is not base64, inflating bytes that
//! are not compressed — **drops the payload with a reason** rather than passing it through unchanged.
//! Passing it through would send a payload the operator did not ask for while the report said the
//! rule was applied. Reasons are grouped and counted, the same way [`crate::ErrorBucket`] groups send
//! failures: one line per distinct reason, never one per payload.
//!
//! # Errors at construction
//!
//! [`Chain::new`] compiles every regex and resolves every layer and algorithm name. Nothing reaches
//! the per-payload loop uncompiled, and an unparseable pattern is one error at the edge rather than
//! N identical drops — the same discipline as `burpsy_tools::matchreplace::Rule`.

use crate::hash::HashAlg;
use crate::payload::PayloadSet;
use burpsy_tools::decoder::{self, Layer};
use bytes::Bytes;
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

/// Distinct reasons are bounded for the same reason result buckets are: a chain that drops 199 999
/// payloads for one reason is one row.
const MAX_DROP_REASONS: usize = 32;

/// Why some payloads never went out, and how many.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DropReason {
    pub reason: String,
    pub count: usize,
}

/// One processing rule, in the form it arrives over the wire.
///
/// Split from the compiled [`Chain`] so patterns are validated once, at the edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "rule")]
pub enum RuleSpec {
    AddPrefix { text: String },
    AddSuffix { text: String },
    /// Regex match and replace. `$1` in `replace` refers to a capture group.
    Replace {
        pattern: String,
        replace: String,
        /// Replace every occurrence rather than only the first.
        #[serde(default)]
        all: bool,
    },
    /// ASCII case only. A payload is bytes and may not be UTF-8 at all, so a Unicode-aware fold
    /// would have to decide what to do with the bytes that are not text; ASCII case-folding is
    /// total, and it is what Burp's own case rules do.
    Uppercase,
    Lowercase,
    /// Encode the whole payload as one layer: `url`, `html`, `base64`, `base64url`, `hex`, `gzip`,
    /// `deflate`. Names and behaviour come from `burpsy_tools::decoder`.
    Encode { layer: String },
    /// The inverse. A payload the layer cannot decode is dropped with a reason, not passed through.
    Decode { layer: String },
    /// Replace the payload with its digest, as lowercase hex. `md5` or `sha256`.
    Hash { algorithm: String },
    /// Drop the payload before it is sent if it matches. Position in the chain matters: put it after
    /// a decode to test the decoded form, before it to test the original.
    SkipIfMatches { pattern: String },
}

/// A rule that could not be built. Every variant is an operator typo, reported once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    BadRegex { pattern: String, message: String },
    UnknownLayer(String),
    UnknownHash(String),
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleError::BadRegex { pattern, message } => {
                write!(f, "bad regex {pattern:?}: {message}")
            }
            RuleError::UnknownLayer(l) => write!(
                f,
                "unknown encoding {l:?}: expected url, html, base64, base64url, hex, gzip or deflate"
            ),
            RuleError::UnknownHash(a) => {
                write!(f, "unknown hash {a:?}: expected md5 or sha256")
            }
        }
    }
}

impl std::error::Error for RuleError {}

/// A compiled rule.
#[derive(Debug)]
enum Step {
    AddPrefix(Vec<u8>),
    AddSuffix(Vec<u8>),
    Replace {
        re: Regex,
        replace: Vec<u8>,
        all: bool,
    },
    Uppercase,
    Lowercase,
    Encode(Layer),
    Decode(Layer),
    Hash(HashAlg),
    SkipIfMatches(Regex),
}

/// An ordered chain of processing rules, ready to run.
#[derive(Debug, Default)]
pub struct Chain {
    steps: Vec<Step>,
}

/// What the chain did with one payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Processed {
    /// Send this.
    Keep(Bytes),
    /// Do not send it, for this reason.
    Drop(String),
}

impl Chain {
    /// Compile the chain. Order is the order given.
    pub fn new(specs: &[RuleSpec]) -> Result<Self, RuleError> {
        let mut steps = Vec::with_capacity(specs.len());
        for s in specs {
            steps.push(match s {
                RuleSpec::AddPrefix { text } => Step::AddPrefix(text.clone().into_bytes()),
                RuleSpec::AddSuffix { text } => Step::AddSuffix(text.clone().into_bytes()),
                RuleSpec::Replace {
                    pattern,
                    replace,
                    all,
                } => Step::Replace {
                    re: compile(pattern)?,
                    replace: replace.clone().into_bytes(),
                    all: *all,
                },
                RuleSpec::Uppercase => Step::Uppercase,
                RuleSpec::Lowercase => Step::Lowercase,
                RuleSpec::Encode { layer } => Step::Encode(layer_of(layer)?),
                RuleSpec::Decode { layer } => Step::Decode(layer_of(layer)?),
                RuleSpec::Hash { algorithm } => Step::Hash(
                    HashAlg::parse(algorithm)
                        .ok_or_else(|| RuleError::UnknownHash(algorithm.clone()))?,
                ),
                RuleSpec::SkipIfMatches { pattern } => Step::SkipIfMatches(compile(pattern)?),
            });
        }
        Ok(Self { steps })
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Run the chain over one payload, in rule order.
    pub fn apply(&self, payload: &[u8]) -> Processed {
        let mut cur: Vec<u8> = payload.to_vec();
        for (i, step) in self.steps.iter().enumerate() {
            match step {
                Step::AddPrefix(p) => {
                    let mut v = Vec::with_capacity(p.len() + cur.len());
                    v.extend_from_slice(p);
                    v.extend_from_slice(&cur);
                    cur = v;
                }
                Step::AddSuffix(s) => cur.extend_from_slice(s),
                Step::Replace { re, replace, all } => {
                    cur = if *all {
                        re.replace_all(&cur, replace.as_slice()).into_owned()
                    } else {
                        re.replace(&cur, replace.as_slice()).into_owned()
                    };
                }
                Step::Uppercase => cur.make_ascii_uppercase(),
                Step::Lowercase => cur.make_ascii_lowercase(),
                Step::Encode(l) => match decoder::encode(*l, &cur) {
                    Ok(v) => cur = v,
                    Err(e) => return Processed::Drop(format!("rule {i} ({}): {e}", l.as_str())),
                },
                Step::Decode(l) => match decoder::decode(*l, &cur) {
                    // A partial decode is a different payload than the one the rule describes, and
                    // `decoder` exists to make that visible instead of returning a prefix as a
                    // success. Dropping it is the honest end of that signal.
                    Ok((_, true)) => {
                        return Processed::Drop(format!(
                            "rule {i} ({}): decoded only part of the payload",
                            l.as_str()
                        ));
                    }
                    Ok((v, false)) => cur = v,
                    Err(e) => return Processed::Drop(format!("rule {i} ({}): {e}", l.as_str())),
                },
                Step::Hash(a) => cur = a.hex(&cur).into_bytes(),
                Step::SkipIfMatches(re) => {
                    if re.is_match(&cur) {
                        return Processed::Drop(format!("rule {i}: skipped, matches {}", re.as_str()));
                    }
                }
            }
            if cur.len() > crate::payload::MAX_ITEM_LEN {
                return Processed::Drop(format!(
                    "rule {i}: payload grew to {} bytes, over the {}-byte limit",
                    cur.len(),
                    crate::payload::MAX_ITEM_LEN
                ));
            }
        }
        Processed::Keep(Bytes::from(cur))
    }

    /// Apply the chain to every payload in `set`, in place.
    ///
    /// Dropped payloads are removed rather than blanked, so the set that comes out is exactly what
    /// will be sent — and `set.skipped` plus `set.dropped` account for the difference. An empty chain
    /// is a no-op and does not even walk the set.
    pub fn run(&self, set: &mut PayloadSet) {
        if self.steps.is_empty() {
            return;
        }
        let mut kept = Vec::with_capacity(set.items.len());
        for p in &set.items {
            match self.apply(p) {
                Processed::Keep(b) => kept.push(b),
                Processed::Drop(why) => {
                    set.skipped += 1;
                    note_drop(&mut set.dropped, why);
                }
            }
        }
        set.items = kept;
    }
}

fn note_drop(into: &mut Vec<DropReason>, reason: String) {
    if let Some(d) = into.iter_mut().find(|d| d.reason == reason) {
        d.count += 1;
    } else if into.len() < MAX_DROP_REASONS {
        into.push(DropReason { reason, count: 1 });
    }
}

fn compile(pattern: &str) -> Result<Regex, RuleError> {
    Regex::new(pattern).map_err(|e| RuleError::BadRegex {
        pattern: pattern.to_string(),
        message: e.to_string(),
    })
}

fn layer_of(name: &str) -> Result<Layer, RuleError> {
    // `jwt` parses as a layer but is one-way, and `encode` rejects it with `NotReversible`. That is
    // a real error message at the right time, so it is not special-cased here.
    Layer::parse(name).ok_or_else(|| RuleError::UnknownLayer(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::PayloadSource;

    fn chain(specs: &[RuleSpec]) -> Chain {
        Chain::new(specs).expect("specs must compile")
    }

    fn one(specs: &[RuleSpec], payload: &str) -> Processed {
        chain(specs).apply(payload.as_bytes())
    }

    fn kept(p: Processed) -> String {
        match p {
            Processed::Keep(b) => String::from_utf8_lossy(&b).into_owned(),
            Processed::Drop(why) => panic!("dropped: {why}"),
        }
    }

    fn set_of(items: &[&str]) -> PayloadSet {
        PayloadSource::List {
            items: items.iter().map(|s| (*s).to_string()).collect(),
        }
        .resolve(1_000)
        .unwrap()
    }

    #[test]
    fn rules_apply_in_the_order_they_were_given() {
        // prefix-then-uppercase and uppercase-then-prefix are different attacks.
        let a = kept(one(
            &[
                RuleSpec::AddPrefix { text: "abc".into() },
                RuleSpec::Uppercase,
            ],
            "xy",
        ));
        let b = kept(one(
            &[
                RuleSpec::Uppercase,
                RuleSpec::AddPrefix { text: "abc".into() },
            ],
            "xy",
        ));
        assert_eq!(a, "ABCXY");
        assert_eq!(b, "abcXY");
    }

    #[test]
    fn prefix_and_suffix_wrap_the_payload() {
        let s = kept(one(
            &[
                RuleSpec::AddPrefix { text: "'or ".into() },
                RuleSpec::AddSuffix { text: "--".into() },
            ],
            "1=1",
        ));
        assert_eq!(s, "'or 1=1--");
    }

    #[test]
    fn regex_replace_uses_capture_groups_and_honours_the_all_flag() {
        let first = kept(one(
            &[RuleSpec::Replace {
                pattern: r"(\d+)".into(),
                replace: "[$1]".into(),
                all: false,
            }],
            "a1b2",
        ));
        assert_eq!(first, "a[1]b2");
        let all = kept(one(
            &[RuleSpec::Replace {
                pattern: r"(\d+)".into(),
                replace: "[$1]".into(),
                all: true,
            }],
            "a1b2",
        ));
        assert_eq!(all, "a[1]b[2]");
    }

    /// The point of depending on `burpsy-tools` rather than writing these again: the codecs are the
    /// same ones the Decoder tool uses, so a payload encoded here round-trips there.
    #[test]
    fn encode_and_decode_reuse_the_decoder_codecs() {
        assert_eq!(
            kept(one(
                &[RuleSpec::Encode {
                    layer: "url".into()
                }],
                "a b&c=d"
            )),
            // Uppercase hex digits, because that is what `burpsy_tools::decoder` emits — the point of
            // reusing it is that a payload encoded here is byte-identical to one encoded in the
            // Decoder tool, including this.
            "a%20b%26c%3Dd"
        );
        assert_eq!(
            kept(one(
                &[RuleSpec::Encode {
                    layer: "base64".into()
                }],
                "admin"
            )),
            "YWRtaW4="
        );
        assert_eq!(
            kept(one(
                &[RuleSpec::Decode {
                    layer: "base64".into()
                }],
                "YWRtaW4="
            )),
            "admin"
        );
        assert_eq!(
            kept(one(
                &[RuleSpec::Encode {
                    layer: "html".into()
                }],
                "<script>"
            )),
            "&lt;script&gt;"
        );
        // Chained, which is how an operator actually uses these.
        assert_eq!(
            kept(one(
                &[
                    RuleSpec::Encode {
                        layer: "base64".into()
                    },
                    RuleSpec::Encode {
                        layer: "url".into()
                    }
                ],
                "a?"
            )),
            "YT8%3D"
        );
    }

    #[test]
    fn a_hash_step_produces_lowercase_hex() {
        assert_eq!(
            kept(one(
                &[RuleSpec::Hash {
                    algorithm: "md5".into()
                }],
                "abc"
            )),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        // Hash then encode is the combination that makes hex the right default: the operator can get
        // to base64 in one more step, but cannot get back from raw bytes spliced into a URL.
        assert_eq!(
            kept(one(
                &[
                    RuleSpec::Hash {
                        algorithm: "sha256".into()
                    },
                    RuleSpec::Uppercase
                ],
                "abc"
            )),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
    }

    #[test]
    fn skip_if_matches_drops_the_payload_with_its_reason() {
        let p = one(
            &[RuleSpec::SkipIfMatches {
                pattern: r"^\d+$".into(),
            }],
            "12345",
        );
        match p {
            Processed::Drop(why) => assert!(why.contains("skipped"), "{why}"),
            Processed::Keep(_) => panic!("a numeric payload must be skipped"),
        }
        assert_eq!(
            kept(one(
                &[RuleSpec::SkipIfMatches {
                    pattern: r"^\d+$".into()
                }],
                "12a45"
            )),
            "12a45"
        );
    }

    /// Where in the chain the skip sits decides what it tests. This is why it is a rule rather than a
    /// separate filter applied first.
    #[test]
    fn a_skip_after_a_decode_tests_the_decoded_form() {
        let specs = [
            RuleSpec::Decode {
                layer: "base64".into(),
            },
            RuleSpec::SkipIfMatches {
                pattern: "admin".into(),
            },
        ];
        assert!(matches!(one(&specs, "YWRtaW4="), Processed::Drop(_)));
        assert!(matches!(one(&specs, "Z3Vlc3Q="), Processed::Keep(_)));
    }

    #[test]
    fn a_payload_a_rule_cannot_process_is_dropped_not_passed_through() {
        // `zz` is not hex. Passing it through unchanged while the report claims a hex decode ran
        // would send a payload the operator did not ask for.
        let p = one(
            &[RuleSpec::Decode {
                layer: "hex".into(),
            }],
            "zz",
        );
        match p {
            Processed::Drop(why) => assert!(why.contains("hex digit"), "{why}"),
            Processed::Keep(b) => panic!("passed through: {b:?}"),
        }
    }

    #[test]
    fn run_shortens_the_set_and_accounts_for_every_payload_it_dropped() {
        let mut set = set_of(&["1", "2", "admin", "3", "root"]);
        chain(&[RuleSpec::SkipIfMatches {
            pattern: r"^\d+$".into(),
        }])
        .run(&mut set);
        assert_eq!(set.len(), 2, "only the non-numeric payloads survive");
        assert_eq!(set.skipped, 3);
        assert_eq!(set.dropped.len(), 1, "one reason, three payloads");
        assert_eq!(set.dropped[0].count, 3);
    }

    #[test]
    fn an_empty_chain_leaves_the_set_exactly_as_it_was() {
        let mut set = set_of(&["a", "b", "c"]);
        let before = set.items.clone();
        Chain::default().run(&mut set);
        assert_eq!(set.items, before);
        assert_eq!(set.skipped, 0);
        assert!(set.dropped.is_empty());
    }

    #[test]
    fn a_bad_pattern_is_one_error_at_construction_not_n_drops_at_run_time() {
        let e = Chain::new(&[RuleSpec::SkipIfMatches {
            pattern: "([unclosed".into(),
        }])
        .unwrap_err();
        assert!(matches!(e, RuleError::BadRegex { .. }), "{e}");
    }

    #[test]
    fn an_unknown_layer_or_hash_is_refused_at_construction() {
        assert_eq!(
            Chain::new(&[RuleSpec::Encode {
                layer: "rot13".into()
            }])
            .unwrap_err(),
            RuleError::UnknownLayer("rot13".into())
        );
        assert_eq!(
            Chain::new(&[RuleSpec::Hash {
                algorithm: "sha3".into()
            }])
            .unwrap_err(),
            RuleError::UnknownHash("sha3".into())
        );
    }

    #[test]
    fn a_rule_that_would_grow_a_payload_past_the_limit_drops_it() {
        // Nine gzip layers of a kilobyte is not a payload anyone means, but a chain that ran away
        // must not be able to put 64 MiB into one spliced request.
        let big = "A".repeat(4_000);
        let specs: Vec<RuleSpec> = (0..12)
            .map(|_| RuleSpec::Encode {
                layer: "hex".into(),
            })
            .collect();
        match chain(&specs).apply(big.as_bytes()) {
            Processed::Drop(why) => assert!(why.contains("over the"), "{why}"),
            Processed::Keep(b) => panic!("built a {}-byte payload", b.len()),
        }
    }

    #[test]
    fn jwt_is_a_layer_that_cannot_be_encoded_and_says_so_at_run_time() {
        // It parses as a layer, so this is not a construction error; it is a per-payload refusal
        // carrying the decoder's own message.
        match one(
            &[RuleSpec::Encode {
                layer: "jwt".into(),
            }],
            "anything",
        ) {
            Processed::Drop(why) => assert!(why.contains("cannot be encoded"), "{why}"),
            Processed::Keep(_) => panic!("jwt has no inverse"),
        }
    }
}
