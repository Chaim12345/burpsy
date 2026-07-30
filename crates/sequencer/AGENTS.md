<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-29 | Updated: 2026-07-29 -->

# sequencer (`burpsy-sequencer`)

## Purpose

Statistical randomness analysis of captured session tokens — the Sequencer. Burp's answers one
question: is the value this application uses as a session id or a CSRF token actually
unpredictable? It answers it two ways at once (a character-level view and the bit-level FIPS 140-2
battery) from either a live capture loop or a block of pasted text, and so does this.

## Key Files

| File | Description |
|------|-------------|
| `src/lib.rs` | `SequencerReport`, `Grade`, `analyse`/`analyse_as`, `tokens_from_text`. The verdict is assembled here |
| `src/fips.rs` | The four FIPS 140-2 statistical tests, `Encoding` (raw/hex/base64), `BitStats`. Every threshold is quoted with its spec section |
| `src/chars.rs` | Alphabet, per-position distribution, Shannon entropy |
| `src/capture.rs` | The live capture loop, `Extractor`, `ResponsePart`, `CaptureProgress` |

## For AI Agents

### The three refusals this crate is built on — do not "fix" them

**1. A verdict is only printed where the test it comes from applies.** Every FIPS 140-2 threshold is
a function of a 20,000-bit sample: the monobit bounds are `10_000 ± 2.58σ` for `σ = sqrt(20_000)/2`,
and the runs intervals are centred on `20_000 / 2^(k+1)`. So the stream is cut into **whole**
20,000-bit blocks, each is tested exactly as specified, and the remainder is reported as untested.
Fewer than one whole block yields `tests: None` and `Grade::Insufficient`.

Rescaling the constants for a shorter sample is the obvious "improvement" and it is wrong — it is a
different test, and it would print a confident number that means nothing. This is the root
`AGENTS.md` rule about honest counting applied to statistics.

**2. The bit stream is decoded before it is tested.** A 32-character hex session id read as ASCII is
256 bits in which bit 7 of every byte is structurally zero, and it fails monobit by more than a
thousand for reasons about hex rather than about the generator. `Encoding::detect` picks the
narrowest alphabet that fits and the report names it. `fips.rs`'s
`the_same_tokens_pass_decoded_and_fail_as_ascii_which_is_why_encoding_is_detected` is the whole
argument in one test; if you change the encoding logic, that test is the one that matters.

**3. The network is not this crate's to touch.** Live capture goes out through
`burpsy_sender::AuthorisedSender::send_async` and nothing else. `tokio` is pinned to
`default-features = false, features = ["time"]` so `sleep` is the only runtime capability reachable
here — the same statement `intruder` makes with its own narrowing. Adding a transport, a client, or
the `net` feature to the production dependency would both break the intent and trip
`sender/tests/no_alternate_egress.rs`.

### Also deliberately absent

- **No significance levels or Burp-comparable "effective entropy".** Burp reports entropy from a set
  of per-position hypothesis tests at a chosen significance level. That is a larger statistical
  claim than four counted thresholds, and half-implementing it would produce a number that looks
  like Burp's and is not comparable to it. What is here instead is raw per-position entropy, the
  sample ceiling that bounds it, and an explicit `assumes_positional_independence` flag.
- **No token store.** Tokens arrive as `Bytes`, are analysed, and are dropped.
- **No scope of its own.** Like `intruder`'s engine, this crate has no concept of engagement scope
  and should not grow one. The decision belongs to the sender it is handed.

### Where the numbers came from

The known-answer tests are not self-consistency checks. Every reference figure was computed
independently (in Python) from the same xorshift64\* definition before the Rust existed:

| Vector | Reference |
|--------|-----------|
| xorshift64\* seed 1, 2500 bytes | 9,956 ones · Σf(i)² = 1,566,958 → X = 14.2656 · runs zeros `[2491,1281,598,297,166,167]` ones `[2517,1282,587,302,151,161]` · longest run 18 · passes all four |
| alternating `0101…` | 10,000 ones (passes monobit), X = 75,000, 20,000 length-1 runs (fails poker and runs), longest run 1 (passes long-runs) |
| nibbles cycling `0..15` | f = 313×8, 312×8 → X = 64/5000 = **0.0128 exactly**, which fails the *lower* bound 2.16 |
| the same seed-1 bytes hex-encoded | 9,956 ones decoded (pass) vs 8,698 and 8,750 as ASCII (fail) |

The third is the one worth keeping in mind: the poker interval is two-sided, and a *perfectly* even
nibble spread fails it. If a change makes that vector pass, the change is wrong.

### Bounds, and why each exists

`DEFAULT_TOKENS` 100 · `MAX_TOKENS` 20,000 · `MAX_CONSECUTIVE_FAILURES` 10. The last is the one that
is easy to leave out and shouldn't be: a misconfigured extractor fails identically every time, and
without it a wrong regex spends the whole 20,000-request budget discovering that.

### Testing Requirements

```bash
cargo test -p burpsy-sequencer     # 45 tests, all inline
cargo test --workspace
```

Tests must not touch DNS — the same rule as `sender`. The capture tests stand up a real local
listener on `127.0.0.1:0`; a hostname would cost a resolver timeout.

## Dependencies

### Internal

- `burpsy-core` — `Span`/`parse` for locating a token in a response
- `burpsy-sender` — `AuthorisedSender`, the only way out

### External

- `bytes` — tokens are `Bytes`, so a capture copies each token once and nothing else
- `regex` — `regex::bytes`, because a response body need not be UTF-8
- `serde` — the report crosses a JSON boundary (Serialize only; it is an output)
- `tokio` — `time` only, for the wait between captures

<!-- MANUAL: -->
