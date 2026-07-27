//! Decoder — transformations between an encoded payload and the bytes underneath it.
//!
//! # Smart decode: what Burp actually does, and why
//!
//! Guessing is where a decoder can do real damage, because a wrong guess applied silently
//! *destroys evidence* — you paste a session token, get back mojibake, and cannot tell whether the
//! token was already garbage or the tool mangled it. Burp settled this question years ago and the
//! shipped implementation is readable, so the design here follows its semantics rather than a
//! fresh heuristic. (`Zryp.ZZ` is the driver; `Zbpx` is the codec interface; the codecs are
//! `Zsj1` gzip, `Zekp` URL, `Zer8` HTML entity, `Zwyl` base64, `Zey7` ASCII hex, `Zmaz` radix.)
//!
//! **It scans per position, not per input.** A cursor walks the bytes. At each position every
//! codec is asked to *score* itself (`Zbpx.ZC` returns a `short`); the highest scorer wins and
//! consumes some bytes; a best score below **3** means "emit this byte verbatim and step forward
//! one". So `id=%41&t=%42` decodes both escapes, and the plain text between them survives
//! untouched. A whole-input guesser cannot do that.
//!
//! **It only fires on proof.** This is the part worth copying. `Zwyl.ZC` (base64) and `Zey7.ZC`
//! (ASCII hex) both `return 0` — they are *never* selected by smart decode, only by an explicit
//! "decode as". Their alphabets occur constantly in ordinary text, so guessing them is how you
//! mangle data. Only structural markers score: a `%` followed by two hex digits (5), an `&…;` that
//! resolves to a real character reference (5), the gzip magic `1f 8b 08` (4).
//!
//! **Provenance is per byte.** The driver records the winning codec once for every byte it
//! consumed, which is what colours the Decoder pane. That is Burp's answer to "make a wrong guess
//! recoverable": you can see exactly which bytes each codec claimed.
//!
//! # What this module keeps, and where it diverges
//!
//! Kept: the per-position scan, the scores, the threshold of 3, the refusal to guess alphabets,
//! and provenance — as [`Run`]s carrying spans into both the pass input and the pass output.
//! Layers come from repeated passes ([`Smart::passes`]), each retaining its own input, which is
//! how Burp's stacked decoder panes behave.
//!
//! Diverged, deliberately:
//!
//! * **Base64 and hex can be guessed, but only on request.** [`SmartOptions::guess_alphabets`] is
//!   off by default, matching Burp. Turned on, a guess must clear three bars: the alphabet and
//!   length have to be valid, the decoded output has to be valid UTF-8 and at least 90%
//!   non-control characters, and the pass has to have found *nothing structural anywhere in the
//!   input* — a guessed alphabet never competes with a proven marker, not even at a different
//!   offset. That last rule exists because greediness bites: in `c2Vzc2lvbg%3D%3D` the base64 run
//!   starts at offset 0 and would be claimed before the percent escapes that terminate it.
//!   `deadbeefdeadbeef` is valid hex *and* valid base64; neither decoding is plausible, so even
//!   with guessing on it stays plain text. A guess is flagged [`Confidence::Likely`].
//! * **zlib/deflate and JWT are added.** Both are structural: a zlib header is a multiple of 31,
//!   and a JWT is three base64url segments whose first is JSON carrying `alg`.
//! * **Numeric character references above 255 decode.** `Zer8` caps at a byte because it writes
//!   one; this module emits UTF-8, so `&#x1F600;` works.

use burpsy_core::Span;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// One reversible (or, for [`Layer::Jwt`], one-way) transformation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    /// Percent-encoding, as in a URL.
    Url,
    /// HTML character references.
    Html,
    Base64,
    /// Base64 over the URL-safe alphabet (`-` and `_`), as used by JWT.
    Base64Url,
    Hex,
    Gzip,
    /// `Content-Encoding: deflate`. See [`decode`] for the zlib-versus-raw ambiguity.
    Deflate,
    /// Split a JWT into pretty-printed header and payload. One-way: see [`encode`].
    Jwt,
}

impl Layer {
    pub fn as_str(self) -> &'static str {
        match self {
            Layer::Url => "url",
            Layer::Html => "html",
            Layer::Base64 => "base64",
            Layer::Base64Url => "base64url",
            Layer::Hex => "hex",
            Layer::Gzip => "gzip",
            Layer::Deflate => "deflate",
            Layer::Jwt => "jwt",
        }
    }

    /// Parse the name used on the wire. Returns `None` rather than guessing.
    pub fn parse(s: &str) -> Option<Layer> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "url" | "urlencoded" | "percent" => Layer::Url,
            "html" | "htmlentity" | "entity" => Layer::Html,
            "base64" | "b64" => Layer::Base64,
            "base64url" | "b64url" => Layer::Base64Url,
            "hex" | "hexadecimal" | "ascii-hex" => Layer::Hex,
            "gzip" | "gz" => Layer::Gzip,
            "deflate" | "zlib" => Layer::Deflate,
            "jwt" => Layer::Jwt,
            _ => return None,
        })
    }

    /// Every layer, in the order the UI should list them.
    pub const ALL: [Layer; 8] = [
        Layer::Url,
        Layer::Html,
        Layer::Base64,
        Layer::Base64Url,
        Layer::Hex,
        Layer::Gzip,
        Layer::Deflate,
        Layer::Jwt,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The layer has no inverse. Only [`Layer::Jwt`]: re-encoding needs the signing key, and
    /// emitting an unsigned token that looks like the original would be worse than refusing.
    NotReversible(Layer),
    OddHexDigits(usize),
    NotHex(u8),
    /// Compression failed. Carries the underlying message; partial output is returned instead
    /// whenever any bytes decompressed, so a truncated capture still yields what it held.
    Compression(String),
    Malformed(&'static str),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::NotReversible(l) => {
                write!(f, "{} cannot be encoded, only decoded", l.as_str())
            }
            DecodeError::OddHexDigits(n) => write!(f, "hex input has {n} digits; a byte needs two"),
            DecodeError::NotHex(b) => write!(f, "not a hex digit: {:?}", *b as char),
            DecodeError::Compression(m) => write!(f, "decompression failed: {m}"),
            DecodeError::Malformed(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Refuse to inflate more than this from one input.
///
/// A 46-byte gzip stream expands to a megabyte of zeroes, and a few kilobytes reach terabytes. The
/// decoder runs on bytes an attacker chose, so an unbounded `read_to_end` is a remote OOM. 64 MiB
/// is far past any response worth reading by hand and far short of hurting the process.
const MAX_INFLATE: u64 = 64 * 1024 * 1024;

/// Decode one layer, applied to the whole input. This is the explicit "decode as" path.
pub fn decode(layer: Layer, input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    match layer {
        Layer::Url => Ok(url_decode(input)),
        Layer::Html => Ok(html_decode(input)),
        Layer::Base64 => Ok(base64_decode(input, false)),
        Layer::Base64Url => Ok(base64_decode(input, true)),
        Layer::Hex => hex_decode(input),
        Layer::Gzip => inflate(flate2::read::GzDecoder::new(input)),
        // `Content-Encoding: deflate` is specified as zlib-wrapped, and that is what nearly every
        // server sends — but a minority emit a raw deflate stream, and Burp users hit both. Try the
        // spec-compliant framing first and fall back, rather than making the operator pick.
        Layer::Deflate => match inflate(flate2::read::ZlibDecoder::new(input)) {
            Ok(v) if !v.is_empty() => Ok(v),
            _ => inflate(flate2::read::DeflateDecoder::new(input)),
        },
        Layer::Jwt => jwt_decode(input),
    }
}

/// Encode one layer — the inverse of [`decode`], where one exists.
pub fn encode(layer: Layer, input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    match layer {
        Layer::Url => Ok(url_encode(input)),
        Layer::Html => Ok(html_encode(input)),
        Layer::Base64 => Ok(base64_encode(input, false, true)),
        Layer::Base64Url => Ok(base64_encode(input, true, false)),
        Layer::Hex => Ok(hex_encode(input)),
        Layer::Gzip => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(input)
                .and_then(|()| e.finish())
                .map_err(|e| DecodeError::Compression(e.to_string()))
        }
        Layer::Deflate => {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(input)
                .and_then(|()| e.finish())
                .map_err(|e| DecodeError::Compression(e.to_string()))
        }
        Layer::Jwt => Err(DecodeError::NotReversible(Layer::Jwt)),
    }
}

fn inflate<R: Read>(r: R) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::new();
    match r.take(MAX_INFLATE).read_to_end(&mut out) {
        Ok(_) => Ok(out),
        // A truncated capture is the common case in a pentest, and the bytes that did decompress
        // are exactly the ones being looked for. Only a stream that produced nothing is an error.
        Err(e) if out.is_empty() => Err(DecodeError::Compression(e.to_string())),
        Err(_) => Ok(out),
    }
}

// ---- percent encoding -------------------------------------------------------------------------

/// Decode `%XX`. A `%` that is not followed by two hex digits is left alone.
///
/// `+` is **not** turned into a space here. That conversion belongs to
/// `application/x-www-form-urlencoded`, and applying it unconditionally corrupts a very common
/// payload: base64 carried in a query string, where `+` is a data byte. Burp resolves this by
/// context rather than by rule — `Zekp.ZC` scores a leading `+` at only **2**, below the
/// smart-decode threshold, unless a genuine `%XX` appears later in the same buffer, in which case
/// it scores 5 and the `+` becomes a space. That rule lives in the smart scanner ([`smart_pass`]),
/// where the surrounding context is available; this function is the context-free primitive.
pub fn url_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%'
            && i + 2 < input.len()
            && let (Some(h), Some(l)) = (hex_val(input[i + 1]), hex_val(input[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

/// Percent-encode everything outside RFC 3986's unreserved set.
///
/// Aggressive on purpose: an encoder used for attack payloads should escape `&`, `=` and `/`,
/// because leaving them raw is how a payload breaks out of the parameter it was meant to sit in.
pub fn url_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3);
    for &b in input {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(HEX_UPPER[(b >> 4) as usize]);
            out.push(HEX_UPPER[(b & 0x0f) as usize]);
        }
    }
    out
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn is_percent_escape(b: &[u8], i: usize) -> bool {
    i + 2 < b.len() && b[i] == b'%' && hex_val(b[i + 1]).is_some() && hex_val(b[i + 2]).is_some()
}

// ---- HTML character references ----------------------------------------------------------------

/// The named references worth carrying. Injection testing lives on these five plus `nbsp`; the
/// full HTML5 table is 2231 entries of mostly typography and would be dead weight.
const ENTITIES: &[(&str, char)] = &[
    ("amp", '&'),
    ("lt", '<'),
    ("gt", '>'),
    ("quot", '"'),
    ("apos", '\''),
    ("nbsp", '\u{a0}'),
];

/// How far past `&` a character reference may run before we stop looking. `Zer8` scans 8.
const ENTITY_SCAN: usize = 8;

/// Decode named and numeric character references. An unrecognised `&...;` is left verbatim —
/// swallowing it would lose the very bytes that reveal a filter's behaviour.
pub fn html_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'&' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        match entity_at(input, i) {
            Some((c, len)) => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                i += len;
            }
            None => {
                out.push(b'&');
                i += 1;
            }
        }
    }
    out
}

/// The character reference starting at `i`, and how many input bytes it spans.
fn entity_at(b: &[u8], i: usize) -> Option<(char, usize)> {
    debug_assert_eq!(b[i], b'&');
    let start = i + 1;
    // A numeric reference can be longer than a named one; allow for `&#x10FFFF;`.
    let limit = (start + ENTITY_SCAN.max(9)).min(b.len());
    let end = b.get(start..limit)?.iter().position(|&c| c == b';')?;
    let c = entity_char(&b[start..start + end])?;
    Some((c, end + 2))
}

fn entity_char(body: &[u8]) -> Option<char> {
    if body.is_empty() {
        return None;
    }
    if body[0] == b'#' {
        let (digits, radix) = if body.len() > 1 && (body[1] | 0x20) == b'x' {
            (&body[2..], 16)
        } else {
            (&body[1..], 10)
        };
        if digits.is_empty() {
            return None;
        }
        let s = std::str::from_utf8(digits).ok()?;
        return char::from_u32(u32::from_str_radix(s, radix).ok()?);
    }
    let name = std::str::from_utf8(body).ok()?;
    ENTITIES.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
}

/// Encode the five characters that change how a browser parses the surrounding markup. Anything
/// else is left as-is: escaping ordinary text to numeric references makes payloads unreadable
/// without making them safer.
pub fn html_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\'' => out.extend_from_slice(b"&#39;"),
            _ => out.push(b),
        }
    }
    out
}

// ---- base64 -----------------------------------------------------------------------------------

/// Decode base64, tolerating absent padding, embedded whitespace and stray characters.
///
/// Tolerant because the input is usually a value lifted out of a header or a cookie, where line
/// wrapping and truncated padding are normal. Returns bytes, not text: a layer above may be gzip.
pub fn base64_decode(input: &[u8], url_alphabet: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in input {
        if c == b'=' {
            break;
        }
        let Some(v) = b64_val(c, url_alphabet) else {
            continue;
        };
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn b64_val(c: u8, url_alphabet: bool) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' if !url_alphabet => Some(62),
        b'/' if !url_alphabet => Some(63),
        b'-' if url_alphabet => Some(62),
        b'_' if url_alphabet => Some(63),
        _ => None,
    }
}

pub fn base64_encode(input: &[u8], url_alphabet: bool, pad: bool) -> Vec<u8> {
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let alpha = if url_alphabet { URL } else { STD };
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = b0 << 16 | b1 << 8 | b2;
        out.push(alpha[(n >> 18 & 63) as usize]);
        out.push(alpha[(n >> 12 & 63) as usize]);
        if chunk.len() > 1 {
            out.push(alpha[(n >> 6 & 63) as usize]);
        } else if pad {
            out.push(b'=');
        }
        if chunk.len() > 2 {
            out.push(alpha[(n & 63) as usize]);
        } else if pad {
            out.push(b'=');
        }
    }
    out
}

// ---- hex --------------------------------------------------------------------------------------

/// Decode ASCII hex, ignoring whitespace and `:` separators (the form `tcpdump` and Wireshark
/// produce). Anything else is an error rather than a silent skip: a stray character in a hex dump
/// means the selection was wrong, and quietly dropping it would produce plausible garbage.
pub fn hex_decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let mut nibbles = Vec::with_capacity(input.len());
    for &c in input {
        if c.is_ascii_whitespace() || c == b':' {
            continue;
        }
        match hex_val(c) {
            Some(v) => nibbles.push(v),
            None => return Err(DecodeError::NotHex(c)),
        }
    }
    if nibbles.len() % 2 != 0 {
        return Err(DecodeError::OddHexDigits(nibbles.len()));
    }
    Ok(nibbles.chunks(2).map(|p| p[0] << 4 | p[1]).collect())
}

pub fn hex_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 2);
    for &b in input {
        out.push(HEX_LOWER[(b >> 4) as usize]);
        out.push(HEX_LOWER[(b & 0x0f) as usize]);
    }
    out
}

// ---- JWT --------------------------------------------------------------------------------------

/// A token split into its parts. The signature stays base64url-encoded: it is a raw MAC or
/// signature, and rendering it as bytes would be noise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwt {
    pub header: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: String,
    pub alg: Option<String>,
}

/// Split and base64url-decode a compact-serialisation JWT.
pub fn jwt(input: &[u8]) -> Result<Jwt, DecodeError> {
    let s = std::str::from_utf8(input)
        .map_err(|_| DecodeError::Malformed("a JWT is ASCII; these bytes are not UTF-8"))?;
    // Tolerate the `Authorization: Bearer <token>` form, which is how the value is usually copied.
    let s = s.trim();
    let s = s.strip_prefix("Bearer ").unwrap_or(s).trim();
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(DecodeError::Malformed(
            "not a compact JWT: expected header.payload.signature",
        ));
    }
    let header = base64_decode(parts[0].as_bytes(), true);
    let payload = base64_decode(parts[1].as_bytes(), true);
    let alg = serde_json::from_slice::<serde_json::Value>(&header)
        .ok()
        .and_then(|v| v.get("alg").and_then(|a| a.as_str().map(str::to_owned)));
    Ok(Jwt {
        header,
        payload,
        signature: parts[2].to_string(),
        alg,
    })
}

/// Render a token as pretty JSON. A segment that is not JSON is shown as a string rather than
/// dropped, because a malformed segment is itself the finding.
fn jwt_decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let t = jwt(input)?;
    let as_json = |b: &[u8]| {
        serde_json::from_slice::<serde_json::Value>(b)
            .unwrap_or_else(|_| serde_json::Value::String(String::from_utf8_lossy(b).into_owned()))
    };
    let v = serde_json::json!({
        "header": as_json(&t.header),
        "payload": as_json(&t.payload),
        "signature": t.signature,
    });
    serde_json::to_vec_pretty(&v)
        .map_err(|_| DecodeError::Malformed("could not render the decoded token"))
}

// ---- smart decode -------------------------------------------------------------------------

/// A best score below this means "not encoded here": emit the byte verbatim and step forward one.
/// The value is Burp's (`Zryp.ZZ`), and the individual codec scores below are calibrated to it.
const MIN_SCORE: u16 = 3;

/// How sure the detector is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// A structural marker the input could not plausibly have carried by accident.
    Definite,
    /// The alphabet fits and the decoded bytes look like text. Only ever produced with
    /// [`SmartOptions::guess_alphabets`] on.
    Likely,
}

/// A stretch of one pass's input and the output it produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// `None` when the bytes passed through untouched.
    pub layer: Option<Layer>,
    pub confidence: Option<Confidence>,
    /// The evidence, in words. Shown to the operator so a wrong guess can be argued with.
    pub why: &'static str,
    /// Region of this pass's input that was consumed.
    pub input: Span,
    /// Region of this pass's output that it produced.
    pub output: Span,
}

impl Run {
    pub fn is_plain(&self) -> bool {
        self.layer.is_none()
    }
}

/// One left-to-right scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pass {
    pub output: Vec<u8>,
    pub runs: Vec<Run>,
}

impl Pass {
    /// True when at least one codec fired.
    pub fn changed(&self) -> bool {
        self.runs.iter().any(|r| !r.is_plain())
    }
}

/// The full decode ladder. `output` is the last pass's output, or the input when nothing fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smart {
    pub passes: Vec<Pass>,
    pub output: Vec<u8>,
}

impl Smart {
    /// Every codec that fired, in the order it fired, across all passes.
    pub fn layers(&self) -> Vec<Layer> {
        self.passes
            .iter()
            .flat_map(|p| p.runs.iter().filter_map(|r| r.layer))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmartOptions {
    /// Cap on the number of passes, bounding a pathological chain.
    pub max_passes: usize,
    /// Let base64 and hex be guessed. Off by default, as in Burp: their alphabets occur constantly
    /// in ordinary text, so guessing them is the main way a decoder mangles data.
    pub guess_alphabets: bool,
}

impl Default for SmartOptions {
    fn default() -> Self {
        Self {
            max_passes: 4,
            guess_alphabets: false,
        }
    }
}

/// Peel layers until a pass recognises nothing.
pub fn smart_decode(input: &[u8], opts: &SmartOptions) -> Smart {
    let mut passes = Vec::new();
    let mut cur = input.to_vec();
    while passes.len() < opts.max_passes {
        let pass = smart_pass(&cur, opts);
        // A pass that recognised nothing, or that produced what it was given, is a fixed point.
        if !pass.changed() || pass.output == cur {
            break;
        }
        cur = pass.output.clone();
        passes.push(pass);
    }
    Smart {
        output: cur,
        passes,
    }
}

/// One left-to-right greedy scan: at each position the highest-scoring codec wins, and a best
/// score below [`MIN_SCORE`] copies one byte through.
///
/// Guessed alphabets are held back until a scan that found nothing structural. Without that,
/// greediness bites: in `c2Vzc2lvbg%3D%3D` the base64 run starts at offset 0 and would be claimed
/// before the percent escapes that terminate it, leaving a mangled `==` tail. Peeling what can be
/// proven first, and only then guessing, keeps each layer whole.
pub fn smart_pass(input: &[u8], opts: &SmartOptions) -> Pass {
    let strict = scan(input, false);
    if strict.changed() || !opts.guess_alphabets {
        return strict;
    }
    scan(input, true)
}

fn scan(input: &[u8], guess_alphabets: bool) -> Pass {
    let opts = &SmartOptions {
        guess_alphabets,
        ..SmartOptions::default()
    };
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut runs: Vec<Run> = Vec::new();
    let mut i = 0;

    while i < input.len() {
        match best_hit(input, i, opts) {
            Some(hit) => {
                let run = Run {
                    layer: Some(hit.layer),
                    confidence: Some(hit.confidence),
                    why: hit.why,
                    input: Span::new(i, hit.consumed),
                    output: Span::new(out.len(), hit.decoded.len()),
                };
                out.extend_from_slice(&hit.decoded);
                i += hit.consumed;
                // Merge with the previous run when the same codec fired again next door, so
                // `%41%42%43` reads as one region rather than three.
                match runs.last_mut() {
                    Some(prev)
                        if prev.layer == run.layer && prev.input.end() == run.input.offset =>
                    {
                        prev.input.len += run.input.len;
                        prev.output.len += run.output.len;
                    }
                    _ => runs.push(run),
                }
            }
            None => {
                out.push(input[i]);
                match runs.last_mut() {
                    Some(prev) if prev.is_plain() => {
                        prev.input.len += 1;
                        prev.output.len += 1;
                    }
                    _ => runs.push(Run {
                        layer: None,
                        confidence: None,
                        why: "no codec scored above the threshold; passed through",
                        input: Span::new(i, 1),
                        output: Span::new(out.len() - 1, 1),
                    }),
                }
                i += 1;
            }
        }
    }

    Pass { output: out, runs }
}

struct Hit {
    layer: Layer,
    score: u16,
    consumed: usize,
    decoded: Vec<u8>,
    confidence: Confidence,
    why: &'static str,
}

/// A codec probe: given the buffer and a position, score whether its encoding starts there.
type Probe = fn(&[u8], usize, &SmartOptions) -> Option<Hit>;

/// Ask every codec to score this position; the highest wins, earliest listed breaking a tie.
fn best_hit(b: &[u8], i: usize, opts: &SmartOptions) -> Option<Hit> {
    let mut best: Option<Hit> = None;
    let probes: [Probe; 7] = [
        probe_gzip,
        probe_zlib,
        probe_jwt,
        probe_url,
        probe_html,
        probe_hex,
        probe_base64,
    ];
    for p in probes {
        if let Some(hit) = p(b, i, opts)
            && hit.score >= MIN_SCORE
            && best.as_ref().is_none_or(|cur| hit.score > cur.score)
        {
            best = Some(hit);
        }
    }
    best
}

/// `Zsj1.ZC`: score 4 for the gzip magic plus the deflate compression-method byte.
fn probe_gzip(b: &[u8], i: usize, _o: &SmartOptions) -> Option<Hit> {
    if b.len() - i <= 3 || b[i] != 0x1f || b[i + 1] != 0x8b || b[i + 2] != 0x08 {
        return None;
    }
    // Burp's inflater reports how many bytes the stream used; flate2's reader does not, and a
    // gzip member followed by unrelated bytes does not occur in practice, so take the remainder.
    let decoded = decode(Layer::Gzip, &b[i..]).ok()?;
    Some(Hit {
        layer: Layer::Gzip,
        score: 4,
        consumed: b.len() - i,
        decoded,
        confidence: Confidence::Definite,
        why: "gzip magic 1f 8b with the deflate compression method",
    })
}

/// Not a Burp codec. Scored alongside gzip because the evidence is the same kind: a header whose
/// two bytes are a multiple of 31 is a 1-in-31 accident on top of a fixed compression-method nibble.
fn probe_zlib(b: &[u8], i: usize, _o: &SmartOptions) -> Option<Hit> {
    let s = &b[i..];
    if s.len() < 2 || s[0] & 0x0f != 8 || s[0] >> 4 > 7 || (u16::from(s[0]) * 256 + u16::from(s[1])) % 31 != 0
    {
        return None;
    }
    let decoded = decode(Layer::Deflate, s).ok().filter(|d| !d.is_empty())?;
    Some(Hit {
        layer: Layer::Deflate,
        score: 4,
        consumed: s.len(),
        decoded,
        confidence: Confidence::Definite,
        why: "zlib header: deflate method, and the two header bytes are a multiple of 31",
    })
}

/// Not a Burp decoder codec. Structural: three base64url segments whose first is JSON with `alg`.
fn probe_jwt(b: &[u8], i: usize, _o: &SmartOptions) -> Option<Hit> {
    // Only at a token boundary, so we do not start mid-word.
    if i > 0 && (is_jwt_char(b[i - 1]) || b[i - 1] == b'.') {
        return None;
    }
    let end = i + b[i..].iter().take_while(|&&c| is_jwt_char(c)).count();
    let tok = &b[i..end];
    let t = jwt(tok).ok()?;
    t.alg.as_ref()?;
    let decoded = jwt_decode(tok).ok()?;
    Some(Hit {
        layer: Layer::Jwt,
        score: 5,
        consumed: end - i,
        decoded,
        confidence: Confidence::Definite,
        why: "three dot-separated base64url segments whose first is JSON carrying \"alg\"",
    })
}

fn is_jwt_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.')
}

/// `Zekp`: score 5 for `%` plus two hex digits. A leading `+` scores 5 only when a real percent
/// escape appears later in the buffer, otherwise 2 — below the threshold, so it stays a `+`.
fn probe_url(b: &[u8], i: usize, _o: &SmartOptions) -> Option<Hit> {
    let plus_is_space = b[i] == b'+' && (i..b.len()).any(|j| is_percent_escape(b, j));
    if !is_percent_escape(b, i) && !plus_is_space {
        return None;
    }
    // Consume the whole adjacent run so `%41%42` is one region rather than two.
    let mut end = i;
    let mut decoded = Vec::new();
    while end < b.len() {
        if is_percent_escape(b, end) {
            decoded.push(hex_val(b[end + 1]).unwrap() << 4 | hex_val(b[end + 2]).unwrap());
            end += 3;
        } else if b[end] == b'+' && plus_is_space {
            decoded.push(b' ');
            end += 1;
        } else {
            break;
        }
    }
    Some(Hit {
        layer: Layer::Url,
        score: 5,
        consumed: end - i,
        decoded,
        confidence: Confidence::Definite,
        why: "percent escapes: % followed by two hex digits",
    })
}

/// `Zer8`: score 5 for an `&…;` within eight characters that resolves to a real reference.
fn probe_html(b: &[u8], i: usize, _o: &SmartOptions) -> Option<Hit> {
    if b[i] != b'&' {
        return None;
    }
    let mut end = i;
    let mut decoded = Vec::new();
    let mut buf = [0u8; 4];
    while end < b.len() && b[end] == b'&' {
        let Some((c, len)) = entity_at(b, end) else {
            break;
        };
        decoded.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        end += len;
    }
    if end == i {
        return None;
    }
    Some(Hit {
        layer: Layer::Html,
        score: 5,
        consumed: end - i,
        decoded,
        confidence: Confidence::Definite,
        why: "an HTML character reference that resolves to a real character",
    })
}

/// `Zey7.ZC` returns 0 — Burp never guesses hex. Behind an opt-in here, scored exactly at the
/// threshold so any structural marker wins, and gated on the output looking like text.
fn probe_hex(b: &[u8], i: usize, o: &SmartOptions) -> Option<Hit> {
    if !o.guess_alphabets || (i > 0 && b[i - 1].is_ascii_hexdigit()) {
        return None;
    }
    let n = b[i..].iter().take_while(|c| c.is_ascii_hexdigit()).count();
    if n < 8 || n % 2 != 0 {
        return None;
    }
    let decoded = hex_decode(&b[i..i + n]).ok().filter(|d| plausible(d))?;
    Some(Hit {
        layer: Layer::Hex,
        score: MIN_SCORE,
        consumed: n,
        decoded,
        confidence: Confidence::Likely,
        why: "an even run of hex digits decoding to printable text (guessing was requested)",
    })
}

/// `Zwyl.ZC` returns 0 — Burp never guesses base64. Same opt-in and same gate as hex; hex is
/// probed first so an all-hex run gets the more specific reading.
fn probe_base64(b: &[u8], i: usize, o: &SmartOptions) -> Option<Hit> {
    if !o.guess_alphabets {
        return None;
    }
    for url in [false, true] {
        if i > 0 && (b64_val(b[i - 1], url).is_some() || b[i - 1] == b'=') {
            continue;
        }
        let n = b[i..].iter().take_while(|&&c| b64_val(c, url).is_some()).count();
        let pad = b[i + n..].iter().take_while(|&&c| c == b'=').count().min(2);
        // The floor is on the *encoded* length, padding included: `SGVsbG8=` is a legitimate
        // eight-character token, while a five-letter word is not worth guessing at.
        if n + pad < 8 || n % 4 == 1 || (pad > 0 && (n + pad) % 4 != 0) {
            continue;
        }
        let run = &b[i..i + n];
        // Only claim the URL-safe alphabet when the input distinguishes itself; otherwise the
        // standard reading already covers it.
        if url && !run.iter().any(|&c| c == b'-' || c == b'_') {
            continue;
        }
        let decoded = base64_decode(run, url);
        if !plausible(&decoded) {
            continue;
        }
        return Some(Hit {
            layer: if url { Layer::Base64Url } else { Layer::Base64 },
            score: MIN_SCORE,
            consumed: n + pad,
            decoded,
            confidence: Confidence::Likely,
            why: "a base64 run of valid length decoding to printable text (guessing was requested)",
        });
    }
    None
}

/// Valid UTF-8 and at least 90% non-control characters.
///
/// The threshold is a slack allowance, not a guess: real payloads carry the occasional control
/// byte, while a wrong decoding is overwhelmingly control bytes or not UTF-8 at all. The two
/// populations are not close together.
fn plausible(b: &[u8]) -> bool {
    if b.is_empty() {
        return false;
    }
    let Ok(s) = std::str::from_utf8(b) else {
        return false;
    };
    let total = s.chars().count();
    let ok = s
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\t' | '\r' | '\n'))
        .count();
    ok * 10 >= total * 9
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: Vec<u8>) -> String {
        String::from_utf8_lossy(&v).into_owned()
    }

    fn guessing() -> SmartOptions {
        SmartOptions {
            guess_alphabets: true,
            ..SmartOptions::default()
        }
    }

    #[test]
    fn url_decode_leaves_plus_alone_so_base64_in_a_query_survives() {
        // The context-free primitive never touches `+`; the smart scanner decides by context.
        assert_eq!(s(url_decode(b"a%2Bb+c")), "a+b+c");
        assert_eq!(s(url_decode(b"%2f%41%7A")), "/Az");
    }

    #[test]
    fn a_lone_percent_is_left_verbatim_rather_than_swallowed() {
        assert_eq!(s(url_decode(b"100% sure %zz %4")), "100% sure %zz %4");
    }

    #[test]
    fn url_encode_escapes_the_characters_that_break_out_of_a_parameter() {
        assert_eq!(s(url_encode(b"a&b=c/d e")), "a%26b%3Dc%2Fd%20e");
        assert_eq!(s(url_encode(b"safe-_.~09Az")), "safe-_.~09Az");
    }

    #[test]
    fn html_decode_handles_named_decimal_and_hex_references() {
        assert_eq!(
            s(html_decode(b"&lt;script&gt;alert&#40;&#x31;&#41;&lt;/script&gt;")),
            "<script>alert(1)</script>"
        );
    }

    #[test]
    fn an_unknown_entity_is_preserved_not_dropped() {
        // Losing `&unicorn;` would hide what a filter did with it.
        assert_eq!(s(html_decode(b"a &unicorn; b &amp; c")), "a &unicorn; b & c");
    }

    #[test]
    fn base64_round_trips_and_tolerates_missing_padding_and_whitespace() {
        assert_eq!(s(base64_encode(b"Hello, world", false, true)), "SGVsbG8sIHdvcmxk");
        assert_eq!(s(base64_encode(b"ab", false, true)), "YWI=");
        assert_eq!(s(base64_decode(b"SGVs bG8", false)), "Hello");
        assert_eq!(s(base64_decode(b"YWI=", false)), "ab");
    }

    #[test]
    fn base64url_uses_the_url_safe_alphabet_without_padding() {
        let raw = [0xfb_u8, 0xff, 0xbe];
        let enc = base64_encode(&raw, true, false);
        assert_eq!(s(enc.clone()), "-_--");
        assert_eq!(base64_decode(&enc, true), raw.to_vec());
    }

    #[test]
    fn hex_ignores_separators_but_refuses_a_stray_character() {
        assert_eq!(s(hex_decode(b"48 65:6c 6c6f").unwrap()), "Hello");
        assert_eq!(hex_decode(b"4865z"), Err(DecodeError::NotHex(b'z')));
        assert_eq!(hex_decode(b"486"), Err(DecodeError::OddHexDigits(3)));
        assert_eq!(s(hex_encode(b"Hi")), "4869");
    }

    #[test]
    fn gzip_and_deflate_round_trip() {
        let body = b"HTTP/1.1 200 OK\r\n\r\n<html>hello</html>".repeat(50);
        for layer in [Layer::Gzip, Layer::Deflate] {
            let enc = encode(layer, &body).unwrap();
            assert!(enc.len() < body.len(), "{layer:?} should compress this");
            assert_eq!(decode(layer, &enc).unwrap(), body, "{layer:?} round trip");
        }
    }

    #[test]
    fn deflate_decodes_a_raw_stream_as_well_as_a_zlib_wrapped_one() {
        // Servers in the wild send both under `Content-Encoding: deflate`.
        let body = b"the quick brown fox jumps over the lazy dog".repeat(10);
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&body).unwrap();
        let raw = e.finish().unwrap();
        assert_eq!(decode(Layer::Deflate, &raw).unwrap(), body);
    }

    #[test]
    fn a_decompression_bomb_is_capped_rather_than_exhausting_memory() {
        let bomb = encode(Layer::Gzip, &vec![0u8; 100 * 1024 * 1024]).unwrap();
        assert!(bomb.len() < 200_000, "the bomb itself is small: {} bytes", bomb.len());
        let out = decode(Layer::Gzip, &bomb).unwrap();
        assert_eq!(out.len() as u64, MAX_INFLATE, "inflation stops at the cap");
    }

    const TOKEN: &[u8] = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiYWRtaW4iOmZhbHNlfQ.c2ln";

    #[test]
    fn jwt_splits_a_token_and_reads_its_algorithm() {
        let t = jwt(TOKEN).unwrap();
        assert_eq!(t.alg.as_deref(), Some("HS256"));
        assert_eq!(s(t.payload), r#"{"sub":"1","admin":false}"#);
        assert_eq!(t.signature, "c2ln");
    }

    #[test]
    fn a_bearer_prefix_is_tolerated_because_that_is_how_tokens_are_copied() {
        let mut with_prefix = b"Bearer ".to_vec();
        with_prefix.extend_from_slice(TOKEN);
        assert_eq!(jwt(&with_prefix).unwrap().alg.as_deref(), Some("HS256"));
    }

    #[test]
    fn encoding_a_jwt_is_refused_rather_than_faked() {
        // Re-encoding needs the signing key. Emitting something token-shaped and unsigned would
        // look like it worked, which is worse than an error.
        assert_eq!(encode(Layer::Jwt, TOKEN), Err(DecodeError::NotReversible(Layer::Jwt)));
    }

    // ---- smart decode ---------------------------------------------------------------------

    #[test]
    fn a_percent_escape_is_decoded_and_the_text_around_it_is_left_exactly_as_it_was() {
        // The per-position scan is the whole point: a whole-input guesser cannot do this.
        let p = smart_pass(b"id=%41%42&note=hello", &SmartOptions::default());
        assert_eq!(s(p.output.clone()), "id=AB&note=hello");
        let decoded: Vec<&Run> = p.runs.iter().filter(|r| !r.is_plain()).collect();
        assert_eq!(decoded.len(), 1, "one region, not two");
        assert_eq!(decoded[0].layer, Some(Layer::Url));
        assert_eq!(decoded[0].input, Span::new(3, 6), "%41%42");
        assert_eq!(decoded[0].output, Span::new(3, 2), "AB");
    }

    #[test]
    fn base64_and_hex_are_not_guessed_by_default() {
        // Zwyl.ZC and Zey7.ZC both return 0: Burp refuses these, and so does this, because their
        // alphabets are indistinguishable from ordinary text.
        for input in [&b"SGVsbG8sIHdvcmxk"[..], b"48656c6c6f2c20776f726c64"] {
            let r = smart_decode(input, &SmartOptions::default());
            assert!(r.passes.is_empty(), "{:?} was decoded", String::from_utf8_lossy(input));
            assert_eq!(r.output, input.to_vec());
        }
    }

    #[test]
    fn base64_is_decoded_when_the_operator_asks_for_guessing_and_is_flagged_as_a_guess() {
        let r = smart_decode(b"SGVsbG8sIHdvcmxk", &guessing());
        assert_eq!(r.layers(), vec![Layer::Base64]);
        assert_eq!(s(r.output), "Hello, world");
        let run = &r.passes[0].runs[0];
        assert_eq!(run.confidence, Some(Confidence::Likely));
        assert!(run.why.contains("guessing was requested"), "{}", run.why);
    }

    #[test]
    fn a_proven_layer_is_peeled_before_a_guessed_one_even_across_offsets() {
        // `%53%47%56%73…` is a percent-escape run that decodes to base64. The percent layer must
        // come off first and whole; only then is the alphabet guessed.
        let r = smart_decode(b"%53%47%56%73%62%47%38%3d", &guessing());
        assert_eq!(r.passes[0].runs[0].layer, Some(Layer::Url));
        assert_eq!(r.layers(), vec![Layer::Url, Layer::Base64]);
        assert_eq!(s(r.output), "Hello");
    }

    #[test]
    fn a_plus_becomes_a_space_only_when_the_value_is_demonstrably_percent_encoded() {
        // Zekp.ZC scores a lone `+` at 2, below the threshold of 3. This is what stops a base64
        // token in a query string from being corrupted.
        let opts = SmartOptions::default();
        assert_eq!(s(smart_pass(b"a+b+c", &opts).output), "a+b+c");
        assert_eq!(s(smart_pass(b"one+two%21", &opts).output), "one two!");
    }

    #[test]
    fn smart_decode_peels_a_two_layer_percent_stack_and_names_every_layer() {
        let l1 = url_encode(b"admin=true");
        let l2 = url_encode(&l1);
        let r = smart_decode(&l2, &SmartOptions::default());
        assert_eq!(r.layers(), vec![Layer::Url, Layer::Url]);
        assert_eq!(s(r.output), "admin=true");
    }

    #[test]
    fn smart_decode_reports_a_gzip_layer_from_its_magic_bytes() {
        let body = b"<html>a response body long enough to be worth compressing</html>".repeat(4);
        let gz = encode(Layer::Gzip, &body).unwrap();
        let r = smart_decode(&gz, &SmartOptions::default());
        assert_eq!(r.passes[0].runs[0].layer, Some(Layer::Gzip));
        assert_eq!(r.passes[0].runs[0].confidence, Some(Confidence::Definite));
        assert_eq!(r.output, body);
    }

    #[test]
    fn smart_decode_recognises_a_jwt_and_does_not_mistake_it_for_base64() {
        let r = smart_decode(TOKEN, &guessing());
        assert_eq!(r.passes[0].runs[0].layer, Some(Layer::Jwt));
        assert!(s(r.output.clone()).contains("\"admin\": false"), "{}", s(r.output));
    }

    #[test]
    fn ambiguous_input_that_decodes_to_garbage_yields_no_layers_even_with_guessing_on() {
        // `deadbeefdeadbeef` is valid hex AND valid base64. Neither decoding is printable, so the
        // honest answer is "these are plain bytes" rather than a mangled guess.
        let r = smart_decode(b"deadbeefdeadbeef", &guessing());
        assert!(r.passes.is_empty(), "guessed {:?}", r.layers());
        assert_eq!(s(r.output), "deadbeefdeadbeef");
    }

    #[test]
    fn plain_english_is_left_alone_even_with_guessing_on() {
        for input in [
            &b"GET /index.html HTTP/1.1"[..],
            b"the quick brown fox",
            b"HelloWorld",
            b"12345678",
            b"Set-Cookie: sessionid=abcdefghijklmnop",
        ] {
            let r = smart_decode(input, &guessing());
            assert!(
                r.passes.is_empty(),
                "{:?} was decoded as {:?}",
                String::from_utf8_lossy(input),
                r.layers()
            );
        }
    }

    #[test]
    fn every_run_carries_spans_into_both_the_pass_input_and_its_output() {
        // This is the recoverability contract: the operator can point at any output byte and see
        // which codec produced it and which input bytes it came from.
        let input = b"x=%3Cscript%3E&y=1";
        let p = smart_pass(input, &SmartOptions::default());
        assert_eq!(s(p.output.clone()), "x=<script>&y=1");
        for r in &p.runs {
            assert!(r.input.end() <= input.len());
            assert!(r.output.end() <= p.output.len());
            if r.is_plain() {
                assert_eq!(
                    &input[r.input.offset..r.input.end()],
                    &p.output[r.output.offset..r.output.end()],
                    "a plain run must be byte-identical on both sides"
                );
            }
        }
        assert_eq!(p.runs.iter().filter(|r| !r.is_plain()).count(), 2);
    }

    #[test]
    fn a_base64_run_is_not_claimed_before_the_percent_escapes_that_terminate_it() {
        // Purely greedy scanning would take the base64 at offset 0, stop at the `%`, and leave a
        // mangled `==` tail. Holding guesses back until a pass finds nothing structural fixes it.
        let l1 = base64_encode(b"session=aaaaaaaa", false, true);
        let l2 = url_encode(&l1);
        assert!(l2.ends_with(b"%3D%3D"), "{}", s(l2.clone()));
        let r = smart_decode(&l2, &guessing());
        assert_eq!(r.layers(), vec![Layer::Url, Layer::Base64]);
        assert_eq!(s(r.output), "session=aaaaaaaa");
    }

    #[test]
    fn every_pass_keeps_its_output_so_a_wrong_guess_is_recoverable() {
        let l1 = base64_encode(b"session=aaaaaaaa", false, true);
        let l2 = url_encode(&l1);
        let r = smart_decode(&l2, &guessing());
        assert_eq!(r.passes.len(), 2);
        // The operator can take the value from before the pass they disagree with.
        assert_eq!(r.passes[0].output, l1);
    }

    #[test]
    fn max_passes_bounds_the_ladder() {
        let mut v = b"admin=true".to_vec();
        for _ in 0..6 {
            v = url_encode(&v);
        }
        let opts = SmartOptions {
            max_passes: 2,
            ..SmartOptions::default()
        };
        assert_eq!(smart_decode(&v, &opts).passes.len(), 2);
    }

    #[test]
    fn layer_names_round_trip_through_the_wire_form() {
        for l in Layer::ALL {
            assert_eq!(Layer::parse(l.as_str()), Some(l));
        }
        assert_eq!(Layer::parse("nonsense"), None);
    }
}
