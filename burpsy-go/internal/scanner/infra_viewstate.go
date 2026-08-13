package scanner

// ASP.NET ViewState decoding and serialized-object-signature recognition.
//
// Both primitives here are pure byte/string classifiers with no network or
// storage access, mirroring the checks_headers.go shape: a future check
// evaluator calls ParseViewState / DetectSerializedObject and decides what to
// report, while the decision logic itself is independently unit-testable.
//
// Evidence notes (see the project's evidence-source rules):
//   - The __VIEWSTATE form-field name is confirmed Burp evidence: it appears
//     literally in out/clean/root/Ze5g.java (ZA/Zt) and out/clean/root/Zu_t.java,
//     and as a ZKM-restored string literal in
//     out/strings/map_root.tsv (burp.Ze5g / burp.Zw7q / burp.Zu_t rows). Burp's
//     own MAC-enforcement decision (out/clean/root/Zg3y.java, the
//     PPR_VulnerableViewState check) calls into Zbvv.ZC/Zi2s/Zucz after the ZKM
//     scaffolding was stripped, so the actual object-graph walk it performs is
//     not recoverable from the decompiled bytecode; only the surrounding
//     wiring is.
//   - The two-byte LOSFormatter signature (0xFF 0x01) and the HMAC digest
//     lengths (20 bytes for SHA1, 32 for SHA256) are public ASP.NET platform
//     behavior (System.Web.UI.LosFormatter / ObjectStateFormatter), documented
//     in Microsoft's and third-party ViewState research (see the catalog
//     entry's own reference, "Exploiting Deserialisation in ASP.NET via
//     ViewState"). They are not Burp-specific literals, and are used here
//     because the Burp-specific object-graph walk is out of scope.
//   - Burp's serialized-object check class
//     (out/clean/renamed_v4/SerializedObjectInHttpMessageIssue001.java, ast-
//     renamed from Zhcb) holds its signature table in a static String[] field
//     (ZQ) that is populated at runtime from ZKM-stripped ciphertext with no
//     recoverable literal in the decompiled sources. The magic byte sequences
//     below are therefore the public, industry-standard format markers for
//     each serialization scheme (Java Object Serialization Stream, .NET
//     BinaryFormatter, PHP serialize(), Python pickle), not values recovered
//     from Burp.

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// ASP.NET ViewState
// ---------------------------------------------------------------------------

// viewStateSigByte0, viewStateSigByte1 are the two bytes every unencrypted
// __VIEWSTATE value begins with once base64-decoded: the LOSFormatter type
// marker for a Pair (0xFF) followed by the format version (0x01). This is
// public ASP.NET behavior, not a Burp literal (see file header).
const (
	viewStateSigByte0 byte = 0xFF
	viewStateSigByte1 byte = 0x01
)

// sha1DigestLen and sha256DigestLen are the two HMAC digest lengths ASP.NET
// has used to sign ViewState across its history: HMACSHA1 (the long-standing
// default) and HMACSHA256 (the default since .NET 4.5's
// MachineKey/ValidationCompatibilityMode hardening).
const (
	sha1DigestLen   = 20
	sha256DigestLen = 32
)

// minGraphTailBytes is the smallest number of decoded bytes, beyond the
// 2-byte signature, that a real (even trivially small) LOSFormatter object
// graph could plausibly occupy. It exists purely to stop detectMAC from
// treating a short, signature-only blob as "graph + digest" when there is no
// room left for a graph at all.
const minGraphTailBytes = 4

// ViewState is the result of decoding an ASP.NET __VIEWSTATE form-field
// value. Decoded is the raw base64-decoded bytes (empty when decoding
// failed). MACPresent/MACLength report the MAC-enforcement heuristic
// documented on MACEnabled; ParseError is set whenever the value is not a
// recognizable plaintext ViewState blob (invalid base64, or a decoded body
// that does not start with the LOSFormatter signature).
type ViewState struct {
	Decoded     []byte
	MACPresent  bool
	MACLength   int
	Base64Valid bool
	ParseError  string
}

// ParseViewState decodes an ASP.NET __VIEWSTATE field value and classifies it.
// It accepts both the standard ('+', '/') and URL-safe ('-', '_') base64
// alphabets, and tolerates missing '=' padding (a __VIEWSTATE value is often
// captured after URL-decoding has already stripped or mangled padding).
//
// A successfully-decoded body that does not start with the 0xFF 0x01
// LOSFormatter signature is not guessed at further: ParseError records why,
// and MACPresent/MACLength are left at their zero values, because a body with
// no recognizable structure gives no honest basis for a MAC verdict (it may
// be encrypted -- see IsEncrypted -- truncated, or not a ViewState at all).
func ParseViewState(field string) ViewState {
	decoded, err := decodeFlexibleBase64(field)
	if err != nil {
		return ViewState{ParseError: fmt.Sprintf("invalid base64 __VIEWSTATE value: %v", err)}
	}
	v := ViewState{Decoded: decoded, Base64Valid: true}
	if !hasViewStateSignature(decoded) {
		v.ParseError = "decoded value does not begin with the ASP.NET LOSFormatter signature (0xFF 0x01); not a recognizable plaintext ViewState (it may be encrypted, truncated, or not a ViewState at all)"
		return v
	}
	v.MACLength, v.MACPresent = detectMAC(decoded)
	return v
}

// MACEnabled reports whether this ViewState appears to carry a trailing HMAC
// digest appended by ASP.NET's MAC enforcement (Page.EnableViewStateMac).
//
// Faithfully answering this question means parsing the ObjectStateFormatter
// binary graph -- walking every Pair/Triplet/type token in the LOSFormatter
// format -- to find exactly where the serialized object graph ends and where
// any appended digest would begin. That parser is out of scope here (see
// ParseViewState's doc comment on why it isn't attempted), so this method
// instead applies the same length + tail-byte-distribution discriminator
// used by third-party ViewState tooling that also lacks the validation key:
// an HMAC digest is, without the key, indistinguishable from uniform random
// bytes, while the ObjectStateFormatter's own trailing bytes are built from a
// small alphabet of repeated type-token values and are far less diverse.
// detectMAC therefore strips the last 20 or 32 bytes and checks whether they
// look digest-like (high byte-value diversity) while still leaving room for a
// real object graph in front of them.
//
// This is a HEURISTIC, not a proof, and callers MUST NOT treat a false
// result as certainty that no MAC is enforced:
//   - A MAC-enabled ViewState whose object graph happens to be tiny, so that
//     the "digest-like" trailing bytes actually ARE the graph (e.g. a single
//     short encoded string with high byte diversity), can be misread as
//     MAC-less: false negative.
//   - A MAC-less ViewState whose object graph happens to end in high-entropy
//     bytes (an embedded GUID, random token, or compressed blob as the last
//     field) can be misread as MAC-enabled: false positive.
//   - It cannot say which digest algorithm produced a detected MAC beyond
//     "20 bytes" vs "32 bytes" -- both lengths have non-HMAC explanations.
//
// A caller should report this as "MAC not detected by heuristic" rather than
// "MAC is absent".
func (v ViewState) MACEnabled() bool {
	return v.MACPresent
}

// IsEncrypted reports whether this ViewState looks opaque because
// ViewStateEncryptionMode encrypted it, rather than because it merely lacks
// a MAC. ASP.NET encrypts the already-serialized-and-signed bytes with a
// block cipher (historically (3)DES, AES by default since .NET 4.5), so an
// encrypted ViewState's decoded bytes: (a) never start with the plaintext
// LOSFormatter signature, because that signature is itself inside the
// ciphertext; (b) have a length that is a multiple of the cipher's block
// size, because block-cipher output (even with padding removed by the mode)
// lands on a block boundary; and (c) look close to uniformly random
// throughout, since ciphertext retains none of the plaintext's serialization
// structure.
//
// Like MACEnabled, this is a heuristic, not a proof: a MAC-only, unencrypted
// ViewState whose total length coincidentally lands on an 8-byte boundary and
// whose object graph coincidentally has high byte diversity can trip this
// positively, and a genuinely encrypted-but-truncated blob could fail the
// block-alignment check and be missed. A caller MUST treat a true result as
// "opaque, could not be classified further" rather than forensic proof of
// ViewStateEncryptionMode.
func (v ViewState) IsEncrypted() bool {
	if !v.Base64Valid || len(v.Decoded) == 0 {
		return false
	}
	if hasViewStateSignature(v.Decoded) {
		return false // the plaintext signature survived; this is not opaque ciphertext
	}
	const blockSize = 8 // smallest common block size (DES/3DES); AES (16) is also a multiple of 8
	if len(v.Decoded)%blockSize != 0 {
		return false
	}
	return digestLikeTail(v.Decoded)
}

// hasViewStateSignature reports whether b begins with the two-byte
// LOSFormatter marker every unencrypted __VIEWSTATE value starts with.
func hasViewStateSignature(b []byte) bool {
	return len(b) >= 2 && b[0] == viewStateSigByte0 && b[1] == viewStateSigByte1
}

// detectMAC applies the MACEnabled heuristic documented above: it tries the
// SHA256 digest length before SHA1 (the newer default is checked first
// because a SHA256 digest's trailing 20 bytes are themselves indistinguishable
// from a SHA1 digest, so checking the longer, more specific length first
// avoids under-reporting a SHA256 MAC as a SHA1 one).
func detectMAC(decoded []byte) (length int, present bool) {
	const sigLen = 2
	for _, n := range []int{sha256DigestLen, sha1DigestLen} {
		if len(decoded) < sigLen+minGraphTailBytes+n {
			continue
		}
		if digestLikeTail(decoded[len(decoded)-n:]) {
			return n, true
		}
	}
	return 0, false
}

// digestLikeTail reports whether b's byte values are diverse enough to be
// mistaken for a cryptographic digest rather than structured serialized data.
// A genuine HMAC digest draws each byte near-uniformly from 0-255; across
// 20-32 draws, birthday-bound math puts the expected number of distinct
// values close to len(b) itself (collisions are rare at this sample size).
// Serialized data (repeated small type-token values, ASCII text) clusters on
// far fewer distinct byte values. The 70% threshold is deliberately loose in
// the digest's favor: it is a discriminator, not a statistical test, and the
// doc comments on MACEnabled/IsEncrypted spell out exactly which cases it
// cannot separate.
func digestLikeTail(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	seen := make(map[byte]struct{}, len(b))
	for _, c := range b {
		seen[c] = struct{}{}
	}
	return len(seen)*10 >= len(b)*7
}

// decodeFlexibleBase64 decodes s, trying the standard and URL-safe base64
// alphabets and re-padding s to a multiple of 4 characters first, since a
// captured __VIEWSTATE value frequently arrives with '=' padding stripped or
// mangled by whatever transport or logging layer produced it.
func decodeFlexibleBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty value")
	}
	padded := s
	if m := len(padded) % 4; m != 0 {
		padded += strings.Repeat("=", 4-m)
	}
	var lastErr error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		b, err := enc.DecodeString(padded)
		if err == nil {
			return b, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// ---------------------------------------------------------------------------
// Serialized-object signature recognition
// ---------------------------------------------------------------------------

// SerializedObjectKind identifies which language/platform's native
// serialization format a blob's magic bytes match.
type SerializedObjectKind int

// SerializedNone through SerializedPython enumerate the recognizable
// serialization formats. SerializedNone (the zero value) means no recognized
// magic sequence was found.
const (
	SerializedNone SerializedObjectKind = iota
	SerializedJava
	SerializedDotNet
	SerializedPHP
	SerializedPython
)

// String renders k for findings/log text.
func (k SerializedObjectKind) String() string {
	switch k {
	case SerializedJava:
		return "Java serialized object"
	case SerializedDotNet:
		return ".NET BinaryFormatter serialized object"
	case SerializedPHP:
		return "PHP serialized object"
	case SerializedPython:
		return "Python pickle"
	default:
		return "none"
	}
}

// javaMagic is java.io.ObjectStreamConstants.STREAM_MAGIC (0xACED) followed by
// STREAM_VERSION (0x0005): the fixed 4-byte header of every Java Object
// Serialization Stream. Public JDK-documented format, not a Burp literal.
var javaMagic = []byte{0xAC, 0xED, 0x00, 0x05}

// javaMagicB64 is the base64 text produced by encoding javaMagic at a
// base64 block boundary; since STREAM_MAGIC/STREAM_VERSION are fixed for
// every Java serialization stream, every base64-embedded Java blob begins
// with this text verbatim.
const javaMagicB64 = "rO0AB"

// dotNetMagic is the fixed 9-byte header
// System.Runtime.Serialization.Formatters.Binary.BinaryFormatter writes
// before any object graph: a SerializationHeaderRecord
// (RecordTypeEnum.SerializedStreamHeader = 0x00) with root/header IDs of 1
// and -1. Public .NET-documented format, not a Burp literal.
var dotNetMagic = []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}

// dotNetMagicB64 is dotNetMagic's base64 encoding, embedded verbatim in a
// base64-carried BinaryFormatter blob.
const dotNetMagicB64 = "AAEAAAD/////"

// phpSerializedPattern matches PHP's serialize() object-header syntax,
// O:<length>:"<class name>" -- documented PHP language behavior, not a Burp
// literal. Unlike the Java/.NET/Python magics this has no fixed base64
// prefix (the class-name-length digit count varies), so DetectSerializedObject
// checks it against both the raw text and any base64-decoded candidate.
var phpSerializedPattern = regexp.MustCompile(`O:[0-9]+:"`)

// picklePlausibleOpcodes is the complete set of single-byte opcodes defined
// by CPython's pickle module across protocols 0-5 (see Lib/pickle.py's
// opcode constants and https://docs.python.org/3/library/pickle.html).
// This is public Python-language documentation, not evidence recovered from
// Burp: Burp's own serialized-object signature table
// (out/clean/renamed_v4/SerializedObjectInHttpMessageIssue001.java's static
// ZQ field) decodes to ZKM-stripped ciphertext with nothing recoverable, so
// the public protocol spec is the honest fallback (see file header).
var picklePlausibleOpcodes = map[byte]struct{}{
	'(': {}, ')': {}, '.': {}, '0': {}, '1': {}, '2': {},
	'B': {}, 'C': {}, 'F': {}, 'G': {}, 'I': {}, 'J': {}, 'K': {}, 'L': {}, 'M': {}, 'N': {},
	'P': {}, 'Q': {}, 'R': {}, 'S': {}, 'T': {}, 'U': {}, 'V': {}, 'X': {},
	']': {}, 'a': {}, 'b': {}, 'c': {}, 'd': {}, 'e': {}, 'g': {}, 'h': {}, 'i': {}, 'j': {},
	'l': {}, 'o': {}, 'p': {}, 'q': {}, 'r': {}, 's': {}, 't': {}, 'u': {}, '}': {},
	0x81: {}, 0x82: {}, 0x83: {}, 0x84: {}, 0x85: {}, 0x86: {}, 0x87: {}, 0x88: {}, 0x89: {},
	0x8a: {}, 0x8b: {}, 0x8c: {}, 0x8d: {}, 0x8e: {}, 0x8f: {},
	0x90: {}, 0x91: {}, 0x92: {}, 0x93: {}, 0x94: {}, 0x95: {}, 0x96: {}, 0x97: {}, 0x98: {},
}

// pythonMagicB64 is the base64 text for the PROTO(0x80) + protocol-4 version
// byte + FRAME(0x95) opcode sequence CPython's pickler emits by default on
// every modern (3.8+) interpreter: pickle.dumps' default protocol has been 4
// since Python 3.8, and protocol >=4 streams open with a FRAME opcode
// immediately after the header. It is the single most common real-world
// pickle prefix, so it is checked as a literal in addition to the general
// byte-level scan pythonPickleContains performs for protocols 2-4.
const pythonMagicB64 = "gASV"

// DetectSerializedObject scans raw for the magic byte sequence of a known
// native serialization format. It checks raw's own bytes first, then --
// because these blobs travel base64-encoded in request/response parameters
// far more often than as raw bytes -- attempts to base64-decode raw as a
// whole and scans the decoded candidate too. This second pass is what lets
// PHP's serialize() format (which has no fixed-length base64 prefix, unlike
// the other three) be recognized when it arrives base64-encoded.
func DetectSerializedObject(raw []byte) SerializedObjectKind {
	if k := detectSerializedIn(raw); k != SerializedNone {
		return k
	}
	if decoded, err := decodeFlexibleBase64(string(raw)); err == nil {
		if k := detectSerializedIn(decoded); k != SerializedNone {
			return k
		}
	}
	return SerializedNone
}

// detectSerializedIn scans a single byte slice (never a base64 candidate
// derived from it -- that recursion lives in DetectSerializedObject) for
// every recognized magic sequence. Magic bytes/text are matched anywhere in
// b, not only at offset 0, since a blob is frequently embedded inside a
// larger parameter value or message body rather than occupying it exactly.
func detectSerializedIn(b []byte) SerializedObjectKind {
	switch {
	case bytes.Contains(b, javaMagic), bytes.Contains(b, []byte(javaMagicB64)):
		return SerializedJava
	case bytes.Contains(b, dotNetMagic), bytes.Contains(b, []byte(dotNetMagicB64)):
		return SerializedDotNet
	case pythonPickleContains(b), bytes.Contains(b, []byte(pythonMagicB64)):
		return SerializedPython
	case phpSerializedPattern.Match(b):
		return SerializedPHP
	default:
		return SerializedNone
	}
}

// pythonPickleContains reports whether b contains a pickle PROTO header
// (0x80) followed by a protocol version byte pickle actually defines (2, 3,
// or 4 -- protocols 0/1 have no PROTO opcode and protocol 5 added only
// out-of-band buffer opcodes, not a new version byte) and then a byte that is
// itself a valid pickle opcode, anywhere in b.
func pythonPickleContains(b []byte) bool {
	bound := len(b) - 2
	for i := range bound {
		if b[i] != 0x80 {
			continue
		}
		if b[i+1] != 0x02 && b[i+1] != 0x03 && b[i+1] != 0x04 {
			continue
		}
		if _, ok := picklePlausibleOpcodes[b[i+2]]; ok {
			return true
		}
	}
	return false
}
