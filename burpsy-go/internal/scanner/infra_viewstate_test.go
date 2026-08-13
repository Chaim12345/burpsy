package scanner

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// ---------------------------------------------------------------------------
// ParseViewState / signature + base64 handling
// ---------------------------------------------------------------------------

func TestParseViewStateAcceptsStandardBase64WithSignature(t *testing.T) {
	filler := bytes.Repeat([]byte{0x02, 0x03}, 15) // 30 low-diversity bytes
	decoded := append([]byte{0xFF, 0x01}, filler...)
	field := base64.StdEncoding.EncodeToString(decoded)

	vs := ParseViewState(field)

	if !vs.Base64Valid {
		t.Fatal("a validly base64-encoded, signature-prefixed value must decode successfully")
	}
	if vs.ParseError != "" {
		t.Fatalf("a value with the correct LOSFormatter signature must not report a parse error, got %q", vs.ParseError)
	}
	if !bytes.Equal(vs.Decoded, decoded) {
		t.Fatalf("Decoded must be the exact base64-decoded bytes; got %x want %x", vs.Decoded, decoded)
	}
}

func TestParseViewStateAcceptsURLSafeAlphabetAndMissingPadding(t *testing.T) {
	// Signature bytes plus a filler byte (0xFB) chosen so the URL-safe
	// encoding differs from the standard one, proving the URL-safe alphabet
	// path is actually exercised, not just accidentally accepted by std.
	decoded := append([]byte{0xFF, 0x01}, bytes.Repeat([]byte{0xFB, 0x00}, 10)...)
	field := base64.URLEncoding.EncodeToString(decoded)
	// Strip the '=' padding to simulate a captured value that lost it in transit.
	trimmed := field
	for len(trimmed) > 0 && trimmed[len(trimmed)-1] == '=' {
		trimmed = trimmed[:len(trimmed)-1]
	}
	if trimmed == field {
		t.Fatal("test fixture must actually need padding for this case to mean anything")
	}

	vs := ParseViewState(trimmed)

	if !vs.Base64Valid {
		t.Fatal("URL-safe base64 with padding stripped must still decode")
	}
	if !bytes.Equal(vs.Decoded, decoded) {
		t.Fatalf("Decoded must match the original bytes; got %x want %x", vs.Decoded, decoded)
	}
}

func TestParseViewStateInvalidBase64SetsParseError(t *testing.T) {
	vs := ParseViewState("!!!not-valid-base64@@@")

	if vs.Base64Valid {
		t.Fatal("a value containing characters outside both base64 alphabets must not be reported as valid")
	}
	if vs.ParseError == "" {
		t.Fatal("invalid base64 input must set ParseError so a caller knows decoding failed, not silently guessing")
	}
	if len(vs.Decoded) != 0 {
		t.Fatalf("failed decode must not populate Decoded, got %x", vs.Decoded)
	}
}

func TestParseViewStateMissingSignatureSetsParseError(t *testing.T) {
	plaintext := "not a viewstate at all, just some arbitrary text used to exercise the signature check"
	field := base64.StdEncoding.EncodeToString([]byte(plaintext))

	vs := ParseViewState(field)

	if !vs.Base64Valid {
		t.Fatal("the base64 decoding itself succeeded and must be reported as valid")
	}
	if vs.ParseError == "" {
		t.Fatal("a decoded body without the 0xFF 0x01 LOSFormatter signature must set ParseError rather than being treated as a real ViewState")
	}
	if vs.MACPresent {
		t.Fatal("a body that failed the signature check must not also claim a MAC verdict")
	}
}

// ---------------------------------------------------------------------------
// MACEnabled heuristic
// ---------------------------------------------------------------------------

func TestParseViewStateDetectsSHA1LengthMACWhenTailLooksLikeADigest(t *testing.T) {
	filler := bytes.Repeat([]byte{0x05, 0x06}, 5) // 10 low-diversity graph bytes
	digest := []byte{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200}
	decoded := append(append([]byte{0xFF, 0x01}, filler...), digest...)
	field := base64.StdEncoding.EncodeToString(decoded)

	vs := ParseViewState(field)

	if !vs.MACPresent || vs.MACLength != 20 {
		t.Fatalf("a trailing 20 high-diversity bytes must be reported as a SHA1-length MAC, got present=%v length=%d", vs.MACPresent, vs.MACLength)
	}
	if !vs.MACEnabled() {
		t.Fatal("MACEnabled must mirror MACPresent")
	}
}

func TestParseViewStateDetectsSHA256LengthMACOverSHA1WhenBothTailsQualify(t *testing.T) {
	filler := bytes.Repeat([]byte{0x05, 0x06}, 5) // 10 low-diversity graph bytes
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(101 + i) // 32 distinct, high-diversity values
	}
	decoded := append(append([]byte{0xFF, 0x01}, filler...), digest...)
	field := base64.StdEncoding.EncodeToString(decoded)

	vs := ParseViewState(field)

	// The last 20 bytes of a genuine 32-byte digest are themselves just as
	// diverse as a real 20-byte digest would be, so the 32-byte check must run
	// first or this would under-report a SHA256 MAC as a SHA1 one.
	if !vs.MACPresent || vs.MACLength != 32 {
		t.Fatalf("a trailing 32 high-diversity bytes must be reported as a SHA256-length MAC, not misread as a 20-byte one; got present=%v length=%d", vs.MACPresent, vs.MACLength)
	}
}

func TestParseViewStateReportsNoMACWhenTailIsLowDiversitySerializedData(t *testing.T) {
	filler := bytes.Repeat([]byte{0x02, 0x03}, 15) // 30 bytes, only 2 distinct values
	decoded := append([]byte{0xFF, 0x01}, filler...)
	field := base64.StdEncoding.EncodeToString(decoded)

	vs := ParseViewState(field)

	if vs.MACPresent || vs.MACEnabled() {
		t.Fatal("a tail built from only 2 distinct byte values must not look digest-like")
	}
}

// TestViewStateMACEnabledHeuristicFalsePositivesOnHighEntropyGraphTail documents,
// per MACEnabled's own doc comment, that this heuristic can mistake a MAC-less
// ViewState's own high-entropy trailing field (here, a stand-in for something
// like an embedded GUID or random token as the last item in the object graph)
// for an appended HMAC digest. This is an accepted, documented limitation of a
// discriminator that cannot walk the real object graph -- not a bug -- and the
// test exists so a future change to the heuristic has to consciously decide to
// keep, tighten, or accept this trade-off rather than silently drifting.
func TestViewStateMACEnabledHeuristicFalsePositivesOnHighEntropyGraphTail(t *testing.T) {
	tinyRealGraphRemainder := []byte{0x02, 0x03, 0x02, 0x03} // low-diversity: genuinely "graph-like"
	highEntropyLastGraphField := []byte{11, 22, 33, 44, 55, 66, 77, 88, 99, 110, 121, 132, 143, 154, 165, 176, 187, 198, 209, 220}
	decoded := append(append([]byte{0xFF, 0x01}, tinyRealGraphRemainder...), highEntropyLastGraphField...)
	field := base64.StdEncoding.EncodeToString(decoded)

	vs := ParseViewState(field)

	if vs.ParseError != "" {
		t.Fatalf("the fixture is a well-formed signature-prefixed blob and must parse cleanly, got %q", vs.ParseError)
	}
	if !vs.MACEnabled() {
		t.Fatal("this fixture is constructed specifically to trip the documented false-positive case; if this now returns false, MACEnabled's tail-diversity threshold changed and its doc comment must be re-verified against the new behavior")
	}
}

// ---------------------------------------------------------------------------
// IsEncrypted heuristic
// ---------------------------------------------------------------------------

func TestViewStateIsEncryptedRecognizesBlockAlignedOpaquePayload(t *testing.T) {
	decoded := make([]byte, 16) // multiple of the 8-byte block size
	for i := range decoded {
		decoded[i] = byte(1 + i) // 16 distinct values: high diversity throughout
	}
	vs := ViewState{Decoded: decoded, Base64Valid: true}

	if !vs.IsEncrypted() {
		t.Fatal("a block-aligned, high-diversity, signature-less payload must be reported as opaque/encrypted")
	}
}

func TestViewStateIsEncryptedFalseWhenLOSFormatterSignatureSurvived(t *testing.T) {
	tail := make([]byte, 14)
	for i := range tail {
		tail[i] = byte(1 + i)
	}
	decoded := append([]byte{0xFF, 0x01}, tail...) // 16 bytes total, block-aligned, but signed plaintext
	vs := ViewState{Decoded: decoded, Base64Valid: true}

	if vs.IsEncrypted() {
		t.Fatal("a payload whose plaintext LOSFormatter signature is intact must never be reported as opaque ciphertext")
	}
}

func TestViewStateIsEncryptedFalseWhenLengthIsNotBlockAligned(t *testing.T) {
	decoded := make([]byte, 15) // not a multiple of 8
	for i := range decoded {
		decoded[i] = byte(1 + i)
	}
	vs := ViewState{Decoded: decoded, Base64Valid: true}

	if vs.IsEncrypted() {
		t.Fatal("a length that is not a multiple of any common block size must not be reported as encrypted")
	}
}

func TestViewStateIsEncryptedFalseForZeroValue(t *testing.T) {
	var vs ViewState
	if vs.IsEncrypted() {
		t.Fatal("a ViewState with no successfully decoded bytes must never claim to be encrypted")
	}
}

// ---------------------------------------------------------------------------
// DetectSerializedObject: Java
// ---------------------------------------------------------------------------

func TestDetectSerializedObjectRecognizesJavaMagicInRawBytes(t *testing.T) {
	raw := []byte("param=aaaa\xac\xed\x00\x05bbbb&other=1")
	if got := DetectSerializedObject(raw); got != SerializedJava {
		t.Fatalf("raw Java STREAM_MAGIC/STREAM_VERSION bytes must be recognized, got %v", got)
	}
}

func TestDetectSerializedObjectRecognizesJavaMagicBase64Literal(t *testing.T) {
	raw := []byte("state=prefix-rO0ABXNyAAlzb21ldGhpbmc=-suffix")
	if got := DetectSerializedObject(raw); got != SerializedJava {
		t.Fatalf("the fixed 'rO0AB' base64 prefix embedded in a larger value must be recognized, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// DetectSerializedObject: .NET
// ---------------------------------------------------------------------------

func TestDetectSerializedObjectRecognizesDotNetMagicInRawBytes(t *testing.T) {
	raw := []byte("state=xxxx\x00\x01\x00\x00\x00\xff\xff\xff\xffyyyy")
	if got := DetectSerializedObject(raw); got != SerializedDotNet {
		t.Fatalf("raw BinaryFormatter header bytes must be recognized, got %v", got)
	}
}

func TestDetectSerializedObjectRecognizesDotNetMagicBase64Literal(t *testing.T) {
	raw := []byte("token=preAAEAAAD/////postmore")
	if got := DetectSerializedObject(raw); got != SerializedDotNet {
		t.Fatalf("the fixed 'AAEAAAD/////' base64 prefix embedded in a larger value must be recognized, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// DetectSerializedObject: Python pickle
// ---------------------------------------------------------------------------

func TestDetectSerializedObjectRecognizesPickleProtocol2RawOpcodeSequence(t *testing.T) {
	raw := []byte("payload=\x80\x02X-more-data")
	if got := DetectSerializedObject(raw); got != SerializedPython {
		t.Fatalf("PROTO(2) followed by BINUNICODE('X') must be recognized as a pickle, got %v", got)
	}
}

func TestDetectSerializedObjectRecognizesPickleProtocol4RawOpcodeSequence(t *testing.T) {
	raw := []byte("payload=abc\x80\x04\x8cdef") // PROTO(4) + SHORT_BINUNICODE
	if got := DetectSerializedObject(raw); got != SerializedPython {
		t.Fatalf("PROTO(4) followed by SHORT_BINUNICODE must be recognized as a pickle, got %v", got)
	}
}

func TestDetectSerializedObjectRecognizesPickleBase64Literal(t *testing.T) {
	raw := []byte("token=xxxgASVeyJhIjogMX0=yyy")
	if got := DetectSerializedObject(raw); got != SerializedPython {
		t.Fatalf("the common protocol-4 'gASV' (PROTO+version+FRAME) base64 prefix must be recognized, got %v", got)
	}
}

func TestDetectSerializedObjectDoesNotRecognizeProtoWithUndefinedVersionByte(t *testing.T) {
	// 0x80 0x01 is not a real pickle header: PROTO was introduced in protocol
	// 2, so version byte 0x01 never legitimately follows it. This documents
	// that pythonPickleContains is bounded to the versions pickle actually
	// defines, not "any byte after 0x80".
	raw := []byte("payload=\x80\x01X-more-data")
	if got := DetectSerializedObject(raw); got != SerializedNone {
		t.Fatalf("PROTO followed by an undefined version byte must not be misdetected as a pickle, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// DetectSerializedObject: PHP
// ---------------------------------------------------------------------------

func TestDetectSerializedObjectRecognizesPHPSerializedRawText(t *testing.T) {
	raw := []byte(`user_data=O:8:"stdClass":1:{s:4:"name";s:5:"admin";}&other=1`)
	if got := DetectSerializedObject(raw); got != SerializedPHP {
		t.Fatalf("raw PHP serialize() object header text must be recognized, got %v", got)
	}
}

func TestDetectSerializedObjectRecognizesPHPSerializedWhenBase64Encoded(t *testing.T) {
	phpPayload := `O:8:"stdClass":1:{s:4:"name";s:5:"admin";}`
	raw := []byte(base64.StdEncoding.EncodeToString([]byte(phpPayload)))

	got := DetectSerializedObject(raw)
	if got != SerializedPHP {
		t.Fatalf("a whole-value base64-encoded PHP payload must be recognized via the base64-decode fallback pass (PHP has no fixed base64 prefix, unlike Java/.NET/Python), got %v", got)
	}
}

// ---------------------------------------------------------------------------
// DetectSerializedObject: negative cases
// ---------------------------------------------------------------------------

func TestDetectSerializedObjectReturnsNoneForOrdinaryJSON(t *testing.T) {
	raw := []byte(`{"id":42,"name":"widget project","active":true,"tags":["a","b","c"]}`)
	if got := DetectSerializedObject(raw); got != SerializedNone {
		t.Fatalf("ordinary JSON must never be misdetected as a serialized object, got %v", got)
	}
}

func TestDetectSerializedObjectReturnsNoneForOrdinaryHTML(t *testing.T) {
	raw := []byte(`<html><body><h1>Welcome</h1><p>This is a normal page with no serialized payloads at all.</p></body></html>`)
	if got := DetectSerializedObject(raw); got != SerializedNone {
		t.Fatalf("ordinary HTML must never be misdetected as a serialized object, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// SerializedObjectKind.String
// ---------------------------------------------------------------------------

func TestSerializedObjectKindStringNamesEachRecognizedFormat(t *testing.T) {
	cases := map[SerializedObjectKind]string{
		SerializedNone:   "none",
		SerializedJava:   "Java serialized object",
		SerializedDotNet: ".NET BinaryFormatter serialized object",
		SerializedPHP:    "PHP serialized object",
		SerializedPython: "Python pickle",
	}
	for kind, want := range cases {
		if got := kind.String(); got != want {
			t.Fatalf("SerializedObjectKind(%d).String() = %q, want %q", kind, got, want)
		}
	}
}
