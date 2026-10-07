package netauth

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// The NTLMv2 implementation is pinned against MS-NLMP's own published known-answer
// vectors rather than against itself.
//
// # Why this matters more than usual here
//
// There is no domain controller in this environment and there will not be one in CI. An
// NTLMv2 implementation that is only checked for self-consistency — encode a message,
// decode it, assert it round-trips — passes every such test while computing a response no
// Windows server will ever accept, because the mistakes that actually happen (upper-casing
// the domain as well as the user, emitting twelve trailing zero bytes in `temp` instead of
// eight, hashing the request in the wrong order) are all self-consistent.
//
// The section 4.2.4 vectors close that gap: they fix every input, including the two a live
// run would draw from the clock and crypto/rand, so the expected output is a constant
// Microsoft published. Matching it is evidence about the wire, not about this package.
//
// # Provenance of each constant below
//
// Values marked [SPEC] were read from learn.microsoft.com's rendering of MS-NLMP during
// this work and are quoted from it:
//   - NTOWFv2                  §4.2.4.1.1
//   - temp                     §4.2.4.1.3
//   - NTProofStr               §4.2.4.2.2 (the first 16 bytes of the NTLMv2 Response)
//   - the ComputeResponse and NTOWFv2 pseudocode  §3.3.2
//
// Values marked [DERIVED] were computed here from [SPEC] inputs through the [SPEC]
// algorithm. They are not independent evidence — they are the algorithm's output on a
// fixed input — and they are written down so that a later change to this file which alters
// them is caught rather than absorbed. They are labelled rather than presented as spec
// text, because claiming a number came from the spec when it did not is exactly the kind
// of quiet inaccuracy this codebase treats as a defect.

// MS-NLMP §4.2.1 "Common Values", the inputs every §4.2.4 vector is computed from. [SPEC]
const (
	vectorUser     = "User"
	vectorDomain   = "Domain"
	vectorPassword = "Password"
	vectorServer   = "Server"
)

// vectorServerChallenge is CHALLENGE_MESSAGE.ServerChallenge, §4.2.1. [SPEC]
var vectorServerChallenge = [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

// vectorClientChallenge is ClientChallenge, §4.2.1. [SPEC]
var vectorClientChallenge = [8]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}

// vectorTime is Time, §4.2.1: all zeroes. [SPEC]
var vectorTime = [8]byte{}

// vectorTargetInfo is the ServerName AV_PAIR list the §4.2.4.1.3 `temp` dump contains:
// MsvAvNbDomainName "Domain", MsvAvNbComputerName "Server", MsvAvEOL. Built from the
// pair encoding rather than pasted as hex so that a bug in appendAVPair cannot hide by
// being absent from the fixture — the assembled bytes are then checked against the
// spec's dump inside TestNTLMv2TempMatchesTheSpecByteForByte.
func vectorTargetInfo() []byte {
	out := appendAVPair(nil, avIDNbDomain, utf16le(vectorDomain))
	out = appendAVPair(out, 0x0001 /* MsvAvNbComputerName */, utf16le(vectorServer))
	return appendAVPair(out, avIDEOL, nil)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "\n", ""))
	if err != nil {
		t.Fatalf("the test fixture itself is not valid hex, so the vector it encodes cannot be trusted: %v", err)
	}
	return b
}

func TestNTOWFv2MatchesTheKeyMicrosoftPublishedForUserDomainPassword(t *testing.T) {
	// [SPEC] MS-NLMP §4.2.4.1.1.
	want := mustHex(t, "0c868a403bfd7a93a3001ef22ef02e3f")

	got := ntowfv2(vectorUser, vectorDomain, vectorPassword)

	if !bytes.Equal(got, want) {
		t.Fatalf("NTOWFv2 does not match MS-NLMP §4.2.4.1.1.\n"+
			"  got  %x\n  want %x\n"+
			"Every NTLMv2 response and the session key are HMAC'd under this value, so a mismatch here means "+
			"this build cannot authenticate to any NTLM server at all — not that one server is fussy.",
			got, want)
	}
}

func TestNTOWFv2UppercasesTheUserButLeavesTheDomainAlone(t *testing.T) {
	// MS-NLMP §3.3.2 defines NTOWFv2 as HMAC_MD5(MD4(UNICODE(Passwd)),
	// UNICODE(ConcatenationOf(Uppercase(User), UserDom))) — Uppercase wraps User only.
	//
	// This is the mistake that costs a day: an implementation that upper-cases both, or
	// neither, is internally consistent and fails only against a real server. Pinning it
	// as its own claim means the failure names the cause instead of just "response
	// rejected".
	spec := ntowfv2(vectorUser, vectorDomain, vectorPassword)

	if lowerUser := ntowfv2(strings.ToLower(vectorUser), vectorDomain, vectorPassword); !bytes.Equal(spec, lowerUser) {
		t.Errorf("NTOWFv2(%q) and NTOWFv2(%q) differ, so the user name is not being upper-cased; "+
			"MS-NLMP §3.3.2 wraps User in Uppercase() and a server will compute the other value",
			vectorUser, strings.ToLower(vectorUser))
	}
	if upperDomain := ntowfv2(vectorUser, strings.ToUpper(vectorDomain), vectorPassword); bytes.Equal(spec, upperDomain) {
		t.Errorf("NTOWFv2 gives the same key for domain %q and %q, so the domain is being case-folded; "+
			"MS-NLMP §3.3.2 does not wrap UserDom in Uppercase() and a server that was told a mixed-case "+
			"domain will compute a different key",
			vectorDomain, strings.ToUpper(vectorDomain))
	}
}

func TestNTLMv2TempMatchesTheSpecByteForByte(t *testing.T) {
	// [SPEC] MS-NLMP §4.2.4.1.3, transcribed from the hex dump on that page:
	//
	//     01 01 00 00 00 00 00 00 00 00 00 00
	//     00 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 00
	//     02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00
	//     01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00
	//     00 00 00 00 00 00 00 00
	//
	// The last eight bytes are MsvAvEOL (four) followed by the algorithm's trailing Z(4)
	// — not twelve zeroes, and not four. Emitting the wrong count changes NTProofStr and
	// is invisible without this fixture.
	want := mustHex(t, ""+
		"0101000000000000"+
		"0000000000000000"+
		"aaaaaaaaaaaaaaaa"+
		"00000000"+
		"02000c0044006f006d00610069006e00"+
		"01000c00530065007200760065007200"+
		"00000000"+
		"00000000")

	got := ntlmv2Temp(vectorTime, vectorClientChallenge, vectorTargetInfo())

	if !bytes.Equal(got, want) {
		t.Fatalf("the NTLMv2 `temp` blob does not match MS-NLMP §4.2.4.1.3.\n"+
			"  got  %x\n  want %x\n"+
			"temp is hashed into NTProofStr, so any difference here — a wrong Z() run length, a "+
			"re-encoded AV_PAIR list, a missing EOL — makes every response this build sends unverifiable "+
			"by the server, with no error that says so.", got, want)
	}
}

func TestNTLMv2ResponseStartsWithTheNTProofStrMicrosoftPublished(t *testing.T) {
	// [SPEC] MS-NLMP §4.2.4.2.2: the NTLMv2 Response begins with the 16-byte NTProofStr
	// 68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c, and continues with `temp`.
	wantProof := mustHex(t, "68cd0ab851e51c96aabc927bebef6a1c")

	key := ntowfv2(vectorUser, vectorDomain, vectorPassword)
	response, _ := ntlmv2Response(key, vectorServerChallenge, vectorClientChallenge, vectorTime, vectorTargetInfo())

	if len(response) < 16 {
		t.Fatalf("the NTLMv2 response is %d bytes; it cannot even contain the 16-byte NTProofStr it must start with", len(response))
	}
	if !bytes.Equal(response[:16], wantProof) {
		t.Fatalf("NTProofStr does not match MS-NLMP §4.2.4.2.2.\n"+
			"  got  %x\n  want %x\n"+
			"NTProofStr is the entire proof of knowledge of the password. A server recomputes exactly "+
			"this value and compares; a mismatch is a 401 the operator will read as a wrong password.",
			response[:16], wantProof)
	}

	wantTemp := ntlmv2Temp(vectorTime, vectorClientChallenge, vectorTargetInfo())
	if !bytes.Equal(response[16:], wantTemp) {
		t.Fatalf("the NTLMv2 response does not carry `temp` after NTProofStr.\n  got  %x\n  want %x\n"+
			"The server needs the blob back verbatim to recompute the proof; sending a different one "+
			"makes a correct proof look wrong.", response[16:], wantTemp)
	}
}

func TestSessionBaseKeyAndLMv2ResponseStayFixedForTheSpecInputs(t *testing.T) {
	// [DERIVED] — computed here from the [SPEC] inputs through the [SPEC] §3.3.2
	// algorithm, not transcribed from a Microsoft page. They are pinned so a later edit
	// that changes them has to say so out loud; they are not independent evidence that
	// this build is right, and this comment exists so nobody later reads them as if they
	// were.
	//
	// Both values are nonetheless fully determined once NTOWFv2 and NTProofStr match the
	// spec above: SessionBaseKey is HMAC_MD5(ResponseKeyNT, NTProofStr) and LmChallengeResponse
	// is HMAC_MD5(ResponseKeyLM, ServerChallenge || ClientChallenge) || ClientChallenge.
	const wantSessionBaseKey = "8de40ccadbc14a82f15cb0ad0de95ca3"
	const wantLM = "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa"

	key := ntowfv2(vectorUser, vectorDomain, vectorPassword)
	_, sessionBaseKey := ntlmv2Response(key, vectorServerChallenge, vectorClientChallenge, vectorTime, vectorTargetInfo())
	lm := lmv2Response(key, vectorServerChallenge, vectorClientChallenge)

	if got := hex.EncodeToString(sessionBaseKey); got != wantSessionBaseKey {
		t.Errorf("SessionBaseKey changed: got %s, want %s. It is the key the AUTHENTICATE message's MIC is "+
			"HMAC'd under, so a change here silently invalidates the MIC on every handshake against a "+
			"server that asks for one.", got, wantSessionBaseKey)
	}
	if got := hex.EncodeToString(lm); got != wantLM {
		t.Errorf("LmChallengeResponse changed: got %s, want %s. It must end with the same 8-byte client "+
			"challenge the NT response used; a server that checks the pair will reject a mismatched one.",
			got, wantLM)
	}
	if !bytes.Equal(lm[16:], vectorClientChallenge[:]) {
		t.Errorf("LmChallengeResponse does not end with the client challenge it was computed over "+
			"(got %x, want %x); MS-NLMP §3.3.2 appends it so the server can recompute the HMAC",
			lm[16:], vectorClientChallenge[:])
	}
}

func TestParseChallengeRefusesAMessageWhoseTargetInfoRunsPastItsEnd(t *testing.T) {
	// The CHALLENGE_MESSAGE arrives base64-decoded from a WWW-Authenticate header sent by
	// the host under test. It is the one input in this flow a hostile party fully
	// controls, so a length field that lies must produce an error and not a slice past
	// the end of the buffer.
	msg := make([]byte, 48)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmMsgChallenge)
	binary.LittleEndian.PutUint16(msg[40:42], 4096) // TargetInfoLen: a lie
	binary.LittleEndian.PutUint32(msg[44:48], 48)

	_, err := parseChallenge(msg)
	if err == nil {
		t.Fatal("parseChallenge accepted a CHALLENGE_MESSAGE claiming 4096 bytes of target info inside a " +
			"48-byte buffer; a server could crash the client that is trying to authenticate to it")
	}
	if !strings.Contains(err.Error(), "target info") {
		t.Errorf("the refusal does not name the field that was wrong: %v", err)
	}
}

func TestParseChallengeRefusesAChallengeWithNoTargetInfoRatherThanInventingOne(t *testing.T) {
	// A CHALLENGE_MESSAGE without an AV_PAIR list is a server asking for NTLMv1. This
	// build does not implement NTLMv1, and synthesising an empty list so the NTLMv2 path
	// "works" would produce a response the server cannot verify while reporting success —
	// a control that does nothing, which is a defect here even when nothing errors.
	msg := make([]byte, 48)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmMsgChallenge)

	_, err := parseChallenge(msg)
	if err == nil {
		t.Fatal("parseChallenge accepted a CHALLENGE_MESSAGE with no target info; the NTLMv2 response " +
			"computed from it could never be verified by the server that sent it")
	}
	if !strings.Contains(err.Error(), "NTLMv1") {
		t.Errorf("the refusal does not tell the operator that the server is asking for NTLMv1, which is the "+
			"actual reason and the thing they can act on: %v", err)
	}
}

func TestParseChallengeRejectsAnythingThatIsNotAnNTLMSSPChallenge(t *testing.T) {
	long := make([]byte, 64)
	copy(long[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(long[8:12], ntlmMsgNegotiate)

	for name, input := range map[string][]byte{
		"a short buffer":                  []byte("NTLMSSP\x00"),
		"a buffer with no NTLMSSP prefix": bytes.Repeat([]byte{0x41}, 64),
		"a NEGOTIATE message reflected back instead of a CHALLENGE": long,
	} {
		if _, err := parseChallenge(input); err == nil {
			t.Errorf("parseChallenge accepted %s as an NTLM challenge; the handshake would then be computed "+
				"against bytes that are not a challenge at all", name)
		}
	}
}

func TestWithMICFlagPreservesEveryServerAVPairAndSetsOnlyTheMICBit(t *testing.T) {
	// The AV_PAIR list is hashed into NTProofStr, so it must go back to the server with
	// every pair it sent — including pairs this build does not recognise. Dropping one
	// makes a correct password look wrong.
	original := appendAVPair(nil, avIDNbDomain, utf16le("CORP"))
	original = appendAVPair(original, avIDTimestamp, bytes.Repeat([]byte{0x11}, 8))
	original = appendAVPair(original, 0x000a /* MsvAvChannelBindings, unhandled here */, bytes.Repeat([]byte{0x22}, 16))
	original = appendAVPair(original, avIDEOL, nil)

	patched := withMICFlag(original)
	pairs := avPairs(patched)

	if got, ok := pairs[avIDNbDomain]; !ok || !bytes.Equal(got, utf16le("CORP")) {
		t.Errorf("MsvAvNbDomainName was dropped or altered by withMICFlag; the server will recompute "+
			"NTProofStr over its own list and reject a response built from a different one (got %x)", got)
	}
	if got, ok := pairs[0x000a]; !ok || !bytes.Equal(got, bytes.Repeat([]byte{0x22}, 16)) {
		t.Errorf("an AV_PAIR this build does not interpret (0x000a) was dropped by withMICFlag; unknown " +
			"pairs must survive verbatim because the server hashes its own list, not ours")
	}
	flags, ok := pairs[avIDFlags]
	if !ok || len(flags) != 4 {
		t.Fatalf("withMICFlag did not add a 4-byte MsvAvFlags pair, so the server is never told a MIC is " +
			"present and will not validate it — the MIC would be computed for nothing")
	}
	if binary.LittleEndian.Uint32(flags)&avFlagMICPresent == 0 {
		t.Errorf("MsvAvFlags is present but the MIC-present bit (0x2) is clear: got %x", flags)
	}
}

func TestWithMICFlagORsIntoAnExistingMsvAvFlagsInsteadOfReplacingIt(t *testing.T) {
	// A server that already set MsvAvFlags has said something; overwriting the word would
	// discard it.
	var existing [4]byte
	binary.LittleEndian.PutUint32(existing[:], 0x00000004) // "the target is untrusted", MS-NLMP 2.2.2.1
	original := appendAVPair(nil, avIDFlags, existing[:])
	original = appendAVPair(original, avIDEOL, nil)

	flags := avPairs(withMICFlag(original))[avIDFlags]
	got := binary.LittleEndian.Uint32(flags)

	if got&0x00000004 == 0 {
		t.Errorf("withMICFlag cleared a bit the server had set in MsvAvFlags (got %#08x); the client must "+
			"add its MIC claim to the server's word, not replace it", got)
	}
	if got&avFlagMICPresent == 0 {
		t.Errorf("withMICFlag did not set the MIC-present bit alongside the server's own (got %#08x)", got)
	}
}

func TestAuthenticateMessageFieldOffsetsPointAtTheBytesTheyDeclare(t *testing.T) {
	// A field descriptor is (Len, MaxLen, BufferOffset). Getting the payload cursor wrong
	// produces a message that parses — every offset is inside the buffer — but hands the
	// server the wrong slice, so the failure is a 401 rather than a parse error. Reading
	// each field back out is the only way to catch it here.
	key := ntowfv2(vectorUser, vectorDomain, vectorPassword)
	nt, sessionKey := ntlmv2Response(key, vectorServerChallenge, vectorClientChallenge, vectorTime, vectorTargetInfo())
	lm := lmv2Response(key, vectorServerChallenge, vectorClientChallenge)

	msg := buildAuthenticate(authenticateInput{
		domain: vectorDomain, user: vectorUser, workstation: "COMPUTER",
		lmResponse: lm, ntResponse: nt, flags: ntlmClientFlags,
		withMIC: true, micKey: sessionKey,
		negotiateMsg: buildNegotiate(), challengeMsg: []byte("challenge-bytes"),
	})

	read := func(off int) []byte {
		t.Helper()
		length := int(binary.LittleEndian.Uint16(msg[off : off+2]))
		start := int(binary.LittleEndian.Uint32(msg[off+4 : off+8]))
		if start+length > len(msg) {
			t.Fatalf("the field descriptor at offset %d points at bytes %d..%d of an %d-byte AUTHENTICATE "+
				"message; a server reading it would run off the end", off, start, start+length, len(msg))
		}
		return msg[start : start+length]
	}

	if got := read(12); !bytes.Equal(got, lm) {
		t.Errorf("LmChallengeResponseFields does not point at the LM response (got %x, want %x)", got, lm)
	}
	if got := read(20); !bytes.Equal(got, nt) {
		t.Errorf("NtChallengeResponseFields does not point at the NT response; the server would verify the "+
			"wrong bytes and answer 401 (got %d bytes, want %d)", len(got), len(nt))
	}
	if got := read(28); !bytes.Equal(got, utf16le(vectorDomain)) {
		t.Errorf("DomainNameFields does not point at the UTF-16LE domain (got %x)", got)
	}
	if got := read(36); !bytes.Equal(got, utf16le(vectorUser)) {
		t.Errorf("UserNameFields does not point at the UTF-16LE user name; the server would look up the "+
			"wrong account (got %x)", got)
	}
	if got := read(44); !bytes.Equal(got, utf16le("COMPUTER")) {
		t.Errorf("WorkstationFields does not point at the UTF-16LE workstation (got %x)", got)
	}
	if got := binary.LittleEndian.Uint16(msg[52:54]); got != 0 {
		t.Errorf("EncryptedRandomSessionKey is declared as %d bytes, but NTLMSSP_NEGOTIATE_KEY_EXCH is not "+
			"requested, so there is no exchanged key and the field must be empty", got)
	}
	if got := binary.LittleEndian.Uint32(msg[60:64]); got != ntlmClientFlags {
		t.Errorf("the AUTHENTICATE message does not echo the negotiated flags (got %#08x, want %#08x)", got, ntlmClientFlags)
	}
	if got := binary.LittleEndian.Uint32(msg[60:64]) & ntlmNegotiateExtendedSecurity; got == 0 {
		t.Error("NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY is clear; without it a server may treat the " +
			"exchange as NTLMv1-with-session-security, which is precisely what this build refuses to send")
	}
}

func TestTheMICIsComputedOverTheMessageAsSentWithItsOwnMICFieldZeroed(t *testing.T) {
	// MS-NLMP §3.1.5.1.2. The temptation is to build the message twice — once to hash and
	// once to send — which produces a MIC over bytes that differ from the ones on the
	// wire. Recomputing the HMAC here over the *sent* message with the field re-zeroed is
	// the check that they are the same bytes.
	key := ntowfv2(vectorUser, vectorDomain, vectorPassword)
	nt, sessionKey := ntlmv2Response(key, vectorServerChallenge, vectorClientChallenge, vectorTime, vectorTargetInfo())
	negotiate := buildNegotiate()
	challenge := []byte("the challenge message bytes")

	msg := buildAuthenticate(authenticateInput{
		domain: vectorDomain, user: vectorUser, workstation: "WS",
		lmResponse: lmv2Response(key, vectorServerChallenge, vectorClientChallenge),
		ntResponse: nt, flags: ntlmClientFlags,
		withMIC: true, micKey: sessionKey, negotiateMsg: negotiate, challengeMsg: challenge,
	})

	sentMIC := append([]byte(nil), msg[72:88]...)
	if bytes.Equal(sentMIC, make([]byte, 16)) {
		t.Fatal("withMIC was requested but the MIC field is sixteen zero bytes; the message claims a MIC " +
			"through MsvAvFlags and then does not carry one, which a server rejects")
	}

	zeroed := append([]byte(nil), msg...)
	copy(zeroed[72:88], make([]byte, 16))
	recomputed := micOver(sessionKey, negotiate, challenge, zeroed)

	if !bytes.Equal(sentMIC, recomputed) {
		t.Fatalf("the MIC on the message does not verify against the message itself.\n  sent       %x\n  recomputed %x\n"+
			"This is what happens when the hashed bytes and the sent bytes are two different assemblies; "+
			"the server computes the recomputed value and rejects the sent one.", sentMIC, recomputed)
	}
}

func TestBuildAuthenticateLeavesTheMICZeroWhenNoneWasAskedFor(t *testing.T) {
	// A server that sent no MsvAvTimestamp does not expect a MIC. Sending a nonzero one
	// without the MsvAvFlags bit is harmless but dishonest about what was computed; the
	// field must simply stay zero.
	msg := buildAuthenticate(authenticateInput{
		domain: "D", user: "U", workstation: "W",
		lmResponse: make([]byte, 24), ntResponse: make([]byte, 32), flags: ntlmClientFlags,
	})
	if !bytes.Equal(msg[72:88], make([]byte, 16)) {
		t.Errorf("the MIC field is %x for a message built with withMIC=false; it must be zero, because "+
			"MsvAvFlags does not claim a MIC and the server would have nothing to validate it against", msg[72:88])
	}
}

func TestNTLMTimestampIsAWindowsFILETIME(t *testing.T) {
	// MS-NLMP 2.2.2.1: 100-nanosecond ticks since 1601-01-01 UTC, little-endian. The Unix
	// epoch is the one value with a published constant to check against.
	got := binary.LittleEndian.Uint64(func() []byte { ts := ntlmTimestamp(time.Unix(0, 0)); return ts[:] }())
	const unixEpochAsFILETIME = uint64(116444736000000000)

	if got != unixEpochAsFILETIME {
		t.Fatalf("ntlmTimestamp(1970-01-01) is %d ticks; a Windows FILETIME for that instant is %d. "+
			"A timestamp outside the server's skew window makes it reject an otherwise correct response.",
			got, unixEpochAsFILETIME)
	}
}

func TestNewClientChallengeIsNeverTheZeroValue(t *testing.T) {
	// Eight zero bytes produce a response a server still accepts while removing the client
	// entropy that is the entire difference between NTLMv2 and NTLMv1 — a control that
	// looks like it works and does not.
	var zero [8]byte
	seen := map[[8]byte]bool{}
	for i := 0; i < 32; i++ {
		c, err := newClientChallenge()
		if err != nil {
			t.Fatalf("drawing a client challenge failed: %v", err)
		}
		if c == zero {
			t.Fatal("newClientChallenge returned eight zero bytes; the response would still be accepted by " +
				"a server while carrying no client entropy, which is NTLMv1's weakness reintroduced")
		}
		seen[c] = true
	}
	if len(seen) < 32 {
		t.Errorf("32 draws produced only %d distinct client challenges; a repeated challenge lets a captured "+
			"pair be replayed", len(seen))
	}
}
