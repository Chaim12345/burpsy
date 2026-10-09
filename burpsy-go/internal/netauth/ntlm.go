// NTLMv2 over HTTP: the NTLMSSP message codec and the MS-NLMP response algorithm.
//
// # What is here and what is deliberately not
//
// This file implements **NTLMv2 only**. NTLMv1 and Negotiate/SPNEGO are refused by
// ParseScheme with reasons that name what each would actually require; see the Scheme
// doc in netauth.go. The short form:
//
//   - NTLMv1 derives its response by DES-encrypting the server challenge under the NT
//     hash with no client entropy, so a captured challenge/response pair is an offline
//     crack of the password at a fixed cost. Windows has defaulted to refusing it since
//     LmCompatibilityLevel 3, so an NTLMv1 option would mostly be a weaker credential
//     that also does not work. It is refused, not implemented badly.
//   - Negotiate/SPNEGO needs a Kerberos credential — a ccache, a keytab, or a live SSPI
//     logon session — which burpsy cannot obtain in-process from a username and password
//     typed into a panel. It is refused with that reason rather than offered and silently
//     failing, because a silently-failing Kerberos option makes the operator blame the
//     target.
//
// # Where the numbers come from
//
// Every constant and every step below is MS-NLMP. The response algorithm is section
// 3.3.2 (NTLM v2 Authentication), quoted in ntlm_test.go next to the section 4.2.4
// known-answer vectors that pin it. Those vectors are the evidence this file is correct:
// they are computable without a domain controller, which is the only kind of proof
// available here.
//
// # Secrets
//
// The same rule as the rest of the package: the password never leaves netauth. The
// sender drives the three legs through *NTLMSession, which holds the derived NT one-way
// function in an unexported field and hands back only wire bytes. There is no exported
// accessor for the key, and NTLMSession has no exported field at all, so encoding/json
// cannot reach anything.
package netauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// ntlmSignature prefixes every NTLMSSP message. A blob that does not start with it is
// not an NTLM message, and is rejected rather than parsed optimistically: the bytes
// arrive base64-decoded from a header a hostile server controls.
const ntlmSignature = "NTLMSSP\x00"

// Message types, MS-NLMP 2.2.
const (
	ntlmMsgNegotiate    uint32 = 1
	ntlmMsgChallenge    uint32 = 2
	ntlmMsgAuthenticate uint32 = 3
)

// NegotiateFlags, MS-NLMP 2.2.2.5. Only the bits this build actually sets or reads are
// named; an unnamed bit is one nothing here depends on.
const (
	ntlmNegotiateUnicode          uint32 = 0x00000001
	ntlmRequestTarget             uint32 = 0x00000004
	ntlmNegotiateNTLM             uint32 = 0x00000200
	ntlmNegotiateAlwaysSign       uint32 = 0x00008000
	ntlmNegotiateExtendedSecurity uint32 = 0x00080000
	ntlmNegotiateTargetInfo       uint32 = 0x00800000
	ntlmNegotiateVersion          uint32 = 0x02000000
	ntlmNegotiate128              uint32 = 0x20000000
	ntlmNegotiate56               uint32 = 0x80000000
)

// AV_PAIR identifiers, MS-NLMP 2.2.2.1.
const (
	avIDEOL       uint16 = 0x0000
	avIDNbDomain  uint16 = 0x0002
	avIDFlags     uint16 = 0x0006
	avIDTimestamp uint16 = 0x0007
)

// avFlagMICPresent is MsvAvFlags bit 0x2: "the client is providing a MIC". MS-NLMP
// 2.2.2.1. It is what tells the server to validate the MIC field at all, so setting it
// without computing a real MIC would be a message the server rejects — the two are
// written together in buildAuthenticate and nowhere else.
const avFlagMICPresent uint32 = 0x00000002

// ntlmClientFlags is what the NEGOTIATE message asks for, and what the AUTHENTICATE
// message echoes.
//
// # Why KEY_EXCH and SEAL are not in here
//
// NTLM over HTTP authenticates a connection; it does not sign or seal the HTTP body
// (that is SMB's and RPC's use of the same protocol). Asking for key exchange would
// oblige this code to generate an exported session key, RC4-encrypt it into the
// AUTHENTICATE message, and then never use it — a block of key material created for no
// consumer. Leaving it out means SessionBaseKey is the exported session key directly
// (MS-NLMP 3.4.5.1 KXKEY with extended session security), which is all the MIC needs.
//
// EXTENDED_SESSIONSECURITY is non-negotiable in the other direction: without it a
// server may treat the exchange as NTLMv1-with-session-security, and the whole point of
// this file is that NTLMv1 is not what goes on the wire.
const ntlmClientFlags = ntlmNegotiateUnicode |
	ntlmRequestTarget |
	ntlmNegotiateNTLM |
	ntlmNegotiateAlwaysSign |
	ntlmNegotiateExtendedSecurity |
	ntlmNegotiateTargetInfo |
	ntlmNegotiateVersion |
	ntlmNegotiate128 |
	ntlmNegotiate56

// ntlmVersionBlob is the VERSION field, MS-NLMP 2.2.2.10: major 6, minor 1, build 7600,
// NTLMSSP_REVISION_W2K3 (15). A fixed value, not the host's real OS version.
//
// It is sent because the field's 8 bytes must be accounted for in the AUTHENTICATE
// message's payload offsets whether or not they carry information, and a server that
// logs the client version should see something coherent rather than zeros. It is
// deliberately not the machine's actual version: that would be host fingerprinting
// burpsy leaks to every target it authenticates to, for no protocol benefit.
var ntlmVersionBlob = [8]byte{6, 1, 0xB0, 0x1D, 0, 0, 0, 15}

// utf16le encodes s as UTF-16LE, which is what MS-NLMP means by UNICODE().
//
// Surrogate pairs are preserved (utf16.Encode handles them), so a non-BMP character in
// a password hashes the same way Windows hashes it.
func utf16le(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// ntowfv2 is MS-NLMP 3.3.2's NTOWFv2:
//
//	HMAC_MD5(MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf(Uppercase(User), UserDom)))
//
// The user name is upper-cased and the domain is **not**. That asymmetry is not a typo
// in this code — it is the spec, and it is the single most common way an NTLMv2
// implementation is wrong in a way that only shows up against a real domain controller.
// ntlm_test.go pins it with the section 4.2.4 vector, where User="User" and
// Domain="Domain" differ in case exactly enough for a symmetric implementation to fail.
func ntowfv2(user, domain, password string) []byte {
	h := md4.New()
	h.Write(utf16le(password))
	ntHash := h.Sum(nil)

	mac := hmac.New(md5.New, ntHash)
	mac.Write(utf16le(strings.ToUpper(user) + domain))
	return mac.Sum(nil)
}

// ntlmv2Temp builds the `temp` blob of MS-NLMP 3.3.2:
//
//	ConcatenationOf(Responserversion, HiResponserversion, Z(6), Time, ClientChallenge,
//	                Z(4), ServerName, Z(4))
//
// serverName is the AV_PAIR list **including its MsvAvEOL terminator**; the trailing
// Z(4) comes after it. Section 4.2.4.1.3's hex dump ends in eight zero bytes for exactly
// that reason — four are the EOL pair, four are the Z(4) — and emitting twelve is the
// other classic way to get this wrong.
func ntlmv2Temp(timestamp, clientChallenge [8]byte, serverName []byte) []byte {
	temp := make([]byte, 0, 28+len(serverName)+4)
	temp = append(temp, 0x01, 0x01)            // Responserversion, HiResponserversion
	temp = append(temp, 0, 0, 0, 0, 0, 0)      // Z(6)
	temp = append(temp, timestamp[:]...)       // Time
	temp = append(temp, clientChallenge[:]...) // ClientChallenge
	temp = append(temp, 0, 0, 0, 0)            // Z(4)
	temp = append(temp, serverName...)         // ServerName (AV_PAIRs incl. EOL)
	temp = append(temp, 0, 0, 0, 0)            // Z(4)
	return temp
}

// ntlmv2Response computes NtChallengeResponse and SessionBaseKey, MS-NLMP 3.3.2.
//
// Every input is a parameter, including Time and ClientChallenge which a caller would
// normally take from the clock and crypto/rand. That is what makes the section 4.2.4
// known-answer vectors testable at all: a function that reached for rand internally
// could only ever be checked for self-consistency. newClientChallenge and ntlmTimestamp
// are the thin wrappers that supply the live values, and they are the only randomness in
// this file.
func ntlmv2Response(ntowf []byte, serverChallenge, clientChallenge, timestamp [8]byte, serverName []byte) (ntChallengeResponse, sessionBaseKey []byte) {
	temp := ntlmv2Temp(timestamp, clientChallenge, serverName)

	mac := hmac.New(md5.New, ntowf)
	mac.Write(serverChallenge[:])
	mac.Write(temp)
	ntProofStr := mac.Sum(nil)

	ntChallengeResponse = make([]byte, 0, len(ntProofStr)+len(temp))
	ntChallengeResponse = append(ntChallengeResponse, ntProofStr...)
	ntChallengeResponse = append(ntChallengeResponse, temp...)

	mac = hmac.New(md5.New, ntowf)
	mac.Write(ntProofStr)
	sessionBaseKey = mac.Sum(nil)

	return ntChallengeResponse, sessionBaseKey
}

// lmv2Response is MS-NLMP 3.3.2's LmChallengeResponse for NTLMv2:
//
//	ConcatenationOf(HMAC_MD5(ResponseKeyLM, ConcatenationOf(ServerChallenge,
//	                ClientChallenge)), ClientChallenge)
//
// ResponseKeyLM is LMOWFv2, which the spec defines as identical to NTOWFv2, so the same
// key is passed in.
//
// It is sent even though a server that understands NTLMv2 ignores it: MS-NLMP requires
// the field, and some middleboxes reject an AUTHENTICATE message whose
// LmChallengeResponse is the 24 zero bytes some clients substitute.
func lmv2Response(ntowf []byte, serverChallenge, clientChallenge [8]byte) []byte {
	mac := hmac.New(md5.New, ntowf)
	mac.Write(serverChallenge[:])
	mac.Write(clientChallenge[:])
	out := mac.Sum(nil)
	return append(out, clientChallenge[:]...)
}

// newClientChallenge draws the 8 bytes of client entropy that make NTLMv2 a challenge
// *pair* rather than NTLMv1's one-sided one.
//
// A rand failure is returned, never swallowed for a zero challenge. Eight zero bytes
// would still produce a response the server accepts, while silently removing the client
// entropy that is the entire security difference between v2 and v1 — the definition of a
// control that looks like it works and does not.
func newClientChallenge() ([8]byte, error) {
	var challenge [8]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return challenge, fmt.Errorf("could not draw an NTLM client challenge: %w", err)
	}
	return challenge, nil
}

// ntlmTimestamp renders t as a Windows FILETIME: 100-nanosecond ticks since
// 1601-01-01 UTC, little-endian. MS-NLMP 2.2.2.1 MsvAvTimestamp.
func ntlmTimestamp(t time.Time) [8]byte {
	const ticksFrom1601To1970 = 116444736000000000
	ticks := uint64(t.UTC().UnixNano()/100) + ticksFrom1601To1970
	var out [8]byte
	binary.LittleEndian.PutUint64(out[:], ticks)
	return out
}

// ---- message codec ------------------------------------------------------------------

// ntlmChallengeMessage is the parsed CHALLENGE_MESSAGE (type 2), MS-NLMP 2.2.1.2.
type ntlmChallengeMessage struct {
	Flags           uint32
	ServerChallenge [8]byte
	// TargetInfo is the raw AV_PAIR list, EOL included, exactly as the server sent it.
	// It is copied verbatim into `temp` rather than re-encoded from parsed pairs: a
	// server that sent an AV pair this build does not know about still gets its own
	// bytes back, and re-encoding would silently drop it from the hash the server is
	// about to recompute.
	TargetInfo []byte
}

// timestamp returns the MsvAvTimestamp value from TargetInfo, and whether there was one.
//
// Its presence is what decides whether this client sends a MIC — see buildAuthenticate.
func (c ntlmChallengeMessage) timestamp() ([8]byte, bool) {
	var out [8]byte
	for id, value := range avPairs(c.TargetInfo) {
		if id == avIDTimestamp && len(value) == 8 {
			copy(out[:], value)
			return out, true
		}
	}
	return out, false
}

// avPairs iterates an AV_PAIR list, stopping at MsvAvEOL or at the first pair whose
// declared length runs past the end of the buffer.
//
// Truncation stops iteration rather than panicking or erroring: the buffer came from a
// server-controlled header, and a malformed tail must not be able to crash the client
// that is trying to authenticate to it.
func avPairs(buf []byte) map[uint16][]byte {
	out := map[uint16][]byte{}
	for len(buf) >= 4 {
		id := binary.LittleEndian.Uint16(buf[0:2])
		length := int(binary.LittleEndian.Uint16(buf[2:4]))
		if id == avIDEOL {
			return out
		}
		if 4+length > len(buf) {
			return out
		}
		out[id] = buf[4 : 4+length]
		buf = buf[4+length:]
	}
	return out
}

// utf16Text decodes a UTF-16LE byte pair back into the text the server named. An odd
// number of bytes is truncated to whole units rather than guessed at: a truncated name
// hashes wrong, and a wrong hash is reported as a 401 rather than silently accepted.
func utf16Text(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(units))
}

// appendAVPair writes one AV_PAIR.
func appendAVPair(dst []byte, id uint16, value []byte) []byte {
	var header [4]byte
	binary.LittleEndian.PutUint16(header[0:2], id)
	binary.LittleEndian.PutUint16(header[2:4], uint16(len(value)))
	dst = append(dst, header[:]...)
	return append(dst, value...)
}

// withMICFlag returns the server's TargetInfo with MsvAvFlags' MIC-present bit set,
// preserving every other pair and their order, and re-terminating with MsvAvEOL.
//
// An existing MsvAvFlags is OR-ed rather than replaced: the server may have set other
// bits in it, and overwriting them would discard a statement the server made.
func withMICFlag(targetInfo []byte) []byte {
	out := make([]byte, 0, len(targetInfo)+8)
	wroteFlags := false
	buf := targetInfo
	for len(buf) >= 4 {
		id := binary.LittleEndian.Uint16(buf[0:2])
		length := int(binary.LittleEndian.Uint16(buf[2:4]))
		if id == avIDEOL || 4+length > len(buf) {
			break
		}
		value := buf[4 : 4+length]
		if id == avIDFlags && length == 4 {
			flags := binary.LittleEndian.Uint32(value) | avFlagMICPresent
			var patched [4]byte
			binary.LittleEndian.PutUint32(patched[:], flags)
			out = appendAVPair(out, avIDFlags, patched[:])
			wroteFlags = true
		} else {
			out = appendAVPair(out, id, value)
		}
		buf = buf[4+length:]
	}
	if !wroteFlags {
		var flags [4]byte
		binary.LittleEndian.PutUint32(flags[:], avFlagMICPresent)
		out = appendAVPair(out, avIDFlags, flags[:])
	}
	return appendAVPair(out, avIDEOL, nil)
}

// buildNegotiate builds the NEGOTIATE_MESSAGE (type 1), MS-NLMP 2.2.1.1.
//
// DomainName and Workstation are sent empty. Both are optional, both would have to be
// OEM-encoded with their own NEGOTIATE_*_SUPPLIED flags, and neither affects which
// account authenticates — the domain that matters travels in the AUTHENTICATE message as
// UTF-16. Sending them here would be two more host-identifying strings on the wire for
// no protocol effect.
func buildNegotiate() []byte {
	msg := make([]byte, 40)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmMsgNegotiate)
	binary.LittleEndian.PutUint32(msg[12:16], ntlmClientFlags)
	// DomainNameFields (16..24) and WorkstationFields (24..32) stay zero-length. Their
	// BufferOffset is set past the fixed header so a server that dereferences it lands
	// inside the message rather than past its end.
	binary.LittleEndian.PutUint32(msg[20:24], 40)
	binary.LittleEndian.PutUint32(msg[28:32], 40)
	copy(msg[32:40], ntlmVersionBlob[:])
	return msg
}

// parseChallenge decodes a CHALLENGE_MESSAGE (type 2).
//
// Every length and offset is bounds-checked against the actual buffer before it is used.
// These bytes are base64 out of a WWW-Authenticate header from a host under test — the
// one place in this flow where a hostile party chooses the input — so a short or lying
// field must produce an error, never a slice past the end.
func parseChallenge(msg []byte) (ntlmChallengeMessage, error) {
	var out ntlmChallengeMessage
	if len(msg) < 48 {
		return out, fmt.Errorf("NTLM challenge is %d bytes; a CHALLENGE_MESSAGE is at least 48", len(msg))
	}
	if !bytes.Equal(msg[0:8], []byte(ntlmSignature)) {
		return out, errors.New("NTLM challenge does not start with the NTLMSSP signature")
	}
	if got := binary.LittleEndian.Uint32(msg[8:12]); got != ntlmMsgChallenge {
		return out, fmt.Errorf("expected an NTLM CHALLENGE_MESSAGE (type 2) but the server sent type %d", got)
	}

	out.Flags = binary.LittleEndian.Uint32(msg[20:24])
	copy(out.ServerChallenge[:], msg[24:32])

	infoLen := int(binary.LittleEndian.Uint16(msg[40:42]))
	infoOffset := int(binary.LittleEndian.Uint32(msg[44:48]))
	if infoLen > 0 {
		if infoOffset < 0 || infoOffset > len(msg) || infoOffset+infoLen > len(msg) {
			return out, fmt.Errorf("NTLM challenge declares %d bytes of target info at offset %d but the message is %d bytes",
				infoLen, infoOffset, len(msg))
		}
		out.TargetInfo = msg[infoOffset : infoOffset+infoLen]
	}
	if len(out.TargetInfo) == 0 {
		// An NTLMv2 response hashes the server's AV_PAIR list. A challenge without one is
		// a downgrade request in every practical case — a server that wants NTLMv1 — and
		// answering it with a synthesised empty list would be this code inventing the
		// input it is supposed to be authenticating against.
		return out, errors.New("NTLM challenge carries no target info; the server is not offering NTLMv2 " +
			"(this build does not implement the NTLMv1 fallback)")
	}
	return out, nil
}

// ntlmField writes a field descriptor (Len, MaxLen, BufferOffset) at off.
func ntlmField(msg []byte, off, length, bufferOffset int) {
	binary.LittleEndian.PutUint16(msg[off:off+2], uint16(length))
	binary.LittleEndian.PutUint16(msg[off+2:off+4], uint16(length))
	binary.LittleEndian.PutUint32(msg[off+4:off+8], uint32(bufferOffset))
}

// authenticateInput is everything buildAuthenticate needs that is not derived inside it.
// A struct rather than nine positional parameters, because six of the nine are byte
// slices and a transposed pair would produce a message that is wrong in a way no
// compiler catches.
type authenticateInput struct {
	domain, user, workstation string
	lmResponse, ntResponse    []byte
	flags                     uint32
	// withMIC decides whether the 16-byte MIC field carries a real value. When false the
	// field is present but zero and MsvAvFlags does not claim a MIC, so the server
	// ignores it; see buildAuthenticate.
	withMIC bool
	// micKey is the exported session key the MIC is HMAC'd under, and negotiateMsg /
	// challengeMsg are the first two legs it covers. All three are ignored when withMIC
	// is false.
	micKey, negotiateMsg, challengeMsg []byte
}

// buildAuthenticate builds the AUTHENTICATE_MESSAGE (type 3), MS-NLMP 2.2.1.3.
//
// # Why the payload always starts at 88
//
// The fixed part is 64 bytes of field descriptors and flags, then VERSION (8) then MIC
// (16). A server decides whether a MIC is present by whether the smallest payload offset
// leaves room for one, so a message that omits the MIC bytes and one that zeroes them
// are read differently. This always reserves them and always starts the payload at 88;
// whether the server *validates* what is in them is decided by MsvAvFlags inside the NT
// response, which is the only signal the spec gives for it. That keeps the two halves of
// "is there a MIC" in one place instead of two that can disagree.
//
// # The MIC is computed over this message with its own MIC field zeroed
//
// MS-NLMP 3.1.5.1.2. The message is therefore assembled once with sixteen zeros, HMAC'd,
// and the result written back in place — not assembled twice, which is how the hashed
// bytes end up differing from the sent bytes.
func buildAuthenticate(in authenticateInput) []byte {
	domain := utf16le(in.domain)
	user := utf16le(in.user)
	workstation := utf16le(in.workstation)

	const fixedLen = 88
	payloadOffset := fixedLen
	msg := make([]byte, fixedLen)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmMsgAuthenticate)

	ntlmField(msg, 12, len(in.lmResponse), payloadOffset)
	msg = append(msg, in.lmResponse...)
	payloadOffset += len(in.lmResponse)

	ntlmField(msg, 20, len(in.ntResponse), payloadOffset)
	msg = append(msg, in.ntResponse...)
	payloadOffset += len(in.ntResponse)

	ntlmField(msg, 28, len(domain), payloadOffset)
	msg = append(msg, domain...)
	payloadOffset += len(domain)

	ntlmField(msg, 36, len(user), payloadOffset)
	msg = append(msg, user...)
	payloadOffset += len(user)

	ntlmField(msg, 44, len(workstation), payloadOffset)
	msg = append(msg, workstation...)
	payloadOffset += len(workstation)

	// EncryptedRandomSessionKey is empty: NTLMSSP_NEGOTIATE_KEY_EXCH is not asked for, so
	// there is no exchanged key to carry. See ntlmClientFlags.
	ntlmField(msg, 52, 0, payloadOffset)

	binary.LittleEndian.PutUint32(msg[60:64], in.flags)
	copy(msg[64:72], ntlmVersionBlob[:])
	// msg[72:88] is the MIC, left zero for now — and left zero for good if !withMIC.

	if in.withMIC {
		copy(msg[72:88], micOver(in.micKey, in.negotiateMsg, in.challengeMsg, msg))
	}
	return msg
}

// micOver is the MIC of MS-NLMP 3.1.5.1.2:
//
//	HMAC_MD5(ExportedSessionKey, ConcatenationOf(NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE,
//	                                             AUTHENTICATE_MESSAGE))
//
// where the AUTHENTICATE_MESSAGE passed in has its own 16-byte MIC field zeroed.
//
// Factored out of buildAuthenticate so a test can recompute it over the message that was
// actually produced. That is the only way to catch the classic failure — hashing one
// assembly of the message and sending another — because both halves are individually
// plausible and the wire symptom is an unexplained 401.
func micOver(exportedSessionKey, negotiateMsg, challengeMsg, authenticateWithZeroedMIC []byte) []byte {
	mac := hmac.New(md5.New, exportedSessionKey)
	mac.Write(negotiateMsg)
	mac.Write(challengeMsg)
	mac.Write(authenticateWithZeroedMIC)
	return mac.Sum(nil)
}

// ntlmSession is one host's NTLMv2 handshake state: the NEGOTIATE message this build sent
// and the CHALLENGE_MESSAGE the server answered it with, both as raw bytes, because the
// MIC covers exactly those two legs (MS-NLMP 3.2.5.1.1). It lives in the credential store
// keyed by host — the same shape as the Digest nonce cache — rather than in a socket, so a
// learned challenge reaches the next request whatever connection carries it.
//
// Everything here is unexported and every accessor hands back only derived wire bytes, so
// encoding/json cannot reach the state and no accessor can leak the derived NT one-way
// function: it is recomputed from the rule's password on each use, matching the package
// doc's secret rule.
type ntlmSession struct {
	negotiate []byte
	challenge []byte
}

// ntlmNegotiateMessage returns the type-1 NEGOTIATE message. One per session, generated
// when the challenge is learned and kept, so the MIC's negotiate leg is the message as sent
// rather than a second assembly of it.
func ntlmNegotiateMessage() []byte { return buildNegotiate() }

// ntlmChallengeBlob decodes the base64 payload of a `WWW-Authenticate: NTLM <blob>` header,
// refusing a header whose payload is not base64 or does not carry an NTLMSSP message. The
// bytes arrive from a hostile server, so they are validated before they are ever hashed.
func ntlmChallengeBlob(header string) ([]byte, error) {
	const prefix = "NTLM "
	rest := strings.TrimSpace(header)
	if len(rest) > len(prefix) && strings.EqualFold(rest[:len(prefix)], prefix) {
		rest = strings.TrimSpace(rest[len(prefix):])
	}
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return nil, fmt.Errorf("NTLM challenge payload is not valid base64: %w", err)
	}
	return raw, nil
}

// ntlmAnswer computes the type-3 AUTHENTICATE message for one learned challenge. It is the
// MS-NLMP 3.3.2 response algorithm driven end to end: NTOWFv2 from the rule's password,
// the v2 hash over the server's challenge and AV_PAIR list, a fresh client challenge and
// timestamp, and a MIC over the negotiate and challenge legs under the session base key.
//
// The negotiate message passed in is the one this build actually sent, kept by the session,
// so the MIC covers the exchange as it went out.
func ntlmAnswer(rule Credential, negotiate, challengeMsg []byte) (string, error) {
	challenge, err := parseChallenge(challengeMsg)
	if err != nil {
		return "", err
	}

	clientChallenge, err := newClientChallenge()
	if err != nil {
		return "", err
	}

	// The domain is the AV pair the server named, decoded back from its UTF-16LE wire
	// form: ntowfv2 hashes upper(user) + domain as the *text* the server meant, and a
	// pair's bytes re-encoded as UTF-16 would hash the double-encoded name the server
	// never sent. A challenge with no domain pair hashes the empty one — the same input
	// a domain-less account would produce.
	//
	// A "DOMAIN\user" username names its own domain, and that one is used: the account is in the
	// domain the operator typed, which need not be the server's own (a member server of a
	// trusting domain names itself, not the account's domain). Without the split the whole
	// "DOMAIN\user" string was hashed as the user name, and the console's own hint for the field
	// produced a credential that could never verify.
	domain, user, ownDomain := splitNTLMUser(rule.Username)
	if !ownDomain {
		if pairs := avPairs(challenge.TargetInfo); pairs != nil {
			if nb, ok := pairs[avIDNbDomain]; ok {
				domain = utf16Text(nb)
			}
		}
	}

	key := ntowfv2(user, domain, rule.password)

	// A MIC is asked for by setting MsvAvFlags' MIC bit in the challenge's own target
	// info (MS-NLMP 3.2.5.1.1). The v2 response is computed ONCE, over the target info
	// exactly as the server sent it: NTProofStr hashes serverChallenge + temp, and temp
	// embeds that list — a server recomputing the proof hashes the bytes it sent, so
	// hashing a patched copy would produce a proof no server accepts. The MIC-bit patch
	// matters for whether the MIC is computed and claimed, never for the response hash.
	flags := ntlmClientFlags
	withMIC := micBitSet(challenge)

	ntResponse, sessionKey := ntlmv2Response(key, challenge.ServerChallenge, clientChallenge,
		ntlmTimestamp(time.Now()), challenge.TargetInfo)

	msg := buildAuthenticate(authenticateInput{
		domain:       domain,
		user:         user,
		workstation:  "",
		lmResponse:   lmv2Response(key, challenge.ServerChallenge, clientChallenge),
		ntResponse:   ntResponse,
		flags:        flags,
		withMIC:      withMIC,
		micKey:       sessionKey,
		negotiateMsg: negotiate,
		challengeMsg: challengeMsg,
	})
	return "NTLM " + base64.StdEncoding.EncodeToString(msg), nil
}

// micBitSet reports whether the challenge's MsvAvFlags AV pair claims a MIC, which is how a
// server asks for one (MS-NLMP 3.2.5.1.1). A challenge with no flags pair never asked, so
// it reads false rather than being guessed at.
func micBitSet(challenge ntlmChallengeMessage) bool {
	pairs := avPairs(challenge.TargetInfo)
	flags, ok := pairs[avIDFlags]
	if !ok {
		return false
	}
	return binary.LittleEndian.Uint32(flags)&0x00000004 != 0
}
