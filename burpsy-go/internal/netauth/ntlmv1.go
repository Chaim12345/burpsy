package netauth

import (
	"crypto/des"
	"crypto/md5"
	"encoding/base64"

	"golang.org/x/crypto/md4"
)

// NTLMv1, MS-NLMP 3.3.1 — an explicit, per-rule downgrade (SchemeNTLMv1, burpsy-react-ui-sel6).
//
// # When it is used
//
// Only for a rule whose scheme is ntlmv1. An ntlmv2 rule never reaches this file: parseChallenge
// refuses a v1-only challenge for it rather than falling back. Every handshake that reaches
// ntlmv1Answer records a weak-authentication warning (see NTLMExchange.Authenticate).
//
// # Which v1
//
// NTLM2 session security (ESS, "NTLM2 session response") when the server's CHALLENGE sets
// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY — the response then hashes a client challenge too —
// and plain NTLMv1 otherwise. Either way the response is DES under the NT hash.
//
// # No LM hash, ever
//
// The LM one-way function (DES over the upper-cased, 14-byte-truncated password) is not computed.
// MS-NLMP 3.3.1 lets a client that does not send it put the NT response in the LM field
// (NoLMResponseNTLMv1); with ESS the LM field is the client challenge padded with zeros. So the
// weakest password hash in the protocol never leaves this process.

// ntowfv1 is MS-NLMP 3.3.1's NTOWFv1: MD4(UNICODE(Passwd)).
func ntowfv1(password string) []byte {
	h := md4.New()
	h.Write(utf16le(password))
	return h.Sum(nil)
}

// desKeyFrom7 expands 56 key bits into the 8-byte DES key MS-NLMP 6 calls for, seven bits per
// byte with the low (parity) bit left zero — crypto/des ignores parity.
func desKeyFrom7(k []byte) []byte {
	return []byte{
		k[0] & 0xFE,
		(k[0]<<7 | k[1]>>1) & 0xFE,
		(k[1]<<6 | k[2]>>2) & 0xFE,
		(k[2]<<5 | k[3]>>3) & 0xFE,
		(k[3]<<4 | k[4]>>4) & 0xFE,
		(k[4]<<3 | k[5]>>5) & 0xFE,
		(k[5]<<2 | k[6]>>6) & 0xFE,
		k[6] << 1,
	}
}

// desl is MS-NLMP 6's DESL(K, D): the 16-byte key padded to 21 bytes, split in three 7-byte DES
// keys, each encrypting the same 8-byte block; 24 bytes out.
func desl(key []byte, data [8]byte) []byte {
	var k [21]byte
	copy(k[:], key)
	out := make([]byte, 0, 24)
	for i := 0; i < 3; i++ {
		block, err := des.NewCipher(desKeyFrom7(k[i*7 : i*7+7]))
		if err != nil {
			// Unreachable: an 8-byte key is the only input des.NewCipher refuses on length.
			panic(err)
		}
		var sealed [8]byte
		block.Encrypt(sealed[:], data[:])
		out = append(out, sealed[:]...)
	}
	return out
}

// ntlmv1Response computes NtChallengeResponse and LmChallengeResponse, MS-NLMP 3.3.1. All inputs
// are parameters so the section 4.2.2 / 4.2.3 vectors can pin it.
func ntlmv1Response(ntowf []byte, serverChallenge, clientChallenge [8]byte, ess bool) (nt, lm []byte) {
	if ess {
		sum := md5.Sum(append(serverChallenge[:], clientChallenge[:]...))
		var mixed [8]byte
		copy(mixed[:], sum[:8])
		nt = desl(ntowf, mixed)
		lm = append(append([]byte{}, clientChallenge[:]...), make([]byte, 16)...)
		return nt, lm
	}
	nt = desl(ntowf, serverChallenge)
	return nt, append([]byte{}, nt...)
}

// ntlmv1Answer computes the type-3 AUTHENTICATE message for an NTLMv1 rule, and reports whether
// ESS was used. The domain is the one the username names, else the server's NetBIOS domain when
// its challenge carries one.
func ntlmv1Answer(rule Credential, challengeMsg []byte) (msg []byte, ess bool, err error) {
	challenge, err := parseChallengeMessage(challengeMsg)
	if err != nil {
		return nil, false, err
	}
	clientChallenge, err := newClientChallenge()
	if err != nil {
		return nil, false, err
	}
	domain, user, ownDomain := splitNTLMUser(rule.Username)
	if !ownDomain {
		if nb, ok := avPairs(challenge.TargetInfo)[avIDNbDomain]; ok {
			domain = utf16Text(nb)
		}
	}
	ess = challenge.Flags&ntlmNegotiateExtendedSecurity != 0
	nt, lm := ntlmv1Response(ntowfv1(rule.password), challenge.ServerChallenge, clientChallenge, ess)

	flags := ntlmClientFlags &^ ntlmNegotiateTargetInfo
	if !ess {
		flags &^= ntlmNegotiateExtendedSecurity
	}
	return buildAuthenticate(authenticateInput{
		domain:     domain,
		user:       user,
		lmResponse: lm,
		ntResponse: nt,
		flags:      flags,
	}), ess, nil
}

// encodeNTLM renders an NTLMSSP message as an Authorization value in the given header scheme.
func encodeNTLM(wire string, msg []byte) string {
	return wire + " " + base64.StdEncoding.EncodeToString(msg)
}
