package netauth

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// burpsy-react-ui-sel6: the connection-bound NTLM handshake's netauth half. The wire-level proof —
// three legs, one connection, verified by an independent server — is internal/sender's
// connauth_test.go; these pin the exchange's own rules.

// testChallenge is a CHALLENGE_MESSAGE naming domain CORP, with a timestamp, as base64 header value.
func testChallenge() string {
	pair := func(id uint16, value []byte) []byte {
		out := make([]byte, 4, 4+len(value))
		binary.LittleEndian.PutUint16(out[0:2], id)
		binary.LittleEndian.PutUint16(out[2:4], uint16(len(value)))
		return append(out, value...)
	}
	var info []byte
	info = append(info, pair(avIDNbDomain, utf16le("CORP"))...)
	info = append(info, pair(avIDTimestamp, make([]byte, 8))...)
	info = append(info, pair(avIDEOL, nil)...)
	msg := make([]byte, 48)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmMsgChallenge)
	binary.LittleEndian.PutUint32(msg[20:24], ntlmClientFlags)
	copy(msg[24:32], "\x01\x02\x03\x04\x05\x06\x07\x08")
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(info)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(info)))
	binary.LittleEndian.PutUint32(msg[44:48], 48)
	return "NTLM " + base64.StdEncoding.EncodeToString(append(msg, info...))
}

func storeWith(t *testing.T, rules ...Credential) *Credentials {
	t.Helper()
	c := NewCredentials()
	for _, r := range rules {
		c.Add(r)
	}
	return c
}

func mustRule(t *testing.T, host string, scheme Scheme, user, password string) Credential {
	t.Helper()
	r, err := NewCredential(host, scheme, user, password, "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// First-match-wins decides whether a handshake starts: an NTLM rule shadowed by an earlier Basic rule
// for the same host is not reached, and an uncovered host starts nothing.
func TestAConnectionHandshakeStartsOnlyForTheFirstMatchingNTLMRule(t *testing.T) {
	c := storeWith(t,
		mustRule(t, "basic.test", SchemeBasic, "u", "p"),
		mustRule(t, "*.test", SchemeNTLMv2, "u", "p"),
	)
	if _, ok := c.BeginConnectionAuth("basic.test"); ok {
		t.Error("a handshake started for a host whose first rule is Basic")
	}
	if _, ok := c.BeginConnectionAuth("other.test"); !ok {
		t.Error("no handshake for a host whose first rule is NTLM")
	}
	if _, ok := c.BeginConnectionAuth("elsewhere.example"); ok {
		t.Error("a handshake started for a host no rule covers")
	}
}

// The NEGOTIATE carries flags only; the AUTHENTICATE answers the challenge once, and a second call is
// refused — an exchange presents its credential exactly once.
func TestAnExchangeAnswersItsChallengeExactlyOnce(t *testing.T) {
	c := storeWith(t, mustRule(t, "h.test", SchemeNTLMv2, "alice", "pw"))
	x, ok := c.BeginConnectionAuth("h.test")
	if !ok {
		t.Fatal("no exchange")
	}
	neg, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(x.Negotiate(), "NTLM "))
	if err != nil || binary.LittleEndian.Uint32(neg[8:12]) != ntlmMsgNegotiate {
		t.Fatalf("Negotiate() = %q, want a type-1 message", x.Negotiate())
	}
	answer, err := x.Authenticate([]string{"Negotiate", testChallenge()})
	if err != nil || !strings.HasPrefix(answer, "NTLM ") {
		t.Fatalf("Authenticate = %q, %v", answer, err)
	}
	if _, err := x.Authenticate([]string{testChallenge()}); err == nil {
		t.Fatal("a second Authenticate on one exchange presented the credential again")
	}
}

// A 401 with no CHALLENGE_MESSAGE — a bare "NTLM", or other schemes only — is refused by name.
func TestABareOfferIsNotAChallenge(t *testing.T) {
	c := storeWith(t, mustRule(t, "h.test", SchemeNTLMv2, "alice", "pw"))
	x, _ := c.BeginConnectionAuth("h.test")
	for _, challenges := range [][]string{{"NTLM"}, {"Negotiate", "Basic realm=\"x\""}, nil} {
		if _, err := x.Authenticate(challenges); !errors.Is(err, ErrNoNTLMChallenge) {
			t.Errorf("Authenticate(%q) = %v, want ErrNoNTLMChallenge", challenges, err)
		}
	}
}

// A rejection is recorded for the prompt as an NTLM failure of the host — when the prompt is on.
func TestARejectedExchangeIsRecordedAsAFailure(t *testing.T) {
	c := storeWith(t, mustRule(t, "h.test", SchemeNTLMv2, "alice", "pw"))
	x, _ := c.BeginConnectionAuth("h.test")
	x.Rejected([]string{"NTLM"})
	if len(c.Failures()) != 0 {
		t.Fatal("a failure was recorded with the prompt off")
	}
	c.SetPromptOnFailure(true)
	x.Rejected([]string{"Negotiate", "NTLM"})
	x.Rejected(nil)
	f := c.Failures()
	if len(f) != 1 || f[0].Host != "h.test" || f[0].Scheme != "NTLM" || f[0].Reason != FailureRejected || f[0].Count != 2 {
		t.Fatalf("failures = %+v, want one NTLM rejection of h.test counted twice", f)
	}
}

// "DOMAIN\user" splits; a bare account and a UPN do not.
func TestSplitNTLMUser(t *testing.T) {
	for in, want := range map[string][3]string{
		`CORP\alice`:   {"CORP", "alice", "true"},
		`alice`:        {"", "alice", "false"},
		`alice@corp.x`: {"", "alice@corp.x", "false"},
		`\alice`:       {"", "alice", "true"},
	} {
		d, u, ok := splitNTLMUser(in)
		if d != want[0] || u != want[1] || fmt.Sprint(ok) != want[2] {
			t.Errorf("splitNTLMUser(%q) = %q %q %v, want %v", in, d, u, ok, want)
		}
	}
}

// An exchange printed anywhere names the host and account and never the password.
func TestAnExchangeNeverPrintsItsPassword(t *testing.T) {
	c := storeWith(t, mustRule(t, "h.test", SchemeNTLMv2, "alice", "hunter2-secret"))
	x, _ := c.BeginConnectionAuth("h.test")
	for _, s := range []string{fmt.Sprint(x), fmt.Sprintf("%v", x), fmt.Sprintf("%+v", x)} {
		if strings.Contains(s, "hunter2-secret") {
			t.Fatalf("an exchange printed its password: %s", s)
		}
	}
}

// ---- NTLMv1 (opt-in), MS-NLMP 4.2.2 and 4.2.3 ----------------------------------------------

func vecHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The spec's own vectors: User "User", Domain "Domain", Password "Password", ServerChallenge
// 0123456789abcdef, ClientChallenge aaaaaaaaaaaaaaaa.
func TestNTLMv1ResponsesMatchTheVectorsMicrosoftPublished(t *testing.T) {
	key := ntowfv1("Password")
	if want := vecHex(t, "a4f49c406510bdcab6824ee7c30fd852"); !bytes.Equal(key, want) {
		t.Fatalf("NTOWFv1 = %x, want %x (4.2.2.1.2)", key, want)
	}
	server := [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	client := [8]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}

	nt, lm := ntlmv1Response(key, server, client, false)
	if want := vecHex(t, "67c43011f30298a2ad35ece64f16331c44bdbed927841f94"); !bytes.Equal(nt, want) {
		t.Errorf("NTLMv1 NtChallengeResponse = %x, want %x (4.2.2.2.1)", nt, want)
	}
	if !bytes.Equal(lm, nt) {
		t.Errorf("plain v1 LmChallengeResponse = %x, want the NT response (NoLMResponseNTLMv1; no LM hash is computed)", lm)
	}

	nt, lm = ntlmv1Response(key, server, client, true)
	if want := vecHex(t, "7537f803ae367128ca458204bde7caf81e97ed2683267232"); !bytes.Equal(nt, want) {
		t.Errorf("NTLMv1-with-ESS NtChallengeResponse = %x, want %x (4.2.3.2.2)", nt, want)
	}
	if want := vecHex(t, "aaaaaaaaaaaaaaaa 00000000000000000000000000000000"); !bytes.Equal(lm, want) {
		t.Errorf("ESS LmChallengeResponse = %x, want %x (4.2.3.2.1)", lm, want)
	}
}

// v1 is opt-in per rule: an ntlmv2 rule answering a v1-only challenge (no target info) refuses,
// and records no weak-authentication warning — it never falls back.
func TestAnNTLMv2RuleNeverAnswersWithNTLMv1(t *testing.T) {
	c := storeWith(t, mustRule(t, "h.test", SchemeNTLMv2, "alice", "pw"))
	x, _ := c.BeginConnectionAuth("h.test")
	if _, err := x.Authenticate([]string{v1OnlyChallenge(true)}); err == nil {
		t.Fatal("an ntlmv2 rule answered a challenge with no target info — that answer could only be NTLMv1")
	}
	if len(c.Warnings()) != 0 {
		t.Fatalf("an ntlmv2 rule recorded a weak-authentication warning: %+v", c.Warnings())
	}
}

// Every v1 handshake records the warning — with the prompt off, and once per handshake — and the
// rule's own view carries it where the rule is configured.
func TestEveryNTLMv1HandshakeRecordsAWeakAuthWarning(t *testing.T) {
	c := storeWith(t, mustRule(t, "h.test", SchemeNTLMv1, "alice", "pw"))
	if view := c.View(); len(view) != 1 || !strings.Contains(view[0].Warning, "NTLMv1") {
		t.Fatalf("the ntlmv1 rule's view carries no warning: %+v", view)
	}
	for i, ess := range []bool{true, false} {
		x, _ := c.BeginConnectionAuth("h.test")
		answer, err := x.Authenticate([]string{v1OnlyChallenge(ess)})
		if err != nil || !strings.HasPrefix(answer, "NTLM ") {
			t.Fatalf("v1 answer = %q, %v", answer, err)
		}
		w := c.Warnings()
		wantScheme := "NTLMv1"
		if ess {
			wantScheme = "NTLMv1 (ESS)"
		}
		if len(w) != 1 || w[0].Count != i+1 || w[0].Scheme != wantScheme || w[0].Host != "h.test" {
			t.Fatalf("after handshake %d warnings = %+v, want one %s warning counted %d", i+1, w, wantScheme, i+1)
		}
	}
	if v2 := (CredentialView{}); mustRule(t, "x", SchemeNTLMv2, "a", "b").view().Warning != v2.Warning {
		t.Error("an ntlmv2 rule's view carries a weak-scheme warning")
	}
}

// v1OnlyChallenge is a CHALLENGE_MESSAGE with no target info, ESS set or not.
func v1OnlyChallenge(ess bool) string {
	msg := make([]byte, 48)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmMsgChallenge)
	flags := ntlmNegotiateUnicode | ntlmNegotiateNTLM
	if ess {
		flags |= ntlmNegotiateExtendedSecurity
	}
	binary.LittleEndian.PutUint32(msg[20:24], flags)
	copy(msg[24:32], "\x01\x23\x45\x67\x89\xab\xcd\xef")
	return "NTLM " + base64.StdEncoding.EncodeToString(msg)
}

// Negotiate: the exchange moves into the Negotiate header when the server offers only that, sends
// raw NTLM there, answers a raw-NTLM Negotiate challenge, and refuses a SPNEGO token by name.
func TestNegotiateCarriesRawNTLMAndRefusesSPNEGO(t *testing.T) {
	c := storeWith(t, mustRule(t, "h.test", SchemeNTLMv2, "alice", "pw"))
	x, _ := c.BeginConnectionAuth("h.test")
	if x.SwitchToNegotiate([]string{testChallenge()}) {
		t.Fatal("switched to Negotiate although the server answered in the NTLM header")
	}
	if !x.SwitchToNegotiate([]string{"Negotiate"}) || x.Wire() != "Negotiate" || !strings.HasPrefix(x.Negotiate(), "Negotiate TlRMTVNTUAAB") {
		t.Fatalf("did not move to raw NTLM in the Negotiate header: %q", x.Negotiate())
	}
	if x.SwitchToNegotiate([]string{"Negotiate"}) {
		t.Error("switched twice")
	}
	answer, err := x.Authenticate([]string{"Negotiate " + strings.TrimPrefix(testChallenge(), "NTLM ")})
	if err != nil || !strings.HasPrefix(answer, "Negotiate TlRMTVNTUAAD") {
		t.Fatalf("Negotiate answer = %q, %v; want a raw NTLM AUTHENTICATE in the Negotiate header", answer, err)
	}
	// The host is remembered: the next exchange starts in the Negotiate header.
	if y, _ := c.BeginConnectionAuth("h.test"); y.Wire() != "Negotiate" {
		t.Error("the Negotiate-only host was not remembered")
	}

	z, _ := c.BeginConnectionAuth("h.test")
	spnego := base64.StdEncoding.EncodeToString([]byte{0xa1, 0x81, 0x9e, 0x30, 0x81, 0x9b, 0xa0, 0x03})
	if _, err := z.Authenticate([]string{"Negotiate " + spnego}); !errors.Is(err, ErrNegotiateNotNTLM) {
		t.Fatalf("a SPNEGO token was not refused by name: %v", err)
	}
}
