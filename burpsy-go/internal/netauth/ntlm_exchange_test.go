package netauth

import (
	"encoding/base64"
	"encoding/binary"
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
