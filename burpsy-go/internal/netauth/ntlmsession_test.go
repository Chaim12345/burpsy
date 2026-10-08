package netauth

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// challengeHeaderFor builds an `NTLM <base64 CHALLENGE_MESSAGE>` header the way a server
// would, so the session tests drive the real parser rather than a shortcut into it.
func challengeHeaderFor(t *testing.T, serverChallenge [8]byte, targetInfo []byte) string {
	t.Helper()
	msg := make([]byte, 48)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmMsgChallenge)
	binary.LittleEndian.PutUint32(msg[20:24], ntlmClientFlags)
	copy(msg[24:32], serverChallenge[:])
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(msg[44:48], 48)
	msg = append(msg, targetInfo...)
	return "NTLM " + base64.StdEncoding.EncodeToString(msg)
}

func ntlmStore(t *testing.T, spec CredentialSpec) *Credentials {
	t.Helper()
	rule, err := NewCredential(spec)
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	store := NewCredentials()
	store.Add(rule)
	return store
}

// The end-to-end claim this file exists for: driving the session the way the sender does,
// with the section 4.2.4 inputs pinned, must reproduce Microsoft's published NTProofStr.
//
// The three-leg API is where an implementation that is individually correct can still be
// wrong — the password reaching NTOWFv2 with the wrong domain, the challenge parsed from
// the wrong header, the client challenge drawn twice so the NT and LM responses disagree.
// Only running the legs catches those.
func Test_the_handshake_reproduces_the_MS_NLMP_NTProofStr_end_to_end(t *testing.T) {
	store := ntlmStore(t, CredentialSpec{
		Host: "server.example.com", Scheme: SchemeNTLMv2,
		Username: vectorUser, Password: vectorPassword, Domain: vectorDomain,
	})

	session, ok := store.StartNTLM("server.example.com")
	if !ok {
		t.Fatal("StartNTLM refused a host with an NTLMv2 rule on it")
	}
	// Pin the two live inputs to the spec's, which is the whole reason they are injectable.
	session.clientChallenge = func() ([8]byte, error) { return vectorClientChallenge, nil }

	if negotiate := session.Negotiate(); !strings.HasPrefix(negotiate, "NTLM ") {
		t.Fatalf("the first leg is not an NTLM Authorization value: %q", negotiate)
	}

	// The spec's target info carries no MsvAvTimestamp, so no MIC is expected and the
	// timestamp comes from this seam — pinned to the spec's all-zero Time.
	session.timestamp = func() [8]byte { return vectorTime }

	header, err := session.Authenticate(challengeHeaderFor(t, vectorServerChallenge, vectorTargetInfo()))
	if err != nil {
		t.Fatalf("the third leg failed: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "NTLM "))
	if err != nil {
		t.Fatalf("the AUTHENTICATE header is not valid base64: %v", err)
	}
	ntLen := int(binary.LittleEndian.Uint16(raw[20:22]))
	ntOff := int(binary.LittleEndian.Uint32(raw[24:28]))
	if ntOff+ntLen > len(raw) || ntLen < 16 {
		t.Fatalf("the NT response field points at %d..%d of a %d-byte message", ntOff, ntOff+ntLen, len(raw))
	}

	const wantProof = "68cd0ab851e51c96aabc927bebef6a1c"
	if got := hexOf(raw[ntOff : ntOff+16]); got != wantProof {
		t.Fatalf("the handshake produced NTProofStr %s, but MS-NLMP §4.2.4.2.2 says %s for these inputs.\n"+
			"The pieces can each be right and the assembly still wrong — a domain lost between the rule "+
			"and NTOWFv2, or a second client challenge drawn between the NT and LM responses — and this "+
			"is the only test that runs them together.", got, wantProof)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

func Test_a_session_is_single_use(t *testing.T) {
	// The server retires the nonce once it has seen a response. A second AUTHENTICATE
	// against the same challenge is refused here rather than sent, because on the wire it
	// fails as though the password were wrong — and an operator chasing that would change
	// the password, not the retry.
	store := ntlmStore(t, CredentialSpec{Host: "h", Scheme: SchemeNTLMv2, Username: "u", Password: "p"})
	session, _ := store.StartNTLM("h")
	session.Negotiate()
	header := challengeHeaderFor(t, vectorServerChallenge, vectorTargetInfo())

	if _, err := session.Authenticate(header); err != nil {
		t.Fatalf("the first Authenticate failed: %v", err)
	}
	if _, err := session.Authenticate(header); err == nil {
		t.Error("a session answered a second challenge; the response would be computed against a nonce " +
			"the server has already retired, which looks exactly like a wrong password")
	}
}

func Test_authenticate_before_negotiate_is_refused_rather_than_guessed(t *testing.T) {
	// The MIC covers all three messages. Building one without the first leg would mean
	// inventing bytes the server never received, so the MIC would never verify — and the
	// symptom would be a 401 with nothing pointing at the caller's ordering mistake.
	store := ntlmStore(t, CredentialSpec{Host: "h", Scheme: SchemeNTLMv2, Username: "u", Password: "p"})
	session, _ := store.StartNTLM("h")

	_, err := session.Authenticate(challengeHeaderFor(t, vectorServerChallenge, vectorTargetInfo()))
	if err == nil {
		t.Fatal("Authenticate ran without a preceding Negotiate; the message integrity code would cover " +
			"a first leg that was never sent")
	}
	if !strings.Contains(err.Error(), "Negotiate") {
		t.Errorf("the refusal does not name the missing leg: %v", err)
	}
}

func Test_a_server_timestamp_turns_the_MIC_on_and_its_absence_turns_it_off(t *testing.T) {
	// MS-NLMP 3.1.5.1.2. Modern AD sends MsvAvTimestamp and rejects an AUTHENTICATE with no
	// MIC; an older server sends none and has nothing to validate one against. Getting this
	// backwards fails against exactly one of the two, which is the hardest kind of bug to
	// attribute from the operator's chair.
	store := ntlmStore(t, CredentialSpec{Host: "h", Scheme: SchemeNTLMv2, Username: "u", Password: "p"})

	withTimestamp := appendAVPair(nil, avIDNbDomain, utf16le("CORP"))
	withTimestamp = appendAVPair(withTimestamp, avIDTimestamp, make([]byte, 8))
	withTimestamp = appendAVPair(withTimestamp, avIDEOL, nil)

	for name, targetInfo := range map[string][]byte{
		"a server that sent MsvAvTimestamp":    withTimestamp,
		"a server that sent no MsvAvTimestamp": vectorTargetInfo(),
	} {
		session, _ := store.StartNTLM("h")
		session.Negotiate()
		header, err := session.Authenticate(challengeHeaderFor(t, vectorServerChallenge, targetInfo))
		if err != nil {
			t.Fatalf("%s: the handshake failed: %v", name, err)
		}
		raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "NTLM "))
		mic := raw[72:88]
		zero := true
		for _, b := range mic {
			if b != 0 {
				zero = false
			}
		}
		wantMIC := name == "a server that sent MsvAvTimestamp"
		if wantMIC && zero {
			t.Errorf("%s: the AUTHENTICATE message carries no MIC. MS-NLMP 3.1.5.1.2 requires one when the "+
				"challenge carried a timestamp, and current Active Directory rejects the message without it", name)
		}
		if !wantMIC && !zero {
			t.Errorf("%s: the AUTHENTICATE message carries a MIC (%x) the server never asked for and has no "+
				"MsvAvFlags bit telling it to check", name, mic)
		}
	}
}

func Test_StartNTLM_declines_a_host_whose_rule_is_basic_or_digest(t *testing.T) {
	// "This host uses Digest" is a normal answer to "should I run an NTLM handshake", not
	// a failure — the caller then takes the header path it already had. Returning an error
	// would put a spurious line in front of the operator on every Basic request.
	for _, scheme := range []Scheme{SchemeBasic, SchemeDigest} {
		store := ntlmStore(t, CredentialSpec{Host: "h", Scheme: scheme, Username: "u", Password: "p"})
		if _, ok := store.StartNTLM("h"); ok {
			t.Errorf("StartNTLM started a handshake for a %s rule; the credential would go out under a "+
				"scheme the operator did not choose", scheme)
		}
	}
	if _, ok := NewCredentials().StartNTLM("unconfigured.example.com"); ok {
		t.Error("StartNTLM started a handshake for a host with no rule at all")
	}
}

func Test_NTLMChallengeHeader_picks_NTLM_and_leaves_Negotiate_alone(t *testing.T) {
	// A 401 commonly offers several schemes in several headers. Answering the first one
	// would send an NTLM message to a Negotiate challenge.
	got, ok := NTLMChallengeHeader([]string{"Negotiate", "NTLM TlRMTVNTUAACAAAA", `Basic realm="x"`})
	if !ok || !strings.HasPrefix(got, "NTLM ") {
		t.Fatalf("the NTLM challenge was not picked out of a multi-scheme 401: got %q, ok=%v", got, ok)
	}

	// Negotiate can wrap NTLM, but this build does not implement SPNEGO's GSS-API framing.
	// Treating a Negotiate offer as an NTLM one would work against some servers and not
	// others — the intermittent failure that makes an operator blame the target.
	if _, ok := NTLMChallengeHeader([]string{"Negotiate", `Basic realm="x"`}); ok {
		t.Error("a Negotiate challenge was accepted as an NTLM one; this build does not speak SPNEGO and " +
			"answering with a bare NTLMSSP message succeeds only by accident")
	}
	if _, ok := NTLMChallengeHeader(nil); ok {
		t.Error("a 401 with no WWW-Authenticate at all reported an NTLM challenge")
	}
}

func Test_a_server_controlled_challenge_header_cannot_flood_an_error_message(t *testing.T) {
	// Errors from here reach the operator's screen. An unbounded echo of a header the
	// target chose would let it paste arbitrary text — including text dressed up as
	// burpsy's own output — into burpsy's UI.
	_, err := decodeNTLMHeader("Bearer " + strings.Repeat("A", 4096))
	if err == nil {
		t.Fatal("a non-NTLM challenge header was accepted")
	}
	if len(err.Error()) > 200 {
		t.Errorf("the error echoes %d characters of a server-controlled header; it must be bounded", len(err.Error()))
	}
}

func Test_a_bare_NTLM_offer_with_no_challenge_is_named_as_such(t *testing.T) {
	// A server that answers the NEGOTIATE leg with `WWW-Authenticate: NTLM` and nothing
	// else is misconfigured, and that is a different problem from a mangled base64 blob.
	// One error for both would send the operator to the wrong place.
	if _, err := decodeNTLMHeader("NTLM"); err == nil || !strings.Contains(err.Error(), "no challenge") {
		t.Errorf("a bare `NTLM` offer is not reported as a missing challenge: %v", err)
	}
	if _, err := decodeNTLMHeader("NTLM !!!not-base64!!!"); err == nil || !strings.Contains(err.Error(), "base64") {
		t.Errorf("a mangled challenge blob is not reported as a base64 problem: %v", err)
	}
}

// ---- field discipline ---------------------------------------------------------------

func Test_a_field_belonging_to_another_scheme_is_refused_not_ignored(t *testing.T) {
	// Storing it and ignoring it is the defect: the operator sees the value on the panel,
	// believes it is in force, and has no way to find out it was dropped.
	cases := map[string]CredentialSpec{
		"a realm on an NTLMv2 rule": {Host: "h", Scheme: SchemeNTLMv2, Username: "u", Password: "p", Realm: "r"},
		"a realm on a Basic rule":   {Host: "h", Scheme: SchemeBasic, Username: "u", Password: "p", Realm: "r"},
		"a domain on a Basic rule":  {Host: "h", Scheme: SchemeBasic, Username: "u", Password: "p", Domain: "CORP"},
		"a domain on a Digest rule": {Host: "h", Scheme: SchemeDigest, Username: "u", Password: "p", Domain: "CORP"},
		"a workstation on Digest":   {Host: "h", Scheme: SchemeDigest, Username: "u", Password: "p", Workstation: "WS"},
	}
	for name, spec := range cases {
		if _, err := NewCredential(spec); err == nil {
			t.Errorf("%s was accepted; it would sit on the panel looking configured and never reach the wire", name)
		}
	}
}

func Test_a_backslash_in_a_username_is_a_domain_only_for_NTLM(t *testing.T) {
	// A backslash is an ordinary character in a Basic or Digest user-id. Splitting on it
	// there would change which account a working credential names.
	ntlm, err := NewCredential(CredentialSpec{Host: "h", Scheme: SchemeNTLMv2, Username: `CORP\alice`, Password: "p"})
	if err != nil {
		t.Fatalf(`CORP\alice was refused for an NTLMv2 rule: %v`, err)
	}
	if ntlm.Domain != "CORP" || ntlm.Username != "alice" {
		t.Errorf(`CORP\alice split into domain %q user %q; Windows accepts that form and so must this`,
			ntlm.Domain, ntlm.Username)
	}

	basic, err := NewCredential(CredentialSpec{Host: "h", Scheme: SchemeBasic, Username: `weird\name`, Password: "p"})
	if err != nil {
		t.Fatalf(`a Basic username containing a backslash was refused: %v`, err)
	}
	if basic.Username != `weird\name` {
		t.Errorf("a Basic username was split on its backslash into %q; RFC 7617 allows any character but a "+
			"colon in the user-id, and splitting it authenticates as a different account", basic.Username)
	}
}

func Test_two_spellings_of_the_domain_are_refused_together_rather_than_ranked(t *testing.T) {
	// The house rule: two forms of one field are refused together, never silently
	// competing. A precedence rule here would mean the panel shows one domain and the wire
	// carries the other.
	_, err := NewCredential(CredentialSpec{
		Host: "h", Scheme: SchemeNTLMv2, Username: `CORP\alice`, Password: "p", Domain: "OTHER",
	})
	if err == nil {
		t.Fatal(`a rule naming domain CORP in the username and OTHER in the domain field was accepted; ` +
			"whichever one lost, the panel would be showing a domain that is not the one on the wire")
	}
	if !strings.Contains(err.Error(), "CORP") || !strings.Contains(err.Error(), "OTHER") {
		t.Errorf("the refusal does not name both domains, so the operator cannot see which is which: %v", err)
	}

	// The same domain said twice is agreement, not a conflict, and must be accepted.
	if _, err := NewCredential(CredentialSpec{
		Host: "h", Scheme: SchemeNTLMv2, Username: `corp\alice`, Password: "p", Domain: "CORP",
	}); err != nil {
		t.Errorf("a rule that names the same domain twice (case-insensitively) was refused: %v", err)
	}
}

func Test_an_NTLM_session_cannot_serialise_the_key_it_derived(t *testing.T) {
	// The same structural guarantee as the rest of the package: NTOWFv2 is as good as the
	// password for authenticating, so it lives in an unexported field where encoding/json
	// cannot reach it. A handler that marshalled a session by mistake must still not leak.
	store := ntlmStore(t, CredentialSpec{
		Host: "h", Scheme: SchemeNTLMv2, Username: "u", Password: testPassword, Domain: "CORP",
	})
	session, _ := store.StartNTLM("h")
	session.Negotiate()

	encoded, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("marshalling a session failed outright, which is not the guarantee under test: %v", err)
	}
	if strings.Contains(string(encoded), testPassword) {
		t.Fatalf("a marshalled NTLM session carries the password: %s", encoded)
	}
	if string(encoded) != "{}" {
		t.Errorf("a marshalled NTLM session is %s, not {}; a field became exported and the next one may "+
			"be the derived key, which authenticates just as well as the password", encoded)
	}
}

func Test_the_redacted_view_shows_the_domain_and_still_hides_the_password(t *testing.T) {
	// The domain is not a secret — it crosses the wire in clear UTF-16 — and hiding it
	// would leave an operator unable to tell a wrong domain from a wrong password, since
	// both produce the same 401.
	store := ntlmStore(t, CredentialSpec{
		Host: "h", Scheme: SchemeNTLMv2, Username: "alice", Password: testPassword,
		Domain: "CORP", Workstation: "LAPTOP",
	})
	encoded, err := json.Marshal(store.View())
	if err != nil {
		t.Fatalf("marshalling the view failed: %v", err)
	}
	body := string(encoded)
	if strings.Contains(body, testPassword) {
		t.Fatalf("the NTLMv2 rule's view serialised the password: %s", body)
	}
	for _, want := range []string{`"domain":"CORP"`, `"workstation":"LAPTOP"`, `"has_password":true`} {
		if !strings.Contains(body, want) {
			t.Errorf("the view does not carry %s, so the panel cannot show which account the rule uses: %s", want, body)
		}
	}
}
