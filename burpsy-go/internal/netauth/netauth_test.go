package netauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// The password used throughout. A distinctive literal so a leak test can search for it in
// serialised bytes and be sure a hit is this and not an artefact of the encoding.
const testPassword = "corr3ct-h0rse-battery-DO-NOT-LEAK"

const testPassphrase = "p12-pass-DO-NOT-LEAK"

func mustCredential(t *testing.T, host string, scheme Scheme, user, password, realm string) Credential {
	t.Helper()
	rule, err := NewCredential(host, scheme, user, password, realm)
	if err != nil {
		t.Fatalf("NewCredential(%q): %v", host, err)
	}
	return rule
}

// ---- the secret rule ----------------------------------------------------------------

// The structural half of the guarantee: marshalling anything this package hands out must
// not produce the password. Asserted against the whole store, its view, and one rule, so
// that an exported secret field added to any of the three fails here rather than in
// production.
func Test_no_secret_survives_being_marshalled(t *testing.T) {
	store := NewCredentials()
	store.Add(mustCredential(t, "example.com", SchemeBasic, "admin", testPassword, ""))
	store.Add(mustCredential(t, "*.internal", SchemeDigest, "svc", testPassword, "corp"))

	// Learn a challenge first, so the cached digest state — which is derived from the
	// password on every use — is populated when the store is marshalled. A leak through the
	// challenge cache would be missed by a test that skipped this.
	if usable, err := store.Learn("host.internal", `Digest realm="corp", nonce="abc123", qop="auth"`); !usable {
		t.Fatalf("Learn should accept a matching digest challenge, err=%v", err)
	}

	subjects := map[string]any{
		"the store":       store,
		"the view":        store.View(),
		"one rule":        mustCredential(t, "example.com", SchemeBasic, "admin", testPassword, ""),
		"one rule's view": mustCredential(t, "example.com", SchemeBasic, "admin", testPassword, "").view(),
	}
	for name, subject := range subjects {
		encoded, err := json.Marshal(subject)
		if err != nil {
			t.Fatalf("marshalling %s: %v", name, err)
		}
		if strings.Contains(string(encoded), testPassword) {
			t.Errorf("%s serialised the password.\ngot: %s\n"+
				"Secrets live in unexported fields precisely so encoding/json cannot reach them; an "+
				"exported one has been added somewhere and every handler now leaks it.", name, encoded)
		}
	}
}

// The redacted view must still say that a password *exists*, which is the honest-counting
// half: a blank field would read as "nothing configured" for a rule that is live.
func Test_the_view_reports_that_a_password_is_set_without_saying_what_it_is(t *testing.T) {
	store := NewCredentials()
	store.Add(mustCredential(t, "with.example.com", SchemeBasic, "admin", testPassword, ""))
	store.Add(mustCredential(t, "without.example.com", SchemeBasic, "admin", "", ""))

	views := store.View()
	if len(views) != 2 {
		t.Fatalf("expected 2 views, got %d", len(views))
	}
	if !views[0].HasPassword {
		t.Error("a rule with a password reports has_password false, so the panel will read as unconfigured")
	}
	if views[1].HasPassword {
		t.Error("a rule with an empty password reports has_password true, which claims a secret that is not there")
	}
	// An empty password is a legal configuration, not a validation failure: some appliances
	// use one, and refusing it would be this code inventing a policy HTTP does not have.
	if views[1].Username != "admin" {
		t.Errorf("the passwordless rule was not stored: %+v", views[1])
	}
}

// Secrets() is the one deliberate hole, and it has to actually work — persistence depends
// on it. Pinned so that "no secret leaves here" is never enforced by breaking the one
// caller allowed to read them.
func Test_secrets_are_readable_by_the_persistence_hole_and_round_trip(t *testing.T) {
	store := NewCredentials()
	store.Add(mustCredential(t, "example.com", SchemeDigest, "admin", testPassword, "corp"))

	rows := store.Secrets()
	if len(rows) != 1 || rows[0].Password != testPassword {
		t.Fatalf("Secrets() did not carry the password out for persistence: %+v", rows)
	}

	restored, failures := RestoreCredentials(rows)
	if len(failures) != 0 {
		t.Fatalf("restoring a row this build wrote should not fail: %v", failures)
	}
	// The restored rule must be able to authenticate, which is the only proof that the
	// secret survived the round trip — the view deliberately cannot tell us.
	if usable, err := restored.Learn("example.com", `Digest realm="corp", nonce="n1", qop="auth"`); !usable {
		t.Fatalf("restored digest rule could not learn its challenge: %v", err)
	}
	header, ok := restored.Authorization("example.com", http.MethodGet, "/")
	if !ok {
		t.Fatal("restored digest rule produced no Authorization header")
	}
	if strings.Contains(header, testPassword) {
		t.Errorf("the Digest header carries the password in the clear: %s", header)
	}

	// And the round trip must not have leaked it into the redacted view either.
	encoded, _ := json.Marshal(restored.View())
	if strings.Contains(string(encoded), testPassword) {
		t.Errorf("the restored store's view serialised the password: %s", encoded)
	}
}

// ---- schemes ------------------------------------------------------------------------

// The unsupported schemes must be refused by name, not silently coerced. Coercion to
// Basic would put the operator's password in a header the target never asked for.
func Test_unsupported_schemes_are_refused_and_named(t *testing.T) {
	for _, raw := range []string{"ntlm", "NTLMv1", "ntlmv2", "Negotiate", "kerberos"} {
		scheme, err := ParseScheme(raw)
		if err == nil {
			t.Errorf("ParseScheme(%q) returned %q instead of refusing; a selector option that does "+
				"nothing is the defect this is meant to prevent", raw, scheme)
			continue
		}
		if !strings.Contains(err.Error(), "not supported by this build") {
			t.Errorf("ParseScheme(%q) error does not say it is unsupported, so it reads like a typo: %v", raw, err)
		}
	}
	if _, err := ParseScheme("bogus"); err == nil {
		t.Error("an unknown scheme must be an error, never a fallback to basic")
	}
	if _, err := ParseScheme(""); err == nil {
		t.Error("an empty scheme must be refused: a rule with no scheme cannot present anything")
	}
	for _, raw := range []string{"basic", "BASIC", " Digest "} {
		if _, err := ParseScheme(raw); err != nil {
			t.Errorf("ParseScheme(%q) should be accepted case- and space-insensitively: %v", raw, err)
		}
	}
}

// Every scheme the panel is allowed to offer must be one ParseScheme accepts, and every
// scheme named unsupported must be one it refuses. This is what stops the panel and the
// engine from disagreeing about what exists.
func Test_the_advertised_scheme_lists_agree_with_the_parser(t *testing.T) {
	for _, scheme := range SupportedSchemes() {
		if _, err := ParseScheme(string(scheme)); err != nil {
			t.Errorf("SupportedSchemes() offers %q but ParseScheme refuses it: %v", scheme, err)
		}
	}
	for _, name := range UnsupportedSchemes() {
		if _, err := ParseScheme(name); err == nil {
			t.Errorf("UnsupportedSchemes() names %q but ParseScheme accepts it", name)
		}
	}
	if len(UnsupportedSchemes()) == 0 {
		t.Error("UnsupportedSchemes() is empty, so the panel has nothing to tell the operator " +
			"about NTLM and Negotiate and they are left to infer it from an absence")
	}
}

// ---- rule list semantics ------------------------------------------------------------

func Test_a_rule_needs_a_host_and_a_username(t *testing.T) {
	if _, err := NewCredential("  ", SchemeBasic, "admin", testPassword, ""); err == nil {
		t.Error("a blank host pattern must be refused: the rule could never match anything")
	}
	if _, err := NewCredential("example.com", SchemeBasic, " ", testPassword, ""); err == nil {
		t.Error("a blank username must be refused: the rule names no account")
	}
	if _, err := NewCredential("example.com", Scheme("ntlm"), "admin", testPassword, ""); err == nil {
		t.Error("NewCredential must refuse a scheme it does not implement even when handed one directly")
	}
}

// (host, scheme) is the key: re-adding replaces, and two schemes on one host coexist.
func Test_adding_the_same_host_and_scheme_replaces_rather_than_appends(t *testing.T) {
	store := NewCredentials()
	if replaced := store.Add(mustCredential(t, "example.com", SchemeBasic, "first", "a", "")); replaced {
		t.Error("the first Add reported a replacement")
	}
	if replaced := store.Add(mustCredential(t, "example.com", SchemeBasic, "second", "b", "")); !replaced {
		t.Error("re-adding the same host and scheme should report a replacement, not a second row")
	}
	if store.Len() != 1 {
		t.Fatalf("expected one rule after a replacement, got %d", store.Len())
	}
	if got := store.View()[0].Username; got != "second" {
		t.Errorf("the replacement did not take: username is %q", got)
	}
	// A different scheme on the same host is a different rule, not a replacement.
	if replaced := store.Add(mustCredential(t, "example.com", SchemeDigest, "third", "c", "")); replaced {
		t.Error("a different scheme on the same host was treated as a replacement")
	}
	if store.Len() != 2 {
		t.Fatalf("basic and digest on one host should be two rules, got %d", store.Len())
	}
}

// Removal is exact-match on (host, scheme), and an absent key reports false so the API can
// answer 404. Reported as absent rather than quietly succeeding, or a double-click on
// remove would look like two rules had existed.
func Test_removal_is_exact_and_reports_an_absent_rule(t *testing.T) {
	store := NewCredentials()
	store.Add(mustCredential(t, "*.example.com", SchemeBasic, "admin", testPassword, ""))
	store.Add(mustCredential(t, "*.example.com", SchemeDigest, "admin", testPassword, ""))

	// A host the pattern *matches* is not the pattern. Removal keys on the pattern text.
	if store.Remove("api.example.com", SchemeBasic) {
		t.Error("Remove matched a host against a pattern; removal must be exact on the pattern text, " +
			"or an operator cannot tell which row they deleted")
	}
	// The right pattern, the wrong scheme, must not take the other rule with it.
	if !store.Remove("*.example.com", SchemeBasic) {
		t.Fatal("Remove did not find the rule it was given exactly")
	}
	if store.Len() != 1 {
		t.Fatalf("removing basic took digest with it: %d rules left", store.Len())
	}
	if store.Remove("*.example.com", SchemeBasic) {
		t.Error("removing the same rule twice reported success the second time, which would make a " +
			"double-click look like two rules had existed")
	}
}

// First-match-wins, in the operator's order — not longest-pattern-wins. A `*` rule placed
// first shadows everything after it, which is visible on the panel rather than surprising.
func Test_matching_is_first_rule_wins_in_insertion_order(t *testing.T) {
	store := NewCredentials()
	store.Add(mustCredential(t, "*", SchemeBasic, "catch-all", "a", ""))
	store.Add(mustCredential(t, "api.example.com", SchemeBasic, "specific", "b", ""))

	rule, ok := store.Match("api.example.com")
	if !ok {
		t.Fatal("no rule matched a host covered by both")
	}
	if rule.Username != "catch-all" {
		t.Errorf("matching picked %q; the first matching rule must win, so a `*` placed first shadows "+
			"the rest and the panel's order is the order that decides", rule.Username)
	}
	if _, ok := NewCredentials().Match("example.com"); ok {
		t.Error("an empty store matched a host")
	}
}

// ---- egress: Basic ------------------------------------------------------------------

// Basic is preemptive and computable from the rule alone, so a matching rule always
// produces a header. The value is pinned against the RFC 7617 encoding rather than against
// this implementation's own output.
func Test_basic_credentials_are_presented_on_the_first_request(t *testing.T) {
	store := NewCredentials()
	store.Add(mustCredential(t, "*.example.com", SchemeBasic, "Aladdin", "open sesame", ""))

	header, ok := store.Authorization("api.example.com", http.MethodGet, "/x")
	if !ok {
		t.Fatal("a matching Basic rule produced no header; Basic needs no challenge")
	}
	// RFC 7617 §2's own example.
	if want := "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="; header != want {
		t.Errorf("Basic header is %q, want %q", header, want)
	}
	if _, ok := store.Authorization("other.test", http.MethodGet, "/"); ok {
		t.Error("a host no rule covers was given a credential anyway")
	}
}

// ---- egress: Digest -----------------------------------------------------------------

// The two-phase shape: nothing before a challenge, a header after one. "No header yet" is
// an ordinary answer, and collapsing it into an error would make the normal first request
// to a Digest host look like a failure.
func Test_digest_presents_nothing_until_it_has_been_challenged(t *testing.T) {
	store := NewCredentials()
	store.Add(mustCredential(t, "example.com", SchemeDigest, "admin", testPassword, ""))

	if _, ok := store.Authorization("example.com", http.MethodGet, "/"); ok {
		t.Fatal("Digest produced a header before any challenge, so it hashed a nonce it does not have")
	}
	usable, err := store.Learn("example.com", `Digest realm="corp", nonce="dcd98b7102dd2f0e", qop="auth", algorithm=MD5`)
	if !usable {
		t.Fatalf("Learn refused a well-formed challenge: %v", err)
	}
	header, ok := store.Authorization("example.com", http.MethodGet, "/dir/index.html")
	if !ok {
		t.Fatal("Digest produced no header after learning a challenge")
	}
	for _, want := range []string{
		`username="admin"`, `realm="corp"`, `nonce="dcd98b7102dd2f0e"`,
		`uri="/dir/index.html"`, "qop=auth", "nc=00000001", "cnonce=", "algorithm=MD5",
	} {
		if !strings.Contains(header, want) {
			t.Errorf("Digest header is missing %s\ngot: %s", want, header)
		}
	}
}

// The nonce counter must strictly increase for a given nonce, or a server enforcing replay
// protection answers another 401 — which reads exactly like a wrong password.
func Test_the_digest_nonce_count_increases_per_request(t *testing.T) {
	store := NewCredentials()
	store.Add(mustCredential(t, "example.com", SchemeDigest, "admin", testPassword, ""))
	if usable, err := store.Learn("example.com", `Digest realm="r", nonce="n", qop="auth"`); !usable {
		t.Fatalf("Learn: %v", err)
	}
	for i := 1; i <= 3; i++ {
		header, ok := store.Authorization("example.com", http.MethodGet, "/")
		if !ok {
			t.Fatalf("request %d produced no header", i)
		}
		if want := fmt.Sprintf("nc=%08x", i); !strings.Contains(header, want) {
			t.Errorf("request %d has no %s\ngot: %s", i, want, header)
		}
	}
}

// A repeated nonce means the credential was rejected, not that the nonce expired. Learn
// reports it unusable so the caller stops retrying instead of looping the operator's
// password at a host that keeps refusing it — which on an engagement is how an account
// gets locked out.
func Test_the_same_nonce_coming_back_is_reported_unusable_so_a_retry_cannot_loop(t *testing.T) {
	store := NewCredentials()
	store.Add(mustCredential(t, "example.com", SchemeDigest, "admin", testPassword, ""))
	challenge := `Digest realm="r", nonce="same", qop="auth"`

	if usable, _ := store.Learn("example.com", challenge); !usable {
		t.Fatal("the first challenge should be usable")
	}
	if usable, _ := store.Learn("example.com", challenge); usable {
		t.Error("the same nonce a second time was reported usable; a retry loop against a rejected " +
			"credential is how an account gets locked out")
	}
	// A genuinely new nonce is usable again — a stale nonce must not be conflated with a
	// wrong password.
	if usable, err := store.Learn("example.com", `Digest realm="r", nonce="fresh", qop="auth", stale=true`); !usable {
		t.Errorf("a fresh nonce should be usable: %v", err)
	}
}

// A rule scoped to a realm must not present its credentials to a different one. That is the
// credential-to-the-wrong-place mistake the field exists to prevent.
func Test_a_realm_scoped_rule_refuses_a_different_realm(t *testing.T) {
	store := NewCredentials()
	store.Add(mustCredential(t, "example.com", SchemeDigest, "admin", testPassword, "corp"))

	usable, err := store.Learn("example.com", `Digest realm="public", nonce="n", qop="auth"`)
	if usable {
		t.Fatal("credentials scoped to realm \"corp\" were accepted for realm \"public\"")
	}
	if err == nil || !strings.Contains(err.Error(), "realm") {
		t.Errorf("the refusal should say which realms disagreed, got %v", err)
	}
	if _, ok := store.Authorization("example.com", http.MethodGet, "/"); ok {
		t.Error("a header was produced despite the realm mismatch")
	}
}

// Changing a rule's password must invalidate any cached challenge for the hosts it covers:
// replaying a stale nonce with a new secret fails, and the failure would look like the new
// password being wrong.
func Test_replacing_a_rule_forgets_the_cached_challenge(t *testing.T) {
	store := NewCredentials()
	store.Add(mustCredential(t, "*.example.com", SchemeDigest, "admin", "old", ""))
	if usable, _ := store.Learn("api.example.com", `Digest realm="r", nonce="n", qop="auth"`); !usable {
		t.Fatal("Learn: the first challenge should be usable")
	}
	if _, ok := store.Authorization("api.example.com", http.MethodGet, "/"); !ok {
		t.Fatal("no header after the first challenge")
	}

	store.Add(mustCredential(t, "*.example.com", SchemeDigest, "admin", "new", ""))
	if _, ok := store.Authorization("api.example.com", http.MethodGet, "/"); ok {
		t.Error("the cached challenge survived a password change, so the next request would replay a " +
			"stale nonce with the new secret and the failure would read as a wrong password")
	}
}

// ---- challenge parsing --------------------------------------------------------------

// Refuse-by-default on unparseable input, which is the house rule. Each of these would
// otherwise produce a response the server cannot possibly accept, sent at the operator's
// real account and logged at the target.
func Test_unusable_challenges_are_refused_rather_than_guessed_at(t *testing.T) {
	cases := map[string]string{
		"no nonce":              `Digest realm="r", qop="auth"`,
		"not digest at all":     `Basic realm="r"`,
		"unknown algorithm":     `Digest realm="r", nonce="n", algorithm=SHA-512-256`,
		"auth-int only":         `Digest realm="r", nonce="n", qop="auth-int"`,
		"empty":                 ``,
		"scheme with no params": `Digest`,
	}
	for name, header := range cases {
		if _, err := ParseChallenge(header); err == nil {
			t.Errorf("%s: ParseChallenge(%q) was accepted; an unreadable challenge must be refused, "+
				"not guessed at", name, header)
		}
	}
}

// The parser must find the Digest challenge when a server offers several schemes in one
// header, and must handle a nonce containing a comma.
func Test_a_digest_challenge_is_found_among_others(t *testing.T) {
	challenge, err := ParseChallenge(`Basic realm="x", Digest realm="corp", nonce="a,b", qop="auth,auth-int"`)
	if err != nil {
		t.Fatalf("ParseChallenge: %v", err)
	}
	if challenge.Realm != "corp" {
		t.Errorf("realm is %q, want corp", challenge.Realm)
	}
	if challenge.Nonce != "a,b" {
		t.Errorf("nonce is %q, want a,b — a nonce may legally contain a comma", challenge.Nonce)
	}
	// Both qops offered: auth is selected rather than the challenge being refused.
	if !challenge.hasQOP("auth") {
		t.Error("a challenge offering auth and auth-int should select auth")
	}

	// The other order, and the regression this pins. `Digest …, Basic …` must not fold the
	// following scheme's parameters into the Digest challenge: reading `Basic realm="x"` as a
	// realm for Digest would hash the response against a realm the Digest server never sent.
	after, err := ParseChallenge(`Digest realm="corp", nonce="n1", qop="auth", Basic realm="wrong"`)
	if err != nil {
		t.Fatalf("ParseChallenge with Digest first: %v", err)
	}
	if after.Realm != "corp" {
		t.Errorf("realm is %q; the trailing Basic challenge's realm was read as Digest's", after.Realm)
	}

	// A bare scheme with no parameters between the two, which is what a Negotiate offer looks
	// like on a Windows front end.
	past, err := ParseChallenge(`Negotiate, Digest realm="corp", nonce="n2"`)
	if err != nil {
		t.Fatalf("ParseChallenge past a bare scheme: %v", err)
	}
	if past.Nonce != "n2" {
		t.Errorf("nonce is %q, want n2", past.Nonce)
	}
}

// An RFC 2069 challenge — no qop at all — still works, because old appliances emit them,
// and its header must not carry the parameters a 2069-only server would reject.
func Test_a_challenge_with_no_qop_uses_the_rfc_2069_response_shape(t *testing.T) {
	store := NewCredentials()
	store.Add(mustCredential(t, "old.example.com", SchemeDigest, "admin", testPassword, ""))
	if usable, err := store.Learn("old.example.com", `Digest realm="r", nonce="n"`); !usable {
		t.Fatalf("a qop-less challenge should be usable: %v", err)
	}
	header, ok := store.Authorization("old.example.com", http.MethodGet, "/")
	if !ok {
		t.Fatal("no header for a qop-less challenge")
	}
	for _, absent := range []string{"qop=", "nc=", "cnonce="} {
		if strings.Contains(header, absent) {
			t.Errorf("the RFC 2069 response carries %s, which a 2069-only server rejects\ngot: %s", absent, header)
		}
	}
}

// A username or realm containing a quote must not terminate the value early and turn the
// header into different parameters entirely.
func Test_quoted_values_are_escaped(t *testing.T) {
	store := NewCredentials()
	store.Add(mustCredential(t, "example.com", SchemeDigest, `ad"min\x`, testPassword, ""))
	if usable, err := store.Learn("example.com", `Digest realm="r", nonce="n", qop="auth"`); !usable {
		t.Fatalf("Learn: %v", err)
	}
	header, ok := store.Authorization("example.com", http.MethodGet, "/")
	if !ok {
		t.Fatal("no header")
	}
	if !strings.Contains(header, `username="ad\"min\\x"`) {
		t.Errorf("the username was not escaped into the quoted-string\ngot: %s", header)
	}
}

// ---- client certificate bindings ----------------------------------------------------

// Same exact-match removal, and a nil answer from For is the cheap common path that must
// stay correct: it runs on every TLS dial the tool makes.
func Test_an_unbound_host_gets_no_certificate(t *testing.T) {
	store := NewClientCerts()
	if store.For("example.com") != nil {
		t.Error("an empty binding list produced a certificate")
	}
	if store.Remove("example.com") {
		t.Error("removing from an empty list reported success, so the API would answer 200 for an absent binding")
	}
	if store.Len() != 0 || len(store.View()) != 0 {
		t.Error("an empty store is not reporting itself empty")
	}
}
