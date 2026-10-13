package scanner

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// The weak-cryptography check (burpsy-react-ui-0vzb.28) against vulnapp's weak-crypto family. Each
// safe twin is kept quiet by a named guard, and the trace shows that guard decided it.

func TestWeakCryptoKnownAnswers(t *testing.T) {
	// LM and MD4 vectors are what OWASP VulnerableApp answered for "abc123xyz"; NTLM from OpenSSL
	// (MD4 of the UTF-16LE value); LM of "password" is the well-known E52CAC67419A9A224A3B108F3FA6CB6D.
	cases := []struct{ scheme, in, want string }{
		{"LM", "abc123xyz", "b5a8fd76dfe4b4771433090e52f69846"},
		{"LM", "password", "e52cac67419a9a224a3b108f3fa6cb6d"},
		{"MD4", "abc123xyz", "758eaa4ca0611ca47f5c1797baa60d1f"},
		{"NTLM", "abc123xyz", "75f655c3d47bd72e63f6c63b97e4040c"},
		{"NTLM", "password", "8846f7eaee8fb117ad06bdd830b7586c"},
		{"MySQL 4.1 (SHA-1 of SHA-1)", "password", "2470c0c06dee42fd1618bb99005adca2ec9d1e19"},
		{"MD5", "abc123xyz", "65816c49c4ecad1bdcb870caf8b22853"},
		{"SHA-1", "abc123xyz", "1d278c7a5057bac15828468f030f52f07caf70bb"},
		{"SHA-256", "abc123xyz", "604365fa1146d17e81aa41ef72ef03b07a5d3c2e44cfa6f9b817606779eccae6"},
	}
	for _, c := range cases {
		var got string
		for _, sc := range wcSchemes {
			if sc.name == c.scheme {
				got = hex.EncodeToString(sc.sum(c.in))
			}
		}
		if got != c.want {
			t.Errorf("%s(%q) = %s, want %s", c.scheme, c.in, got, c.want)
		}
	}
	if wcLM("pässword") != nil {
		t.Error("LM of a non-ASCII value must be undefined, not a guess")
	}
}

// A first-marker digest is confirmed only by the same scheme's digest of the second marker, in an
// answer that no longer carries the first one.
func TestWeakCryptoSecondMarkerConfirms(t *testing.T) {
	d := func(s string) string { b := md5.Sum([]byte(s)); return hex.EncodeToString(b[:]) }
	hits := wcDigestsIn("hash: "+d("firstmarker1"), "firstmarker1")
	if len(hits) != 1 || hits[0].scheme.name != "MD5" {
		t.Fatalf("first-marker hits = %+v, want MD5 only", hits)
	}
	if _, ok := wcConfirmed(hits[0], "hash: "+d("secondmarker"), "secondmarker"); !ok {
		t.Error("the second marker's MD5 did not confirm")
	}
	if _, ok := wcConfirmed(hits[0], "hash: "+d("firstmarker1"), "secondmarker"); ok {
		t.Error("an answer still showing the FIRST marker's digest confirmed: a page showing one fixed value")
	}
	if _, ok := wcConfirmed(hits[0], "hash: "+d("firstmarker1")+" "+d("secondmarker"), "secondmarker"); ok {
		t.Error("an answer carrying both digests confirmed: the first value is not a function of this input")
	}
	if _, ok := wcConfirmed(hits[0], "hash: 0123456789abcdef0123456789abcdef", "secondmarker"); ok {
		t.Error("an answer with an unrelated hex string confirmed")
	}
}

func wcAudit(t *testing.T, path string) ([]*Finding, map[string]string) {
	t.Helper()
	rt := startRuntimeTarget(t)
	id, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("%s was never seeded", path)
	}
	var mu sync.Mutex
	trace := map[string]string{}
	route, _, _ := strings.Cut(path, "?")
	weakCryptoTrace = func(target, param, outcome string) {
		if !strings.Contains(target, route) {
			return
		}
		mu.Lock()
		trace[param] = outcome
		mu.Unlock()
	}
	defer func() { weakCryptoTrace = nil }()
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckWeakCrypto: true}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	outcome, findings := scan.AuditWithin(ctx, id, scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit of %s failed: %s", path, outcome.Error)
	}
	mu.Lock()
	defer mu.Unlock()
	return findings, trace
}

var wcRows = []string{IssueWeakHashOfInput, IssueWeakPasswordHash, IssueECBEncryptionOfInput, IssuePlaintextPasswordStore}

func wcRowsIn(fs []*Finding) map[string]*Finding {
	out := map[string]*Finding{}
	for _, f := range fs {
		for _, r := range wcRows {
			if f != nil && f.Name == r {
				out[r] = f
			}
		}
	}
	return out
}

func wcRowNames(m map[string]*Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestWeakCryptoFindsEachVulnerableEndpoint(t *testing.T) {
	cases := []struct {
		path    string
		rows    []string
		mustSay []string
	}{
		{"/crypto/digest?token=report-2024", []string{IssueWeakHashOfInput},
			[]string{"unsalted MD5 digest", "A second marker"}},
		{"/crypto/fingerprint?code=device-7", []string{IssueWeakHashOfInput},
			[]string{"unsalted NTLM digest", "upper-case hex"}},
		{"/crypto/check?password=letmein", []string{IssueWeakPasswordHash},
			[]string{"unsalted SHA-256 digest", "A second marker"}},
		{"/crypto/account/login", []string{IssueWeakHashOfInput, IssueWeakPasswordHash},
			[]string{"original value", "unsalted SHA-1 digest", "the answer to the random marker"}},
		{"/crypto/account/login-legacy", []string{IssueWeakPasswordHash},
			[]string{"bcrypt verifies", "cost factor 4"}},
		{"/crypto/account/login-plain", []string{IssuePlaintextPasswordStore},
			[]string{`JSON member "passwordInDB"`, "not echoed"}},
		{"/crypto/seal?data=hello", []string{IssueECBEncryptionOfInput},
			[]string{"16-byte block", "no repeated block", "No token contains the plaintext"}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			fs, trace := wcAudit(t, c.path)
			got := wcRowsIn(fs)
			want := append([]string(nil), c.rows...)
			sort.Strings(want)
			if strings.Join(wcRowNames(got), "|") != strings.Join(want, "|") {
				t.Fatalf("rows = %v, want %v; trace %v", wcRowNames(got), want, trace)
			}
			var all strings.Builder
			for _, f := range got {
				all.WriteString(f.Evidence + "\n")
				if f.Param == "" {
					t.Errorf("%s names no parameter", f.Name)
				}
			}
			for _, s := range c.mustSay {
				if !strings.Contains(all.String(), s) {
					t.Errorf("evidence lacks %q:\n%s", s, all.String())
				}
			}
		})
	}
}

func TestWeakCryptoStaysQuietOnTwins(t *testing.T) {
	cases := []struct {
		path, param, guard string
	}{
		{"/crypto/safe/digest?token=report-2024", "token", "ecb: no repeating token"},
		{"/crypto/safe/strong?token=report-2024", "token", "a strong hash of a non-password value"},
		{"/crypto/safe/static?token=report-2024", "token", "original MD5: also in the marker answer"},
		{"/crypto/safe/check?password=letmein", "password", "ecb: no repeating token"},
		{"/crypto/safe/account/login", "password", "nothing computed was found"},
		{"/crypto/safe/account/login-echo", "password", "plaintext: the field is echoed"},
		{"/crypto/safe/seal?data=hello", "data", "ecb: no repeating token"},
		{"/crypto/safe/encode?data=hello", "data", "contains the plaintext"},
		{"/crypto/safe/receipt?data=hello", "data", "the non-periodic control's token repeats too"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			fs, trace := wcAudit(t, c.path)
			if got := wcRowsIn(fs); len(got) > 0 {
				for _, f := range got {
					t.Errorf("%s reported on a safe twin:\n%s", f.Name, f.Evidence)
				}
			}
			if !strings.Contains(trace[c.param], c.guard) {
				t.Errorf("parameter %q outcome = %q, want the guard %q to decide it (trace %v)",
					c.param, trace[c.param], c.guard, trace)
			}
		})
	}
}

func TestWeakCryptoDoesNotResendAccountChanges(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"POST /account/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=a&password=b", true},
		{"GET /check?password=b HTTP/1.1\r\nHost: x\r\n\r\n", true},
		{"POST /account/register HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=a&password=b", false},
		{"POST /account/password HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nold_password=a&new_password=b", false},
		{"POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\npassword=a&confirmPassword=a", false},
		{"POST /user/delete HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nid=1", false},
		{"PUT /check HTTP/1.1\r\nHost: x\r\n\r\n", false},
	}
	for _, c := range cases {
		if got := wcProbeable(c.raw); got != c.want {
			line, _, _ := strings.Cut(c.raw, "\r\n")
			t.Errorf("wcProbeable(%s ...) = %v, want %v", line, got, c.want)
		}
	}
}

func TestWeakCryptoPlaintextMemberIgnoresTheParameterItself(t *testing.T) {
	if _, ok := wcPlaintextMember(`{"password":"s3cret-pw"}`, "s3cret-pw", "password"); ok {
		t.Error("the parameter's own name echoed back counted as a stored record")
	}
	if k, ok := wcPlaintextMember(`{"content":{"user":"bob","stored":"s3cret-pw"}}`, "s3cret-pw", "password"); !ok || k != "stored" {
		t.Errorf("nested stored member = %q, %v", k, ok)
	}
	if _, ok := wcPlaintextMember(`<p>s3cret-pw</p>`, "s3cret-pw", "password"); ok {
		t.Error("a non-JSON page counted")
	}
}
