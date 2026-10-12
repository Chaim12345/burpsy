package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// The NoSQL injection check (burpsy-react-ui-v0ei.6) against the live vulnapp NoSQL family. Each guard
// has a safe twin it alone stops:
//
//   - TRUE must differ from FALSE: /nosql/safe/login and /nosql/safe/search cast operator objects to
//     the string "[object Object]", so every operator answers alike;
//   - the TRUE answer must be a success or redirect: /nosql/safe/allowlist refuses $ne/$gt/$regex
//     with a 400 and evaluates $eq/$in;
//   - the error-based operator proof needs the valid-operator control to be clean:
//     /nosql/safe/strict/login 500s with a CastError on every object;
//   - the error-based syntax proof needs the repaired control to be clean: /nosql/safe/report names
//     MongoServerError for any quote or backslash, escaped or not;
//   - the read-only gate: /nosql/safe/profile/update is a write with an injectable filter and must
//     receive nothing.
//
// /nosql/safe/echo (echoes the parsed value, operators included, around a constant result) is
// stopped by two guards at once, FALSE-equals-plain and TRUE-class consistency; /nosql/safe/where
// quotes its input properly.

func nosqliAudit(t *testing.T, path string, mod func(*ScanConfig)) ([]*Finding, uint32) {
	t.Helper()
	rt := startRuntimeTarget(t)
	id, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("%s was never seeded", path)
	}
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckNoSQLInjection: true}
	if mod != nil {
		mod(cfg)
	}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	outcome, findings := scan.AuditWithin(ctx, id, scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit of %s failed: %s", path, outcome.Error)
	}
	return findings, outcome.RequestsSent
}

func nosqliFindingIn(fs []*Finding) *Finding {
	for _, f := range fs {
		if f != nil && f.Name == nosqliIssue {
			return f
		}
	}
	return nil
}

func TestNoSQLiFindsEachTechnique(t *testing.T) {
	cases := []struct {
		path, param string
		mustSay     []string
	}{
		// Operator injection in a JSON body: {"$ne": x} for the password logs in.
		{"/nosql/login", "password", []string{`JSON field "password"`, `"$ne"`, `"$in"`, "HTTP 200", "HTTP 401"}},
		// Operator injection through bracket syntax in the query.
		{"/nosql/search?category=books", "category", []string{`query parameter "category"`, "category[$ne]=",
			"category[$regex]=^"}},
		// Syntax injection, boolean: '||'x'=='x matches every product.
		{"/nosql/where?category=books", "category", []string{"server-side JavaScript string", "'||'"}},
		// Syntax injection, error-based: the page is constant, only the MongoDB error shows it.
		{"/nosql/report?category=books", "category", []string{"MongoServerError", `escaped form \'`}},
		// Operator injection, error-based: an unknown operator's error, the valid $eq clean.
		{"/nosql/lookup?sku=A-100", "sku", []string{"unknown operator: $", "sku[$eq]="}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			fs, sent := nosqliAudit(t, c.path, nil)
			f := nosqliFindingIn(fs)
			if f == nil {
				t.Fatalf("%s is injectable but %q was not reported", c.path, nosqliIssue)
			}
			t.Logf("%d requests; evidence: %s", sent, f.Evidence)
			if f.Severity != "high" || f.Confidence != "firm" || f.Param != c.param {
				t.Errorf("severity/confidence/param = %s/%s/%s, want high/firm/%s", f.Severity, f.Confidence, f.Param, c.param)
			}
			for _, s := range c.mustSay {
				if !strings.Contains(f.Description, s) && !strings.Contains(f.Evidence, s) {
					t.Errorf("finding does not say %q:\n%s\nevidence: %s", s, f.Description, f.Evidence)
				}
			}
		})
	}
}

func TestNoSQLiStaysQuietOnTheSafeTwins(t *testing.T) {
	// The check must demonstrably work in this run before silence on a twin means anything.
	if fs, _ := nosqliAudit(t, "/nosql/login", nil); nosqliFindingIn(fs) == nil {
		t.Fatal("the vulnerable login did not fire, so the twins' silence proves nothing")
	}
	for path, why := range map[string]string{
		"/nosql/safe/login":                    "casts the fields to strings",
		"/nosql/safe/search?category=books":    "casts the category to a string",
		"/nosql/safe/strict/login":             "errors on every object alike",
		"/nosql/safe/echo?q=lamp":              "ignores the parameter and echoes it",
		"/nosql/safe/where?category=books":     "quotes the input as a JavaScript string",
		"/nosql/safe/report?category=books":    "names MongoServerError for the repaired control too",
		"/nosql/safe/allowlist?category=books": "refuses every operator but $eq and $in",
	} {
		fs, sent := nosqliAudit(t, path, nil)
		t.Logf("%s: %d requests", path, sent)
		if f := nosqliFindingIn(fs); f != nil {
			t.Errorf("%s %s but was reported: %s\nevidence: %s", path, why, f.Description, f.Evidence)
		}
		// The baseline and at least one TRUE/FALSE pair: silence must be a verdict.
		if sent < 3 {
			t.Errorf("%s: only %d requests sent, so the check never reached its controls", path, sent)
		}
	}
}

// A write is never probed: a match-everything operator there would change every record.
func TestNoSQLiSendsNothingToAWrite(t *testing.T) {
	fs, sent := nosqliAudit(t, "/nosql/safe/profile/update", nil)
	if f := nosqliFindingIn(fs); f != nil {
		t.Errorf("reported against a write: %s", f.Description)
	}
	if sent != 0 {
		t.Errorf("%d request(s) sent to a write endpoint, want 0", sent)
	}
}

func TestNoSQLiIsOffWithoutItsSwitch(t *testing.T) {
	fs, _ := nosqliAudit(t, "/nosql/login", func(c *ScanConfig) {
		c.CheckNoSQLInjection = false
		c.CheckActiveInjection = true // the descriptor it rides is on; the NoSQL half is not
	})
	if f := nosqliFindingIn(fs); f != nil {
		t.Errorf("reported with CheckNoSQLInjection off: %s", f.Description)
	}
}

func TestNoSQLiReadOnlyGate(t *testing.T) {
	for raw, want := range map[string]bool{
		"GET /api/products?category=x HTTP/1.1\r\n\r\n":        true,
		"POST /api/login HTTP/1.1\r\n\r\n":                     true,
		"POST /auth/sign-in HTTP/1.1\r\n\r\n":                  true,
		"POST /users/search HTTP/1.1\r\n\r\n":                  true,
		"POST /api/userLookup HTTP/1.1\r\n\r\n":                true,
		"POST /api/comments HTTP/1.1\r\n\r\n":                  false, // names no read
		"POST /api/user/update HTTP/1.1\r\n\r\n":               false,
		"POST /api/password/reset HTTP/1.1\r\n\r\n":            false,
		"POST /account/forgot-password/login HTTP/1.1\r\n\r\n": false, // a write word wins
		"GET /admin/deleteUser?id=3 HTTP/1.1\r\n\r\n":          false,
		"PUT /api/login HTTP/1.1\r\n\r\n":                      false,
		"DELETE /api/search HTTP/1.1\r\n\r\n":                  false,
	} {
		if got := nosqliReadOnly(raw); got != want {
			t.Errorf("nosqliReadOnly(%q) = %v, want %v", strings.SplitN(raw, "\r\n", 2)[0], got, want)
		}
	}
}

func TestNoSQLiSignaturesAreMongoSpecific(t *testing.T) {
	for body, want := range map[string]bool{
		`{"error":"MongoServerError: unknown operator: $foo"}`:             true,
		`CastError: Cast to ObjectId failed for value "x" at path "_id"`:   true,
		`MongoDB\\Driver\\Exception\\CommandException`:                     true,
		`pymongo.errors.OperationFailure: $where`:                          true,
		`$where clause: SyntaxError: unterminated string literal`:          true,
		`SyntaxError: Unexpected token ' in JSON at position 12`:           false,
		`You have an error in your SQL syntax near ''' at line 1`:          false,
		`TypeError: Cannot read properties of undefined (reading 'mongo')`: false,
		`<p>We use MongoDB Atlas for storage.</p>`:                         false,
	} {
		if got := nosqliSignature(body) != ""; got != want {
			t.Errorf("nosqliSignature(%q) matched=%v, want %v", body, got, want)
		}
	}
}
