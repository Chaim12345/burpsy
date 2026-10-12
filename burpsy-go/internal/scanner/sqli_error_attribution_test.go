package scanner

// burpsy-react-ui-j1mk.40: a SQL error signature counts only when a SQL parser, not a command
// shell, produced it.

import (
	"context"
	"strconv"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

func TestAShellDiagnosticIsNotSQLErrorEvidence(t *testing.T) {
	const base = `{"content":"sh: 1: ping: not found\n","isValid":true}`
	shell := []struct{ name, body string }{
		{"dash in a JSON string", `{"content":"sh: 1: Syntax error: Unterminated quoted string\n","isValid":true}`},
		{"dash, plain text", "sh: 1: Syntax error: Unterminated quoted string\n"},
		{"busybox ash", "sh: syntax error: unterminated quoted string\n"},
		{"absolute path", "/bin/sh: 1: Syntax error: Unterminated quoted string"},
		{"after other output", "PING 127.0.0.1\n<br>sh: 1: Syntax error: Unterminated quoted string"},
		{"HTML-escaped", "<pre>sh: 1: Syntax error: Unterminated quoted string</pre>"},
	}
	for _, c := range shell {
		got := ClassifySQLError(base, c.body)
		if got.Evidence.Confirms() {
			t.Errorf("%s: a shell's own diagnostic confirmed SQL injection (matched %v)", c.name, got.Matched)
		}
		if len(got.Foreign) == 0 {
			t.Errorf("%s: the shell-owned signature was not recorded as foreign: %+v", c.name, got)
		}
	}

	sql := []struct{ name, body string }{
		{"PostgreSQL relayed", "host lookup failed: ERROR:  unterminated quoted string at or near \"'\"\nLINE 1: SELECT 1"},
		{"PostgreSQL in JSON", `{"error":"ERROR: unterminated quoted string at or near \"'\""}`},
		// A word that merely ends in a shell's name is not that shell.
		{"not a shell name", "Hash: unterminated quoted string at or near"},
		// A shell line and a real database error on another line: the database error counts.
		{"both", "sh: 1: Syntax error: Unterminated quoted string\nERROR: unterminated quoted string at or near \"'\""},
		// A shell prefix with arbitrary text between it and the signature is not a shell's diagnostic.
		{"long gap", "sh: 1: psql -c select 1 from t where a=b returned: unterminated quoted string"},
	}
	for _, c := range sql {
		if got := ClassifySQLError(base, c.body); got.Evidence != InjectionEvidenceErrorSignature {
			t.Errorf("%s: a database error lost its SQL attribution: %+v", c.name, got)
		}
	}
}

// End to end: the shell-wrapped ping reports no SQL injection, while the endpoint that relays the
// SAME wording from PostgreSQL still does. The pair is what proves the rule attributes rather than
// suppresses a word.
func TestTheShellWrappedPingIsNotSQLInjectionButTheDatabaseTwinIs(t *testing.T) {
	audit := func(path string) []*Finding {
		scan, id := blindSQLiTarget(t, path)
		_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, AuditConfig{})
		return sqliFindingsNamed(findings, sqlInjectionIssue)
	}
	if got := audit("/ij/net/hosts?name=gateway"); len(got) == 0 {
		t.Fatalf("the PostgreSQL-relaying endpoint lost its %q finding", sqlInjectionIssue)
	}
	if got := audit("/ij/net/ping?host=127.0.0.1"); len(got) != 0 {
		t.Fatalf("the shell-wrapped ping reported %q: %s", sqlInjectionIssue, got[0].Description)
	}
}

// The no-sender path reads the captured response for the signature directly, and applies the same
// attribution: a captured shell diagnostic is not even a tentative SQL injection.
func TestTheOfflineSQLSignatureReadAttributesShellDiagnostics(t *testing.T) {
	offline := func(body string) ([]*Finding, error) {
		store := core.NewTrafficStore()
		reqID, err := store.Put([]byte("GET /ping?host=127.0.0.1 HTTP/1.1\r\nHost: example.test\r\n\r\n"), core.DirectionRequest)
		if err != nil {
			t.Fatal(err)
		}
		respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body), core.DirectionResponse)
		if err != nil {
			t.Fatal(err)
		}
		ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: "example.test", Port: 80,
			Method: "GET", Path: "/ping?host=127.0.0.1"}
		store.AddExchange(ex)
		scan := NewActiveScanner(store, zap.NewNop())
		return checkSQLInjectionCore(context.Background(), &CheckContext{Scanner: scan, Exchange: ex})
	}
	if got, _ := offline("sh: 1: Syntax error: Unterminated quoted string\n"); len(got) != 0 {
		t.Fatalf("a captured shell diagnostic was reported offline as SQL injection: %s", got[0].Description)
	}
	got, err := offline("ERROR:  unterminated quoted string at or near \"'\"\n")
	if err != nil || len(got) != 1 || got[0].Confidence != "tentative" {
		t.Fatalf("a captured PostgreSQL error should still be a tentative offline finding; got %v, %v", got, err)
	}
}
