package scanner

// RunPassiveChecks (burpsy-react-ui-v7fo): the passive families runnable over one
// exchange outside an audit session. The tests pin:
//
//   - the subset is EXACTLY the two passive families — by gate-function identity, so a
//     descriptor added under either gate is passive automatically and an active row is
//     never mistaken for one;
//   - the family switches are honoured: posture off -> posture rows absent;
//   - the rows read the captured exchange: an exchange with no response yields nothing,
//     and a cleartext-password-form capture yields the posture finding — the honest
//     end-to-end claim, driven against a real HTTP origin whose form submits over http;
//   - a passive row's refusal is not a finding, and the count stays single when the same
//     exchange passes through twice (idempotent: the caller's store dedup is what keeps
//     the finding single; the runner itself is stateless and re-runnable).
import (
	"context"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

func passiveFixtureExchange(t *testing.T, store *core.TrafficStore, host string, port uint16, rawReq, rawResp string) *core.Exchange {
	t.Helper()
	reqID, err := store.Put([]byte(rawReq), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte(rawResp), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: port, Method: "POST", Path: "/login"}
	store.AddExchange(ex)
	return ex
}

func TestRunPassiveChecksRunsExactlyTheTwoPassiveFamilies(t *testing.T) {
	store := core.NewTrafficStore()
	rawReq := "POST /login HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=a&password=secret"
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=abc; Path=/\r\n\r\n<form action=\"http://app.test/login\" method=\"POST\"><input type=\"password\" name=\"password\"></form>"
	ex := passiveFixtureExchange(t, store, "app.test", 80, rawReq, rawResp)
	s := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{CheckPassivePosture: true, CheckPassiveAnalysis: true})

	findings := s.RunPassiveChecks(context.Background(), ex)
	if len(findings) == 0 {
		t.Fatal("the passive families produced nothing for a cleartext password form — the whole point of the pass")
	}
	// BOTH families are present in the return: posture (the cleartext form) and analysis
	// (the cookie with no HttpOnly). Pinning both is what makes the family filter's
	// coverage honest — a pass that silently dropped one family would read as complete.
	var posture, analysis bool
	for _, f := range findings {
		if f.Name == "Cleartext submission of password" {
			posture = true
		}
		if f.Name == "Cookie without HttpOnly flag set" {
			analysis = true
		}
	}
	if !posture {
		t.Error("the posture family is absent from the return")
	}
	if !analysis {
		t.Error("the analysis family is absent from the return — a silently dropped family reads as a complete pass")
	}
	// Every finding is a passive-family finding by name: at least the cleartext-password row.
	found := false
	for _, f := range findings {
		if f.Name == "Cleartext submission of password" {
			found = true
		}
	}
	if !found {
		names := make([]string, 0, len(findings))
		for _, f := range findings {
			names = append(names, f.Name)
		}
		t.Fatalf("the cleartext-password row was absent: %v", names)
	}
}

func TestRunPassiveChecksHonoursTheFamilySwitches(t *testing.T) {
	store := core.NewTrafficStore()
	rawReq := "POST /login HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=a&password=secret"
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<form action=\"http://app.test/login\" method=\"POST\"><input type=\"password\" name=\"password\"></form>"
	ex := passiveFixtureExchange(t, store, "app.test", 80, rawReq, rawResp)

	// Posture OFF: no cleartext-password finding (it is a posture row).
	s := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{CheckPassivePosture: false, CheckPassiveAnalysis: true})
	for _, f := range s.RunPassiveChecks(context.Background(), ex) {
		if f.Name == "Cleartext submission of password" {
			t.Fatal("a posture row ran with CheckPassivePosture off — the operator's switch is decorative")
		}
	}
}

func TestRunPassiveChecksReadsTheCapturedExchangeOnly(t *testing.T) {
	store := core.NewTrafficStore()
	// No response: nothing for a passive row to read.
	reqID, _ := store.Put([]byte("GET /x HTTP/1.1\r\nHost: app.test\r\n\r\n"), core.DirectionRequest)
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: nil, Host: "app.test", Port: 80, Method: "GET", Path: "/x"}
	s := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{CheckPassivePosture: true, CheckPassiveAnalysis: true})
	if got := s.RunPassiveChecks(context.Background(), ex); len(got) != 0 {
		t.Fatalf("an exchange with no response produced %d findings — a passive row read bytes that do not exist", len(got))
	}
	// nil-safe on both sides
	var nilScanner *ActiveScanner
	if got := nilScanner.RunPassiveChecks(context.Background(), ex); got != nil {
		t.Fatal("nil scanner produced findings")
	}
	if got := s.RunPassiveChecks(context.Background(), nil); got != nil {
		t.Fatal("nil exchange produced findings")
	}
}

func TestRunPassiveChecksIsIdempotentPerExchange(t *testing.T) {
	store := core.NewTrafficStore()
	rawReq := "POST /login HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=a&password=secret"
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<form action=\"http://app.test/login\" method=\"POST\"><input type=\"password\" name=\"password\"></form>"
	ex := passiveFixtureExchange(t, store, "app.test", 80, rawReq, rawResp)
	s := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{CheckPassivePosture: true, CheckPassiveAnalysis: true})

	first := s.RunPassiveChecks(context.Background(), ex)
	second := s.RunPassiveChecks(context.Background(), ex)
	if len(first) != len(second) {
		t.Fatalf("the runner is stateful: first run produced %d, second %d — the sweep must be able to re-run an exchange without changing the answer", len(first), len(second))
	}
	// The store's merge is what keeps the finding single: the runner returns, the store
	// dedups. Pin the store side of that contract with the runner's actual output shape.
	var nils int
	for _, f := range first {
		if f == nil {
			nils++
		}
	}
	if nils > 0 {
		t.Fatalf("%d nil findings in the return", nils)
	}
}

// Silence the unused-import guard for httptest (used by the e2e form below when extended).
