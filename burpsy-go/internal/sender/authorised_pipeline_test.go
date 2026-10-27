package sender

// The pipelined and keep-alive batch sends (W1's 0vzb.40) go through the same authorised
// chokepoint as every other send: a smuggled prefix can address a different target than the
// socket, so EVERY raw is gated on the bytes that will actually leave - hook output, not the
// caller's original - before any byte of the batch moves.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// One out-of-scope member is refused and counted, the rest of the batch still sends, and the
// results stay index-preserved: the caller zips nothing back together.
func TestSendPipelinedRefusesOneMemberWithoutAbortingTheBatch(t *testing.T) {
	target := newCountingTarget(t, nil)
	sc := core.NewScope()
	sc.AddInclude(target.host)
	sc.Add(core.NewScopeRuleWithPath(core.ScopeExclude, target.host, "/admin"))
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), target.host, target.port, false)

	raws := [][]byte{
		[]byte(fmt.Sprintf("GET /ok HTTP/1.1\r\nHost: %s\r\n\r\n", target.host)),
		[]byte(fmt.Sprintf("GET /admin/delete HTTP/1.1\r\nHost: %s\r\n\r\n", target.host)),
		[]byte(fmt.Sprintf("GET /also-ok HTTP/1.1\r\nHost: %s\r\n\r\n", target.host)),
	}
	results, err := a.SendPipelined(context.Background(), raws)
	if err != nil {
		t.Fatalf("one refused member aborted the batch: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("results = %d entries, want one per raw", len(results))
	}
	if a.Refused() != 1 {
		t.Fatalf("Refused = %d, want 1 for the /admin member", a.Refused())
	}
	if results[1].ReadErr == nil {
		t.Fatal("the refused member carries no error - a silent refusal")
	}
	for _, i := range []int{0, 2} {
		if results[i].ReadErr != nil || len(results[i].Response) == 0 {
			t.Fatalf("member %d did not complete: ReadErr=%v", i, results[i].ReadErr)
		}
	}
	if a.Sent() != 2 {
		t.Fatalf("Sent = %d, want 2 - the refused member's bytes must never leave", a.Sent())
	}
}

// The scope gate reads the hook's OUTPUT, never the caller's original: a plugin that rewrites a
// member onto an excluded path gets that member refused, proving hook -> gate -> pacing -> wire.
func TestSendPipelinedGatesTheHookOutput(t *testing.T) {
	target := newCountingTarget(t, nil)
	sc := core.NewScope()
	sc.AddInclude(target.host)
	sc.Add(core.NewScopeRuleWithPath(core.ScopeExclude, target.host, "/admin"))
	hook := HTTPHookFunc(func(ctx context.Context, phase string, raw []byte) HTTPHookResult {
		if phase == "request" {
			return HTTPHookResult{Raw: []byte(fmt.Sprintf("GET /admin HTTP/1.1\r\nHost: %s\r\n\r\n", target.host)), Changed: true}
		}
		return HTTPHookResult{Raw: raw}
	})
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()).WithHTTPHook(hook), target.host, target.port, false)

	raws := [][]byte{[]byte(fmt.Sprintf("GET /ok HTTP/1.1\r\nHost: %s\r\n\r\n", target.host))}
	results, err := a.SendPipelined(context.Background(), raws)
	if err != nil {
		t.Fatalf("batch aborted: %v", err)
	}
	if results[0].ReadErr == nil {
		t.Fatal("the gate authorised the caller's bytes, not the hook's replacement")
	}
	if a.Refused() != 1 {
		t.Fatalf("Refused = %d, want 1", a.Refused())
	}
	if got := target.total(); got != 0 {
		t.Fatalf("the target saw %d requests, want 0 - the refused replacement left anyway", got)
	}
}

// A pacer that cannot admit the batch declines every member by name and nothing reaches the wire.
func TestSendKeepAliveReportsAPacingDeclinePerMember(t *testing.T) {
	target := newCountingTarget(t, nil)
	a := NewAuthorisedSender(core.NewScopeAllowEverything(), NewSender(DefaultSenderConfig()), target.host, target.port, false).
		WithPace(groupPaceFunc(func(ctx context.Context, n int) (func(), error) {
			return nil, errors.New("pool full")
		}))
	raws := [][]byte{
		[]byte(fmt.Sprintf("GET /a HTTP/1.1\r\nHost: %s\r\n\r\n", target.host)),
		[]byte(fmt.Sprintf("GET /b HTTP/1.1\r\nHost: %s\r\n\r\n", target.host)),
	}
	results, err := a.SendKeepAlive(context.Background(), raws)
	if err == nil {
		t.Fatal("a pacing decline returned success")
	}
	if len(results) != 2 {
		t.Fatalf("results = %d entries, want one per member", len(results))
	}
	for i, r := range results {
		if r.ReadErr == nil || !strings.Contains(r.ReadErr.Error(), "pacing") {
			t.Fatalf("member %d ReadErr = %v, want the pacing decline named", i, r.ReadErr)
		}
	}
	if a.Sent() != 0 {
		t.Fatalf("Sent = %d, want 0 - a declined batch leaves nothing", a.Sent())
	}
}

// The happy path: every member rides the one connection in order, counted, with its own response.
func TestSendKeepAliveSendsEveryMemberInOrder(t *testing.T) {
	target := newCountingTarget(t, nil)
	a := NewAuthorisedSender(core.NewScopeAllowEverything(), NewSender(DefaultSenderConfig()), target.host, target.port, false).
		WithPace(groupPaceFunc(func(ctx context.Context, n int) (func(), error) { return func() {}, nil }))
	raws := [][]byte{
		[]byte(fmt.Sprintf("GET /one HTTP/1.1\r\nHost: %s\r\n\r\n", target.host)),
		[]byte(fmt.Sprintf("GET /two HTTP/1.1\r\nHost: %s\r\n\r\n", target.host)),
	}
	results, err := a.SendKeepAlive(context.Background(), raws)
	if err != nil {
		t.Fatalf("SendKeepAlive: %v", err)
	}
	for i, r := range results {
		if r.ReadErr != nil || len(r.Response) == 0 {
			t.Fatalf("member %d did not complete: ReadErr=%v", i, r.ReadErr)
		}
		if string(r.Raw) != string(raws[i]) {
			t.Fatalf("member %d Raw does not echo what was sent", i)
		}
	}
	if a.Sent() != 2 {
		t.Fatalf("Sent = %d, want 2", a.Sent())
	}
}

// An empty batch is a caller error, named, not a silent no-op.
func TestSendPipelinedRefusesAnEmptyBatch(t *testing.T) {
	a := NewAuthorisedSender(core.NewScopeAllowEverything(), NewSender(DefaultSenderConfig()), "127.0.0.1", 80, false)
	if _, err := a.SendPipelined(context.Background(), nil); err == nil {
		t.Fatal("an empty batch sent nothing and said nothing")
	}
}
