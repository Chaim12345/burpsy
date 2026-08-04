package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"go.uber.org/zap"
)

// HARD-03 for the session-macro surface reached from the CLI. The web layer has its own test
// (internal/web/session_scope_test.go); this one exists because `burpsy session login` runs its own
// MacroStepRunner, and a chokepoint that only one of two entry points goes through is not a
// chokepoint. Both used to call sender.Send, which authorises nothing.
//
// The assertion is a counter on the target, not on the sender: only a target that saw nothing proves
// the dial did not happen.
func TestCliMacroRunnerRefusesAStepOutsideTheEngagementScope(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("X-Auth", "1")
		io.WriteString(w, "logged in")
	}))
	defer target.Close()

	host, _, _, _, err := parseTargetURL(target.URL)
	if err != nil {
		t.Fatalf("parseTargetURL(%q): %v", target.URL, err)
	}

	scope := core.NewScope()
	scope.AddInclude(host)
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, host, "/login"))
	ctx := &cliContext{
		scope:   scope,
		logger:  zap.NewNop(),
		sess:    session.NewCoordinator(zap.NewNop()),
		toolLog: toollog.New(),
		sender:  sender.NewSender(sender.DefaultSenderConfig()),
		out:     io.Discard,
	}
	run := ctx.cliMacroRunner(5)

	if _, err := run(session.MacroStep{Method: "POST", URL: target.URL + "/login"}); err == nil {
		t.Fatal("a macro step outside the engagement scope must fail, not send")
	} else if !strings.Contains(err.Error(), "refused") {
		t.Fatalf("error = %v, want a scope refusal naming the rule that produced it", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("the target saw %d requests, want 0", got)
	}

	// The in-scope step still goes out, so the zero above is a refusal rather than a runner that
	// cannot run.
	res, err := run(session.MacroStep{Method: "GET", URL: target.URL + "/account"})
	if err != nil {
		t.Fatalf("the in-scope step must be sent: %v", err)
	}
	if res.Status != 200 {
		t.Fatalf("status = %d, want 200", res.Status)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("the target saw %d requests, want exactly the in-scope one", got)
	}
}
