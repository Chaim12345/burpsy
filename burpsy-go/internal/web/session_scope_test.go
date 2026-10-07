package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// HARD-03 for the session-macro surface: login and recovery traffic is authorised through the shared
// chokepoint, and the proof is a target that received nothing.
//
// This is the per-surface test HARD-03 asks for and did not have. It was missing at exactly the wrong
// moment: the macro runner called sender.Send, which authorises nothing, so a login macro pointed
// outside the engagement — by a typo, a stale saved rule, or a {{placeholder}} interpolating into a
// path — put credentials on the wire with no scope decision made about them. The chokepoint existed;
// this surface simply did not go through it.
//
// Every assertion here is a hit count on the target, never a refusal counter on the sender. A counter
// proves bookkeeping, and bookkeeping can be correct while the request still goes out; only a silent
// target proves the dial did not happen.
//
// The engagement scope (core.Scope) and a session rule's own scope are different things and both
// matter here: the rule's scope decides which rule covers a host, and the engagement scope decides
// whether anything may be sent there at all. These tests set the rule to cover the target — so the
// coordinator genuinely selects it and genuinely tries to run the macro — and let the engagement scope
// be the thing that stops it.

// scopedSessionTestServer is sessionTestServer with a stated engagement scope rather than the empty,
// default-allow one.
func scopedSessionTestServer(scope *core.Scope) *Server {
	return NewServer(core.NewTrafficStore(), scope).
		WithSender(sender.NewSender(sender.DefaultSenderConfig()))
}

// postLogin posts a probe to /api/session/login and decodes the body whatever the status is. The
// refusal outcomes here are 502s, and postJSONInto only decodes 2xx.
func postLogin(t *testing.T, srv *Server, probeURL string) (int, wireLoginResp) {
	t.Helper()
	rec := postJSON(t, srv, "/api/session/login", map[string]any{
		"probe": map[string]any{"method": "GET", "url": probeURL, "headers": []any{}, "body": ""},
	})
	var resp wireLoginResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %d response %q: %v", rec.Code, rec.Body.String(), err)
	}
	return rec.Code, resp
}

// The sharp case: the probe is in scope and goes out, the macro step is not and does not. The probe's
// hit is what makes the macro step's zero mean something — without it, a zero would be equally well
// explained by a sender that cannot send at all.
func TestALoginMacroStepOutsideTheEngagementScopeNeverReachesTheTarget(t *testing.T) {
	target := newLoginTarget(t, true)
	host, _, _, err := targetParts(target.url)
	if err != nil {
		t.Fatalf("targetParts(%q): %v", target.url, err)
	}

	// In scope everywhere on this host except the login endpoint itself.
	scope := core.NewScope()
	scope.AddInclude(host)
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, host, "/login"))
	srv := scopedSessionTestServer(scope)
	installLoginRule(t, srv, target, host, 3)

	code, resp := postLogin(t, srv, target.url+"/account")

	if got := target.hitCount("/login"); got != 0 {
		t.Fatalf("/login was hit %d times, want 0: a macro step outside the engagement scope must never reach the target", got)
	}
	if got := target.hitCount("/account"); got != 1 {
		t.Fatalf("/account was hit %d times, want 1: the in-scope probe must still be sent, or the zero above proves nothing", got)
	}
	if resp.Outcome == "recovered" {
		t.Fatal("outcome = recovered, but the login macro was never sent: a refused step must not be reported as a login")
	}
	// macro_failed is the honest outcome — the step could not be sent — and 502 is how this handler
	// reports "nothing left the process".
	if resp.Outcome != "macro_failed" || code != http.StatusBadGateway {
		t.Fatalf("outcome = %q with status %d, want macro_failed with 502: %+v", resp.Outcome, code, resp)
	}
	if resp.Error == "" {
		t.Fatal("macro_failed must carry the refusal, so an operator learns which rule tripped rather than that 'login failed'")
	}
	if resp.StepIndex == nil || *resp.StepIndex != 0 {
		t.Fatalf("step_index = %v, want 0: the operator needs the step that was refused", resp.StepIndex)
	}
}

// A whole host outside the engagement: nothing at all leaves, probe included.
func TestALoginForAHostOutsideTheEngagementScopeSendsNothingAtAll(t *testing.T) {
	target := newLoginTarget(t, true)
	host, _, _, err := targetParts(target.url)
	if err != nil {
		t.Fatalf("targetParts(%q): %v", target.url, err)
	}

	scope := core.NewScope()
	scope.AddInclude("somewhere.else.test")
	srv := scopedSessionTestServer(scope)
	// The rule covers the target, so the coordinator selects it: what stops the traffic is the
	// engagement scope, not a missing rule. TestLoginForATargetNoRuleCoversSendsNothingAndSaysWhy
	// already covers the missing-rule case, and it would pass whether or not this gate existed.
	installLoginRule(t, srv, target, host, 3)

	code, resp := postLogin(t, srv, target.url+"/account")

	if got := target.hitCount("/account"); got != 0 {
		t.Fatalf("/account was hit %d times, want 0: a probe outside the engagement scope must never be sent", got)
	}
	if got := target.hitCount("/login"); got != 0 {
		t.Fatalf("/login was hit %d times, want 0", got)
	}
	if resp.Outcome != "probe_failed" || code != http.StatusBadGateway {
		t.Fatalf("outcome = %q with status %d, want probe_failed with 502: %+v", resp.Outcome, code, resp)
	}
	if resp.Error == "" {
		t.Fatal("probe_failed must carry the reason it could not be sent")
	}
}

// The manual "run macro" button is the third caller of macroRunner, and it is gated by the same
// construction rather than by each caller remembering to check.
func TestRunningAMacroByHandIsGatedByTheEngagementScope(t *testing.T) {
	target := newLoginTarget(t, true)
	host, _, _, err := targetParts(target.url)
	if err != nil {
		t.Fatalf("targetParts(%q): %v", target.url, err)
	}

	scope := core.NewScope()
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, host, "/login"))
	srv := scopedSessionTestServer(scope)
	id := installLoginRule(t, srv, target, host, 3)

	var run wireRunResp
	postJSONInto(t, srv, fmt.Sprintf("/api/session/rules/%d/run", id), map[string]any{}, &run)

	if got := target.hitCount("/login"); got != 0 {
		t.Fatalf("/login was hit %d times, want 0: the manual run must be authorised too", got)
	}
	if run.Outcome == "ok" {
		t.Fatal("outcome = ok, but nothing was sent")
	}
}

// The parameter scope (burpsy-react-ui-9hip) round-trips through the wire: scope_params on
// create, echoed on read, and the created rule honours it against the coordinator.
func TestARuleCanCarryAParameterScope(t *testing.T) {
	srv := sessionTestServer()
	var created struct {
		Rule wireSessionRule `json:"rule"`
	}
	rec := postJSON(t, srv, "/api/session/rules", map[string]any{
		"name":         "csrf refresh",
		"enabled":      true,
		"scope":        hostScope("app.test"),
		"scope_params": []string{"csrf_token", "session_id"},
		"steps":        []any{map[string]any{"method": "POST", "url": "https://app.test/refresh", "headers": []any{}, "body": ""}},
		"validity":     map[string]any{"status_is": 200},
	})
	code := rec.Code
	if code != http.StatusOK {
		t.Fatalf("POST with scope_params = %d (%s)", code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Rule.ScopeParams) != 2 {
		t.Fatalf("created rule scope_params = %v, want two names", created.Rule.ScopeParams)
	}

	// Read it back through the list.
	var list struct {
		Rules []wireSessionRule `json:"rules"`
	}
	if err := json.Unmarshal(get(t, srv, "/api/session/rules").Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range list.Rules {
		if r.Name == "csrf refresh" {
			found = true
			if len(r.ScopeParams) != 2 || r.ScopeParams[0] != "csrf_token" {
				t.Fatalf("listed scope_params = %v", r.ScopeParams)
			}
		}
	}
	if !found {
		t.Fatal("the rule did not appear in the list")
	}

	// The engine behaviour: the rule applies only where its parameter exists.
	rule := srv.sessionCoordinator.AllRules()[0]
	if !rule.MatchParams([]string{"csrf_token", "session_id", "extra"}) {
		t.Error("the created rule refused a request carrying its parameters")
	}
	if rule.MatchParams([]string{"user"}) {
		t.Error("the created rule claimed a request without its parameters; the wire restriction did not reach the engine")
	}
}

// A rule submitted without scope_params is unrestricted — the shape every existing client
// sends, and the meaning it must keep.
func TestARuleWithoutParameterScopeStaysUnrestricted(t *testing.T) {
	srv := sessionTestServer()
	rec := postJSON(t, srv, "/api/session/rules", map[string]any{
		"name":     "plain login",
		"enabled":  true,
		"scope":    hostScope("app.test"),
		"steps":    []any{map[string]any{"method": "POST", "url": "https://app.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST without scope_params = %d", rec.Code)
	}
	rule := srv.sessionCoordinator.AllRules()[0]
	if len(rule.ScopeParams) != 0 {
		t.Fatalf("a rule created without scope_params came back with %v; the field must default to unrestricted", rule.ScopeParams)
	}
	if !rule.MatchParams(nil) {
		t.Error("an unrestricted rule refused a parameter-less request")
	}
}
