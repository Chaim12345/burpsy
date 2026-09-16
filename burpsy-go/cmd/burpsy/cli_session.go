package main

import (
	"context"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

func init() {
	registerCLI(
		&cliCommand{
			name:  "session",
			usage: "session handling: burpsy session (rules|login|cookies)",
			run:   cmdSession,
		},
	)
}

// parseTargetURL splits a full URL into host, port, tls and path, matching the
// web handler's targetParts behaviour without importing internal/web.
func parseTargetURL(raw string) (host string, port uint16, tls bool, path string, err error) {
	scheme := "http"
	rest := raw
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme = strings.ToLower(raw[:i])
		rest = raw[i+3:]
	}
	tls = scheme == "https"
	hostport := rest
	if i := strings.Index(rest, "/"); i >= 0 {
		hostport = rest[:i]
		path = rest[i:]
	} else {
		path = "/"
	}
	host, port, err = resolveHostPort(hostport, tls)
	if err != nil {
		return "", 0, false, "", fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	return host, port, tls, path, nil
}

func cmdSession(ctx *cliContext, args []string) error {
	sub := "rules"
	if len(args) > 0 && args[0] != "-h" && args[0] != "--help" && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "rules":
		return sessionRules(ctx, args)
	case "login":
		return sessionLogin(ctx, args)
	case "cookies":
		return sessionCookies(ctx, args)
	default:
		return fmt.Errorf("usage: burpsy session (rules|login|cookies)")
	}
}

func sessionRules(ctx *cliContext, args []string) error {
	sub := "list"
	if len(args) > 0 && args[0] != "-h" && args[0] != "--help" && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "list":
		return sessionRulesList(ctx, args)
	case "add":
		return sessionRulesAdd(ctx, args)
	case "remove":
		return sessionRulesRemove(ctx, args)
	case "toggle":
		return sessionRulesToggle(ctx, args)
	default:
		return fmt.Errorf("usage: burpsy session rules (list|add|remove|toggle)")
	}
}

func sessionRulesList(ctx *cliContext, args []string) error {
	fs := newFlagSet("session rules list")
	jsonOut := fs.Bool("json", false, "emit the RulesResp shape the UI uses")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rules := ctx.sess.AllRules()
	if *jsonOut {
		dtos := make([]map[string]interface{}, 0, len(rules))
		for _, r := range rules {
			steps := make([]map[string]interface{}, 0, len(r.Steps))
			for _, s := range r.Steps {
				steps = append(steps, map[string]interface{}{
					"method": s.Method,
					"url":    s.URL,
					"body":   s.Body,
				})
			}
			dtos = append(dtos, map[string]interface{}{
				"id":           int64(r.ID),
				"name":         r.Name,
				"enabled":      r.Enabled,
				"scope":        r.ScopeHosts,
				"steps":        steps,
				"max_attempts": r.MaxAttempts,
			})
		}
		return printJSON(ctx.out, map[string]interface{}{"wired": true, "rules": dtos})
	}
	if len(rules) == 0 {
		fmt.Fprintln(ctx.out, "no session rules")
		return nil
	}
	for _, r := range rules {
		state := "off"
		if r.Enabled {
			state = "on"
		}
		fmt.Fprintf(ctx.out, "%d [%s] %-20s hosts=%v steps=%d\n", r.ID, state, r.Name, r.ScopeHosts, len(r.Steps))
	}
	return nil
}

func sessionRulesAdd(ctx *cliContext, args []string) error {
	fs := newFlagSet("session rules add")
	name := fs.String("name", "", "rule name")
	hosts := fs.String("host", "", "comma-separated scope hosts")
	steps := fs.String("steps", "", "comma-separated macro URLs to replay on login")
	validBody := fs.String("valid-body", "", "validity check: response must contain this body text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *hosts == "" || *steps == "" {
		return fmt.Errorf("usage: burpsy session rules add -name N -host H1,H2 -steps URL1,URL2")
	}
	var macro []session.MacroStep
	for _, u := range splitCSV(*steps) {
		macro = append(macro, session.MacroStep{Method: "GET", URL: u})
	}
	rule := session.NewSessionRule(*name, splitCSV(*hosts), macro)
	if *validBody != "" {
		rule.Validity = &session.ValidityRule{BodyContains: *validBody}
	}
	// The CLI earns the same refusals the web API does: AddRule validates, and a rule the operator
	// typed wrongly is reported here rather than silently installed and discovered later as a login
	// button that does nothing.
	id, err := ctx.sess.AddRule(rule)
	if err != nil {
		return err
	}
	ctx.saveState()
	fmt.Fprintf(ctx.out, "added rule %d\n", id)
	return nil
}

func sessionRulesRemove(ctx *cliContext, args []string) error {
	fs := newFlagSet("session rules remove")
	idStr := fs.String("id", "", "rule id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := parseRuleID(fs, *idStr)
	if err != nil {
		return err
	}
	if ctx.sess.Rule(id) == nil {
		return fmt.Errorf("rule %d not found", id)
	}
	ctx.sess.RemoveRule(id)
	ctx.saveState()
	fmt.Fprintf(ctx.out, "removed rule %d\n", id)
	return nil
}

func sessionRulesToggle(ctx *cliContext, args []string) error {
	fs := newFlagSet("session rules toggle")
	idStr := fs.String("id", "", "rule id")
	enabled := fs.Bool("enabled", true, "true to enable, false to disable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := parseRuleID(fs, *idStr)
	if err != nil {
		return err
	}
	rule := ctx.sess.Rule(id)
	if rule == nil {
		return fmt.Errorf("rule %d not found", id)
	}
	rule.Enabled = *enabled
	// A stored rule that no longer validates (one saved before a check existed) must not be silently
	// left enabled-but-unchanged: report it so the operator can fix the rule rather than wonder why
	// toggling it had no effect.
	if err := ctx.sess.UpdateRule(id, rule); err != nil {
		return err
	}
	ctx.saveState()
	fmt.Fprintf(ctx.out, "rule %d %s\n", id, onOff(*enabled))
	return nil
}

func parseRuleID(fs *flag.FlagSet, s string) (session.RuleID, error) {
	if s == "" && fs.NArg() > 0 {
		s = fs.Arg(0)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid rule id %q", s)
	}
	return session.RuleID(n), nil
}

func onOff(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

// sessionLogin is the direct-engine twin of the web's POST /api/session/login: resolve the rule that
// covers the probe host, send the probe with the coordinator's jar attached, and hand the response to
// the coordinator's recovery path — which is what actually runs the login macro (single-flight per
// rule, bounded by max_attempts) and retries the probe with the fresh session.
//
// It used to walk the rule's steps itself and then print "recovered" unconditionally at the end,
// whatever the last response said, so the command reported success for having established nothing.
// Every outcome is now named distinctly, for the reason the coordinator's docs give: "this is working"
// and "this has quietly stopped trying" must be tellable apart.
func sessionLogin(ctx *cliContext, args []string) error {
	fs := newFlagSet("session login")
	url := fs.String("url", "", "probe URL (the host picks the rule)")
	method := fs.String("method", "GET", "probe method")
	timeoutSec := fs.Int("timeout", 30, "per-request timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" && fs.NArg() > 0 {
		*url = fs.Arg(0)
	}
	if *url == "" {
		return fmt.Errorf("usage: burpsy session login -url https://host/...")
	}
	host, port, tls, path, err := parseTargetURL(*url)
	if err != nil {
		return err
	}
	// Resolved before anything is sent: with no rule for this target there is no macro to run with
	// whatever comes back, so sending the probe would cost the target a request to no purpose.
	//
	// The probe's full identity, not its host (7nh2): a rule scoped to a path, port or scheme must
	// not be the rule that fires for a probe URL its own editor excludes. A rule configured for
	// "Use suite scope" is judged against this process's Target scope, read live.
	// The tool is stated (so3): `burpsy session check` is the Session tool's own probe, the same
	// attribution the tool log gives it below, so a rule restricted to other tools must not fire
	// for it — and one restricted to the session tool must.
	rule := ctx.sess.MatchingRuleForRequest(
		session.RequestIdentity{Host: host, Path: path, Port: port, TLS: tls, Tool: toollog.ToolSession.String()},
		nil,
		func() bool { return ctx.scope.Contains(host, port, path, tls) })
	if rule == nil {
		fmt.Fprintf(ctx.out, "no_rule_applies url=%s rules=%d\n", *url, len(ctx.sess.AllRules()))
		return nil
	}
	runner := ctx.cliMacroRunner(*timeoutSec)
	probe := session.MacroStep{Method: strings.ToUpper(*method), URL: *url}
	response, err := runner(probe)
	if err != nil {
		fmt.Fprintf(ctx.out, "probe_failed rule=%s error=%s\n", rule.Name, err)
		return nil
	}
	outcome := ctx.sess.HandleRecovery(toollog.ToolSession.String(), probe, response, runner)
	switch outcome.Kind {
	case session.RecoveryNoRuleApplies:
		// Unreachable here, since the rule was resolved above. Printed faithfully anyway rather than
		// falling through to something that reads like success.
		fmt.Fprintf(ctx.out, "no_rule_applies url=%s\n", outcome.URL)
	case session.RecoveryAlreadyValid:
		fmt.Fprintf(ctx.out, "already_valid rule=%s\n", rule.Name)
	case session.RecoveryRuleApplied:
		// No login was attempted: the rule's actions rewrote the request and it was re-sent. Reported
		// apart from recovered for the reason the kinds are apart — "a session was established" and
		// "a header was set" are different things to go and check.
		fmt.Fprintf(ctx.out, "rule_applied rule=%s actions=%d\n", rule.Name, len(outcome.Actions))
	case session.RecoveryRecovered:
		fmt.Fprintf(ctx.out, "recovered rule=%s login_attempts=%d\n", rule.Name, outcome.LoginAttempts)
	case session.RecoveryStillInvalidAfterRelogin:
		fmt.Fprintf(ctx.out, "still_invalid_after_relogin rule=%s login_attempts=%d\n", rule.Name, outcome.LoginAttempts)
	case session.RecoveryGaveUp:
		fmt.Fprintf(ctx.out, "gave_up rule=%s login_attempts=%d\n", rule.Name, outcome.LoginAttempts)
	case session.RecoveryMacroFailed:
		fmt.Fprintf(ctx.out, "macro_failed rule=%s attempt=%d %s\n", rule.Name, outcome.Attempt, outcome.Failure)
	case session.RecoveryRetryFailed:
		fmt.Fprintf(ctx.out, "retry_failed rule=%s login_attempts=%d error=%s\n", rule.Name, outcome.LoginAttempts, outcome.Error)
	default:
		// A new outcome kind must be printed here; saying so beats printing nothing and exiting 0.
		return fmt.Errorf("recovery outcome kind %d has no cli mapping", int(outcome.Kind))
	}
	return nil
}

// cliMacroRunner is the session package's MacroStepRunner seam bound to the CLI's sender, so the CLI
// drives the same coordinator the web layer does. It carries the step's own headers and returns the
// response's, which is what a HeaderPresent validity rule needs in order to mean anything from here —
// the bespoke per-step sender this replaces sent only Host and discarded every response header.
//
// Like the web runner, each step leaves through an AuthorisedSender bound to that step's own
// authority, so `burpsy session login` is gated by the engagement scope the same way the UI is
// (HARD-03). One surface reachable two ways is still one surface: gating only the web path would
// leave the CLI as the way around it.
func (ctx *cliContext) cliMacroRunner(timeoutSec int) session.MacroStepRunner {
	return func(step session.MacroStep) (*session.StepResult, error) {
		host, port, tls, path, err := parseTargetURL(step.URL)
		if err != nil {
			return nil, err
		}
		method := strings.ToUpper(step.Method)
		if method == "" {
			method = "GET"
		}
		req := &sender.Request{
			Method:  method,
			Host:    host,
			Path:    path,
			Headers: map[string]string{"Host": host},
			Body:    []byte(step.Body),
			TLS:     tls,
			Port:    port,
		}
		for k, v := range step.Headers {
			req.Headers[k] = v
		}
		// The coordinator attaches the jar's cookie to a step it owns; fill one in only when the step
		// did not carry one (the operator's own probe).
		if _, has := req.Headers["Cookie"]; !has {
			if cookie := ctx.sess.CookieHeader(host, port, tls); cookie != "" {
				req.Headers["Cookie"] = cookie
			}
		}
		c, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
		defer cancel()
		resp, err := sender.NewAuthorisedSender(ctx.scope, ctx.sender, host, port, tls).SendRequest(c, req)
		if err != nil {
			// nil: the step never got a response to measure.
			ctx.toolLog.Record(toollog.ToolSession, host, port, tls, method, path, 0, nil, 0, err.Error(), nil)
			return nil, err
		}
		hdrs := make(map[string]string, len(resp.Headers))
		for k, v := range resp.Headers {
			hdrs[k] = v
			if strings.EqualFold(k, "Set-Cookie") {
				// The step's own path and tool, so a path- or tool-scoped rule judges this response
				// against the request that produced it rather than against a host alone (7nh2, so3).
				ctx.sess.HandleResponseFor(
					session.RequestIdentity{Host: host, Path: path, Port: port, TLS: tls, Tool: toollog.ToolSession.String()},
					resp.StatusCode, map[string]string{"Set-Cookie": v}, resp.Body,
					func() bool { return ctx.scope.Contains(host, port, path, tls) })
			}
		}
		// The body's length only — see the same record in internal/web/api_session.go for why a session
		// step has no raw response to count.
		ctx.toolLog.Record(toollog.ToolSession, host, port, tls, method, path, resp.StatusCode,
			toollog.Bytes(len(resp.Body)), uint64(resp.Duration.Milliseconds()), "", nil)
		return &session.StepResult{Status: resp.StatusCode, Headers: hdrs, Body: resp.Body}, nil
	}
}

func sessionCookies(ctx *cliContext, args []string) error {
	fs := newFlagSet("session cookies")
	host := fs.String("host", "", "authority to show cookies for")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" && fs.NArg() > 0 {
		*host = fs.Arg(0)
	}
	if *host == "" {
		return fmt.Errorf("usage: burpsy session cookies -host HOST")
	}
	cookie := ctx.sess.CookieHeader(*host, 80, false)
	if cookie == "" {
		fmt.Fprintln(ctx.out, "(no cookies held)")
		return nil
	}
	fmt.Fprintln(ctx.out, cookie)
	return nil
}
