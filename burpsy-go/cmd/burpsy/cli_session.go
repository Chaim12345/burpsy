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
	id := ctx.sess.AddRule(rule)
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
	ctx.sess.UpdateRule(id, rule)
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

// sessionLogin replays the macro of the rule whose scope covers the probe host
// through the HTTP sender, absorbing Set-Cookie into the coordinator's jar,
// then reports whether the probe came back valid. This is the direct-engine
// twin of the web's /api/session/login.
func sessionLogin(ctx *cliContext, args []string) error {
	fs := newFlagSet("session login")
	url := fs.String("url", "", "probe URL (the host picks the rule)")
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
	host, _, _, _, err := parseTargetURL(*url)
	if err != nil {
		return err
	}
	rule := ctx.sess.MatchingRule(host)
	if rule == nil {
		fmt.Fprintln(ctx.out, "no_rule")
		return nil
	}
	for _, step := range rule.Steps {
		status, body, err := ctx.cliRunStep(step.URL, step.Method, step.Body, *timeoutSec)
		if err != nil {
			fmt.Fprintf(ctx.out, "failed rule=%s step=%s\n", rule.Name, step.URL)
			return nil
		}
		if rule.Validity != nil {
			state := rule.Validity.Evaluate(status, nil, []byte(body))
			if state == session.Valid {
				fmt.Fprintf(ctx.out, "already_valid rule=%s\n", rule.Name)
				return nil
			}
		}
		_ = status
	}
	fmt.Fprintf(ctx.out, "recovered rule=%s\n", rule.Name)
	return nil
}

// cliRunStep executes one macro step through the sender, absorbing cookies.
func (ctx *cliContext) cliRunStep(url, method, body string, timeoutSec int) (int, string, error) {
	host, port, tls, path, err := parseTargetURL(url)
	if err != nil {
		return 0, "", err
	}
	if method == "" {
		method = "GET"
	}
	req := &sender.Request{
		Method: strings.ToUpper(method),
		Host:   host,
		Path:   path,
		Headers: map[string]string{
			"Host": host,
		},
		Body: []byte(body),
		TLS:  tls,
		Port: port,
	}
	if cookie := ctx.sess.CookieHeader(host, port, tls); cookie != "" {
		req.Headers["Cookie"] = cookie
	}
	c, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()
	resp, err := ctx.sender.Send(c, req)
	if err != nil {
		ctx.toolLog.Record(toollog.ToolSession, host, port, tls, method, path, 0, 0, err.Error())
		return 0, "", err
	}
	for k, v := range resp.Headers {
		if strings.EqualFold(k, "Set-Cookie") {
			ctx.sess.HandleResponse(host, port, tls, resp.StatusCode, map[string]string{"Set-Cookie": v}, resp.Body)
		}
	}
	ctx.toolLog.Record(toollog.ToolSession, host, port, tls, method, path, resp.StatusCode, uint64(resp.Duration.Milliseconds()), "")
	return resp.StatusCode, string(resp.Body), nil
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
