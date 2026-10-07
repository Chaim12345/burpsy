package web

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/extension"
	"github.com/burpsy-go/burpsy/internal/session"
)

// ---- A session rule's "Invoke an extension" action, over this tree's extension host -----------------
//
// internal/session defines the seam (session.SessionActionInvoker) and refuses to import the
// extension host itself, because the host sits above the coordinator in the dependency direction: the
// proxy consults session rules on every request, and dragging a plugin process into that package
// would put a subprocess on the request path of the proxy's own import graph. This file is the
// adapter, and internal/web is where it belongs — the same place every other "wire the seam to the
// real component" decision is made.
//
// # Why the host is resolved per call rather than captured
//
// extensionHost() builds an empty host on first use and the API can be exercised before any plugin is
// allowlisted. An adapter that captured a host at construction would hold whichever one existed when
// the server was built, and a host is not replaceable — so a plugin loaded later through
// POST /api/extensions/load would be invisible to every rule. Resolving through the server on each
// invocation means there is exactly one host and one place that decides when it exists.
//
// # What is refused rather than guessed
//
// A registration that no loaded plugin declares, an ambiguous one, a plugin that errors, and an
// answer with no method or no absolute URL are all refusals. Each one leaves the rule's request
// alone and records why, which is the contract internal/session's action relies on: the alternative
// — sending a request assembled from a partial answer — is a real request with real credentials and
// no trace of which half of it was guessed.

// sessionActionInvoker adapts the extension host to session.SessionActionInvoker.
type sessionActionInvoker struct {
	s *Server
	// timeout bounds one plugin call. The host has its own CallTimeout; this exists so a rule walk
	// cannot outlive the proxy request that started it by an unbounded margin even if the host is
	// configured generously.
	timeout time.Duration
}

// InvokeSessionAction runs the plugin registration a rule names and returns the request it wants
// sent.
func (i sessionActionInvoker) InvokeSessionAction(req session.SessionActionRequest) (session.MacroStep, error) {
	name, err := i.s.extensionHost().ResolveRegistration(req.Registration, extension.KindSessionAction)
	if err != nil {
		return session.MacroStep{}, err
	}
	timeout := i.timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := i.s.extensionHost().Invoke(ctx, name, extension.InvokeParams{
		Registration: req.Registration,
		Request:      sessionRequestToWire(req.Request),
		Response:     sessionResponseToWire(req.Response),
		Values:       copyStringMap(req.Values),
	})
	if err != nil {
		return session.MacroStep{}, err
	}
	// No request in the answer is a legitimate answer — a plugin that only observed, or only wrote to
	// its own console — and it means "send what the rule already built", so the caller's request is
	// returned unchanged rather than refused.
	if result.Request == nil {
		return req.Request, nil
	}
	step, err := wireToSessionRequest(*result.Request)
	if err != nil {
		return session.MacroStep{}, fmt.Errorf("plugin %q registration %q answered with an unusable "+
			"request: %w", name, req.Registration, err)
	}
	return step, nil
}

// sessionRequestToWire renders the request the rule has built so far for a plugin.
//
// Headers are sorted, because the session walk holds them in a map and a Go map has no order. That is
// a loss — the order the request arrived in is not recoverable here — and it is stated rather than
// hidden: the walk's own rewrite actions have already flattened the request through the same map, so
// a plugin is handed the same view every other action sees, and nothing downstream depends on an
// order this call would be the only one to preserve.
func sessionRequestToWire(step session.MacroStep) *extension.SessionRequest {
	return &extension.SessionRequest{
		Method:  step.Method,
		URL:     step.URL,
		Headers: sortedHeaderPairs(step.Headers),
		Body:    step.Body,
	}
}

func sortedHeaderPairs(headers map[string]string) [][]string {
	if len(headers) == 0 {
		return nil
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([][]string, 0, len(names))
	for _, name := range names {
		out = append(out, []string{name, headers[name]})
	}
	return out
}

func sessionResponseToWire(resp *session.StepResult) *extension.SessionResponse {
	if resp == nil {
		// Absent means the rule has observed no response — a rule whose actions never check validity
		// has nothing to read. Omitted rather than sent as a zero-valued object, so a plugin can tell
		// "no response arrived" from "the response was empty", which are different facts about the
		// engagement.
		return nil
	}
	return &extension.SessionResponse{
		Status:  resp.Status,
		Headers: sortedHeaderPairs(resp.Headers),
		Body:    string(resp.Body),
	}
}

// wireToSessionRequest reads a plugin's answer back as a macro step.
//
// Refused rather than repaired: a step with no method or no URL cannot be sent, and a rule that
// silently kept the request it had would report a plugin invocation that did nothing. The absolute
// URL check is the same one validate.go applies to a stored step, for the same reason — a hostless
// URL leaves the sender choosing an authority, which is a decision the operator made when they
// scoped the rule and not a decision to delegate to a plugin's typo.
func wireToSessionRequest(w extension.SessionRequest) (session.MacroStep, error) {
	method := strings.TrimSpace(w.Method)
	if method == "" {
		return session.MacroStep{}, fmt.Errorf("the method is empty")
	}
	url := strings.TrimSpace(w.URL)
	if url == "" {
		return session.MacroStep{}, fmt.Errorf("the URL is empty")
	}
	if !strings.Contains(url, "://") {
		return session.MacroStep{}, fmt.Errorf("the URL %q is not absolute; a request needs its host "+
			"from somewhere, and deriving it here would decide an authority the operator never stated", url)
	}
	headers := make(map[string]string, len(w.Headers))
	for _, pair := range w.Headers {
		if len(pair) != 2 {
			return session.MacroStep{}, fmt.Errorf("a header entry is a %d-element list, not a name/value pair", len(pair))
		}
		if strings.TrimSpace(pair[0]) == "" {
			return session.MacroStep{}, fmt.Errorf("a header has an empty name")
		}
		headers[pair[0]] = pair[1]
	}
	return session.MacroStep{Method: method, URL: url, Headers: headers, Body: w.Body}, nil
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
