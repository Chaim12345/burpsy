package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/burpsy-go/burpsy/internal/web"
)

// confirmToolName is the one tool this transport adds to the manifest's own surface. It is the
// mint step of the confirmation flow: separate, explicitly named, and documented as an act that
// needs a human behind it (see the package comment).
const confirmToolName = "burpsy_confirm"

// tool is one MCP tool descriptor. Route and the marshalling split is deliberate: everything
// exported by JSON is wire, and `route` is the manifest entry the descriptor was derived from,
// carried along so a call can be bound back to it without a second lookup table.
type tool struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	InputSchema map[string]any   `json:"inputSchema"`
	Annotations map[string]any   `json:"annotations,omitempty"`
	route       web.MCPRouteInfo `json:"-"`
}

type callArgs struct {
	Method string            `json:"method,omitempty"`
	Path   string            `json:"path,omitempty"`
	Query  map[string]string `json:"query,omitempty"`
	Body   json.RawMessage   `json:"body,omitempty"`
	// Confirm is the one-time token minted by burpsy_confirm. It is relayed as the gate's header.
	Confirm string `json:"confirm,omitempty"`
	// Route is burpsy_confirm's own argument: the exact manifest pattern to mint for.
	Route string `json:"route,omitempty"`
}

type callResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// errResult is a tool-execution failure. MCP distinguishes this from a protocol error on purpose:
// a tool that could not run its input is something the model should see and correct, so it comes
// back as a result with isError set rather than as a JSON-RPC error the host may hide.
func errResult(text string) callResult {
	return callResult{Content: []contentBlock{{Type: "text", Text: text}}, IsError: true}
}

// ---- descriptors --------------------------------------------------------------------------------

// buildTools turns the exposed manifest into descriptors, in stable order, and fills the lookup
// maps. Called once from New.
func (s *Server) buildTools() []tool {
	routes := append([]web.MCPRouteInfo(nil), s.routes...)
	sort.Slice(routes, func(i, j int) bool { return routes[i].Pattern < routes[j].Pattern })

	// The transport's own tool name is claimed first so a manifest route can never shadow it: a
	// descriptor list where "burpsy_confirm" means a route is a list where the confirm flow is
	// unreachable.
	used := map[string]bool{confirmToolName: true}

	out := make([]tool, 0, len(routes)+1)
	for _, r := range routes {
		t := tool{
			Name:        uniqueToolName(r, used),
			Description: describeRoute(r),
			InputSchema: schemaForRoute(r),
			Annotations: annotationsForRoute(r),
			route:       r,
		}
		out = append(out, t)
		s.byName[t.Name] = t
	}

	confirm := s.confirmToolDescriptor(routes)
	out = append(out, confirm)
	s.byName[confirm.Name] = confirm
	return out
}

// toolNameFor normalises a route pattern into a tool name: "/api/crawl/start" -> "api_crawl_start".
//
// The manifest holds both an exact route and the subtree under it ("/api/pools" and "/api/pools/"),
// and normalization maps both onto one name. That collision is resolved rather than allowed,
// because MCP tool names are the addressing scheme: two descriptors with one name is a tool a
// client cannot call unambiguously.
func toolNameFor(pattern string) string {
	trimmed := strings.Trim(pattern, "/")
	if trimmed == "" {
		// The "/" entry is the console's own asset route (index.html and the SPA catch-all).
		return "root"
	}
	var b strings.Builder
	pending := false
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			pending = false
		case !pending:
			b.WriteByte('_')
			pending = true
		}
	}
	return strings.Trim(b.String(), "_")
}

// uniqueToolName assigns a name no descriptor has used yet. The subtree half of a collision gets a
// "_subtree" suffix, which names the difference rather than numbering it: "/api/pools" and
// "/api/pools/" are not two spellings of one route, and an operator reading the list should be able
// to tell which one they are about to call.
func uniqueToolName(r web.MCPRouteInfo, used map[string]bool) string {
	base := toolNameFor(r.Pattern)
	name := base
	if used[name] && strings.HasSuffix(r.Pattern, "/") {
		name = base + "_subtree"
	}
	for i := 2; used[name]; i++ {
		name = fmt.Sprintf("%s_%d", base, i)
	}
	used[name] = true
	return name
}

// describeRoute writes what a model needs before calling: what the route is, what it costs, and
// whether it will be refused. Everything in it is derived — the verb list and summary from the
// manifest, the risk wording from the risk class — so a description cannot drift from the route.
func describeRoute(r web.MCPRouteInfo) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n%s\n", strings.Join(r.Methods, "/"), r.Pattern, r.Summary)
	fmt.Fprintf(&b, "Risk class: %s (%s). Escalation tier: %s.", r.Risk, r.Safety, r.Tier)
	if len(r.Hints) > 0 {
		fmt.Fprintf(&b, " Hints: %s.", strings.Join(r.Hints, ", "))
	}
	b.WriteString("\n")

	if r.NeedsConfirm {
		if gated := mutatingMethods(r.Methods); len(gated) > 0 {
			fmt.Fprintf(&b, "Confirmation: REQUIRED for %s — the server refuses those with HTTP 428 unless a one-time token from %s is supplied. A GET on this route is a read and is not gated.",
				strings.Join(gated, "/"), confirmToolName)
		} else {
			fmt.Fprintf(&b, "Confirmation: not required for %s only — the gate refuses mutating verbs, and this route answers none.", strings.Join(r.Methods, "/"))
		}
	} else {
		b.WriteString("Confirmation: not required.")
	}

	if strings.HasSuffix(r.Pattern, "/") {
		fmt.Fprintf(&b, " This is a subtree pattern, not a requestable URL: the path argument is required, for example %s.", pathExample(r))
	}
	return b.String()
}

// annotationsForRoute carries the risk class as structured data alongside MCP's four standard
// hints.
//
// The standard four are read from agent_tools.go's derivations rather than re-judged here: a
// descriptor that called an attack route idempotent, or a credential read world-opening, would be
// exactly the drift between a published safety claim and the enforced one that the risk taxonomy
// exists to prevent. The extra keys are for hosts that want to gate on burpsy's own vocabulary —
// MCP's four booleans cannot express "widens scope" or "hands out a credential".
func annotationsForRoute(r web.MCPRouteInfo) map[string]any {
	return map[string]any{
		"readOnlyHint":         hasHint(r.Hints, "READ_ONLY"),
		"idempotentHint":       hasHint(r.Hints, "IDEMPOTENT"),
		"destructiveHint":      hasHint(r.Hints, "DESTRUCTIVE"),
		"openWorldHint":        hasHint(r.Hints, "OPEN_WORLD"),
		"riskClass":            r.Risk,
		"escalationTier":       r.Tier,
		"requiresConfirmation": r.NeedsConfirm,
		"route":                r.Pattern,
	}
}

func hasHint(hints []string, want string) bool {
	for _, h := range hints {
		if h == want {
			return true
		}
	}
	return false
}

// mutatingMethods filters a route's verbs to the ones the gate can refuse, using the gate's own
// predicate.
func mutatingMethods(methods []string) []string {
	var out []string
	for _, m := range methods {
		if web.MCPMethodMutates(m) {
			out = append(out, m)
		}
	}
	return out
}

// schemaForRoute is the InputSchema every route tool shares. It is intentionally permissive about
// the body: the wire shapes are the handlers' own structs, they are documented per route in the
// console's API docs (/api/apidoc), and inventing a stricter schema here would be a second
// definition of each route's payload that nothing checks.
func schemaForRoute(r web.MCPRouteInfo) map[string]any {
	methods := make([]string, 0, len(r.Methods))
	for _, m := range r.Methods {
		methods = append(methods, strings.ToUpper(m))
	}
	sort.Strings(methods)

	props := map[string]any{
		"method": map[string]any{
			"type": "string", "enum": methods,
			"description": "HTTP method. Optional when the route answers exactly one verb, or when it answers GET and no body is supplied; otherwise required.",
		},
		"query": map[string]any{
			"type":                 "object",
			"additionalProperties": map[string]any{"type": "string"},
			"description":          "Query string parameters.",
		},
		"body": map[string]any{
			"description": "JSON request body, sent verbatim as application/json. See /api/apidoc for this route's shape.",
		},
		"confirm": map[string]any{
			"type":        "string",
			"description": "One-time confirmation token minted by " + confirmToolName + ". The server refuses a mutating call to a confirmation-worthy route without it (HTTP 428).",
		},
	}

	required := []string{}
	if strings.HasSuffix(r.Pattern, "/") {
		props["path"] = map[string]any{
			"type": "string",
			"description": fmt.Sprintf("Concrete request path under %s, for example %s. Required: %s is a subtree pattern and is not itself a requestable URL.",
				r.Pattern, pathExample(r), r.Pattern),
		}
		required = append(required, "path")
	} else {
		props["path"] = map[string]any{
			"type":        "string",
			"description": fmt.Sprintf("Concrete request path. Must be exactly %s; any other path is refused by this layer, because a tool named for one route may only call that route.", r.Pattern),
		}
	}

	return map[string]any{"type": "object", "properties": props, "required": required}
}

// pathExample is a concrete path under a subtree pattern: the manifest's own subPath when it names
// one, otherwise a placeholder that makes the shape obvious.
func pathExample(r web.MCPRouteInfo) string {
	if r.SubPath != "" {
		return r.Pattern + r.SubPath
	}
	return r.Pattern + "{id}"
}

// confirmToolDescriptor describes the mint step.
//
// The description carries the argument the gate's own comment makes, because it is the only place
// an MCP host or model is told what the checkpoint is for: an agent that mints its own
// confirmations has turned a checkpoint into a formality. The separation — a distinct tool, a
// distinct call in the transcript — is the most a server can do; the enforcement point is the host
// that decides whether to ask its human first.
func (s *Server) confirmToolDescriptor(routes []web.MCPRouteInfo) tool {
	gated := make([]string, 0, len(routes))
	for _, r := range routes {
		if r.NeedsConfirm {
			gated = append(gated, r.Pattern)
		}
	}
	sort.Strings(gated)

	description := fmt.Sprintf(`Mint a one-time confirmation for a burpsy route whose risk class requires one.

Use this only when a human has asked for that specific action. A confirmation is the server's checkpoint in front of the routes that send unbounded traffic, widen what the engagement is allowed to touch, read or replay credentials, or discard evidence. An agent that mints its own confirmations has turned that checkpoint into a formality — this tool is a separate call precisely so the escalation is visible in the transcript and can be approved by the host as its own act, not as a field filled in silently.

Minting does not perform the action. The token that comes back is single-use, expires in %d seconds, is bound to the route it was minted for, and is spent by setting the "confirm" argument of the call it authorises.

route must be the exact pattern %s, not a concrete path — the refusal message and the tool's own annotations both print it.`, web.MCPConfirmTTLSeconds(), `(for example "/api/audit/")`)

	return tool{
		Name:        confirmToolName,
		Description: description,
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"route": map[string]any{
					"type":        "string",
					"enum":        gated,
					"description": "The exact route pattern to mint a confirmation for.",
				},
			},
			"required": []string{"route"},
		},
		Annotations: map[string]any{
			"readOnlyHint":         false,
			"destructiveHint":      false,
			"idempotentHint":       false,
			"openWorldHint":        false,
			"riskClass":            "confirm-mint",
			"requiresConfirmation": false,
			"requiresHumanIntent":  true,
		},
	}
}

// listTools answers tools/list.
func (s *Server) listTools(req request) response {
	return s.ok(req, map[string]any{"tools": s.tools})
}

// ---- tools/call ---------------------------------------------------------------------------------

func (s *Server) callTool(ctx context.Context, req request) response {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments,omitempty"`
	}
	if r := s.parseParams(req, &params); r != nil {
		return *r
	}
	if strings.TrimSpace(params.Name) == "" {
		return s.fail(req, codeInvalidParams, "tools/call requires a tool name")
	}

	var args callArgs
	if len(params.Arguments) > 0 {
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return s.fail(req, codeInvalidParams, "could not read arguments for %s: %v", params.Name, err)
		}
	}

	if params.Name == confirmToolName {
		return s.callConfirm(ctx, req, args)
	}

	t, ok := s.byName[params.Name]
	if !ok {
		// An unknown NAME is a protocol-level mistake — the caller asked for something that does
		// not exist, which is not the tool's input being wrong. An unknown ARGUMENT is the other
		// case and comes back as isError.
		return s.fail(req, codeInvalidParams, "no tool named %q; call tools/list for the surface", params.Name)
	}

	res := s.invoke(ctx, t, args)
	out := map[string]any{"content": res.Content}
	if res.IsError {
		out["isError"] = true
	}
	return s.ok(req, out)
}

// invoke performs one tool call: it validates that the path names this tool's route and the method
// is one the route declares, then forwards the request to the console and maps the answer.
//
// It makes no authorisation decision. Whether the call is permitted is the running console's
// answer, and the only thing this function does with a confirmation is relay the caller's token.
func (s *Server) invoke(ctx context.Context, t tool, args callArgs) callResult {
	path, err := s.resolvePath(t, args)
	if err != nil {
		return errResult(err.Error())
	}
	method, err := chooseMethod(t.route, args)
	if err != nil {
		return errResult(err.Error())
	}

	target := s.baseURL + path
	if len(args.Query) > 0 {
		q := url.Values{}
		for k, v := range args.Query {
			q.Set(k, v)
		}
		target += "?" + q.Encode()
	}

	var body io.Reader
	if len(args.Body) > 0 {
		body = bytes.NewReader(args.Body)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return errResult("could not build the request: " + err.Error())
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	// The confirmation travels as a header, not as a body field: the gate's comment explains why
	// (a field the payload can set is not a confirmation). Relaying is the whole of this layer's
	// involvement — it never mints one, never retries without one, and never caches one.
	if args.Confirm != "" {
		req.Header.Set(web.MCPConfirmHeaderName, args.Confirm)
	}

	resp, err := s.http.Do(req)
	if err != nil {
		return errResult(fmt.Sprintf("could not reach the burpsy console at %s: %v", s.baseURL, err))
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "text/event-stream") {
		// A streaming route would block the whole MCP session until the client timeout. Saying so
		// is better than a call that appears to hang.
		return errResult(fmt.Sprintf("HTTP %d: this route streams (text/event-stream) and cannot be delivered as one tool result", resp.StatusCode))
	}

	payload, truncated, err := readCapped(resp.Body, maxResultBytes)
	if err != nil {
		return errResult("could not read the console's response: " + err.Error())
	}

	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d %s %s\n", resp.StatusCode, method, path)
	if truncated {
		fmt.Fprintf(&b, "(truncated at %d bytes — the console's full response is larger)\n", maxResultBytes)
	}
	b.Write(payload)
	text := b.String()

	if resp.StatusCode == http.StatusPreconditionRequired {
		return errResult(refusalText(t, text))
	}
	if resp.StatusCode >= 400 {
		return errResult(text)
	}
	return callResult{Content: []contentBlock{{Type: "text", Text: text}}}
}

// resolvePath decides the concrete path a tool call will request, and refuses anything that is not
// this tool's own route.
//
// That refusal is not a policy decision and does not duplicate the gate: it is what the tool name
// MEANS. A tool listed as /api/advisories that could be pointed at /api/audit/selected would be a
// descriptor whose published risk class describes a route other than the one it reaches. The
// resolution itself is web.MCPRouteForPath, which is the gate's own longest-prefix rule, so the
// binding and the gate cannot disagree about which route a path names.
func (s *Server) resolvePath(t tool, args callArgs) (string, error) {
	r := t.route
	raw := strings.TrimSpace(args.Path)

	if raw != "" {
		if !strings.HasPrefix(raw, "/") {
			return "", fmt.Errorf("path %q must start with %q", raw, "/")
		}
		if strings.ContainsAny(raw, "?#") {
			return "", fmt.Errorf("path %q must not carry a query string or fragment; pass those as the \"query\" argument", raw)
		}
		if strings.Contains(raw, "..") {
			return "", fmt.Errorf("path %q must not contain \"..\"", raw)
		}
	}

	if !strings.HasSuffix(r.Pattern, "/") {
		if raw == "" {
			raw = r.Pattern
		}
		if raw != r.Pattern {
			return "", fmt.Errorf("the %s tool calls %s and nothing else; %q is a different route — call its own tool", t.Name, r.Pattern, raw)
		}
	} else if raw == "" {
		return "", fmt.Errorf("%s is a subtree pattern and is not itself a URL: supply \"path\", for example %s", r.Pattern, pathExample(r))
	}

	resolved, ok := web.MCPRouteForPath(raw)
	if !ok || resolved.Pattern != r.Pattern {
		got := "no route in the manifest"
		if ok {
			got = resolved.Pattern
		}
		return "", fmt.Errorf("path %q resolves to %s, not %s: the tool named for one route may only call that route", raw, got, r.Pattern)
	}
	return raw, nil
}

// chooseMethod picks the verb, honouring only what the manifest declares.
func chooseMethod(r web.MCPRouteInfo, args callArgs) (string, error) {
	allowed := make(map[string]bool, len(r.Methods))
	for _, m := range r.Methods {
		allowed[strings.ToUpper(m)] = true
	}
	if m := strings.ToUpper(strings.TrimSpace(args.Method)); m != "" {
		if !allowed[m] {
			return "", fmt.Errorf("method %s is not one of this route's verbs (%s)", m, strings.Join(r.Methods, ", "))
		}
		return m, nil
	}
	if len(r.Methods) == 1 {
		return strings.ToUpper(r.Methods[0]), nil
	}
	// Several verbs. A GET is chosen only when the call carries no body, because a body on a GET is
	// meaningless; a route that answers neither GET nor POST must be told which verb it is, rather
	// than being guessed at with a write.
	if allowed[http.MethodGet] && len(args.Body) == 0 {
		return http.MethodGet, nil
	}
	if allowed[http.MethodPost] {
		return http.MethodPost, nil
	}
	return "", fmt.Errorf("this route answers %s: state one with \"method\"", strings.Join(r.Methods, ", "))
}

// refusalText turns the gate's 428 into the next step. The gate's own body is kept verbatim — it
// is the evidence, and it carries the route, the risk class and the header name — and the
// instruction this transport adds is what to do with it.
//
// The mint path is computed here rather than read out of the gate's message because the gate prints
// the MANIFEST pattern, so a subtree route renders as "POST /api/audit//confirm" — one slash too
// many. This layer prints the path it will actually POST to, and a test mints through the console
// for every confirmation-worthy route so the derivation cannot drift from the registered endpoint.
func refusalText(t tool, gate string) string {
	return fmt.Sprintf(`%s
burpsy refused this call: a mutating call to a route whose risk class is %q needs a one-time confirmation.
Next step, as its own visible action: call the %s tool with {"route":%q}. It returns a token.
Then re-issue this call with "confirm" set to that token. The token is single-use, expires in %d seconds, and is bound to %s.
Minting is a POST to %s. (The console's own message above prints the route pattern, so a subtree route reads with a doubled slash; the path here is the one this transport will use.)
Only do this when a human has asked for this specific action.`,
		gate, t.route.Risk, confirmToolName, t.route.Pattern, web.MCPConfirmTTLSeconds(), t.route.Pattern, web.MCPConfirmEndpoint(t.route.Pattern))
}

// callConfirm mints a confirmation through the console's own endpoint.
//
// The route pattern is validated against the manifest before it is used to build a URL — not as an
// authorisation decision (the server makes that, and answers 400 for a route that needs no
// confirmation) but because the pattern is interpolated into a URL, and a caller-supplied string
// in a URL is a request the caller chose. Only strings the manifest actually contains are used.
func (s *Server) callConfirm(ctx context.Context, req request, args callArgs) response {
	route := strings.TrimSpace(args.Route)
	r, ok := s.byPattern[route]
	if !ok {
		return s.ok(req, errResult(fmt.Sprintf("%q is not a route in burpsy's manifest. Pass the exact \"route\" value printed by a refusal (for example %q), not a concrete path.",
			route, "/api/audit/")))
	}

	target := s.baseURL + web.MCPConfirmEndpoint(r.Pattern)
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	if err != nil {
		return s.ok(req, errResult("could not build the confirmation request: "+err.Error()))
	}
	hreq.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(hreq)
	if err != nil {
		return s.ok(req, errResult(fmt.Sprintf("could not reach the burpsy console at %s: %v", s.baseURL, err)))
	}
	defer resp.Body.Close()

	payload, truncated, err := readCapped(resp.Body, maxResultBytes)
	if err != nil {
		return s.ok(req, errResult("could not read the console's response: "+err.Error()))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d POST %s\n", resp.StatusCode, web.MCPConfirmEndpoint(r.Pattern))
	if truncated {
		fmt.Fprintf(&b, "(truncated at %d bytes)\n", maxResultBytes)
	}
	b.Write(payload)

	if resp.StatusCode != http.StatusOK {
		return s.ok(req, errResult(b.String()))
	}

	fmt.Fprintf(&b, "\nOne-time token minted for %s. It is single-use, expires in %d seconds, and authorises one mutating call to that route. Re-issue the refused call with \"confirm\" set to the token value.\nOnly proceed if a human asked for that specific action.",
		r.Pattern, web.MCPConfirmTTLSeconds())
	return s.ok(req, callResult{Content: []contentBlock{{Type: "text", Text: b.String()}}})
}

// readCapped reads at most limit bytes and reports whether there was more. Reading one byte over
// the limit is what makes "was it truncated" answerable without buffering the whole body.
func readCapped(r io.Reader, limit int) ([]byte, bool, error) {
	buf, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, false, err
	}
	if len(buf) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}
