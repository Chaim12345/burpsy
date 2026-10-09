package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"

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
	// ops is set for a grouped tool and nil for a route tool. Each op is exactly one (pattern, verb)
	// of the manifest; byOp is the same list keyed by op name.
	ops  []op          `json:"-"`
	byOp map[string]op `json:"-"`
}

// op is one operation of a grouped tool: one manifest route and one of its verbs.
type op struct {
	name   string
	route  web.MCPRouteInfo
	method string
}

type callArgs struct {
	// Op names the operation of a grouped tool, spelled "VERB /pattern" exactly as the tool's enum
	// lists it. Ignored by route tools.
	Op string `json:"op,omitempty"`
	// ID is a shortcut for Path on a subtree operation: the path becomes the pattern plus ID, so
	// {"op":"GET /api/message/","id":"12"} requests /api/message/12.
	ID     string            `json:"id,omitempty"`
	Method string            `json:"method,omitempty"`
	Path   string            `json:"path,omitempty"`
	Query  map[string]string `json:"query,omitempty"`
	Body   json.RawMessage   `json:"body,omitempty"`
	// Confirm is the one-time token minted by burpsy_confirm. It is relayed as the gate's header.
	Confirm string `json:"confirm,omitempty"`
	// Tool and Arguments are burpsy_confirm's own arguments: the tool the confirmation is for, and the
	// exact arguments that call will carry. The confirmation is bound to the call they resolve to
	// (burpsy-react-ui-e0yq), so they are resolved by the same code the call itself goes through.
	Tool      string          `json:"tool,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
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

// buildTools builds the descriptor list for the configured surface and fills the lookup maps.
// Called once from New.
func (s *Server) buildTools() ([]tool, error) {
	if s.surface == SurfaceRoutes {
		return s.buildRouteTools(), nil
	}
	return s.buildGroupedTools()
}

// buildRouteTools turns the exposed manifest into one descriptor per route, in stable order. This is
// the -surface routes debugging view: every manifest pattern, assets and subtree spellings included.
func (s *Server) buildRouteTools() []tool {
	routes := append([]web.MCPRouteInfo(nil), s.routes...)
	sort.Slice(routes, func(i, j int) bool { return routes[i].Pattern < routes[j].Pattern })

	// The transport's own tool name is claimed first so a manifest route can never shadow it: a
	// descriptor list where "burpsy_confirm" means a route is a list where the confirm flow is
	// unreachable.
	used := map[string]bool{confirmToolName: true, taskStatusToolName: true}

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

	confirm := s.confirmToolDescriptor(out)
	out = append(out, confirm)
	s.byName[confirm.Name] = confirm
	status := taskStatusDescriptor()
	out = append(out, status)
	s.byName[status.Name] = status
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

// schemaForRoute is a route tool's InputSchema. The body and query are typed per verb from the
// handler's own request type (web.MCPSchemaFor, burpsy-react-ui-3zw0); a route answering several
// verbs offers each verb's body as one titled branch.
func schemaForRoute(r web.MCPRouteInfo) map[string]any {
	methods := make([]string, 0, len(r.Methods))
	for _, m := range r.Methods {
		methods = append(methods, strings.ToUpper(m))
	}
	sort.Strings(methods)

	ops := make([]op, 0, len(methods))
	for _, m := range methods {
		ops = append(ops, op{name: m + " " + r.Pattern, route: r, method: m})
	}
	props := map[string]any{
		"method": map[string]any{
			"type": "string", "enum": methods,
			"description": "HTTP method. Optional when the route answers exactly one verb, or when it answers GET and no body is supplied; otherwise required.",
		},
		"query": querySchemaFor(ops),
		"body":  bodySchemaFor(ops),
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
//
// What the host's human is asked to approve is the call itself, not a route name: burpsy_confirm
// takes the tool and the exact arguments of the call it confirms, and its answer is the console's
// preview of the resolved request — the method, the URL and the body the token is bound to
// (burpsy-react-ui-e0yq). A host that shows its human this call's arguments is showing them what
// will run; the gate refuses the token on any other request.
func (s *Server) confirmToolDescriptor(tools []tool) tool {
	gated := make([]string, 0, len(tools))
	for _, t := range tools {
		if toolNeedsConfirm(t) {
			gated = append(gated, t.Name)
		}
	}
	sort.Strings(gated)

	description := fmt.Sprintf(`Mint a one-time confirmation for ONE specific call to a burpsy tool whose risk class requires one.

Use this only when a human has asked for that specific action. A confirmation is the server's checkpoint in front of the routes that send unbounded traffic, widen what the engagement is allowed to touch, read or replay credentials, or discard evidence. An agent that mints its own confirmations has turned that checkpoint into a formality — this tool is a separate call precisely so the escalation is visible in the transcript and can be approved by the host as its own act, not as a field filled in silently.

Pass "tool" (the tool you will call) and "arguments" (exactly the arguments you will call it with, without "confirm"). The answer is a preview of the resolved request — method, URL, body and the body's hash — and the token is bound to that request: it is refused, and burned, if the call that spends it differs in method, path, query or body. Minting does not perform the action. The token is single-use, expires in %d seconds, and is spent by setting the "confirm" argument of that call.`, web.MCPConfirmTTLSeconds())

	return tool{
		Name:        confirmToolName,
		Description: description,
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tool": map[string]any{
					"type":        "string",
					"enum":        gated,
					"description": "The tool whose call this confirmation is for.",
				},
				"arguments": map[string]any{
					"type":                 "object",
					"additionalProperties": true,
					"description":          "The exact arguments the confirmed call will carry (op, id or path, method, query, body), without \"confirm\". The token is bound to the request they resolve to.",
				},
			},
			"required": []string{"tool", "arguments"},
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

// toolNeedsConfirm reports whether any operation a tool reaches is confirmation-worthy.
func toolNeedsConfirm(t tool) bool {
	if t.ops == nil {
		return t.route.NeedsConfirm
	}
	for _, o := range t.ops {
		if o.route.NeedsConfirm {
			return true
		}
	}
	return false
}

// ---- the grouped surface ------------------------------------------------------------------------

// buildGroupedTools builds the capability-grouped surface from groupedTools (groups.go).
//
// It refuses to build a surface whose table names an operation the manifest does not have — a
// pattern that is not registered, or a verb the route does not answer — because that tool would
// advertise a call that can only fail. The tests catch the same mismatch at build time; this is what
// keeps a stale table from shipping as a server that starts and then 404s.
func (s *Server) buildGroupedTools() ([]tool, error) {
	out := make([]tool, 0, len(groupedTools)+1)
	for _, g := range groupedTools {
		if _, taken := s.byName[g.name]; taken || g.name == confirmToolName || g.name == taskStatusToolName {
			return nil, fmt.Errorf("mcp: grouped tool name %q is used twice", g.name)
		}
		t := tool{Name: g.name, byOp: make(map[string]op, len(g.ops))}
		for _, name := range g.ops {
			o, err := s.resolveOpSpec(name)
			if err != nil {
				return nil, fmt.Errorf("mcp: grouped tool %s: %w", g.name, err)
			}
			if _, dup := t.byOp[o.name]; dup {
				return nil, fmt.Errorf("mcp: grouped tool %s lists %s twice", g.name, o.name)
			}
			t.ops = append(t.ops, o)
			t.byOp[o.name] = o
		}
		if len(t.ops) == 0 {
			return nil, fmt.Errorf("mcp: grouped tool %s fronts no operation", g.name)
		}
		// One risk class per tool, so the tool-level annotations are true of every op it reaches.
		risk := t.ops[0].route.Risk
		for _, o := range t.ops[1:] {
			if o.route.Risk != risk {
				return nil, fmt.Errorf("mcp: grouped tool %s spans two risk classes (%s is %s, %s is %s)",
					g.name, t.ops[0].name, risk, o.name, o.route.Risk)
			}
		}
		t.route = t.ops[0].route
		t.Description = describeGrouped(g, t.ops)
		t.InputSchema = schemaForGrouped(t.ops)
		t.Annotations = annotationsForGrouped(g, t.ops)
		out = append(out, t)
		s.byName[t.Name] = t
	}

	confirm := s.confirmToolDescriptor(out)
	out = append(out, confirm)
	s.byName[confirm.Name] = confirm
	status := taskStatusDescriptor()
	out = append(out, status)
	s.byName[status.Name] = status
	return out, nil
}

// resolveOpSpec turns a table entry "VERB /pattern" into an op bound to the exposed manifest.
func (s *Server) resolveOpSpec(spec string) (op, error) {
	verb, pattern, ok := strings.Cut(strings.TrimSpace(spec), " ")
	if !ok || verb == "" || pattern == "" {
		return op{}, fmt.Errorf("operation %q is not spelled \"VERB /pattern\"", spec)
	}
	verb = strings.ToUpper(verb)
	r, ok := s.byPattern[pattern]
	if !ok {
		return op{}, fmt.Errorf("operation %q names %s, which is not a manifest route", spec, pattern)
	}
	for _, m := range r.Methods {
		if strings.EqualFold(m, verb) {
			return op{name: verb + " " + pattern, route: r, method: verb}, nil
		}
	}
	return op{}, fmt.Errorf("operation %q: %s answers %s, not %s", spec, pattern, strings.Join(r.Methods, "/"), verb)
}

// describeGrouped writes the grouped tool's description: the one-line short description, then what
// the tool costs and whether it is refused, then each operation with the manifest's own summary.
// Everything after the first line is derived, so it cannot drift from the routes.
func describeGrouped(g groupSpec, ops []op) string {
	r := ops[0].route
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", g.short)
	fmt.Fprintf(&b, "Group: %s. Risk class: %s (%s). Escalation tier: %s.\n", g.group, r.Risk, r.Safety, r.Tier)
	gated := []string{}
	if r.NeedsConfirm {
		for _, o := range ops {
			if web.MCPMethodMutates(o.method) {
				gated = append(gated, o.name)
			}
		}
	}
	if len(gated) > 0 {
		fmt.Fprintf(&b, "Confirmation: REQUIRED for %s — the server refuses those with HTTP 428 unless a one-time token from %s is supplied as \"confirm\". A GET is a read and is not gated.\n",
			strings.Join(gated, ", "), confirmToolName)
	} else {
		b.WriteString("Confirmation: not required.\n")
	}
	b.WriteString("Operations (pass one as \"op\"):")
	for _, o := range ops {
		fmt.Fprintf(&b, "\n- %s — %s", o.name, o.route.Summary)
		if strings.HasSuffix(o.route.Pattern, "/") {
			fmt.Fprintf(&b, " [subtree: pass \"path\" (e.g. %s) or \"id\"]", pathExample(o.route))
		}
	}
	return b.String()
}

// annotationsForGrouped carries the shared risk class and MCP's four standard hints.
//
// The hints come from the manifest's risk class exactly as for a route tool, with one derivation on
// top: readOnlyHint is false for a tool that can PUT, PATCH or DELETE, whatever its class says. That
// is not a re-judgement of the class — a verb that replaces or removes state is not read-only by
// definition. It was written for DELETE /api/history, which the manifest classed riskRead until
// burpsy-react-ui-gf68 moved it to its own riskDestructive pattern; it stays as the backstop for
// the next mutating verb that lands under a read class.
func annotationsForGrouped(g groupSpec, ops []op) map[string]any {
	r := ops[0].route
	readOnly := hasHint(r.Hints, "READ_ONLY")
	names := make([]string, 0, len(ops))
	for _, o := range ops {
		names = append(names, o.name)
		switch o.method {
		case http.MethodPut, http.MethodPatch, http.MethodDelete:
			readOnly = false
		}
	}
	return map[string]any{
		"readOnlyHint":         readOnly,
		"idempotentHint":       hasHint(r.Hints, "IDEMPOTENT"),
		"destructiveHint":      hasHint(r.Hints, "DESTRUCTIVE"),
		"openWorldHint":        hasHint(r.Hints, "OPEN_WORLD"),
		"riskClass":            r.Risk,
		"escalationTier":       r.Tier,
		"requiresConfirmation": r.NeedsConfirm,
		"group":                g.group,
		"shortDescription":     g.short,
		"operations":           names,
	}
}

// schemaForGrouped is a grouped tool's input schema: which operation, and that operation's path,
// query and body.
func schemaForGrouped(ops []op) map[string]any {
	names := make([]string, 0, len(ops))
	subtree := false
	for _, o := range ops {
		names = append(names, o.name)
		if strings.HasSuffix(o.route.Pattern, "/") {
			subtree = true
		}
	}
	props := map[string]any{
		"op": map[string]any{
			"type": "string", "enum": names,
			"description": "The operation: one HTTP verb and route of the burpsy console, exactly as listed.",
		},
		"query": querySchemaFor(ops),
		"body":  bodySchemaFor(ops),
		"confirm": map[string]any{
			"type":        "string",
			"description": "One-time confirmation token minted by " + confirmToolName + ". The server refuses a mutating call to a confirmation-worthy route without it (HTTP 428).",
		},
	}
	if subtree {
		props["path"] = map[string]any{
			"type":        "string",
			"description": "Concrete request path for a subtree operation (one whose pattern ends in \"/\"), e.g. /api/message/12. It must resolve to the operation's own route.",
		}
		props["id"] = map[string]any{
			"type":        "string",
			"description": "Shortcut for path on a subtree operation: the path becomes the pattern followed by id.",
		}
	}
	required := []string{}
	if len(ops) > 1 {
		required = append(required, "op")
	}
	return map[string]any{"type": "object", "properties": props, "required": required}
}

// bodySchemaFor is the "body" property for a set of operations: each operation's body schema,
// reflected from the handler's own request type by web.MCPSchemaFor. One operation with a body
// publishes its schema directly; several publish one branch each, titled with the operation it
// belongs to, so a model reads which body goes with which op. Operations that take no body are named
// in the description rather than given an empty branch.
func bodySchemaFor(ops []op) map[string]any {
	var branches []map[string]any
	var none []string
	for _, o := range ops {
		spec, ok := web.MCPSchemaFor(o.method, o.route.Pattern)
		if !ok || spec.Body == nil {
			none = append(none, o.name)
			continue
		}
		b := cloneMap(spec.Body)
		b["title"] = o.name
		desc, _ := b["description"].(string)
		req := "required"
		if !spec.BodyRequired {
			req = "optional"
		}
		b["description"] = strings.TrimSpace(fmt.Sprintf("Body for %s (%s). %s", o.name, req, desc))
		branches = append(branches, b)
	}
	note := "JSON request body, sent as application/json. The server decodes it strictly for an agent: an unknown field is refused with HTTP 400 naming the field."
	if len(none) > 0 {
		note += " No body for: " + strings.Join(none, ", ") + "."
	}
	switch len(branches) {
	case 0:
		return map[string]any{"description": "These operations take no body; omit it. (" + strings.Join(none, ", ") + ")"}
	case 1:
		b := branches[0]
		b["description"] = fmt.Sprint(b["description"]) + " " + note
		return b
	}
	anyOf := make([]any, 0, len(branches))
	for _, b := range branches {
		anyOf = append(anyOf, b)
	}
	return map[string]any{"anyOf": anyOf, "description": note + " Each branch is titled with the operation it belongs to."}
}

// querySchemaFor is the "query" property: the union of the declared query parameters of the
// operations, each described with the operations that read it. Values are strings on the wire.
func querySchemaFor(ops []op) map[string]any {
	props := map[string]any{}
	users := map[string][]string{}
	for _, o := range ops {
		spec, ok := web.MCPSchemaFor(o.method, o.route.Pattern)
		if !ok || spec.Query == nil {
			continue
		}
		qp, _ := spec.Query["properties"].(map[string]any)
		for name, p := range qp {
			if _, seen := props[name]; !seen {
				props[name] = cloneMap(p.(map[string]any))
			}
			users[name] = append(users[name], o.name)
		}
	}
	for name, p := range props {
		m := p.(map[string]any)
		desc, _ := m["description"].(string)
		m["description"] = strings.TrimSpace(desc + " (read by " + strings.Join(users[name], ", ") + ")")
	}
	return map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": map[string]any{"type": "string"},
		"description":          "Query string parameters. The named ones are the parameters the handlers read; values are strings.",
	}
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// resolveOp picks the operation a grouped-tool call names.
func resolveOp(t tool, args callArgs) (op, error) {
	name := strings.TrimSpace(args.Op)
	if name == "" {
		if len(t.ops) == 1 {
			name = t.ops[0].name
		} else {
			return op{}, fmt.Errorf("the %s tool fronts %d operations: state one as \"op\" (%s)",
				t.Name, len(t.ops), strings.Join(opNames(t.ops), ", "))
		}
	}
	if verb, pattern, ok := strings.Cut(name, " "); ok {
		name = strings.ToUpper(verb) + " " + strings.TrimSpace(pattern)
	}
	o, ok := t.byOp[name]
	if !ok {
		return op{}, fmt.Errorf("%q is not an operation of the %s tool; it fronts %s", args.Op, t.Name, strings.Join(opNames(t.ops), ", "))
	}
	if m := strings.ToUpper(strings.TrimSpace(args.Method)); m != "" && m != o.method {
		return op{}, fmt.Errorf("method %s contradicts the operation %s; the operation names its own verb", m, o.name)
	}
	return o, nil
}

func opNames(ops []op) []string {
	out := make([]string, 0, len(ops))
	for _, o := range ops {
		out = append(out, o.name)
	}
	return out
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
		Meta      struct {
			ProgressToken json.RawMessage `json:"progressToken,omitempty"`
		} `json:"_meta"`
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
	call := callState{progressToken: params.Meta.ProgressToken}
	if params.Name == taskStatusToolName {
		return s.ok(req, s.taskStatus(ctx, params.Arguments, call))
	}

	t, ok := s.byName[params.Name]
	if !ok {
		// An unknown NAME is a protocol-level mistake — the caller asked for something that does
		// not exist, which is not the tool's input being wrong. An unknown ARGUMENT is the other
		// case and comes back as isError.
		return s.fail(req, codeInvalidParams, "no tool named %q; call tools/list for the surface", params.Name)
	}

	res := s.invoke(ctx, t, args, call)
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
func (s *Server) invoke(ctx context.Context, t tool, args callArgs, call callState) callResult {
	rc, err := s.resolveCall(t, args)
	if err != nil {
		return errResult(err.Error())
	}
	route, method, path := rc.route, rc.method, rc.path
	target := s.baseURL + rc.url
	var body io.Reader
	if rc.body != nil {
		body = bytes.NewReader(rc.body)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return errResult("could not build the request: " + err.Error())
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	// Marks the call as an agent's, which opts it into strict body decoding: a guessed field name is
	// refused with 400 naming it, rather than dropped while the request runs without it.
	req.Header.Set(web.MCPAgentHeaderName, "burpsy-mcp")
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
	if bodyErr := resp.Header.Get(web.BodyErrorHeader); bodyErr != "" {
		fmt.Fprintf(&b, "\nbody error: %s", bodyErr)
	}
	text := b.String()

	if resp.StatusCode == http.StatusPreconditionRequired {
		return errResult(refusalText(route, t.Name, args, text))
	}
	if resp.StatusCode == http.StatusAccepted && !truncated {
		if id, ok := taskIDOf(payload); ok {
			return s.awaitTask(ctx, id, text, call)
		}
	}
	if resp.StatusCode >= 400 {
		return errResult(text)
	}
	return callResult{Content: []contentBlock{{Type: "text", Text: text}}}
}

// resolvedCall is a tool call resolved to the request it sends: the one definition both the call
// and burpsy_confirm use, so the request a confirmation previews is the request the call sends.
type resolvedCall struct {
	route  web.MCPRouteInfo
	method string
	// path is the concrete path; url is the path plus the encoded query, relative to the console.
	path string
	url  string
	// body is the exact body sent, nil for none — after any transformation this layer applies
	// (withAsync), because that transformed body is what the gate compares.
	body []byte
}

// resolveCall validates a call's arguments against its tool and resolves the request it will send.
func (s *Server) resolveCall(t tool, args callArgs) (resolvedCall, error) {
	route := t.route
	var method string
	if t.ops != nil {
		o, err := resolveOp(t, args)
		if err != nil {
			return resolvedCall{}, err
		}
		route, method = o.route, o.method
		if strings.TrimSpace(args.Path) == "" && strings.TrimSpace(args.ID) != "" && strings.HasSuffix(route.Pattern, "/") {
			args.Path = route.Pattern + strings.TrimPrefix(strings.TrimSpace(args.ID), "/")
		}
	}
	path, err := s.resolvePath(t.Name, route, args)
	if err != nil {
		return resolvedCall{}, err
	}
	if method == "" {
		if method, err = chooseMethod(route, args); err != nil {
			return resolvedCall{}, err
		}
	}
	target := path
	if len(args.Query) > 0 {
		q := url.Values{}
		for k, v := range args.Query {
			q.Set(k, v)
		}
		target += "?" + q.Encode()
	}
	// An audit started through the transport runs as a console task and is awaited for the sync
	// window (burpsy-react-ui-wdza): the call answers with the finished result, or with a task handle
	// the session can keep working past. "async": false in the body keeps the old blocking call.
	if asyncOps[method+" "+route.Pattern] {
		args.Body = withAsync(args.Body)
	}
	var body []byte
	if len(args.Body) > 0 {
		body = []byte(args.Body)
	}
	return resolvedCall{route: route, method: method, path: path, url: target, body: body}, nil
}

// resolvePath decides the concrete path a tool call will request, and refuses anything that is not
// this tool's own route.
//
// That refusal is not a policy decision and does not duplicate the gate: it is what the tool name
// MEANS. A tool listed as /api/advisories that could be pointed at /api/audit/selected would be a
// descriptor whose published risk class describes a route other than the one it reaches. The
// resolution itself is web.MCPRouteForPath, which is the gate's own longest-prefix rule, so the
// binding and the gate cannot disagree about which route a path names.
func (s *Server) resolvePath(name string, r web.MCPRouteInfo, args callArgs) (string, error) {
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
			return "", fmt.Errorf("the %s tool calls %s and nothing else; %q is a different route — call its own tool", name, r.Pattern, raw)
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
// instruction this transport adds is what to do with it: confirm THIS call, by its tool and its
// arguments, because the token is bound to the request they resolve to.
func refusalText(r web.MCPRouteInfo, toolName string, args callArgs, gate string) string {
	args.Confirm = ""
	confirmArgs, _ := json.Marshal(map[string]any{"tool": toolName, "arguments": args})
	return fmt.Sprintf(`%s
burpsy refused this call: a mutating call to a route whose risk class is %q needs a one-time confirmation of this exact call.
Next step, as its own visible action: call the %s tool with %s. It returns a preview of the request and a token bound to it.
Then re-issue this call, unchanged, with "confirm" set to that token. The token is single-use, expires in %d seconds, and is refused on any call whose method, path, query or body differs.
Minting is a POST to %s.
Only do this when a human has asked for this specific action.`,
		gate, r.Risk, confirmToolName, confirmArgs, web.MCPConfirmTTLSeconds(), web.MCPConfirmEndpoint(r.Pattern))
}

// mintDescription is the body of a mint request: the call a confirmation is for, as the console's
// mint endpoint reads it.
type mintDescription struct {
	Method     string  `json:"method"`
	URL        string  `json:"url"`
	Body       *string `json:"body,omitempty"`
	BodyBase64 *string `json:"body_base64,omitempty"`
}

// mintPreview is the part of the console's mint answer this layer renders for the approver.
type mintPreview struct {
	Token   string `json:"token"`
	Binding string `json:"binding"`
	Call    struct {
		Method        string   `json:"method"`
		URL           string   `json:"url"`
		BodyBytes     int      `json:"body_bytes"`
		BodySHA256    string   `json:"body_sha256"`
		BodyKind      string   `json:"body_kind"`
		Body          string   `json:"body"`
		BodyTruncated bool     `json:"body_truncated"`
		Redacted      []string `json:"redacted"`
	} `json:"call"`
}

// callConfirm mints a confirmation for one resolved call through the console's own endpoint.
//
// The call is resolved by resolveCall — the code tools/call itself runs — so the request the
// console binds the token to is the request the call will send, including what this layer adds to
// it (withAsync). The tool name is validated against the surface before anything is built, and the
// route pattern used for the mint URL comes from the manifest, never from the caller.
//
// It makes no authorisation decision: a call that needs no confirmation is still POSTed, and the
// console's own refusal is passed through, so the two cannot disagree about which classes are gated.
func (s *Server) callConfirm(ctx context.Context, req request, args callArgs) response {
	name := strings.TrimSpace(args.Tool)
	t, ok := s.byName[name]
	if !ok || name == confirmToolName || name == taskStatusToolName {
		return s.ok(req, errResult(fmt.Sprintf("%q is not a tool on this surface. Pass \"tool\" (the tool you will call) and \"arguments\" (its exact arguments); the refusal of the call prints both.", name)))
	}
	var callArgsOf callArgs
	if len(args.Arguments) > 0 {
		if err := json.Unmarshal(args.Arguments, &callArgsOf); err != nil {
			return s.ok(req, errResult("could not read \"arguments\": "+err.Error()))
		}
	}
	if callArgsOf.Confirm != "" || callArgsOf.Tool != "" || len(callArgsOf.Arguments) > 0 {
		return s.ok(req, errResult("\"arguments\" are the confirmed call's own arguments; they carry no \"confirm\", \"tool\" or nested \"arguments\""))
	}
	rc, err := s.resolveCall(t, callArgsOf)
	if err != nil {
		return s.ok(req, errResult(err.Error()))
	}
	desc := mintDescription{Method: rc.method, URL: rc.url}
	if rc.body != nil {
		if utf8.Valid(rc.body) {
			b := string(rc.body)
			desc.Body = &b
		} else {
			b := base64.StdEncoding.EncodeToString(rc.body)
			desc.BodyBase64 = &b
		}
	}
	descJSON, err := json.Marshal(desc)
	if err != nil {
		return s.ok(req, errResult("could not describe the call: "+err.Error()))
	}

	endpoint := web.MCPConfirmEndpoint(rc.route.Pattern)
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+endpoint, bytes.NewReader(descJSON))
	if err != nil {
		return s.ok(req, errResult("could not build the confirmation request: "+err.Error()))
	}
	hreq.Header.Set("Accept", "application/json")
	hreq.Header.Set("Content-Type", "application/json")

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
	fmt.Fprintf(&b, "HTTP %d POST %s\n", resp.StatusCode, endpoint)
	if truncated {
		fmt.Fprintf(&b, "(truncated at %d bytes)\n", maxResultBytes)
	}
	b.Write(payload)

	if resp.StatusCode != http.StatusOK {
		return s.ok(req, errResult(b.String()))
	}
	var minted mintPreview
	if truncated || json.Unmarshal(payload, &minted) != nil || minted.Token == "" {
		return s.ok(req, errResult(b.String()+"\nthe console's answer is not a mint result; no token is usable from it"))
	}
	// The drift check this layer can make: the console must have bound the token to the request this
	// layer will send. A disagreement would be a token for a call nobody is going to make — or a
	// preview that is not of the call — and either way it is not handed out as if it were fine.
	if minted.Call.Method != rc.method || minted.Call.URL != canonicalURL(rc.url) {
		return s.ok(req, errResult(fmt.Sprintf("%s\nthe console bound the token to %s %s, but this call sends %s %s; not using it",
			b.String(), minted.Call.Method, minted.Call.URL, rc.method, canonicalURL(rc.url))))
	}

	p := minted.Call
	fmt.Fprintf(&b, "\n\nPreview — the one request this token authorises (show this to the human approving it):\n  %s %s\n", p.Method, p.URL)
	switch p.BodyKind {
	case "none":
		b.WriteString("  body: none\n")
	case "binary":
		fmt.Fprintf(&b, "  body: %d bytes of binary content (not shown)\n", p.BodyBytes)
	default:
		fmt.Fprintf(&b, "  body (%s, %d bytes):\n", p.BodyKind, p.BodyBytes)
		for _, line := range strings.Split(p.Body, "\n") {
			b.WriteString("    " + line + "\n")
		}
		if p.BodyTruncated {
			b.WriteString("    … (preview truncated; the hash below covers the whole body)\n")
		}
	}
	if len(p.Redacted) > 0 {
		fmt.Fprintf(&b, "  withheld from this preview (still bound by the hash): %s\n", strings.Join(p.Redacted, ", "))
	}
	fmt.Fprintf(&b, "  body sha256 (canonical): %s\n", p.BodySHA256)
	fmt.Fprintf(&b, "One-time token minted for exactly this call to %s. It is single-use, expires in %d seconds, and is refused (and burned) on any call whose method, path, query or body differs. Re-issue the %s call with these arguments, unchanged, and \"confirm\" set to the token value.\nOnly proceed if a human asked for that specific action.",
		t.Name, web.MCPConfirmTTLSeconds(), t.Name)
	return s.ok(req, callResult{Content: []contentBlock{{Type: "text", Text: b.String()}}})
}

// canonicalURL is a relative URL with its query in sorted, re-encoded form — the form the console's
// preview reports — so the drift check compares like with like.
func canonicalURL(raw string) string {
	path, query, found := strings.Cut(raw, "?")
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded // the console reports the decoded path, as the gate compares it
	}
	if !found || query == "" {
		return path
	}
	if v, err := url.ParseQuery(query); err == nil {
		query = v.Encode()
	}
	return path + "?" + query
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
