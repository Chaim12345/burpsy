package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/web"
)

// The burpsy-react-ui-cvzq acceptance tests: the default tools/list is the capability-grouped
// surface, it has no asset routes and no subtree spellings, every route-verb is reachable from
// exactly one grouped tool (or is on notExposed with a reason), and no grouped tool spans two risk
// classes. Every test drives the real stdio session against a real gated console.

func askGrouped(t *testing.T, base string, lines ...string) []rpcReply {
	t.Helper()
	return askWith(t, Options{BaseURL: base}, lines...)
}

// callGrouped runs one tools/call on the default (grouped) surface.
func callGrouped(t *testing.T, base, name string, args map[string]any) callResult {
	t.Helper()
	replies := askGrouped(t, base, rpcRequest(t, 1, "tools/call", map[string]any{"name": name, "arguments": args}))
	if len(replies) != 1 {
		t.Fatalf("tools/call %s drew %d replies, want 1", name, len(replies))
	}
	if replies[0].Error != nil {
		t.Fatalf("tools/call %s is a protocol error: %s", name, replies[0].Error.Message)
	}
	var res callResult
	if err := json.Unmarshal(replies[0].Result, &res); err != nil {
		t.Fatalf("decoding the tools/call result: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("tools/call %s returned no content", name)
	}
	return res
}

type groupedTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations struct {
		ReadOnly             bool     `json:"readOnlyHint"`
		RiskClass            string   `json:"riskClass"`
		RequiresConfirmation bool     `json:"requiresConfirmation"`
		Group                string   `json:"group"`
		ShortDescription     string   `json:"shortDescription"`
		Operations           []string `json:"operations"`
	} `json:"annotations"`
}

// listGrouped returns the default tools/list and the raw JSON it was decoded from.
func listGrouped(t *testing.T) ([]groupedTool, string) {
	t.Helper()
	_, base := newConsole(t)
	replies := askGrouped(t, base, rpcRequest(t, 1, "tools/list", nil))
	if len(replies) != 1 || replies[0].Error != nil {
		t.Fatalf("tools/list failed: %+v", replies)
	}
	var listed struct {
		Tools []groupedTool `json:"tools"`
	}
	if err := json.Unmarshal(replies[0].Result, &listed); err != nil {
		t.Fatalf("decoding tools/list: %v", err)
	}
	return listed.Tools, string(replies[0].Result)
}

// routeVerbs is every (verb, pattern) of the real manifest, spelled the way an op is.
func routeVerbs() map[string]web.MCPRouteInfo {
	out := map[string]web.MCPRouteInfo{}
	for _, r := range web.MCPRoutes() {
		for _, m := range r.Methods {
			out[strings.ToUpper(m)+" "+r.Pattern] = r
		}
	}
	return out
}

func TestTheDefaultSurfaceIsGroupedWithNoAssetsAndNoSubtreeSpellings(t *testing.T) {
	tools, raw := listGrouped(t)
	if len(tools) != len(groupedTools)+2 {
		t.Fatalf("tools/list published %d tools, want the %d grouped tools plus %s and %s", len(tools), len(groupedTools), confirmToolName, taskStatusToolName)
	}
	if len(tools) >= 100 {
		t.Fatalf("the grouped surface has %d tools; it exists to be far smaller than the 147-route surface", len(tools))
	}
	for _, tl := range tools {
		switch {
		case tl.Name == "root", tl.Name == "ca_crt":
			t.Fatalf("an asset route is published as tool %q", tl.Name)
		case strings.HasSuffix(tl.Name, "_subtree"), strings.HasPrefix(tl.Name, "api_"):
			t.Fatalf("tool %q is a route-surface name on the grouped surface", tl.Name)
		}
		if tl.Name == confirmToolName || tl.Name == taskStatusToolName {
			continue
		}
		if tl.Annotations.Group == "" || tl.Annotations.ShortDescription == "" {
			t.Fatalf("tool %q has no group or short description: %+v", tl.Name, tl.Annotations)
		}
		if !strings.HasPrefix(tl.Description, tl.Annotations.ShortDescription) {
			t.Fatalf("tool %q's description does not lead with its short description:\n%s", tl.Name, tl.Description)
		}
		for _, o := range tl.Annotations.Operations {
			if strings.HasPrefix(o, "GET / ") || o == "GET /" || o == "GET /ca.crt" {
				t.Fatalf("tool %q reaches the asset %s", tl.Name, o)
			}
		}
	}
	// The marshalled shape: a single-op tool states "required":[], not null, because a client
	// iterating a null required list is the failure this house keeps finding.
	if strings.Contains(raw, `"required":null`) {
		t.Fatalf("a grouped tool's schema marshals required as null:\n%.400s", raw)
	}
}

// The coverage rule, both directions: every route-verb is reachable from exactly one grouped tool or
// is deliberately not exposed with a reason; nothing on the not-exposed list is also exposed; and the
// not-exposed list names only route-verbs that exist, so it cannot rot into a list of nothing.
func TestEveryRouteVerbIsReachableFromExactlyOneGroupedTool(t *testing.T) {
	tools, _ := listGrouped(t)
	verbs := routeVerbs()

	owner := map[string]string{}
	for _, tl := range tools {
		for _, o := range tl.Annotations.Operations {
			if _, ok := verbs[o]; !ok {
				t.Fatalf("tool %q publishes %q, which is not a route-verb of the manifest", tl.Name, o)
			}
			if prev, dup := owner[o]; dup {
				t.Fatalf("%s is reachable from two tools, %q and %q; a route-verb has exactly one owner", o, prev, tl.Name)
			}
			owner[o] = tl.Name
		}
	}
	var missing []string
	for v := range verbs {
		reason, hidden := notExposed[v]
		_, exposed := owner[v]
		switch {
		case hidden && exposed:
			t.Fatalf("%s is on the not-exposed list and is also published by %q", v, owner[v])
		case hidden && strings.TrimSpace(reason) == "":
			t.Fatalf("%s is not exposed and gives no reason", v)
		case !hidden && !exposed:
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("route-verbs reachable from no grouped tool and not on notExposed:\n  %s\nPlace each in a tool in groups.go, or add it to notExposed with the reason.",
			strings.Join(missing, "\n  "))
	}
	for v := range notExposed {
		if _, ok := verbs[v]; !ok {
			t.Fatalf("notExposed names %q, which is not a route-verb of the manifest — a stale entry", v)
		}
	}
}

// A grouped tool's annotations are tool-level, so they are only true if every operation shares the
// risk class. Asserted against the manifest, not against the table.
func TestNoGroupedToolSpansTwoRiskClasses(t *testing.T) {
	tools, _ := listGrouped(t)
	verbs := routeVerbs()
	for _, tl := range tools {
		if tl.Name == confirmToolName || tl.Name == taskStatusToolName {
			continue
		}
		if len(tl.Annotations.Operations) == 0 {
			t.Fatalf("tool %q fronts no operation", tl.Name)
		}
		for _, o := range tl.Annotations.Operations {
			r := verbs[o]
			if r.Risk != tl.Annotations.RiskClass {
				t.Fatalf("tool %q is published as %s but its operation %s is %s", tl.Name, tl.Annotations.RiskClass, o, r.Risk)
			}
			if r.NeedsConfirm != tl.Annotations.RequiresConfirmation {
				t.Fatalf("tool %q requiresConfirmation=%v disagrees with %s (%v)", tl.Name, tl.Annotations.RequiresConfirmation, o, r.NeedsConfirm)
			}
			if !strings.Contains(tl.Description, o+" — "+r.Summary) {
				t.Fatalf("tool %q does not describe %s with the manifest's summary", tl.Name, o)
			}
		}
		// A tool that can replace or remove state is not read-only, whatever its class.
		for _, o := range tl.Annotations.Operations {
			verb, _, _ := strings.Cut(o, " ")
			if (verb == "PUT" || verb == "PATCH" || verb == "DELETE") && tl.Annotations.ReadOnly {
				t.Fatalf("tool %q can %s and is published readOnlyHint=true", tl.Name, o)
			}
		}
	}
}

// The history removal (burpsy-react-ui-gf68) is published as what it is: not a read, and gated.
// Before gf68 it was DELETE /api/history under the read route's riskRead class, so this tool said
// requiresConfirmation=false and the console let it through unconfirmed.
func TestTheHistoryDeleteIsNotPublishedAsARead(t *testing.T) {
	tools, _ := listGrouped(t)
	for _, tl := range tools {
		for _, o := range tl.Annotations.Operations {
			if o == "DELETE /api/history" {
				t.Fatalf("tool %q still fronts DELETE /api/history, which the read route no longer serves", tl.Name)
			}
		}
	}
	for _, tl := range tools {
		for _, o := range tl.Annotations.Operations {
			if o != "DELETE /api/history/rows" {
				continue
			}
			if tl.Name == "history" {
				t.Fatal("DELETE /api/history/rows rides the read-only history tool")
			}
			if tl.Annotations.ReadOnly {
				t.Fatalf("tool %q clears history and is published readOnlyHint=true", tl.Name)
			}
			if tl.Annotations.RiskClass != "destructive" || !tl.Annotations.RequiresConfirmation {
				t.Fatalf("tool %q clears history and is published risk=%s requiresConfirmation=%v, want destructive and true",
					tl.Name, tl.Annotations.RiskClass, tl.Annotations.RequiresConfirmation)
			}
			return
		}
	}
	t.Fatal("DELETE /api/history/rows is not published at all")
}

func TestAGroupedReadOperationReturnsThatRoutesResult(t *testing.T) {
	_, base := newConsole(t)
	res := callGrouped(t, base, "issues", map[string]any{"op": "GET /api/advisories"})
	if res.IsError || !strings.HasPrefix(textOf(res), "HTTP 200 GET /api/advisories\n") {
		t.Fatalf("the grouped read did not reach /api/advisories:\n%.300s", textOf(res))
	}
	// A subtree operation takes "id" as the path segment.
	res = callGrouped(t, base, "issues", map[string]any{"op": "GET /api/advisories/", "id": "00100200"})
	if res.IsError || !strings.HasPrefix(textOf(res), "HTTP 200 GET /api/advisories/00100200\n") {
		t.Fatalf("the subtree op with an id did not reach /api/advisories/00100200:\n%.300s", textOf(res))
	}
	if !strings.Contains(textOf(res), "SQL injection") {
		t.Fatalf("the advisory read did not return the 00100200 definition:\n%.300s", textOf(res))
	}
	// A single-op tool needs no op.
	res = callGrouped(t, base, "proxy_ca", nil)
	if res.IsError || !strings.HasPrefix(textOf(res), "HTTP 200 GET /api/proxy/ca\n") {
		t.Fatalf("the single-op tool did not default its op:\n%.300s", textOf(res))
	}
}

// The gate is the console's, on the grouped surface exactly as on the route surface: refused, minted
// through burpsy_confirm, then let through once.
func TestAGroupedGatedOperationIsRefusedThenConfirmedOnce(t *testing.T) {
	_, base := newConsole(t)
	args := map[string]any{"op": "POST /api/audit/", "id": "999999"}

	refused := callGrouped(t, base, "scan", args)
	if !refused.IsError || !strings.Contains(textOf(refused), "HTTP 428") || !strings.Contains(textOf(refused), `{"arguments":{"op":"POST /api/audit/","id":"999999"},"tool":"scan"}`) {
		t.Fatalf("the unconfirmed audit was not refused by the gate with the next step:\n%s", textOf(refused))
	}

	minted := callGrouped(t, base, confirmToolName, map[string]any{"tool": "scan", "arguments": args})
	var token struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(bodyLine(t, textOf(minted))), &token); err != nil || token.Token == "" {
		t.Fatalf("mint failed: %v\n%s", err, textOf(minted))
	}
	args["confirm"] = token.Token
	if run := callGrouped(t, base, "scan", args); run.IsError || !strings.HasPrefix(textOf(run), "HTTP 202 POST /api/audit/999999 -> task") {
		t.Fatalf("the confirmed audit did not reach the handler:\n%s", textOf(run))
	}
	if replay := callGrouped(t, base, "scan", args); !replay.IsError || !strings.Contains(textOf(replay), "HTTP 428") {
		t.Fatalf("the token was spent twice:\n%s", textOf(replay))
	}
}

// TestAToolCannotReachARouteItDoesNotName's rule on the grouped surface: an operation reaches its
// own route and nothing else. The console is a closed port, so every refusal must be local.
func TestAGroupedToolCannotReachARouteItDoesNotName(t *testing.T) {
	dead := "http://127.0.0.1:1"
	cases := []struct {
		why  string
		name string
		args map[string]any
		want string
	}{
		{"an op the tool does not front", "history", map[string]any{"op": "POST /api/audit/", "id": "1"}, "is not an operation of the history tool"},
		{"a subtree op pointed at a more specific route", "scan", map[string]any{"op": "POST /api/audit/", "path": "/api/audit/selected"}, "resolves to /api/audit/selected"},
		{"an exact op pointed at another route", "issues", map[string]any{"op": "GET /api/advisories", "path": "/api/crawl"}, "is a different route"},
		{"a method contradicting the op", "issues", map[string]any{"op": "GET /api/advisories", "method": "DELETE"}, "contradicts the operation"},
		{"a multi-op tool with no op", "issues", nil, "state one as \"op\""},
		{"a subtree op with no path or id", "scan", map[string]any{"op": "POST /api/audit/"}, "is not itself a URL"},
		{"a query smuggled through the path", "issues", map[string]any{"op": "GET /api/advisories", "path": "/api/advisories?q=x"}, "must not carry a query string"},
	}
	for _, tc := range cases {
		res := callGrouped(t, dead, tc.name, tc.args)
		if !res.IsError || !strings.Contains(textOf(res), tc.want) {
			t.Fatalf("%s: got %q, want an error mentioning %q", tc.why, textOf(res), tc.want)
		}
		if strings.Contains(textOf(res), "could not reach the burpsy console") {
			t.Fatalf("%s: a request was attempted before refusing", tc.why)
		}
	}
}

// A table that names a route the manifest does not have would publish a tool that can only fail.
// The server refuses to build that surface rather than start and 404.
func TestTheGroupedSurfaceRefusesAnOperationTheManifestLacks(t *testing.T) {
	var routes []web.MCPRouteInfo
	for _, r := range web.MCPRoutes() {
		if r.Pattern != "/api/history" {
			routes = append(routes, r)
		}
	}
	_, err := New(Options{BaseURL: "http://127.0.0.1:1", Routes: routes})
	if err == nil || !strings.Contains(err.Error(), "/api/history") {
		t.Fatalf("a grouped surface naming a missing route was built: err=%v", err)
	}
	// The route surface has no table, so the same manifest builds there.
	if _, err := New(Options{BaseURL: "http://127.0.0.1:1", Routes: routes, Surface: SurfaceRoutes}); err != nil {
		t.Fatalf("the route surface refused a manifest it does not depend on: %v", err)
	}
	if _, err := New(Options{BaseURL: "http://127.0.0.1:1", Surface: "bogus"}); err == nil {
		t.Fatal("an unknown surface was accepted")
	}
}

// Every op enum is exactly the tool's operations, and a tool reaching a subtree op offers path and id.
func TestEachGroupedSchemaOffersExactlyItsOperations(t *testing.T) {
	tools, _ := listGrouped(t)
	for _, tl := range tools {
		if tl.Name == confirmToolName || tl.Name == taskStatusToolName {
			continue
		}
		props, _ := tl.InputSchema["properties"].(map[string]any)
		opProp, _ := props["op"].(map[string]any)
		enum, _ := opProp["enum"].([]any)
		if fmt.Sprint(enum) != fmt.Sprint(toAny(tl.Annotations.Operations)) {
			t.Fatalf("tool %q: op enum %v is not its operations %v", tl.Name, enum, tl.Annotations.Operations)
		}
		subtree := false
		for _, o := range tl.Annotations.Operations {
			if strings.HasSuffix(o, "/") {
				subtree = true
			}
		}
		_, hasPath := props["path"]
		_, hasID := props["id"]
		if subtree != hasPath || subtree != hasID {
			t.Fatalf("tool %q: subtree=%v but path=%v id=%v", tl.Name, subtree, hasPath, hasID)
		}
	}
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
