package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/web"
)

// The burpsy-react-ui-q31t acceptance tests.
//
// Two rules shape every test here.
//
// First, the CONSOLE IS REAL. Each test that calls a tool mounts a web.NewServer's fully-gated
// handler on an httptest server and points the MCP layer at it. The acceptance criterion forbids a
// second implementation of the confirmation gate, and the only way to prove there is not one is to
// watch the real confirmStore spend a real token: a fake would pass whether or not the production
// path exists.
//
// Second, the SESSION IS REAL. Requests go in as newline-delimited JSON-RPC on a reader and replies
// come back the same way, rather than by calling a handler directly. Framing and the "notifications
// get no reply" rule are part of the transport, and a test that skipped them would not be testing
// the thing an MCP client talks to.

// ---- harness ------------------------------------------------------------------------------------

type rpcReply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// toolList is the tools/list result shape, reduced to what these tests assert on.
type toolList struct {
	Tools []struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		InputSchema map[string]any `json:"inputSchema"`
		Annotations map[string]any `json:"annotations"`
	} `json:"tools"`
}

// newConsole starts a real burpsy console in-process and returns its URL.
func newConsole(t *testing.T) (*web.Server, string) {
	t.Helper()
	srv := web.NewServer(core.NewTrafficStore(), core.NewScope())
	ts := httptest.NewServer(srv.MCPGuarded())
	t.Cleanup(ts.Close)
	return srv, ts.URL
}

// askWith runs one stdio session: the lines are the input stream, and every line the server writes
// is parsed as one JSON-RPC message.
func askWith(t *testing.T, opts Options, lines ...string) []rpcReply {
	t.Helper()
	var out bytes.Buffer
	opts.In = strings.NewReader(strings.Join(lines, "\n") + "\n")
	opts.Out = &out
	s, err := New(opts)
	if err != nil {
		t.Fatalf("mcp.New: %v", err)
	}
	if err := s.Serve(context.Background()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var replies []rpcReply
	for _, line := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r rpcReply
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("stdout is not one JSON-RPC message per line: %v (line %q)", err, line)
		}
		replies = append(replies, r)
	}
	return replies
}

func ask(t *testing.T, base string, lines ...string) []rpcReply {
	t.Helper()
	return askWith(t, Options{BaseURL: base}, lines...)
}

// request builds one JSON-RPC request line.
func rpcRequest(t *testing.T, id int, method string, params any) string {
	t.Helper()
	m := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		m["params"] = params
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshalling the request: %v", err)
	}
	return string(b)
}

// call runs one tools/call in its own session and returns the result, failing the test if the
// reply is a protocol error rather than a tool result.
func call(t *testing.T, base, name string, args map[string]any) callResult {
	t.Helper()
	replies := ask(t, base, rpcRequest(t, 1, "tools/call", map[string]any{"name": name, "arguments": args}))
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

func textOf(res callResult) string { return res.Content[0].Text }

// bodyLine is the JSON body a tool result carries after its status line.
func bodyLine(t *testing.T, text string) string {
	t.Helper()
	lines := strings.SplitN(text, "\n", 3)
	if len(lines) < 2 {
		t.Fatalf("result has no body line: %q", text)
	}
	return lines[1]
}

// ---- tools/list ---------------------------------------------------------------------------------

// The whole point of the transport: the surface a client lists is the routes the server will
// enforce, class by class. A tool whose published risk disagreed with its route's would be a
// descriptor that lies about what the call does.
func TestToolsListCarriesEveryManifestRouteWithItsRiskClass(t *testing.T) {
	_, base := newConsole(t)

	replies := ask(t, base, rpcRequest(t, 1, "tools/list", nil))
	if len(replies) != 1 {
		t.Fatalf("tools/list drew %d replies, want 1", len(replies))
	}
	var listed toolList
	if err := json.Unmarshal(replies[0].Result, &listed); err != nil {
		t.Fatalf("decoding tools/list: %v", err)
	}

	manifest := web.MCPRoutes()
	byRoute := make(map[string]web.MCPRouteInfo, len(manifest))
	for _, r := range manifest {
		byRoute[r.Pattern] = r
	}
	if len(listed.Tools) != len(manifest)+1 {
		t.Fatalf("tools/list exposed %d tools, want %d manifest routes plus the confirm tool",
			len(listed.Tools), len(manifest))
	}

	names := make(map[string]bool, len(listed.Tools))
	seen := make(map[string]bool, len(manifest))
	for _, tl := range listed.Tools {
		if names[tl.Name] {
			t.Fatalf("two tools are named %q; an MCP tool name is an address and has to name one tool", tl.Name)
		}
		names[tl.Name] = true
		if tl.Name == confirmToolName {
			continue
		}

		route, _ := tl.Annotations["route"].(string)
		r, ok := byRoute[route]
		if !ok {
			t.Fatalf("tool %q annotates route %q, which is not in the manifest", tl.Name, route)
		}
		seen[route] = true

		if got := tl.Annotations["riskClass"]; got != r.Risk {
			t.Fatalf("tool %q carries riskClass %v, want the manifest's %q", tl.Name, got, r.Risk)
		}
		if !strings.Contains(tl.Description, "Risk class: "+r.Risk) {
			t.Fatalf("tool %q description does not state its risk class:\n%s", tl.Name, tl.Description)
		}
		if got := tl.Annotations["requiresConfirmation"]; got != r.NeedsConfirm {
			t.Fatalf("tool %q requiresConfirmation = %v, want %v", tl.Name, got, r.NeedsConfirm)
		}
		if got := tl.Annotations["escalationTier"]; got != r.Tier {
			t.Fatalf("tool %q escalationTier = %v, want %q", tl.Name, got, r.Tier)
		}
		if !strings.Contains(tl.Description, r.Summary) {
			t.Fatalf("tool %q description does not carry the manifest summary:\n%s", tl.Name, tl.Description)
		}
	}
	for _, r := range manifest {
		if !seen[r.Pattern] {
			t.Fatalf("manifest route %q is not exposed as a tool", r.Pattern)
		}
	}
}

// The manifest holds both an exact route and the subtree under it, and normalising the pattern maps
// both onto one name. Two descriptors with one name would be a tool a client cannot call
// unambiguously, so the subtree half is named for what it is.
func TestACollidingSubtreeRouteGetsItsOwnToolName(t *testing.T) {
	_, base := newConsole(t)
	replies := ask(t, base, rpcRequest(t, 1, "tools/list", nil))
	var listed toolList
	if err := json.Unmarshal(replies[0].Result, &listed); err != nil {
		t.Fatalf("decoding tools/list: %v", err)
	}
	nameOf := map[string]string{}
	for _, tl := range listed.Tools {
		if route, ok := tl.Annotations["route"].(string); ok {
			nameOf[route] = tl.Name
		}
	}
	if got := nameOf["/api/pools"]; got != "api_pools" {
		t.Fatalf("the exact route /api/pools is tool %q, want api_pools", got)
	}
	if got := nameOf["/api/pools/"]; got != "api_pools_subtree" {
		t.Fatalf("the subtree /api/pools/ is tool %q, want api_pools_subtree (it must not share the exact route's name)", got)
	}
}

// The gated classes are the ones a model must not be able to reach without the confirmation step;
// the read classes are the ones it should be able to use freely. Both halves are asserted here
// because a manifest misread in either direction is the defect the transport would amplify.
func TestToolsListMarksExactlyTheConfirmationWorthyRoutes(t *testing.T) {
	_, base := newConsole(t)
	replies := ask(t, base, rpcRequest(t, 1, "tools/list", nil))
	var listed toolList
	if err := json.Unmarshal(replies[0].Result, &listed); err != nil {
		t.Fatalf("decoding tools/list: %v", err)
	}
	gated := map[string]bool{}
	for _, r := range web.MCPRoutes() {
		if r.NeedsConfirm {
			gated[r.Pattern] = true
		}
	}
	if len(gated) == 0 {
		t.Fatal("the manifest names no confirmation-worthy route; this test cannot mean anything")
	}
	flagged := 0
	for _, tl := range listed.Tools {
		if tl.Annotations["requiresConfirmation"] != true {
			continue
		}
		route, _ := tl.Annotations["route"].(string)
		if !gated[route] {
			t.Fatalf("tool %q (%s) is marked as needing confirmation, but its route's class does not", tl.Name, route)
		}
		flagged++
		// Only a route with a mutating verb can actually be refused, so only that kind must
		// explain how to satisfy the gate. A gated-class route that answers GET alone is a read
		// the gate never refuses — and its description says so.
		mutating := false
		for _, r := range web.MCPRoutes() {
			if r.Pattern != route {
				continue
			}
			for _, m := range r.Methods {
				if web.MCPMethodMutates(m) {
					mutating = true
				}
			}
		}
		if mutating && !strings.Contains(tl.Description, confirmToolName) {
			t.Fatalf("tool %q needs confirmation for a mutating call and does not say how to get one:\n%s", tl.Name, tl.Description)
		}
		if !mutating && !strings.Contains(tl.Description, "Confirmation: not required") {
			t.Fatalf("tool %q can only be read and its description does not say the gate does not apply:\n%s", tl.Name, tl.Description)
		}
	}
	if flagged != len(gated) {
		t.Fatalf("%d tools are marked confirmation-worthy, want %d", flagged, len(gated))
	}
}

// ---- a read route -------------------------------------------------------------------------------

// The read half of the acceptance criterion: a riskRead tool call reaches the handler and comes
// back with that route's result. The assertion is on the route's own payload — the advisory
// catalogue, which /api/advisories serves — not merely on a 200.
func TestARiskReadToolCallReturnsThatRoutesResult(t *testing.T) {
	_, base := newConsole(t)

	res := call(t, base, "api_advisories", nil)
	if res.IsError {
		t.Fatalf("a read tool call came back as an error: %s", textOf(res))
	}
	text := textOf(res)
	if !strings.HasPrefix(text, "HTTP 200 GET /api/advisories") {
		t.Fatalf("result does not report the route it called:\n%s", text)
	}

	var view struct {
		Loaded     bool `json:"loaded"`
		Count      int  `json:"count"`
		Advisories []struct {
			TypeIndex string `json:"type_index"`
			Name      string `json:"name"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal([]byte(bodyLine(t, text)), &view); err != nil {
		t.Fatalf("the route's result is not the catalogue view: %v\n%s", err, text)
	}
	if !view.Loaded || view.Count == 0 {
		t.Fatalf("the catalogue came back empty (loaded=%v count=%d); the tool call did not reach the route", view.Loaded, view.Count)
	}
	found := false
	for _, a := range view.Advisories {
		if a.TypeIndex == "00100200" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the catalogue carries no 00100200 definition; got %d rows", len(view.Advisories))
	}
}

// A GET on a route whose class needs confirmation is a read of the state the gate protects, and the
// gate does not refuse it. The transport's descriptions claim exactly that, so it is checked.
func TestAGetOnAConfirmationWorthyRouteIsNotGated(t *testing.T) {
	_, base := newConsole(t)

	res := call(t, base, "api_scope", nil)
	if res.IsError {
		t.Fatalf("a GET of the scope route was refused: %s", textOf(res))
	}
	if !strings.HasPrefix(textOf(res), "HTTP 200 GET /api/scope") {
		t.Fatalf("unexpected result for the scope read:\n%s", textOf(res))
	}
}

// ---- the gate -----------------------------------------------------------------------------------

// The acceptance criterion's safety half: an attack-class call with no confirmation must come back
// with the SERVER's refusal — the real 428, naming the header and the mint path — not with a
// locally invented one and not with a success.
func TestAGatedToolCallWithoutAConfirmationSurfacesTheRealGateRefusal(t *testing.T) {
	_, base := newConsole(t)

	res := call(t, base, "api_audit", map[string]any{"path": "/api/audit/999999"})
	if !res.IsError {
		t.Fatalf("an unconfirmed attack call succeeded; the gate did not stand:\n%s", textOf(res))
	}
	text := textOf(res)
	for _, want := range []string{
		"HTTP 428",
		`"confirm_with"`,         // the gate's own body, verbatim
		web.MCPConfirmHeaderName, // …carrying the header name it told the caller to use
		`"risk":"attack"`,        // …and the risk class it resolved
		confirmToolName,          // and the next step this layer adds
		"/api/audit/confirm",     // the mint path, without the gate message's double slash
		`"route":"/api/audit/"`,  // the exact pattern to mint for
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("the refusal does not mention %q:\n%s", want, text)
		}
	}
	// The console's own body prints the manifest pattern, so for a subtree route its message reads
	// "POST /api/audit//confirm". That text is evidence and is passed through untouched; what has to
	// be right is the path this transport tells the caller to use, which is a different string.
	if !strings.Contains(text, "Minting is a POST to /api/audit/confirm") {
		t.Fatalf("the refusal does not give the path a confirmation is minted at:\n%s", text)
	}
}

// The other half: a token minted through the console's own endpoint lets the same call through, and
// is spent by the real store — a second attempt with it is refused again. That replay check is what
// distinguishes "the real confirmStore is in the path" from "some check happened to pass".
func TestAMintedConfirmationLetsTheGatedCallThroughExactlyOnce(t *testing.T) {
	_, base := newConsole(t)

	minted := call(t, base, confirmToolName, map[string]any{"route": "/api/audit/"})
	if minted.IsError {
		t.Fatalf("minting a confirmation through the console failed: %s", textOf(minted))
	}
	var token struct {
		Token string `json:"token"`
		Route string `json:"route"`
	}
	if err := json.Unmarshal([]byte(bodyLine(t, textOf(minted))), &token); err != nil {
		t.Fatalf("the mint result is not the console's own response: %v\n%s", err, textOf(minted))
	}
	if token.Token == "" || token.Route != "/api/audit/" {
		t.Fatalf("mint returned token=%q route=%q, want a token bound to /api/audit/", token.Token, token.Route)
	}

	run := call(t, base, "api_audit", map[string]any{"path": "/api/audit/999999", "confirm": token.Token})
	if run.IsError {
		t.Fatalf("the confirmed call was still refused: %s", textOf(run))
	}
	if !strings.HasPrefix(textOf(run), "HTTP 200 POST /api/audit/999999") {
		t.Fatalf("the confirmed call did not reach the handler:\n%s", textOf(run))
	}

	replay := call(t, base, "api_audit", map[string]any{"path": "/api/audit/999999", "confirm": token.Token})
	if !replay.IsError || !strings.Contains(textOf(replay), "HTTP 428") {
		t.Fatalf("the same confirmation authorised a second call; a one-time token is being reused:\n%s", textOf(replay))
	}
}

// The mint path is derived, not listed, so it can drift from the endpoints the gate actually
// registers. Minting for every confirmation-worthy route through the console catches that for all
// of them, including the subtree patterns whose registered path is not the pattern itself.
func TestEveryConfirmationWorthyRouteCanBeMinted(t *testing.T) {
	_, base := newConsole(t)

	gated := 0
	for _, r := range web.MCPRoutes() {
		if !r.NeedsConfirm {
			continue
		}
		gated++
		res := call(t, base, confirmToolName, map[string]any{"route": r.Pattern})
		if res.IsError {
			t.Fatalf("minting for %s (class %s) failed: %s", r.Pattern, r.Risk, textOf(res))
		}
		var minted struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal([]byte(bodyLine(t, textOf(res))), &minted); err != nil {
			t.Fatalf("mint for %s did not return the console's JSON: %v\n%s", r.Pattern, err, textOf(res))
		}
		if minted.Token == "" {
			t.Fatalf("mint for %s returned no token:\n%s", r.Pattern, textOf(res))
		}
	}
	if gated != 35 {
		// Not a hardcoded desire for 35: a change in the gated set should be a deliberate act, and a
		// silent one would mean the loop above stopped covering what it was written to cover.
		t.Logf("note: the manifest now has %d confirmation-worthy routes (was 35 when this test was written)", gated)
	}
}

// burpsy_confirm must not be its own policy. A route that needs no confirmation is refused by the
// CONSOLE (400, with its own message), and the transport passes that through rather than
// pre-empting it — otherwise the two would be free to disagree about which classes are gated.
func TestBurpsyConfirmPassesTheConsolesOwnRefusalThrough(t *testing.T) {
	_, base := newConsole(t)

	res := call(t, base, confirmToolName, map[string]any{"route": "/api/advisories"})
	if !res.IsError {
		t.Fatalf("minting for a read route was accepted:\n%s", textOf(res))
	}
	// The console has no mint endpoint for an ungated pattern, so the POST lands on the read
	// handler and is answered 405 by the server. The assertion is not that this particular status
	// is ideal — it is that this layer did not invent its own answer to a question the console owns.
	if !strings.Contains(textOf(res), "HTTP 405") || !strings.Contains(textOf(res), "Method not allowed") {
		t.Fatalf("the refusal is not the console's own:\n%s", textOf(res))
	}
}

// A route pattern the manifest does not contain is refused before any URL is built, because the
// pattern is interpolated into one.
func TestBurpsyConfirmRefusesARouteThatDoesNotExist(t *testing.T) {
	_, base := newConsole(t)

	res := call(t, base, confirmToolName, map[string]any{"route": "http://example.invalid/api/audit/"})
	if !res.IsError {
		t.Fatalf("a non-manifest route was accepted:\n%s", textOf(res))
	}
	if !strings.Contains(textOf(res), "not a route in burpsy's manifest") {
		t.Fatalf("unexpected refusal:\n%s", textOf(res))
	}
}

// ---- tool/route binding -------------------------------------------------------------------------

// A tool may only call the route it names. Without this, a descriptor's published risk class would
// describe a route other than the one a call reaches — the published surface and the enforced one
// would be different surfaces.
//
// The base URL points at a closed port on purpose: every case here must be refused WITHOUT a
// request, and a connection error would prove the refusal happened too late.
func TestAToolCannotReachARouteItDoesNotName(t *testing.T) {
	dead := "http://127.0.0.1:1"
	cases := []struct {
		why  string
		name string
		args map[string]any
		want string
	}{
		{
			why:  "a subtree tool must not reach a more specific route nested under it",
			name: "api_audit",
			args: map[string]any{"path": "/api/audit/selected", "method": "POST"},
			want: "resolves to /api/audit/selected",
		},
		{
			why:  "an exact tool must not reach another route",
			name: "api_advisories",
			args: map[string]any{"path": "/api/crawl"},
			want: "is a different route",
		},
		{
			why:  "a subtree tool must not be called without a path",
			name: "api_audit",
			args: nil,
			want: "is not itself a URL",
		},
		{
			why:  "a verb the route does not declare must be refused",
			name: "api_advisories",
			args: map[string]any{"method": "DELETE"},
			want: "not one of this route's verbs",
		},
		{
			why:  "a query string must not be smuggled through the path",
			name: "api_advisories",
			args: map[string]any{"path": "/api/advisories?q=sql"},
			want: "must not carry a query string",
		},
	}
	for _, tc := range cases {
		res := call(t, dead, tc.name, tc.args)
		if !res.IsError {
			t.Fatalf("%s: the call was accepted:\n%s", tc.why, textOf(res))
		}
		if !strings.Contains(textOf(res), tc.want) {
			t.Fatalf("%s: refusal %q does not mention %q", tc.why, textOf(res), tc.want)
		}
		if strings.Contains(textOf(res), "could not reach the burpsy console") {
			t.Fatalf("%s: the refusal was not local — a request was attempted:\n%s", tc.why, textOf(res))
		}
	}
}

// ---- protocol -----------------------------------------------------------------------------------

func TestInitializeEchoesAKnownProtocolVersionAndAdvertisesTools(t *testing.T) {
	_, base := newConsole(t)

	for _, v := range []string{"2024-11-05", "2025-03-26", "2025-06-18"} {
		replies := ask(t, base, rpcRequest(t, 1, "initialize", map[string]any{"protocolVersion": v}))
		var init struct {
			ProtocolVersion string `json:"protocolVersion"`
			Capabilities    struct {
				Tools struct {
					ListChanged bool `json:"listChanged"`
				} `json:"tools"`
			} `json:"capabilities"`
			ServerInfo struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
			Instructions string `json:"instructions"`
		}
		if err := json.Unmarshal(replies[0].Result, &init); err != nil {
			t.Fatalf("decoding initialize: %v", err)
		}
		if init.ProtocolVersion != v {
			t.Fatalf("client asked for %s, got %s: a client must not be told it speaks a revision it did not ask for", v, init.ProtocolVersion)
		}
		if init.ServerInfo.Name != "burpsy" {
			t.Fatalf("serverInfo.name = %q, want burpsy", init.ServerInfo.Name)
		}
		if !strings.Contains(init.Instructions, confirmToolName) {
			t.Fatalf("instructions do not explain the confirmation flow:\n%s", init.Instructions)
		}
	}

	// An unknown revision falls back to the newest one this server knows, rather than echoing
	// something it cannot speak.
	replies := ask(t, base, rpcRequest(t, 1, "initialize", map[string]any{"protocolVersion": "1999-01-01"}))
	var init struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(replies[0].Result, &init); err != nil {
		t.Fatalf("decoding initialize: %v", err)
	}
	if init.ProtocolVersion != protocolVersions[len(protocolVersions)-1] {
		t.Fatalf("unknown protocol version answered %q, want the newest known", init.ProtocolVersion)
	}
}

// A notification gets no reply. Replying to one makes a client that reuses ids attribute the reply
// to the wrong request, which is why this is worth a test rather than a comment.
func TestNotificationsGetNoReplyAndUnknownMethodsAreReported(t *testing.T) {
	_, base := newConsole(t)

	replies := ask(t, base,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		rpcRequest(t, 7, "tools/list", nil),
	)
	if len(replies) != 1 {
		t.Fatalf("a notification drew a reply: %d replies for 2 messages, want 1", len(replies))
	}
	if string(replies[0].ID) != "7" {
		t.Fatalf("the reply carries id %s, want 7 — replies are being attributed to the wrong message", replies[0].ID)
	}

	replies = ask(t, base, rpcRequest(t, 9, "no/such/method", nil))
	if replies[0].Error == nil || replies[0].Error.Code != codeMethodNotFound {
		t.Fatalf("an unknown method answered %+v, want error %d", replies[0].Error, codeMethodNotFound)
	}

	replies = ask(t, base, rpcRequest(t, 10, "tools/call", map[string]any{"name": "not_a_tool"}))
	if replies[0].Error == nil || replies[0].Error.Code != codeInvalidParams {
		t.Fatalf("an unknown tool answered %+v, want error %d", replies[0].Error, codeInvalidParams)
	}

	// A malformed line is still answered — a parse error is the one case where the id is unknowable.
	replies = ask(t, base, `{"jsonrpc":"2.0","id":11,`)
	if len(replies) != 1 || replies[0].Error == nil || replies[0].Error.Code != codeParseError {
		t.Fatalf("a malformed line answered %+v, want parse error %d", replies, codeParseError)
	}
}

// ---- result handling ----------------------------------------------------------------------------

// A route whose response is larger than the cap must say it was cut. A result that looks complete
// and is not is worse than an error, which is why the cut is reported rather than silent.
func TestAnOversizedResultIsTruncatedAndSaysSo(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxResultBytes+4096))
	}))
	t.Cleanup(big.Close)

	// A REAL manifest route, with the console faked: the tool-to-route binding resolves against the
	// manifest, so a fabricated route name would be refused for reaching somewhere else — which is
	// the property TestAToolCannotReachARouteItDoesNotName covers on purpose.
	replies := askWith(t, Options{BaseURL: big.URL},
		rpcRequest(t, 1, "tools/call", map[string]any{"name": "api_advisories"}))
	var res callResult
	if err := json.Unmarshal(replies[0].Result, &res); err != nil {
		t.Fatalf("decoding the result: %v", err)
	}
	text := textOf(res)
	if !strings.Contains(text, "truncated at") {
		t.Fatalf("a %d-byte response came back as if complete:\n%.200s", maxResultBytes+4096, text)
	}
	if len(text) > maxResultBytes+200 {
		t.Fatalf("the result carries %d bytes despite the %d-byte cap", len(text), maxResultBytes)
	}
}

// A streaming route cannot be one tool result. Saying so beats a call that appears to hang until
// the client's timeout.
func TestAStreamingRouteIsRefusedRatherThanAllowedToHang(t *testing.T) {
	stream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	t.Cleanup(stream.Close)

	replies := askWith(t, Options{BaseURL: stream.URL},
		rpcRequest(t, 1, "tools/call", map[string]any{"name": "api_advisories"}))
	var res callResult
	if err := json.Unmarshal(replies[0].Result, &res); err != nil {
		t.Fatalf("decoding the result: %v", err)
	}
	if !res.IsError || !strings.Contains(textOf(res), "streams") {
		t.Fatalf("a streaming route was not refused with a reason:\n%s", textOf(res))
	}
}

// ---- naming -------------------------------------------------------------------------------------

func TestToolNamesAreDerivedFromTheRoutePattern(t *testing.T) {
	cases := map[string]string{
		"/api/crawl/start":         "api_crawl_start",
		"/api/advisories":          "api_advisories",
		"/api/audit/":              "api_audit",
		"/api/scanner/audit-items": "api_scanner_audit_items",
		"/":                        "root",
		"/ca.crt":                  "ca_crt",
	}
	for pattern, want := range cases {
		if got := toolNameFor(pattern); got != want {
			t.Fatalf("toolNameFor(%q) = %q, want %q", pattern, got, want)
		}
	}
}

// Guard against a manifest entry whose name would not survive as an MCP tool name, and against a
// silent collision: both are properties of the real manifest, not of the derivation.
func TestEveryExposedToolNameIsUsableAndUnique(t *testing.T) {
	_, base := newConsole(t)
	replies := ask(t, base, rpcRequest(t, 1, "tools/list", nil))
	var listed toolList
	if err := json.Unmarshal(replies[0].Result, &listed); err != nil {
		t.Fatalf("decoding tools/list: %v", err)
	}
	seen := map[string]bool{}
	for _, tl := range listed.Tools {
		if tl.Name == "" || len(tl.Name) > 64 {
			t.Fatalf("tool name %q is not 1..64 characters", tl.Name)
		}
		for _, r := range tl.Name {
			ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-'
			if !ok {
				t.Fatalf("tool name %q contains %q, which MCP's name grammar does not allow", tl.Name, r)
			}
		}
		if seen[tl.Name] {
			t.Fatalf("tool name %q appears twice", tl.Name)
		}
		seen[tl.Name] = true
		if len(tl.InputSchema) == 0 {
			t.Fatalf("tool %q has no input schema", tl.Name)
		}
	}
	if !seen[confirmToolName] {
		t.Fatalf("the confirm tool %q is missing from tools/list", confirmToolName)
	}
}

// Every route tool must accept a method argument drawn only from the verbs its route declares; a
// schema that offered a verb the manifest does not list would be an invitation to a 405.
func TestEachToolsMethodEnumIsTheRoutesOwnVerbs(t *testing.T) {
	_, base := newConsole(t)
	replies := ask(t, base, rpcRequest(t, 1, "tools/list", nil))
	var listed toolList
	if err := json.Unmarshal(replies[0].Result, &listed); err != nil {
		t.Fatalf("decoding tools/list: %v", err)
	}
	byPattern := map[string]web.MCPRouteInfo{}
	for _, r := range web.MCPRoutes() {
		byPattern[r.Pattern] = r
	}
	for _, tl := range listed.Tools {
		route, ok := tl.Annotations["route"].(string)
		if !ok {
			continue
		}
		r := byPattern[route]
		props, _ := tl.InputSchema["properties"].(map[string]any)
		method, _ := props["method"].(map[string]any)
		enumRaw, _ := method["enum"].([]any)
		got := map[string]bool{}
		for _, v := range enumRaw {
			got[fmt.Sprint(v)] = true
		}
		if len(got) != len(r.Methods) {
			t.Fatalf("tool %q offers %d verbs, route %s declares %d", tl.Name, len(got), route, len(r.Methods))
		}
		for _, m := range r.Methods {
			if !got[strings.ToUpper(m)] {
				t.Fatalf("tool %q does not offer the route's %s verb", tl.Name, m)
			}
		}
		// The subtree distinction must be visible in the schema: a subtree route cannot be called
		// without a concrete path, and an exact one must not be pointed elsewhere.
		required, _ := tl.InputSchema["required"].([]any)
		needsPath := false
		for _, req := range required {
			if fmt.Sprint(req) == "path" {
				needsPath = true
			}
		}
		if wantPath := strings.HasSuffix(route, "/"); wantPath != needsPath {
			t.Fatalf("tool %q (route %s) requires path = %v, want %v", tl.Name, route, needsPath, wantPath)
		}
	}
}

// The manifest's collisions today are all exact-route/subtree pairs, so the "_subtree" rule is the
// one that fires. The numeric fallback exists for a third route normalising onto a name already
// taken by a NON-subtree route — unreachable with today's manifest, and therefore only testable
// directly. Without this, deleting the fallback would silently allow two tools to share a name.
func TestAThirdCollisionIsNumberedRatherThanDuplicated(t *testing.T) {
	used := map[string]bool{"api_x": true}
	got := uniqueToolName(web.MCPRouteInfo{Pattern: "/api-x"}, used)
	if got != "api_x_2" {
		t.Fatalf("a third route normalising onto a taken name became %q, want api_x_2", got)
	}
	if !used["api_x_2"] {
		t.Fatal("the assigned name was not claimed, so a fourth route could take it too")
	}

	// And the subtree rule takes precedence when it applies, because it says which route this is.
	used = map[string]bool{"api_x": true}
	got = uniqueToolName(web.MCPRouteInfo{Pattern: "/api-x/"}, used)
	if got != "api_x_subtree" {
		t.Fatalf("the subtree half of a collision became %q, want api_x_subtree", got)
	}
}
