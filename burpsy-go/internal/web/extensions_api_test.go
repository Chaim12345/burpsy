package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/extension"
)

// The EXTENDER routes, driven over the mux.
//
// The empty-allowlist cases come first and are not filler: a burpsy started without -plugins is the
// common case, and the thing that must not happen is the Extensions tab reading as "this feature is
// missing". So the assertions are about what the empty answer *says*, not just its status code.

func Test_the_extensions_list_on_a_server_with_no_allowlist_says_so(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/api/extensions")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/extensions = %d, want 200 — an empty allowlist is a supported state, not an error",
			rec.Code)
	}
	var view extension.ListView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode list: %v (body %s)", err, rec.Body.String())
	}
	if view.Allowlisted != 0 || len(view.Extensions) != 0 {
		t.Errorf("list reports %d allowlisted plugin(s) on a server that was given none", view.Allowlisted)
	}
	for _, want := range []string{"No plugin is allowlisted", "-plugins", "registry"} {
		if !strings.Contains(view.Detail, want) {
			t.Errorf("detail %q does not mention %q, so an operator cannot tell empty from unimplemented",
				view.Detail, want)
		}
	}
	// The policy travels with the list, and the store's absence is a value rather than something to
	// infer from a missing field.
	if view.Policy.Registry != nil {
		t.Errorf("policy names a registry (%q); there is no store to talk to", *view.Policy.Registry)
	}
	if view.Policy.Flag == "" || view.Policy.LoadTimeoutMs == 0 || view.Policy.MaxConsoleLines == 0 {
		t.Errorf("policy = %+v, want the admitting flag and the bounds in force", view.Policy)
	}
}

func Test_loading_a_plugin_that_is_not_allowlisted_is_refused_by_name(t *testing.T) {
	s := newTestServer()

	// The safety model, over HTTP: a path in the body is not a plugin. This must be a 404 about an
	// unknown name and must not reach exec.
	rec := postJSON(t, s, "/api/extensions/load", map[string]any{"name": "/bin/sh"})
	if rec.Code != http.StatusNotFound {
		t.Errorf("load of an unlisted name = %d, want 404\nbody: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "allowlist") {
		t.Errorf("refusal does not name the allowlist as the reason: %s", rec.Body.String())
	}

	for _, body := range []map[string]any{{}, {"name": ""}} {
		rec := postJSON(t, s, "/api/extensions/load", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("load with body %v = %d, want 400", body, rec.Code)
		}
	}
	if rec := postJSON(t, s, "/api/extensions/unload", map[string]any{"name": "nope"}); rec.Code != http.StatusNotFound {
		t.Errorf("unload of an unlisted name = %d, want 404", rec.Code)
	}
	if rec := postJSON(t, s, "/api/extensions/invoke", map[string]any{"name": "nope"}); rec.Code != http.StatusBadRequest {
		t.Errorf("invoke with no registration = %d, want 400", rec.Code)
	}
	if rec := postJSON(t, s, "/api/extensions/invoke",
		map[string]any{"name": "nope", "registration": "x"}); rec.Code != http.StatusNotFound {
		t.Errorf("invoke against an unlisted plugin = %d, want 404", rec.Code)
	}
}

func Test_the_console_route_needs_a_name_and_reports_the_bound(t *testing.T) {
	s := newTestServer()
	if rec := get(t, s, "/api/extensions/console"); rec.Code != http.StatusBadRequest {
		t.Errorf("console with no name = %d, want 400", rec.Code)
	}
	if rec := get(t, s, "/api/extensions/console?name=nope"); rec.Code != http.StatusNotFound {
		t.Errorf("console for an unlisted plugin = %d, want 404", rec.Code)
	}
	if rec := get(t, s, "/api/extensions/console?name=nope&limit=abc"); rec.Code != http.StatusBadRequest {
		t.Errorf("console with a non-numeric limit = %d, want 400", rec.Code)
	}
}

// The APIs route is what a plugin author reads, so it has to carry the whole contract: the method set,
// the three registration kinds, and the absences.
func Test_the_apis_route_serves_the_protocol_contract(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/api/extensions/apis")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/extensions/apis = %d, want 200", rec.Code)
	}
	var view extension.APIView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode apis: %v", err)
	}
	if view.ProtocolVersion != extension.ProtocolVersion {
		t.Errorf("protocol = %d, want %d", view.ProtocolVersion, extension.ProtocolVersion)
	}
	if len(view.Methods) != len(extension.MethodSpecs) {
		t.Errorf("served %d method(s) against %d in the table — the tab renders this, so it has to be all of it",
			len(view.Methods), len(extension.MethodSpecs))
	}
	// Against the package's own count, not a literal. The literal was 4 and went stale the moment a
	// fifth kind landed (burpsy-react-ui-wsu4): the implementation was right and the pin read it as
	// broken. A count that moves WITH the table is the only kind of pin that can distinguish "the
	// route dropped one" from "the table gained one" — and this failure was the second.
	if len(view.Kinds) != extension.KindCount() {
		t.Errorf("served %d registration kind(s), want every one the protocol offers (%d)",
			len(view.Kinds), extension.KindCount())
	}
	if len(view.Unsupported) == 0 {
		t.Error("nothing is declared unsupported, so the BApp Store's absence is left to be inferred")
	}
}

// End to end over the mux: load a real child process, read its consoles, invoke what it registered,
// unload it. This is what proves the routes are wired to the host rather than to a shape that looks
// like one.
func Test_a_plugin_loads_invokes_and_unloads_over_the_api(t *testing.T) {
	host := extension.NewHost(extension.Config{
		Plugins:       map[string]extension.PluginSpec{"probe": webHelperPlugin()},
		LoadTimeout:   10 * time.Second,
		ShutdownGrace: 2 * time.Second,
	})
	t.Cleanup(host.Close)
	s := newTestServer().WithExtensions(host)

	rec := postJSON(t, s, "/api/extensions/load", map[string]any{"name": "probe"})
	if rec.Code != http.StatusOK {
		t.Fatalf("load = %d, want 200\nbody: %s", rec.Code, rec.Body.String())
	}
	var loaded struct {
		Extension extension.PluginView `json:"extension"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &loaded); err != nil {
		t.Fatalf("decode load: %v", err)
	}
	if loaded.Extension.State != extension.StateLoaded || len(loaded.Extension.Registrations) != 2 {
		t.Fatalf("loaded row = %+v, want the menu action and the hotkey in state loaded", loaded.Extension)
	}

	// A second load is a conflict, not a second process.
	if rec := postJSON(t, s, "/api/extensions/load", map[string]any{"name": "probe"}); rec.Code != http.StatusConflict {
		t.Errorf("second load = %d, want 409", rec.Code)
	}

	// The console carries the plugin's own line, attributed to the plugin, and the host's load note
	// attributed to the host.
	console := get(t, s, "/api/extensions/console?name=probe")
	if console.Code != http.StatusOK {
		t.Fatalf("console = %d, want 200", console.Code)
	}
	var view extension.ConsoleView
	if err := json.Unmarshal(console.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode console: %v", err)
	}
	var fromPlugin, fromHost bool
	for _, line := range view.Output {
		switch line.Source {
		case extension.SourcePlugin:
			fromPlugin = fromPlugin || strings.Contains(line.Text, "the plugin is up")
		case extension.SourceHost:
			fromHost = true
		}
	}
	if !fromPlugin || !fromHost {
		t.Errorf("console lines = %+v, want the plugin's own line and the host's load note kept apart",
			view.Output)
	}
	if view.Limit == 0 {
		t.Error("console does not report the bound in force, so a full console reads as a complete one")
	}

	invoke := postJSON(t, s, "/api/extensions/invoke", map[string]any{"name": "probe", "registration": "act"})
	if invoke.Code != http.StatusOK {
		t.Fatalf("invoke = %d, want 200\nbody: %s", invoke.Code, invoke.Body.String())
	}
	var result struct {
		Result extension.InvokeResult `json:"result"`
	}
	if err := json.Unmarshal(invoke.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode invoke: %v", err)
	}
	if result.Result.Output != "ran act" {
		t.Errorf("invoke output = %q, want the plugin's own answer", result.Result.Output)
	}
	if rec := postJSON(t, s, "/api/extensions/invoke",
		map[string]any{"name": "probe", "registration": "never"}); rec.Code != http.StatusNotFound {
		t.Errorf("invoking a registration the plugin never declared = %d, want 404", rec.Code)
	}

	if rec := postJSON(t, s, "/api/extensions/unload", map[string]any{"name": "probe"}); rec.Code != http.StatusOK {
		t.Fatalf("unload = %d, want 200\nbody: %s", rec.Code, rec.Body.String())
	}
	// Unloading twice is a conflict: an unload that reported success against a plugin that was not
	// running would make a crash indistinguishable from an operator's own stop.
	if rec := postJSON(t, s, "/api/extensions/unload", map[string]any{"name": "probe"}); rec.Code != http.StatusConflict {
		t.Errorf("second unload = %d, want 409", rec.Code)
	}
	// And an invocation after the unload is refused rather than restarting the plugin.
	if rec := postJSON(t, s, "/api/extensions/invoke",
		map[string]any{"name": "probe", "registration": "act"}); rec.Code != http.StatusConflict {
		t.Errorf("invoke after unload = %d, want 409", rec.Code)
	}
}

// ---- the helper plugin -------------------------------------------------------------------------

// webHelperEnv names a re-exec of this test binary as a plugin. The extension package's own tests use
// the same technique and explain it at length; the short version is that the host's contract is with a
// real process, so the tests use one, and re-execing the already-built test binary needs no toolchain.
const webHelperEnv = "BURPSY_WEB_TEST_PLUGIN"

func webHelperPlugin() extension.PluginSpec {
	return extension.PluginSpec{
		Path: os.Args[0],
		Args: []string{"-test.run=^TestHelperPluginForExtensionsAPI$"},
		Env:  []string{webHelperEnv + "=1"},
	}
}

// TestHelperPluginForExtensionsAPI is the plugin process. A no-op in a normal run.
func TestHelperPluginForExtensionsAPI(t *testing.T) {
	if os.Getenv(webHelperEnv) == "" {
		t.Skip("not a helper invocation")
	}
	// os.Exit rather than returning, so the testing framework's "PASS" never reaches the host's stdout
	// reader — which would correctly record it as a plugin that does not speak the protocol.
	runWebHelperPlugin()
}

func runWebHelperPlugin() {
	emit := func(v map[string]any) {
		encoded, err := json.Marshal(v)
		if err != nil {
			os.Exit(70)
		}
		fmt.Fprintln(os.Stdout, string(encoded))
	}
	reader := bufio.NewScanner(os.Stdin)
	for reader.Scan() {
		line := strings.TrimSpace(reader.Text())
		if line == "" {
			continue
		}
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			os.Exit(70)
		}
		switch msg.Method {
		case "initialize":
			emit(map[string]any{"jsonrpc": "2.0", "method": "log",
				"params": map[string]any{"stream": "output", "message": "the plugin is up"}})
			emit(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{
				"name": "probe", "version": "1.0", "type": "go-test", "protocol": extension.ProtocolVersion,
				"registrations": []map[string]any{
					{"id": "act", "kind": "menu", "label": "Run the action"},
					{"id": "hk", "kind": "hotkey", "label": "Hotkey probe", "chord": "Ctrl+Shift+G"},
				},
			}})
		case "menu.invoke":
			emit(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{"output": "ran act"}})
		case "hotkey.invoke":
			// Echo the params verbatim so the test can see exactly what the host was handed.
			emit(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{"output": string(msg.Params)}})
		case "shutdown":
			emit(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{}})
			os.Exit(0)
		default:
			emit(map[string]any{"jsonrpc": "2.0", "id": msg.ID,
				"error": map[string]any{"code": -32601, "message": "no such method"}})
		}
	}
	os.Exit(0)
}

// gqvg: a hotkey invocation carries the operator's selection and open editor message through
// to the plugin. The host enforces the cap and strips the fields on other kinds (pinned in
// internal/extension); the edge repeats the cap so an oversized selection is a 400, not a 502.
func Test_a_hotkey_invoke_carries_the_selection_and_editor(t *testing.T) {
	host := extension.NewHost(extension.Config{
		Plugins:       map[string]extension.PluginSpec{"probe": webHelperPlugin()},
		LoadTimeout:   10 * time.Second,
		ShutdownGrace: 2 * time.Second,
	})
	t.Cleanup(host.Close)
	s := newTestServer().WithExtensions(host)
	if rec := postJSON(t, s, "/api/extensions/load", map[string]any{"name": "probe"}); rec.Code != http.StatusOK {
		t.Fatalf("load = %d: %s", rec.Code, rec.Body.String())
	}
	defer postJSON(t, s, "/api/extensions/unload", map[string]any{"name": "probe"})

	invoke := postJSON(t, s, "/api/extensions/invoke", map[string]any{
		"name": "probe", "registration": "hk",
		"selected": []map[string]any{
			{"exchange": 0},
			{"exchange": 4, "raw": "GET /x HTTP/1.1\r\n\r\n"},
		},
		"editor": map[string]any{"message": 7, "raw": "GET /e HTTP/1.1\r\n\r\n"},
	})
	if invoke.Code != http.StatusOK {
		t.Fatalf("invoke = %d: %s", invoke.Code, invoke.Body.String())
	}
	var result struct {
		Result extension.InvokeResult `json:"result"`
	}
	if err := json.Unmarshal(invoke.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	out := result.Result.Output
	for _, want := range []string{`"exchange":4`, `"message":7`, "GET /x", "GET /e"} {
		if !strings.Contains(out, want) {
			t.Errorf("plugin saw no %s in %s", want, out)
		}
	}
	// Exchange 0 is a real id and must arrive as 0, not be dropped as empty.
	if !strings.Contains(out, `"exchange":0`) {
		t.Errorf("the zero-id row did not arrive: %s", out)
	}
}

func Test_a_hotkey_invoke_over_the_selection_cap_is_a_400(t *testing.T) {
	s := newTestServer()
	rows := make([]map[string]any, 0, extension.MaxHotkeySelection+1)
	for i := 0; i <= extension.MaxHotkeySelection; i++ {
		rows = append(rows, map[string]any{"exchange": i})
	}
	rec := postJSON(t, s, "/api/extensions/invoke", map[string]any{
		"name": "probe", "registration": "hk", "selected": rows,
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("over-cap invoke = %d, want 400", rec.Code)
	}
}

// gqvg hardening at the edge: exactly the cap passes, a row without an id or a negative id is a 400
// (not null on the wire, not a 502), and `editor: {}` is a 400 while an absent editor is fine.
// Row cap: MaxHotkeySelection rows. The request body has its own, separate line/body cap (1 MiB on
// the plugin's stdio line); a 100-row selection with large raws is bounded by that, not by this.
func Test_a_hotkey_invoke_of_exactly_the_cap_is_served_with_first_raw_and_second_id_3(t *testing.T) {
	host := extension.NewHost(extension.Config{
		Plugins:       map[string]extension.PluginSpec{"probe": webHelperPlugin()},
		LoadTimeout:   10 * time.Second,
		ShutdownGrace: 2 * time.Second,
	})
	t.Cleanup(host.Close)
	s := newTestServer().WithExtensions(host)
	if rec := postJSON(t, s, "/api/extensions/load", map[string]any{"name": "probe"}); rec.Code != http.StatusOK {
		t.Fatalf("load = %d: %s", rec.Code, rec.Body.String())
	}
	defer postJSON(t, s, "/api/extensions/unload", map[string]any{"name": "probe"})
	rows := make([]map[string]any, 0, extension.MaxHotkeySelection)
	for i := 0; i < extension.MaxHotkeySelection; i++ {
		rows = append(rows, map[string]any{"exchange": i})
	}
	rows[0]["raw"] = "GET /first HTTP/1.1\r\n\r\n"
	rows[1] = map[string]any{"exchange": 3, "raw": "GET /second HTTP/1.1\r\n\r\n"}
	rec := postJSON(t, s, "/api/extensions/invoke", map[string]any{"name": "probe", "registration": "hk", "selected": rows})
	if rec.Code != http.StatusOK {
		t.Fatalf("exactly-cap invoke = %d: %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Result extension.InvokeResult `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	out := result.Result.Output
	for _, want := range []string{"GET /first", "GET /second", `"exchange":3`, `"exchange":99`} {
		if !strings.Contains(out, want) {
			t.Errorf("plugin saw no %s", want)
		}
	}
}

func Test_a_hotkey_invoke_with_a_malformed_context_is_a_400(t *testing.T) {
	host := extension.NewHost(extension.Config{
		Plugins:       map[string]extension.PluginSpec{"probe": webHelperPlugin()},
		LoadTimeout:   10 * time.Second,
		ShutdownGrace: 2 * time.Second,
	})
	t.Cleanup(host.Close)
	s := newTestServer().WithExtensions(host)
	if rec := postJSON(t, s, "/api/extensions/load", map[string]any{"name": "probe"}); rec.Code != http.StatusOK {
		t.Fatalf("load = %d: %s", rec.Code, rec.Body.String())
	}
	defer postJSON(t, s, "/api/extensions/unload", map[string]any{"name": "probe"})
	for name, body := range map[string]map[string]any{
		"row without id":  {"selected": []map[string]any{{"raw": "x"}}},
		"negative id":     {"selected": []map[string]any{{"exchange": -1}}},
		"empty editor":    {"editor": map[string]any{}},
		"negative editor": {"editor": map[string]any{"message": -3}},
	} {
		body["name"], body["registration"] = "probe", "hk"
		if rec := postJSON(t, s, "/api/extensions/invoke", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400: %s", name, rec.Code, rec.Body.String())
		}
	}
}
