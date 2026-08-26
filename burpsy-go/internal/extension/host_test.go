package extension

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// testHost builds a host over one helper plugin named "probe", with the tight timeouts a test wants.
func testHost(t *testing.T, behaviour string, tune ...func(*Config)) *Host {
	t.Helper()
	cfg := Config{
		Plugins:       map[string]PluginSpec{"probe": helper(behaviour)},
		LoadTimeout:   10 * time.Second,
		CallTimeout:   5 * time.Second,
		ShutdownGrace: 2 * time.Second,
	}
	for _, apply := range tune {
		apply(&cfg)
	}
	h := NewHost(cfg)
	t.Cleanup(h.Close)
	return h
}

// consoleText joins one stream's lines so a test can assert what an operator would read.
func consoleText(t *testing.T, h *Host, name string, stream Stream) string {
	t.Helper()
	view, err := h.Console(name, 0)
	if err != nil {
		t.Fatalf("Console(%q): %v", name, err)
	}
	lines := view.Output
	if stream == StreamError {
		lines = view.Error
	}
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(string(line.Source))
		b.WriteString(": ")
		b.WriteString(line.Text)
		b.WriteString("\n")
	}
	return b.String()
}

// A name the operator did not allowlist cannot be loaded. This is the whole safety model — the same
// one scanner.execToolRunner.Run enforces for `run tool` — so it is asserted before anything else.
func Test_a_plugin_not_on_the_allowlist_cannot_be_loaded(t *testing.T) {
	h := NewHost(Config{})
	t.Cleanup(h.Close)

	if _, err := h.Load("/bin/sh"); !errors.Is(err, ErrUnknownPlugin) {
		t.Errorf("Load(%q) error = %v, want ErrUnknownPlugin", "/bin/sh", err)
	}
	if _, err := h.Unload("probe"); !errors.Is(err, ErrUnknownPlugin) {
		t.Errorf("Unload of an unlisted name error = %v, want ErrUnknownPlugin", err)
	}
	if _, err := h.Console("probe", 0); !errors.Is(err, ErrUnknownPlugin) {
		t.Errorf("Console of an unlisted name error = %v, want ErrUnknownPlugin", err)
	}

	// And the empty list says so in words. A table with no rows that reads as "no plugins exist" is
	// the failure this field is for.
	view := h.List()
	if view.Allowlisted != 0 || len(view.Extensions) != 0 {
		t.Fatalf("empty host lists %d plugin(s)", view.Allowlisted)
	}
	for _, want := range []string{"No plugin is allowlisted", "-plugins", "no registry"} {
		if !strings.Contains(view.Detail, want) {
			t.Errorf("empty-list detail %q does not mention %q", view.Detail, want)
		}
	}
}

func Test_a_load_completes_the_handshake_and_reports_the_manifest(t *testing.T) {
	h := testHost(t, "good")

	view, err := h.Load("probe")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if view.State != StateLoaded {
		t.Fatalf("state = %q, want %q (detail: %s)", view.State, StateLoaded, view.Detail)
	}
	// The allowlist name and the plugin's own name are two different facts, and the second must never
	// overwrite the first: every route takes the allowlist key.
	if view.Name != "probe" || view.DeclaredName != "probe" {
		t.Errorf("Name = %q, DeclaredName = %q", view.Name, view.DeclaredName)
	}
	if view.Version != "1.2.3" || view.Type != "go-test" {
		t.Errorf("version/type = %q/%q, want 1.2.3/go-test", view.Version, view.Type)
	}
	if len(view.Registrations) != 3 || view.RegistrationsRefused != 0 {
		t.Errorf("registrations = %d accepted, %d refused; want 3 and 0",
			len(view.Registrations), view.RegistrationsRefused)
	}

	list := h.List()
	if list.Loaded != 1 || list.Unloaded != 0 || list.Failed != 0 || list.Crashed != 0 {
		t.Errorf("breakdown = %+v, want exactly one loaded", list)
	}

	// A second load is refused rather than spawning a second process behind the first.
	if _, err := h.Load("probe"); !errors.Is(err, ErrAlreadyLoaded) {
		t.Errorf("second Load error = %v, want ErrAlreadyLoaded", err)
	}

	unloaded, err := h.Unload("probe")
	if err != nil {
		t.Fatalf("Unload: %v", err)
	}
	if unloaded.State != StateUnloaded {
		t.Errorf("state after unload = %q, want %q", unloaded.State, StateUnloaded)
	}
	// The registrations go with the session. Keeping them would leave actions in the operator's list
	// that nothing can dispatch.
	if len(unloaded.Registrations) != 0 {
		t.Errorf("unloaded plugin still lists %d registration(s)", len(unloaded.Registrations))
	}
	if _, err := h.Unload("probe"); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("second Unload error = %v, want ErrNotLoaded", err)
	}
}

// The three registration kinds each invoke their own method, and the pairing is asserted by driving a
// real plugin that echoes which method arrived. MethodSpecs claims the mapping; this is what checks it.
func Test_each_registration_kind_invokes_its_documented_method(t *testing.T) {
	h := testHost(t, "good")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}

	exchange, message := 0, 0
	cases := []struct {
		registration string
		params       InvokeParams
		wantMethod   string
		field        func(InvokeResult) string
	}{
		{"ctx", InvokeParams{Registration: "ctx", Exchange: &exchange}, "contextMenu.invoke",
			func(r InvokeResult) string { return r.Output }},
		{"act", InvokeParams{Registration: "act"}, "menu.invoke",
			func(r InvokeResult) string { return r.Output }},
		{"tab", InvokeParams{Registration: "tab", Message: &message, Raw: "GET / HTTP/1.1\r\n\r\n"}, "editor.render",
			func(r InvokeResult) string { return r.Text }},
	}
	for _, tc := range cases {
		result, err := h.Invoke(context.Background(), "probe", tc.params)
		if err != nil {
			t.Fatalf("Invoke(%q): %v", tc.registration, err)
		}
		got := tc.field(result)
		if !strings.Contains(got, "method="+tc.wantMethod) {
			t.Errorf("registration %q reached %q, want %q", tc.registration, got, tc.wantMethod)
		}
	}

	// Exchange 0 and message 0 are real ids in this engine, so they must appear on the wire rather
	// than being omitted as zero values — which is why InvokeParams carries pointers.
	result, err := h.Invoke(context.Background(), "probe", InvokeParams{Registration: "ctx", Exchange: &exchange})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if !strings.Contains(result.Output, `"exchange":0`) {
		t.Errorf("exchange 0 did not reach the plugin: %s", result.Output)
	}

	if _, err := h.Invoke(context.Background(), "probe", InvokeParams{Registration: "never-declared"}); !errors.Is(err, ErrUnknownRegistration) {
		t.Errorf("invoking an undeclared registration error = %v, want ErrUnknownRegistration", err)
	}

	view := h.List().Extensions[0]
	if view.Invocations != 4 || view.InvocationFailures != 0 {
		t.Errorf("counters = %d invocations / %d failures, want 4 and 0",
			view.Invocations, view.InvocationFailures)
	}
}

func Test_an_invocation_the_plugin_declines_is_counted_as_a_failure(t *testing.T) {
	h := testHost(t, "invoke-fails")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := h.Invoke(context.Background(), "probe", InvokeParams{Registration: "act"}); err == nil {
		t.Fatal("Invoke of a declining plugin succeeded, want the plugin's error")
	}
	view := h.List().Extensions[0]
	if view.Invocations != 1 || view.InvocationFailures != 1 {
		t.Errorf("counters = %d invocations / %d failures, want 1 and 1",
			view.Invocations, view.InvocationFailures)
	}
	if got := consoleText(t, h, "probe", StreamError); !strings.Contains(got, "the plugin declined") {
		t.Errorf("error console does not carry the plugin's reason:\n%s", got)
	}
}

// Invoking a plugin that is not running fails rather than starting one. A load is an act the operator
// performs; an invocation must never be a back door to it.
func Test_invoking_an_unloaded_plugin_does_not_start_it(t *testing.T) {
	h := testHost(t, "good")
	if _, err := h.Invoke(context.Background(), "probe", InvokeParams{Registration: "act"}); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("Invoke before load error = %v, want ErrNotLoaded", err)
	}
	if state := h.List().Extensions[0].State; state != StateUnloaded {
		t.Errorf("state after a refused invoke = %q, want %q", state, StateUnloaded)
	}
}

func Test_a_protocol_mismatch_refuses_the_load(t *testing.T) {
	h := testHost(t, "protocol-mismatch")
	view, err := h.Load("probe")
	if err == nil {
		t.Fatal("Load of a mismatched plugin succeeded, want a refusal")
	}
	if view.State != StateFailed {
		t.Errorf("state = %q, want %q", view.State, StateFailed)
	}
	if !strings.Contains(view.Detail, "protocol 99") {
		t.Errorf("detail = %q, want the numbers of both protocols", view.Detail)
	}
	if got := consoleText(t, h, "probe", StreamError); !strings.Contains(got, "load failed") {
		t.Errorf("error console does not record the failed load:\n%s", got)
	}
}

func Test_a_launch_that_cannot_start_reports_the_path(t *testing.T) {
	h := NewHost(Config{Plugins: map[string]PluginSpec{
		"missing": {Path: "/nonexistent/burpsy-plugin"},
		"empty":   {},
	}})
	t.Cleanup(h.Close)

	view, err := h.Load("missing")
	if err == nil {
		t.Fatal("Load of a missing executable succeeded")
	}
	if view.State != StateFailed || !strings.Contains(view.Detail, "/nonexistent/burpsy-plugin") {
		t.Errorf("state/detail = %q/%q, want failed with the path named", view.State, view.Detail)
	}
	if _, err := h.Load("empty"); err == nil {
		t.Error("Load of an allowlist entry with no path succeeded")
	}
}

func Test_a_plugin_that_exits_without_being_asked_is_reported_as_crashed(t *testing.T) {
	h := testHost(t, "crash-after-load")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// The crash is observed by a goroutine watching the process, so the state settles a moment after
	// the load returns. Polled rather than slept on: a fixed sleep is either flaky or slow.
	view := waitForState(t, h, "probe", StateCrashed)
	if view.Exit == nil {
		t.Fatal("crashed plugin has no exit information, which is the thing that says how it died")
	}
	if view.Exit.Code != 9 {
		t.Errorf("exit code = %d, want 9", view.Exit.Code)
	}
	if !strings.Contains(view.Detail, "exit status 9") {
		t.Errorf("detail = %q, want the exit status", view.Detail)
	}
	if got := consoleText(t, h, "probe", StreamError); !strings.Contains(got, "without being asked to") {
		t.Errorf("error console does not say the exit was unrequested:\n%s", got)
	}

	list := h.List()
	if list.Crashed != 1 || list.Unloaded != 0 {
		t.Errorf("breakdown = %+v, want the crash counted as crashed and not as unloaded", list)
	}
	if !strings.Contains(list.Detail, "exited without being asked to") {
		t.Errorf("list detail = %q, want the crash stated in words", list.Detail)
	}
}

func Test_a_plugin_that_dies_during_the_handshake_fails_the_load(t *testing.T) {
	h := testHost(t, "die-in-handshake")
	view, err := h.Load("probe")
	if err == nil {
		t.Fatal("Load succeeded against a plugin that exited mid-handshake")
	}
	if view.State != StateFailed {
		t.Errorf("state = %q, want %q (detail %q)", view.State, StateFailed, view.Detail)
	}
	if !strings.Contains(view.Detail, "handshake failed") {
		t.Errorf("detail = %q, want the handshake named as what failed", view.Detail)
	}
}

func Test_a_plugin_that_never_answers_initialize_times_out(t *testing.T) {
	h := testHost(t, "silent", func(c *Config) { c.LoadTimeout = 300 * time.Millisecond })
	start := time.Now()
	view, err := h.Load("probe")
	if err == nil {
		t.Fatal("Load succeeded against a plugin that answered nothing")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Load took %s; the load timeout did not bound it", elapsed)
	}
	if view.State != StateFailed || !strings.Contains(view.Detail, "deadline exceeded") {
		t.Errorf("state/detail = %q/%q, want failed with the timeout stated", view.State, view.Detail)
	}
}

// A plugin that answers `shutdown` and keeps running is still stopped, because stdin is closed after
// the grace period and the process killed after that. An unload that reported success while the
// process was still alive would be a lie the next load would trip over.
func Test_a_plugin_that_ignores_shutdown_is_still_stopped(t *testing.T) {
	h := testHost(t, "ignores-shutdown", func(c *Config) { c.ShutdownGrace = 500 * time.Millisecond })
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	view, err := h.Unload("probe")
	if err != nil {
		t.Fatalf("Unload: %v", err)
	}
	if view.State != StateUnloaded || view.Exit == nil {
		t.Fatalf("state = %q with exit %v, want unloaded and reaped", view.State, view.Exit)
	}
	// Loading again proves the first process is really gone: the host refuses a second load while one
	// is running, so a successful reload is the strongest available evidence.
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("reload after unload: %v", err)
	}
}

// Every stream a plugin produces is attributed, because "the plugin's output" cannot mean "whatever
// appeared on stdout" when stdout is the transport.
func Test_the_two_consoles_separate_the_plugin_from_the_transport(t *testing.T) {
	h := testHost(t, "noisy")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}

	view := waitForConsole(t, h, "probe", func(v ConsoleView) bool {
		var stderrSeen bool
		for _, line := range v.Error {
			if line.Source == SourceStderr {
				stderrSeen = true
			}
		}
		return stderrSeen && len(v.Output) >= 2
	})

	want := map[Source]map[string]bool{
		SourcePlugin:   {"hello from the plugin": false, "and a problem the plugin found": false},
		SourceStderr:   {"a runtime warning on stderr": false},
		SourceProtocol: {"not a JSON-RPC message: print debugging, straight to stdout": false},
	}
	for _, line := range append(append([]Line{}, view.Output...), view.Error...) {
		if byText, ok := want[line.Source]; ok {
			for text := range byText {
				if strings.Contains(line.Text, text) {
					byText[text] = true
				}
			}
		}
	}
	for source, byText := range want {
		for text, seen := range byText {
			if !seen {
				t.Errorf("no %s line carrying %q", source, text)
			}
		}
	}

	// A plugin's own log lines land on the console it asked for; the host's notes are attributed to
	// the host so they cannot be read as plugin output.
	var hostLines int
	for _, line := range view.Output {
		if line.Source == SourceHost {
			hostLines++
		}
	}
	if hostLines == 0 {
		t.Error("nothing on the output console is attributed to the host, so the load note is missing")
	}

	// An unimplemented method from the plugin is counted rather than ignored.
	row := h.List().Extensions[0]
	if row.ProtocolErrors < 2 {
		t.Errorf("protocol errors = %d, want at least the stray stdout line and the unknown method",
			row.ProtocolErrors)
	}
}

func Test_a_console_evicts_oldest_first_and_says_how_many_it_dropped(t *testing.T) {
	con := newConsole(3, 16)
	for _, text := range []string{"one", "two", "three", "four", "five"} {
		con.append(StreamOutput, SourcePlugin, text)
	}
	con.append(StreamError, SourcePlugin, strings.Repeat("z", 40))

	view := con.view(0)
	if len(view.Output) != 3 {
		t.Fatalf("retained %d line(s), want the 3-line bound", len(view.Output))
	}
	if view.Output[0].Text != "three" || view.Output[2].Text != "five" {
		t.Errorf("retained %q…%q, want the newest three", view.Output[0].Text, view.Output[2].Text)
	}
	if view.OutputDropped != 2 {
		t.Errorf("dropped = %d, want 2 — a console that forgets silently reports a lie", view.OutputDropped)
	}
	if view.Truncated != 1 || !strings.Contains(view.Error[0].Text, "[truncated]") {
		t.Errorf("truncation not reported: truncated=%d text=%q", view.Truncated, view.Error[0].Text)
	}
	if view.Limit != 3 {
		t.Errorf("limit = %d, want the bound in force reported", view.Limit)
	}

	// A limit narrows the view without changing what was retained or what was dropped.
	tailed := con.view(1)
	if len(tailed.Output) != 1 || tailed.Output[0].Text != "five" || tailed.OutputDropped != 2 {
		t.Errorf("view(1) = %+v, want the newest line with the drop count intact", tailed)
	}
}

// A message over the bound ends the session rather than being resynchronised, and says so.
func Test_a_message_over_the_bound_ends_the_session_with_a_reason(t *testing.T) {
	h := testHost(t, "long-line", func(c *Config) {
		c.MaxMessageBytes = 4 << 10
		c.LoadTimeout = 3 * time.Second
	})
	view, err := h.Load("probe")
	if err == nil {
		t.Fatal("Load succeeded after a message over the bound")
	}
	if view.State != StateFailed {
		t.Errorf("state = %q, want %q", view.State, StateFailed)
	}
	if got := consoleText(t, h, "probe", StreamError); !strings.Contains(got, "cannot be resynchronised") {
		t.Errorf("error console does not state why the stream ended:\n%s", got)
	}
}

// A registration that could not be invoked is refused individually and counted, rather than the whole
// load failing or the bad row being accepted as an inert entry in the operator's list.
func Test_unusable_registrations_are_refused_individually_and_counted(t *testing.T) {
	h := testHost(t, "bad-registrations")
	view, err := h.Load("probe")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(view.Registrations) != 1 || view.Registrations[0].ID != "ok" {
		t.Fatalf("accepted %d registration(s) %+v, want just the working one",
			len(view.Registrations), view.Registrations)
	}
	if view.RegistrationsRefused != 4 {
		t.Errorf("refused = %d, want 4 (no id, duplicate, unknown kind, no label)", view.RegistrationsRefused)
	}

	errs := consoleText(t, h, "probe", StreamError)
	for _, want := range []string{"no id", "declared twice", "suite-tab", "no label"} {
		if !strings.Contains(errs, want) {
			t.Errorf("error console does not say why %q was refused:\n%s", want, errs)
		}
	}
}

func Test_the_registration_bound_refuses_the_excess(t *testing.T) {
	h := testHost(t, "good", func(c *Config) { c.MaxRegistrations = 2 })
	view, err := h.Load("probe")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(view.Registrations) != 2 || view.RegistrationsRefused != 1 {
		t.Errorf("accepted %d, refused %d; want 2 and 1", len(view.Registrations), view.RegistrationsRefused)
	}
}

// The five states partition the allowlist exactly. There is no total field precisely because a second
// way to say the size of the list is a place for the two to disagree.
func Test_the_state_counts_partition_the_allowlist(t *testing.T) {
	h := NewHost(Config{Plugins: map[string]PluginSpec{
		"good":     helper("good"),
		"mismatch": helper("protocol-mismatch"),
		"quiet":    helper("no-registrations"),
		"missing":  {Path: "/nonexistent/burpsy-plugin"},
	}})
	t.Cleanup(h.Close)

	if _, err := h.Load("good"); err != nil {
		t.Fatalf("Load(good): %v", err)
	}
	if _, err := h.Load("mismatch"); err == nil {
		t.Fatal("Load(mismatch) succeeded")
	}
	if _, err := h.Load("missing"); err == nil {
		t.Fatal("Load(missing) succeeded")
	}

	view := h.List()
	sum := view.Loaded + view.Loading + view.Unloaded + view.Failed + view.Crashed
	if sum != view.Allowlisted || view.Allowlisted != 4 {
		t.Errorf("states sum to %d over an allowlist of %d, want 4 and 4", sum, view.Allowlisted)
	}
	if view.Loaded != 1 || view.Failed != 2 || view.Unloaded != 1 {
		t.Errorf("breakdown = loaded %d, failed %d, unloaded %d; want 1, 2, 1",
			view.Loaded, view.Failed, view.Unloaded)
	}
	// Sorted by allowlist name, so a refresh does not reshuffle the operator's table.
	names := make([]string, 0, len(view.Extensions))
	for _, row := range view.Extensions {
		names = append(names, row.Name)
	}
	if strings.Join(names, ",") != "good,mismatch,missing,quiet" {
		t.Errorf("list order = %v, want sorted by allowlist name", names)
	}
}

// Close stops every running plugin. A host that left children behind after the server it belonged to
// went away would leave the operator with processes nothing knows to stop.
func Test_closing_the_host_stops_every_running_plugin(t *testing.T) {
	h := NewHost(Config{Plugins: map[string]PluginSpec{
		"a": helper("good"),
		"b": helper("good"),
	}})
	for _, name := range []string{"a", "b"} {
		if _, err := h.Load(name); err != nil {
			t.Fatalf("Load(%q): %v", name, err)
		}
	}
	h.Close()

	view := h.List()
	if view.Loaded != 0 {
		t.Errorf("%d plugin(s) still loaded after Close", view.Loaded)
	}
	for _, row := range view.Extensions {
		if row.Exit == nil {
			t.Errorf("plugin %q has no exit information after Close", row.Name)
		}
	}
}

// The policy view reports this process's bounds rather than the defaults in the source, and states the
// two absences a caller would otherwise have to infer: no shell, and no registry.
func Test_the_policy_view_reports_this_process_and_not_the_defaults(t *testing.T) {
	h := testHost(t, "good", func(c *Config) {
		c.CallTimeout = 1234 * time.Millisecond
		c.MaxConsoleLines = 42
	})
	policy := h.Policy()
	if policy.CallTimeoutMs != 1234 || policy.MaxConsoleLines != 42 {
		t.Errorf("policy = %+v, want the configured call timeout and console bound", policy)
	}
	if policy.Allowlisted != 1 || policy.Flag == "" {
		t.Errorf("policy names %d plugin(s) admitted by %q", policy.Allowlisted, policy.Flag)
	}
	if policy.Shell {
		t.Error("policy claims a shell; the executable is run directly and this field must say so")
	}
	if policy.Registry != nil || !strings.Contains(policy.RegistryDetail, "BApp Store") {
		t.Errorf("registry = %v with detail %q, want null and a stated reason",
			policy.Registry, policy.RegistryDetail)
	}
	if policy.ProtocolVersion != ProtocolVersion {
		t.Errorf("protocol version = %d, want %d", policy.ProtocolVersion, ProtocolVersion)
	}
	// The child's environment is the short list, not the operator's whole shell.
	for _, key := range policy.EnvironmentPassed {
		switch key {
		case "PATH", "HOME", "LANG", "TMPDIR":
		default:
			t.Errorf("policy passes %q to a child; the list is meant to be the four a runtime needs", key)
		}
	}
}

func waitForState(t *testing.T, h *Host, name string, want State) PluginView {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, row := range h.List().Extensions {
			if row.Name == name && row.State == want {
				return row
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("plugin %q never reached state %q", name, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForConsole(t *testing.T, h *Host, name string, ready func(ConsoleView) bool) ConsoleView {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		view, err := h.Console(name, 0)
		if err != nil {
			t.Fatalf("Console(%q): %v", name, err)
		}
		if ready(view) {
			return view
		}
		if time.Now().After(deadline) {
			t.Fatalf("console for %q never reached the expected state: %+v", name, view)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
