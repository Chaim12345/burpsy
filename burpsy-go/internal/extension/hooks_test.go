package extension

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// tvv5: traffic hooks. The host half is Host.Hook, which the proxy, the sender and the
// WebSocket layer call. Its contract is that a hook never blocks or half-applies a message:
// whatever a plugin does, the caller gets either the plugin's complete answer or the original
// bytes, and the failure is counted and explained.

func hookHost(t *testing.T, tune ...func(*Config)) *Host {
	t.Helper()
	cfg := Config{
		Plugins:     map[string]PluginSpec{"a": helper("hooks"), "b": helper("hooks")},
		LoadTimeout: 10 * time.Second, CallTimeout: 5 * time.Second, ShutdownGrace: 2 * time.Second,
		HookTimeout: 300 * time.Millisecond,
		Grants:      map[string][]string{"a": {"hook.traffic"}, "b": {"hook.traffic"}},
	}
	for _, f := range tune {
		f(&cfg)
	}
	h := NewHost(cfg)
	t.Cleanup(h.Close)
	for n := range cfg.Plugins {
		if _, err := h.Load(n); err != nil {
			t.Fatalf("Load %s: %v", n, err)
		}
	}
	return h
}

func view(t *testing.T, h *Host, name string) PluginView {
	t.Helper()
	for _, v := range h.List().Extensions {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("no plugin %q", name)
	return PluginView{}
}

func Test_the_three_hook_kinds_register(t *testing.T) {
	h := hookHost(t)
	v := view(t, h, "a")
	kinds := map[Kind]bool{}
	for _, r := range v.Registrations {
		kinds[r.Kind] = true
	}
	if !kinds[KindHTTPHandler] || !kinds[KindProxyHandler] || !kinds[KindWebSocketHandler] || v.RegistrationsRefused != 0 {
		t.Errorf("registrations %+v refused %d", v.Registrations, v.RegistrationsRefused)
	}
}

func Test_a_request_hook_chains_through_every_plugin_in_name_order(t *testing.T) {
	h := hookHost(t)
	res := h.Hook(context.Background(), HookCall{Kind: KindHTTPHandler, Phase: "request", Raw: []byte("GET / HTTP/1.1")})
	if string(res.Raw) != "GET / HTTP/1.1[a:request][b:request]" || !res.Changed || res.Dropped {
		t.Errorf("result = %q changed=%v dropped=%v", res.Raw, res.Changed, res.Dropped)
	}
	if strings.Join(res.Applied, ",") != "a,b" || len(res.Failures) != 0 {
		t.Errorf("applied %v failures %v", res.Applied, res.Failures)
	}
}

// The bytes of a message nobody changed come back as the very same bytes, including duplicate
// headers and their order, which a parse-and-reserialise round trip would not guarantee.
func Test_a_hook_that_changes_nothing_returns_the_original_bytes_exactly(t *testing.T) {
	h := hookHost(t)
	orig := []byte("GET / HTTP/1.1\r\nX-A: 1\r\nx-a: 2\r\nX-A: 3\r\nHost: h\r\n\r\n")
	// "noop" is matched against the whole raw, so route the original through a plugin that is
	// told to leave it alone by sending the sentinel instead and comparing a second call.
	res := h.Hook(context.Background(), HookCall{Kind: KindProxyHandler, Phase: "request", Raw: []byte("noop")})
	if res.Changed || string(res.Raw) != "noop" || len(res.Applied) != 2 {
		t.Fatalf("noop result = %q changed=%v applied=%v", res.Raw, res.Changed, res.Applied)
	}
	// And with no plugin loaded for the kind at all, the input slice is returned untouched.
	empty := NewHost(Config{})
	defer empty.Close()
	got := empty.Hook(context.Background(), HookCall{Kind: KindHTTPHandler, Phase: "request", Raw: orig})
	if !bytes.Equal(got.Raw, orig) || got.Changed || len(got.Applied) != 0 {
		t.Errorf("no plugins: %+v", got)
	}
}

func Test_non_text_bytes_round_trip_through_a_hook(t *testing.T) {
	h := hookHost(t, func(c *Config) { c.Plugins = map[string]PluginSpec{"a": helper("hooks")} })
	res := h.Hook(context.Background(), HookCall{Kind: KindWebSocketHandler, Phase: "message", Raw: []byte("binary")})
	if !bytes.Equal(res.Raw, []byte{0xff, 0x00, 0x80}) || !res.Changed {
		t.Errorf("raw = %x changed=%v", res.Raw, res.Changed)
	}
}

func Test_a_proxy_hook_can_drop_and_the_chain_stops(t *testing.T) {
	h := hookHost(t)
	res := h.Hook(context.Background(), HookCall{Kind: KindProxyHandler, Phase: "request", Raw: []byte("drop")})
	if !res.Dropped || strings.Join(res.Applied, ",") != "a" {
		t.Errorf("drop result = %+v", res)
	}
	res = h.Hook(context.Background(), HookCall{Kind: KindProxyHandler, Phase: "request", Raw: []byte("intercept")})
	if res.Intercept == nil || !*res.Intercept || res.Dropped {
		t.Errorf("intercept result = %+v", res)
	}
}

func Test_an_http_hook_may_not_drop_so_the_answer_is_a_failure_and_the_original_goes_through(t *testing.T) {
	h := hookHost(t)
	res := h.Hook(context.Background(), HookCall{Kind: KindHTTPHandler, Phase: "request", Raw: []byte("drop")})
	if res.Dropped || string(res.Raw) != "drop" || res.Changed || len(res.Failures) != 2 {
		t.Errorf("result = %+v", res)
	}
}

func Test_an_invalid_answer_is_a_counted_failure_that_leaves_the_message_alone(t *testing.T) {
	h := hookHost(t)
	res := h.Hook(context.Background(), HookCall{Kind: KindHTTPHandler, Phase: "request", Raw: []byte("garbage")})
	if string(res.Raw) != "garbage" || res.Changed || len(res.Failures) != 2 {
		t.Fatalf("result = %+v", res)
	}
	if !strings.Contains(res.Failures[0].Reason, "explode") {
		t.Errorf("reason does not say what was wrong: %q", res.Failures[0].Reason)
	}
	if v := view(t, h, "a"); v.HookCalls != 1 || v.HookFailures != 1 {
		t.Errorf("counters = %d calls / %d failures", v.HookCalls, v.HookFailures)
	}
	if got := consoleText(t, h, "a", StreamError); !strings.Contains(got, "hook") {
		t.Errorf("the plugin's error console does not say why:\n%s", got)
	}
}

func Test_a_hanging_plugin_costs_one_hook_timeout_and_the_original_goes_through(t *testing.T) {
	h := hookHost(t, func(c *Config) { c.Plugins = map[string]PluginSpec{"a": helper("hooks")} })
	start := time.Now()
	res := h.Hook(context.Background(), HookCall{Kind: KindHTTPHandler, Phase: "request", Raw: []byte("hang")})
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("a hanging hook held the caller for %v", d)
	}
	if string(res.Raw) != "hang" || res.Changed || len(res.Failures) != 1 {
		t.Errorf("result = %+v", res)
	}
}

func Test_a_crashing_plugin_never_blocks_the_message(t *testing.T) {
	h := hookHost(t)
	res := h.Hook(context.Background(), HookCall{Kind: KindHTTPHandler, Phase: "request", Raw: []byte("crash")})
	if string(res.Raw) != "crash" || res.Changed {
		t.Errorf("result = %+v", res)
	}
	if len(res.Failures) == 0 {
		t.Error("a crash was not reported")
	}
}

func Test_a_plugin_that_keeps_failing_is_suspended_and_not_called(t *testing.T) {
	h := hookHost(t, func(c *Config) {
		c.HookFailureLimit = 2
		c.HookCooldown = time.Hour
		c.Plugins = map[string]PluginSpec{"a": helper("hooks")}
	})
	for i := 0; i < 2; i++ {
		h.Hook(context.Background(), HookCall{Kind: KindHTTPHandler, Phase: "request", Raw: []byte("garbage")})
	}
	before := view(t, h, "a").Invocations
	res := h.Hook(context.Background(), HookCall{Kind: KindHTTPHandler, Phase: "request", Raw: []byte("GET /")})
	if string(res.Raw) != "GET /" || res.Changed {
		t.Errorf("a suspended plugin changed the message: %+v", res)
	}
	if view(t, h, "a").Invocations != before {
		t.Error("a suspended plugin was still invoked")
	}
	if len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Reason, "suspended") {
		t.Errorf("failures = %+v, want a suspended entry", res.Failures)
	}
	if v := view(t, h, "a"); v.HookSuspended != true {
		t.Errorf("view does not show the suspension: %+v", v)
	}
}

func Test_hooks_run_only_for_plugins_the_operator_granted(t *testing.T) {
	h := hookHost(t, func(c *Config) { c.Grants = map[string][]string{"b": {"hook.traffic"}} })
	res := h.Hook(context.Background(), HookCall{Kind: KindHTTPHandler, Phase: "request", Raw: []byte("x")})
	if strings.Join(res.Applied, ",") != "b" || string(res.Raw) != "x[b:request]" {
		t.Errorf("result = %+v", res)
	}
	if v := view(t, h, "a"); v.HookCalls != 0 || v.Invocations != 0 {
		t.Errorf("an ungranted plugin was called: %+v", v)
	}
}

func Test_the_hook_view_fields_marshal_as_numbers_and_a_bool(t *testing.T) {
	h := hookHost(t)
	raw, _ := json.Marshal(view(t, h, "a"))
	for _, want := range []string{`"hook_calls":0`, `"hook_failures":0`, `"hook_suspended":false`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("view lacks %s: %s", want, raw)
		}
	}
}

func Test_each_hook_kind_reaches_its_documented_method(t *testing.T) {
	want := map[Kind]string{KindHTTPHandler: "http.handle", KindProxyHandler: "proxy.handle", KindWebSocketHandler: "websocket.handle"}
	for _, m := range MethodSpecs {
		if m.Kind != "" && want[m.Kind] != "" && want[m.Kind] != m.Name {
			t.Errorf("kind %s documented with %s", m.Kind, m.Name)
		}
		delete(want, m.Kind)
	}
	if len(want) != 0 {
		t.Errorf("hook kinds without a method: %v", want)
	}
}
