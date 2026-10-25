package extension

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

// The plugin->host service methods (rvq2 event.raise, 97dk storage.*, xpuh ai.prompt,
// p81m http.send). Every one needs a per-plugin grant from the operator, so a plugin the
// operator never granted gets a distinct JSON-RPC error and the service is never reached.
// Tested against a real child process (the plugin_helper_test.go re-exec).

type fakeServices struct {
	mu     sync.Mutex
	events []string
	store  map[string]json.RawMessage
	sends  []SessionRequest
	prompt []string
	refuse bool
}

func (f *fakeServices) services() Services {
	f.store = map[string]json.RawMessage{}
	return Services{
		RaiseEvent: func(plugin string, level EventLevel, message string) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.events = append(f.events, plugin+"|"+string(level)+"|"+message)
		},
		Storage: f,
		Prompt: func(_ context.Context, plugin, system, prompt string) (string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.prompt = append(f.prompt, plugin+"|"+system+"|"+prompt)
			return "answer to " + prompt, nil
		},
		Send: func(_ context.Context, plugin string, req SessionRequest) (SessionResponse, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.sends = append(f.sends, req)
			if f.refuse {
				return SessionResponse{}, ErrOutOfScope
			}
			return SessionResponse{Status: 200, Headers: [][]string{{"X-A", "1"}}, Body: "ok"}, nil
		},
	}
}

func (f *fakeServices) Get(plugin string, scope StorageScope, key string) (json.RawMessage, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.store[plugin+"|"+string(scope)+"|"+key]
	return v, ok, nil
}
func (f *fakeServices) Set(plugin string, scope StorageScope, key string, value json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.store[plugin+"|"+string(scope)+"|"+key] = value
	return nil
}
func (f *fakeServices) Delete(plugin string, scope StorageScope, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.store, plugin+"|"+string(scope)+"|"+key)
	return nil
}

type hostReply struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// callHost has the plugin send `method` with `params` and returns the host's answer.
func callHost(t *testing.T, h *Host, method string, params any) hostReply {
	t.Helper()
	if h.List().Extensions[0].State != StateLoaded {
		if _, err := h.Load("probe"); err != nil {
			t.Fatalf("Load: %v", err)
		}
	}
	enc, _ := json.Marshal(map[string]any{"method": method, "params": params})
	res, err := h.Invoke(context.Background(), "probe", InvokeParams{Registration: "act", Selection: string(enc)})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	var out hostReply
	if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
		t.Fatalf("host answer is not JSON-RPC: %v: %s", err, res.Output)
	}
	return out
}

func hostWith(t *testing.T, fs *fakeServices, grants ...string) *Host {
	return testHost(t, "host-caller", func(c *Config) {
		c.Services = fs.services()
		c.Grants = map[string][]string{"probe": grants}
	})
}

func Test_a_host_method_without_a_grant_gets_the_distinct_no_grant_error(t *testing.T) {
	cases := []struct {
		method string
		params any
	}{
		{"event.raise", map[string]any{"level": "error", "message": "x"}},
		{"storage.get", map[string]any{"scope": "project", "key": "k"}},
		{"storage.set", map[string]any{"scope": "project", "key": "k", "value": 1}},
		{"storage.delete", map[string]any{"scope": "project", "key": "k"}},
		{"ai.prompt", map[string]any{"prompt": "hi"}},
		{"http.send", map[string]any{"request": map[string]any{"method": "GET", "url": "http://a/"}}},
	}
	for _, tc := range cases {
		fs := &fakeServices{}
		h := hostWith(t, fs) // no grants at all
		got := callHost(t, h, tc.method, tc.params)
		if got.Error == nil || got.Error.Code != CodeNoGrant {
			t.Errorf("%s without a grant answered %+v, want error code %d", tc.method, got, CodeNoGrant)
		}
		if len(fs.events)+len(fs.sends)+len(fs.prompt)+len(fs.store) != 0 {
			t.Errorf("%s reached a service without a grant", tc.method)
		}
		view := h.List().Extensions[0]
		if view.RefusedHostCalls != 1 {
			t.Errorf("%s: refused_host_calls = %d, want 1", tc.method, view.RefusedHostCalls)
		}
	}
}

func Test_a_grant_for_one_method_does_not_open_another(t *testing.T) {
	fs := &fakeServices{}
	h := hostWith(t, fs, "event.raise")
	got := callHost(t, h, "http.send", map[string]any{"request": map[string]any{"method": "GET", "url": "http://a/"}})
	if got.Error == nil || got.Error.Code != CodeNoGrant || len(fs.sends) != 0 {
		t.Errorf("http.send under an event.raise grant = %+v (sends %d), want no-grant", got, len(fs.sends))
	}
}

func Test_event_raise_reaches_the_service_with_the_plugin_name(t *testing.T) {
	fs := &fakeServices{}
	h := hostWith(t, fs, "event.raise")
	got := callHost(t, h, "event.raise", map[string]any{"level": "critical", "message": "token expired"})
	if got.Error != nil {
		t.Fatalf("error: %+v", got.Error)
	}
	if len(fs.events) != 1 || fs.events[0] != "probe|critical|token expired" {
		t.Errorf("events = %v", fs.events)
	}
	bad := callHost(t, h, "event.raise", map[string]any{"level": "fatal", "message": "x"})
	if bad.Error == nil || bad.Error.Code != CodeInvalidParams {
		t.Errorf("unknown level answered %+v, want invalid params", bad)
	}
	if len(fs.events) != 1 {
		t.Errorf("an invalid level still raised an event: %v", fs.events)
	}
}

func Test_storage_round_trips_a_json_value_per_plugin_and_scope(t *testing.T) {
	fs := &fakeServices{}
	h := hostWith(t, fs, "storage.get", "storage.set", "storage.delete")
	if got := callHost(t, h, "storage.set", map[string]any{"scope": "project", "key": "seen", "value": map[string]any{"n": []int{1, 2}}}); got.Error != nil {
		t.Fatalf("set: %+v", got.Error)
	}
	got := callHost(t, h, "storage.get", map[string]any{"scope": "project", "key": "seen"})
	if got.Error != nil || !strings.Contains(string(got.Result), `"found":true`) || !strings.Contains(string(got.Result), `"n":[1,2]`) {
		t.Errorf("get = %s / %+v", got.Result, got.Error)
	}
	other := callHost(t, h, "storage.get", map[string]any{"scope": "preferences", "key": "seen"})
	if !strings.Contains(string(other.Result), `"found":false`) {
		t.Errorf("preferences scope saw the project value: %s", other.Result)
	}
	callHost(t, h, "storage.delete", map[string]any{"scope": "project", "key": "seen"})
	gone := callHost(t, h, "storage.get", map[string]any{"scope": "project", "key": "seen"})
	if !strings.Contains(string(gone.Result), `"found":false`) {
		t.Errorf("delete left the value: %s", gone.Result)
	}
	bad := callHost(t, h, "storage.get", map[string]any{"scope": "global", "key": "x"})
	if bad.Error == nil || bad.Error.Code != CodeInvalidParams {
		t.Errorf("unknown scope answered %+v", bad)
	}
	empty := callHost(t, h, "storage.set", map[string]any{"scope": "project", "key": "", "value": 1})
	if empty.Error == nil || empty.Error.Code != CodeInvalidParams {
		t.Errorf("empty key answered %+v", empty)
	}
}

func Test_ai_prompt_returns_the_text_the_service_produced(t *testing.T) {
	fs := &fakeServices{}
	h := hostWith(t, fs, "ai.prompt")
	got := callHost(t, h, "ai.prompt", map[string]any{"system": "be terse", "prompt": "summarise"})
	if got.Error != nil || !strings.Contains(string(got.Result), `"text":"answer to summarise"`) {
		t.Errorf("answer = %s / %+v", got.Result, got.Error)
	}
	if len(fs.prompt) != 1 || fs.prompt[0] != "probe|be terse|summarise" {
		t.Errorf("service saw %v", fs.prompt)
	}
	empty := callHost(t, h, "ai.prompt", map[string]any{"prompt": ""})
	if empty.Error == nil || empty.Error.Code != CodeInvalidParams {
		t.Errorf("empty prompt answered %+v", empty)
	}
}

func Test_http_send_returns_the_response_and_reports_a_scope_refusal_distinctly(t *testing.T) {
	fs := &fakeServices{}
	h := hostWith(t, fs, "http.send")
	req := map[string]any{"request": map[string]any{"method": "GET", "url": "http://in-scope.test/", "headers": [][]string{{"A", "b"}}}}
	got := callHost(t, h, "http.send", req)
	if got.Error != nil || !strings.Contains(string(got.Result), `"status":200`) || !strings.Contains(string(got.Result), `"body":"ok"`) {
		t.Fatalf("send = %s / %+v", got.Result, got.Error)
	}
	if len(fs.sends) != 1 || fs.sends[0].URL != "http://in-scope.test/" {
		t.Errorf("service saw %v", fs.sends)
	}
	fs.refuse = true
	refused := callHost(t, h, "http.send", req)
	if refused.Error == nil || refused.Error.Code != CodeRefused {
		t.Errorf("out-of-scope send answered %+v, want code %d", refused, CodeRefused)
	}
	view := h.List().Extensions[0]
	if view.RefusedHostCalls != 1 {
		t.Errorf("refused_host_calls = %d, want the out-of-scope send counted", view.RefusedHostCalls)
	}
	missing := callHost(t, h, "http.send", map[string]any{"request": map[string]any{"method": "GET"}})
	if missing.Error == nil || missing.Error.Code != CodeInvalidParams {
		t.Errorf("a send without a url answered %+v", missing)
	}
}

func Test_a_granted_method_with_no_service_wired_says_so(t *testing.T) {
	h := testHost(t, "host-caller", func(c *Config) {
		c.Grants = map[string][]string{"probe": {"http.send"}}
	})
	got := callHost(t, h, "http.send", map[string]any{"request": map[string]any{"method": "GET", "url": "http://a/"}})
	if got.Error == nil || got.Error.Code != CodeNotWired {
		t.Errorf("unwired send answered %+v, want code %d", got, CodeNotWired)
	}
}

// Marshalled JSON, not Go structs: the view's new slices are [] and {} (never null) and
// carry the per-method call counts.
func Test_the_plugin_view_marshals_grants_and_host_call_counts(t *testing.T) {
	fs := &fakeServices{}
	h := hostWith(t, fs, "event.raise")
	before, _ := json.Marshal(h.List().Extensions[0])
	for _, want := range []string{`"grants":["event.raise"]`, `"host_calls":{}`, `"refused_host_calls":0`} {
		if !strings.Contains(string(before), want) {
			t.Errorf("view before any call lacks %s: %s", want, before)
		}
	}
	callHost(t, h, "event.raise", map[string]any{"level": "info", "message": "m"})
	after, _ := json.Marshal(h.List().Extensions[0])
	if !strings.Contains(string(after), `"host_calls":{"event.raise":1}`) {
		t.Errorf("view after a call lacks the count: %s", after)
	}
	ungranted := testHost(t, "good")
	raw, _ := json.Marshal(ungranted.List().Extensions[0])
	if !strings.Contains(string(raw), `"grants":[]`) {
		t.Errorf("an ungranted plugin's grants must marshal as [], not null: %s", raw)
	}
}

func Test_ValidateGrants_rejects_a_name_that_is_not_a_host_method(t *testing.T) {
	if err := ValidateGrants(map[string][]string{"p": {"http.send", "storage.get"}}); err != nil {
		t.Errorf("valid grants refused: %v", err)
	}
	err := ValidateGrants(map[string][]string{"p": {"http.sned"}})
	if err == nil || !strings.Contains(err.Error(), "http.sned") {
		t.Errorf("a misspelt grant error = %v, want it named", err)
	}
	if !errors.Is(err, ErrUnknownGrant) {
		t.Errorf("error does not wrap ErrUnknownGrant: %v", err)
	}
}
