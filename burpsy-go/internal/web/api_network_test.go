package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// ---- /api/network/settings: Burp's Settings → Network ------------------------------------------
//
// Six Burp panels had no burpsy equivalent at all: hostname resolution, DNS lookup policy, timeouts,
// HTTP redirections, 100-continue and streaming responses. The behaviour behind them existed — it was
// scattered across a SenderConfig.Timeout that stood in for three bounds, two transport literals
// nobody could reach, and a read path that returned `100 Continue` as though it were a response — so
// this endpoint is less "new settings" than "the settings that were already being decided, named".
//
// These tests pin the contract the task statement asks for: GET answers the live state, PUT is a
// partial patch, an unknown key is a 400 that NAMES the key rather than a silent accept, and an
// accepted patch is persisted.

func networkSettingsServer() *Server {
	// s.sender is attached by NewServer, so no extra wiring: the endpoint edits the sender every
	// request-originating handler in this process already sends through.
	return newTestServer()
}

func getNetworkSettings(t *testing.T, s *Server) sender.NetworkSettings {
	t.Helper()
	rec := get(t, s, "/api/network/settings")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/network/settings = %d; body %s", rec.Code, rec.Body.String())
	}
	var view struct {
		Settings sender.NetworkSettings `json:"settings"`
		Accepted struct {
			Keys               []string `json:"keys"`
			RedirectModes      []string `json:"redirect_modes"`
			ResolutionPolicies []string `json:"resolution_policies"`
		} `json:"accepted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode network settings %q: %v", rec.Body.String(), err)
	}
	return view.Settings
}

// encodeSettings renders settings for comparison. NetworkSettings carries slices, so == does not
// compile on it, and a field-by-field comparison in a test would silently stop covering a field added
// later.
func encodeSettings(t *testing.T, n sender.NetworkSettings) string {
	t.Helper()
	raw, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	return string(raw)
}

func putNetworkSettings(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/network/settings", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// The default has to be the behaviour that shipped before the panel existed, or adding a settings
// surface silently changed what the tool does. Redirects off is the load-bearing half: internal/sender's
// AGENTS.md states that redirects are never followed and there is no knob, and this endpoint does not
// get to quietly reverse that for every existing caller.
func TestNetworkSettingsGetReportsTheBehaviourThatShippedBeforeThePanel(t *testing.T) {
	got := getNetworkSettings(t, networkSettingsServer())
	if got.Redirects.Mode != sender.RedirectNever {
		t.Errorf("redirects.mode = %q, want %q: following redirects is opt-in, so a process nobody "+
			"configured must not follow any", got.Redirects.Mode, sender.RedirectNever)
	}
	if got.Resolution.Policy != sender.ResolutionSystem {
		t.Errorf("resolution.policy = %q, want %q", got.Resolution.Policy, sender.ResolutionSystem)
	}
	if len(got.Resolution.Overrides) != 0 {
		t.Errorf("resolution.overrides = %v, want none: an override nobody typed would send traffic "+
			"somewhere DNS does not point", got.Resolution.Overrides)
	}
	if got.Timeouts.TotalMS == 0 || got.Timeouts.ConnectMS == 0 {
		t.Errorf("timeouts = %+v, want the connect and total bounds the code carried as literals",
			got.Timeouts)
	}
	if !got.Continue.Understand100 {
		t.Error("continue.understand_100_continue = false; returning an interim 1xx as the response is " +
			"simply wrong, so it is on by default")
	}
}

// The accepted block travels with the state so a panel does not hardcode the enum arms, and its key
// list is what the refusal messages point at. Derived from the patch table rather than typed beside
// it, so this asserts the two agree.
func TestNetworkSettingsGetNamesEveryPatchableKey(t *testing.T) {
	rec := get(t, networkSettingsServer(), "/api/network/settings")
	var view struct {
		Accepted networkAcceptedView `json:"accepted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := 0
	for _, fields := range networkPatchFields {
		want += len(fields)
	}
	if len(view.Accepted.Keys) != want {
		t.Errorf("accepted.keys lists %d entries, want one per patchable field (%d)",
			len(view.Accepted.Keys), want)
	}
	for _, key := range []string{
		"resolution.overrides", "resolution.policy", "timeouts.connect_ms", "redirects.mode",
		"continue.understand_100_continue", "streaming.hosts",
	} {
		found := false
		for _, got := range view.Accepted.Keys {
			if got == key {
				found = true
			}
		}
		if !found {
			t.Errorf("accepted.keys omits %q, so a client cannot discover a key the server accepts", key)
		}
	}
	if len(view.Accepted.RedirectModes) != 4 {
		t.Errorf("accepted.redirect_modes = %v, want Burp's four modes", view.Accepted.RedirectModes)
	}
}

// A patch touches only what it names. The other sections are asserted explicitly because the failure
// mode being guarded is a merge against the defaults rather than against the live state — that would
// make every single-key edit a silent reset of everything else, and nothing in the response would say so.
func TestNetworkSettingsPutPatchesOnlyTheKeysItNames(t *testing.T) {
	s := networkSettingsServer()
	before := getNetworkSettings(t, s)

	rec := putNetworkSettings(t, s, `{"timeouts": {"read_ms": 4000}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT read_ms = %d; body %s", rec.Code, rec.Body.String())
	}
	var view struct {
		Settings sender.NetworkSettings `json:"settings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Settings.Timeouts.ReadMS != 4000 {
		t.Errorf("confirmed read_ms = %d, want 4000", view.Settings.Timeouts.ReadMS)
	}
	if view.Settings.Timeouts.TotalMS != before.Timeouts.TotalMS {
		t.Errorf("total_ms moved from %d to %d on a patch that never mentioned it",
			before.Timeouts.TotalMS, view.Settings.Timeouts.TotalMS)
	}
	if view.Settings.Continue.Understand100 != before.Continue.Understand100 {
		t.Error("continue.understand_100_continue changed on a patch that only named a timeout")
	}
	// The live sender, not just the answer: an endpoint that echoed a confirmed state it had not
	// applied is the exact shape of dishonesty the confirmed-state convention exists to prevent.
	if live := s.sender.Network(); live.Timeouts.ReadMS != 4000 {
		t.Errorf("the sender reports read_ms = %d after a 200; the answer described a state the "+
			"sender is not in", live.Timeouts.ReadMS)
	}
}

// The refusal the task statement calls for by name. Both levels: an unknown section and an unknown key
// inside a known section, each naming what it refused.
func TestNetworkSettingsPutRefusesAnUnknownKeyByName(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantIn string
	}{
		{"unknown section", `{"timeuots": {"read_ms": 1}}`, "timeuots"},
		{"unknown key in a known section", `{"timeouts": {"raed_ms": 1}}`, "timeouts.raed_ms"},
		{"a Burp name we do not implement", `{"redirects": {"follow_relative": true}}`, "redirects.follow_relative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := networkSettingsServer()
			before := s.sender.Network()
			rec := putNetworkSettings(t, s, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("PUT %s = %d, want 400: a key the server does not implement must be refused, "+
					"never silently ignored", tc.body, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tc.wantIn) {
				t.Errorf("refusal %q does not name %q; the operator cannot fix a typo the error will "+
					"not identify", strings.TrimSpace(rec.Body.String()), tc.wantIn)
			}
			// Compared as JSON because NetworkSettings holds slices and is not comparable with ==;
			// the wire form is also the thing an operator would see change.
			if encodeSettings(t, s.sender.Network()) != encodeSettings(t, before) {
				t.Error("a refused patch changed the live settings; a body with one bad key must apply " +
					"no part of itself")
			}
		})
	}
}

// A misspelled member inside an override object is the same class of mistake as a misspelled key, and
// it has a worse failure mode: an entry decoded with an empty address would be refused for the wrong
// reason, telling the operator the address is missing when what is wrong is the word they typed.
func TestNetworkSettingsPutRefusesAMisspelledOverrideMember(t *testing.T) {
	s := networkSettingsServer()
	rec := putNetworkSettings(t, s,
		`{"resolution": {"overrides": [{"host": "a.test", "addr": "10.0.0.1", "enabled": true}]}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with an `addr` member = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "resolution.overrides") {
		t.Errorf("refusal %q does not name the key it refused", strings.TrimSpace(rec.Body.String()))
	}
}

// Validation lives on sender.NetworkSettings, and the endpoint must surface its message rather than
// flatten every bad value into one "invalid request". The override address is the case that matters
// most: a dropped override means the request went where DNS said instead of where the operator did.
func TestNetworkSettingsPutSurfacesTheValidationRefusal(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantIn string
	}{
		{
			"an override address that is not an address",
			`{"resolution": {"overrides": [{"host": "a.test", "address": "b.test", "enabled": true}]}}`,
			"not an IP address",
		},
		{
			"a redirect mode that does not exist",
			`{"redirects": {"mode": "sometimes"}}`,
			"sometimes",
		},
		{
			"a lookup policy that does not exist",
			`{"resolution": {"policy": "magic"}}`,
			"magic",
		},
		{
			"a resolver policy with no resolver",
			`{"resolution": {"policy": "resolver", "resolver": ""}}`,
			"names no address",
		},
		{
			"a connect bound longer than the total",
			`{"timeouts": {"connect_ms": 40000}}`,
			"longer than",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := networkSettingsServer()
			rec := putNetworkSettings(t, s, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("PUT %s = %d, want 400; body %s", tc.body, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantIn) {
				t.Errorf("refusal %q does not mention %q", strings.TrimSpace(rec.Body.String()), tc.wantIn)
			}
		})
	}
}

// Turning redirects on without naming a hop count gets the default bound, not a refusal and not an
// unbounded chain.
//
// This is what Normalise's max_hops arm is for, and it has to work this way: JSON cannot distinguish
// "max_hops absent" from "max_hops: 0", so a patch that only names the mode arrives indistinguishable
// from one asking for zero hops. Filling the default is the only reading that makes a one-key mode
// change work, and the confirmed answer states the bound the operator got, so nothing is hidden.
// sender's own Validate still refuses a zero hop count on a following mode, which is what a direct
// ApplyNetwork caller assembling settings in Go gets; that path does not go through Normalise.
func TestNetworkSettingsPutTurningRedirectsOnGetsABoundedChain(t *testing.T) {
	s := networkSettingsServer()
	rec := putNetworkSettings(t, s, `{"redirects": {"mode": "in_scope"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT mode only = %d; body %s", rec.Code, rec.Body.String())
	}
	live := s.sender.Network()
	if live.Redirects.Mode != sender.RedirectInScope {
		t.Errorf("redirects.mode = %q, want %q", live.Redirects.Mode, sender.RedirectInScope)
	}
	if live.Redirects.MaxHops <= 0 {
		t.Errorf("redirects.max_hops = %d after turning the policy on; a following mode with no bound "+
			"would follow a hostile chain forever", live.Redirects.MaxHops)
	}
	if live.Redirects.MaxHops > sender.MaxRedirectHops {
		t.Errorf("redirects.max_hops = %d, above the %d ceiling", live.Redirects.MaxHops, sender.MaxRedirectHops)
	}
}

// A shape error is not a value error and must not be reported as one: a JSON string where a number
// belongs cannot reach Validate at all, so the endpoint owns that message.
func TestNetworkSettingsPutRefusesAValueOfTheWrongShape(t *testing.T) {
	s := networkSettingsServer()
	rec := putNetworkSettings(t, s, `{"timeouts": {"read_ms": "4s"}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT read_ms=\"4s\" = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "timeouts.read_ms") {
		t.Errorf("refusal %q does not name the key", strings.TrimSpace(rec.Body.String()))
	}
}

// burpsy-react-ui-609d: the three streaming response-handling switches are settable through the
// endpoint and reach the proxy leg, which is where they take effect. Asserted through the proxy's own
// accessors, not the struct: a wrong JSON tag or a field dropped on the way through would still pass a
// struct comparison, and this repo's own lesson is to assert the surface the bytes travel over.
func TestStreamingResponseSwitchesReachTheProxy(t *testing.T) {
	s := newTestServer()
	px := proxy.NewServer(proxy.NewProxyConfig(core.NewTrafficStore()).WithLogger(zap.NewNop()))
	s.WithProxyServer(px)

	rec := putNetworkSettings(t, s, `{"streaming":{"store":false,"strip_chunked_encoding_metadata":true,"use_text_event_stream_header":true}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d; body %s", rec.Code, rec.Body.String())
	}
	if px.Streaming().Store() {
		t.Error("store:false did not reach the proxy; the streamed body would still be recorded")
	}
	if !px.Streaming().StripChunkedMetadata() {
		t.Error("strip_chunked_encoding_metadata did not reach the proxy")
	}
	if !px.Streaming().TreatEventStreamAsStreaming() {
		t.Error("use_text_event_stream_header did not reach the proxy")
	}

	// The GET view carries them back too, so the console can render their state.
	got := getNetworkSettings(t, s)
	if got.Streaming.StoreStreamed() {
		t.Error("the settings view reported store on after it was set off")
	}
	if !got.Streaming.UseTextEventStreamHeader {
		t.Error("the settings view dropped use_text_event_stream_header")
	}
}

// A PUT that touches an unrelated streaming field must not clobber the three switches: the patch is
// merged onto the live document, so an omitted key keeps its value. This is the failure that would
// turn any routine streaming edit into a silent reset of the switches.
func TestAnUnrelatedStreamingEditLeavesTheSwitchesAlone(t *testing.T) {
	s := newTestServer()
	px := proxy.NewServer(proxy.NewProxyConfig(core.NewTrafficStore()).WithLogger(zap.NewNop()))
	s.WithProxyServer(px)

	if rec := putNetworkSettings(t, s, `{"streaming":{"store":false,"use_text_event_stream_header":true}}`); rec.Code != http.StatusOK {
		t.Fatalf("first PUT = %d; body %s", rec.Code, rec.Body.String())
	}
	if rec := putNetworkSettings(t, s, `{"streaming":{"timeout_ms":12000}}`); rec.Code != http.StatusOK {
		t.Fatalf("second PUT = %d; body %s", rec.Code, rec.Body.String())
	}
	if px.Streaming().Store() {
		t.Error("an unrelated streaming edit turned store back on")
	}
	if !px.Streaming().TreatEventStreamAsStreaming() {
		t.Error("an unrelated streaming edit cleared the text/event-stream switch")
	}
}

// store is a pointer so a document that predates the switch reads as on, and an explicit false
// survives a restart rather than decoding back to the zero-value false that a bare bool would give.
func TestStreamingStoreSwitchSurvivesARestartAndDefaultsOn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "burpsy.db")
	store, err := persist.Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	s := NewServer(core.NewTrafficStore(), core.NewScope()).WithLogger(zap.NewNop()).WithPersist(store)
	if rec := putNetworkSettings(t, s, `{"streaming":{"store":false}}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d; body %s", rec.Code, rec.Body.String())
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	reopened, err := persist.Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	restored, err := reopened.LoadNetworkSettings()
	if err != nil {
		t.Fatalf("load network settings: %v", err)
	}
	if restored == nil {
		t.Fatal("no network settings persisted")
	}
	if restored.Streaming.StoreStreamed() {
		t.Error("store:false did not survive the restart; the switch would silently turn back on")
	}

	// A streaming document that never set store reads as on — the shipped behaviour, and the reason the
	// field is a pointer.
	var fresh sender.StreamingSettings
	if !fresh.StoreStreamed() {
		t.Error("a streaming document with no store key should default to storing")
	}
}

func TestNetworkSettingsPutRefusesAnEmptyBody(t *testing.T) {
	s := networkSettingsServer()
	if rec := putNetworkSettings(t, s, `{}`); rec.Code != http.StatusBadRequest {
		t.Errorf("PUT {} = %d, want 400: a patch that names nothing is not an edit", rec.Code)
	}
	if rec := putNetworkSettings(t, s, `not json`); rec.Code != http.StatusBadRequest {
		t.Errorf("PUT of unparseable input = %d, want 400", rec.Code)
	}
}

func TestNetworkSettingsRefusesAVerbItDoesNotImplement(t *testing.T) {
	s := networkSettingsServer()
	req := httptest.NewRequest(http.MethodDelete, "/api/network/settings", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET, PUT" {
		t.Errorf("Allow = %q, want %q", allow, "GET, PUT")
	}
}

// The round trip the task statement asks for: an accepted patch reaches the settings table, and a
// process that reads it back gets the state the operator last confirmed rather than the defaults.
//
// Asserted through the endpoint on the way in and through a second Store on the way out, because the
// failure this guards is a persist that never happened — which an in-memory check would not notice.
func TestNetworkSettingsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "burpsy.db")

	store, err := persist.Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	s := NewServer(core.NewTrafficStore(), core.NewScope()).WithLogger(zap.NewNop()).WithPersist(store)

	rec := putNetworkSettings(t, s, `{
		"resolution": {"overrides": [{"host": "Staging.Example.test", "address": "10.1.2.3", "enabled": true}]},
		"redirects": {"mode": "on_site", "max_hops": 3},
		"streaming": {"hosts": ["*.events.test"], "timeout_ms": 15000},
		"continue": {"remove_expect_header": true}
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d; body %s", rec.Code, rec.Body.String())
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	reopened, err := persist.Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()

	restored, err := reopened.LoadNetworkSettings()
	if err != nil {
		t.Fatalf("load network settings: %v", err)
	}
	if restored == nil {
		t.Fatal("no network settings were persisted; an accepted edit that dies with the process was " +
			"never really a setting")
	}
	if len(restored.Resolution.Overrides) != 1 {
		t.Fatalf("restored %d overrides, want 1", len(restored.Resolution.Overrides))
	}
	// Normalised on the way in, so what comes back is what the dial path matches against rather than
	// what the operator typed. A table that stored `Staging.Example.test` and matched `staging.example.test`
	// would display a rule that never fires.
	if got := restored.Resolution.Overrides[0].Host; got != "staging.example.test" {
		t.Errorf("restored override host = %q, want it lowercased", got)
	}
	if restored.Redirects.Mode != sender.RedirectOnSite || restored.Redirects.MaxHops != 3 {
		t.Errorf("restored redirects = %+v, want on_site with 3 hops", restored.Redirects)
	}
	if !restored.Continue.RemoveExpect {
		t.Error("restored continue.remove_expect_header = false, want the edit that was accepted")
	}

	// The restore path a new process takes, end to end: the settings a fresh sender ends up running.
	fresh := sender.NewSender(sender.DefaultSenderConfig())
	if err := fresh.ApplyNetwork(*restored); err != nil {
		t.Fatalf("a persisted document was refused on restore: %v", err)
	}
	if fresh.Network().Redirects.Mode != sender.RedirectOnSite {
		t.Error("a restored sender is not in the mode that was persisted")
	}
}

// Persistence failing must not lose the operator's edit: the live sender already has it, so the
// endpoint answers 200 and logs. Asserted with no store attached, which is the same code path.
func TestNetworkSettingsApplyWithoutAStoreStillTakesEffect(t *testing.T) {
	s := networkSettingsServer()
	if rec := putNetworkSettings(t, s, `{"timeouts": {"read_ms": 2500}}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT with no persist store = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := s.sender.Network().Timeouts.ReadMS; got != 2500 {
		t.Errorf("read_ms = %d, want 2500", got)
	}
}

// Burp's "Allowed redirect types" (burpsy-react-ui-z9zi) through the route: the defaults are on the
// wire before anything set them, a partial object changes only what it names, and the JavaScript kind
// and an unknown kind are refused by name with the live settings untouched.
func TestNetworkSettingsCarryTheRedirectTypes(t *testing.T) {
	s := networkSettingsServer()
	rec := get(t, s, "/api/network/settings")
	want := `"types":{"understand_3xx_status_code":true,"understand_any_status_code_with_location_header":false,` +
		`"understand_refresh_header":true,"understand_meta_refresh_tag":true,"understand_javascript_driven":false}`
	if !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("GET does not carry Burp's default redirect types %s: %s", want, rec.Body.String())
	}

	rec = putNetworkSettings(t, s, `{"redirects": {"types": {"understand_meta_refresh_tag": false}}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT types = %d %s", rec.Code, rec.Body.String())
	}
	live := s.sender.Network().Redirects.EffectiveTypes()
	if live.UnderstandMetaRefresh || !live.Understand3xx || !live.UnderstandRefreshHeader {
		t.Errorf("after turning only meta refresh off the types are %+v", live)
	}

	for _, body := range []string{
		`{"redirects": {"types": {"understand_javascript_driven": true}}}`,
		`{"redirects": {"types": {"understand_html5_history": true}}}`,
	} {
		rec = putNetworkSettings(t, s, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("PUT %s = %d, want 400", body, rec.Code)
		}
	}
	if !strings.Contains(putNetworkSettings(t, s, `{"redirects": {"types": {"understand_javascript_driven": true}}}`).Body.String(),
		"understand_javascript_driven") {
		t.Error("the JavaScript refusal does not name the key")
	}
	if got := s.sender.Network().Redirects.EffectiveTypes(); got != live {
		t.Errorf("a refused patch changed the types: %+v, was %+v", got, live)
	}
}
