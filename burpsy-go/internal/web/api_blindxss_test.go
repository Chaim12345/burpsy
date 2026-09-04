package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/blindxss"
)

// ---- The blind-XSS callback channel ---------------------------------------------------------------
//
// internal/blindxss was a complete capability nothing outside its own tests constructed. These pin the
// seam, and — the part that actually matters here — that the seam never turns "we were not listening"
// into "we listened and heard nothing". A blind-XSS payload's absence of callbacks is the single
// easiest honest-counting mistake in this whole tree to make, because the wire shape for "no hits" and
// the wire shape for "no channel" want to be the same empty array.

// blindxssStateResp mirrors blindxssStateView for decoding, with only the fields these tests assert on.
type blindxssStateResp struct {
	Configured bool   `json:"configured"`
	Listening  bool   `json:"listening"`
	Reason     string `json:"reason"`
	BaseURL    string `json:"base_url"`
	Payloads   []struct {
		Token       string `json:"token"`
		ScriptURL   string `json:"script_url"`
		ScriptTag   string `json:"script_tag"`
		Outstanding bool   `json:"outstanding"`
		Hits        []struct {
			Token    string `json:"token"`
			Location string `json:"location"`
			Cookies  string `json:"cookies"`
		} `json:"hits"`
	} `json:"payloads"`
	Counts struct {
		Payloads    int `json:"payloads"`
		Hits        int `json:"hits"`
		Fired       int `json:"fired"`
		Outstanding int `json:"outstanding"`
	} `json:"counts"`
	Verdict string `json:"verdict"`
}

func blindxssState(t *testing.T, s *Server) blindxssStateResp {
	t.Helper()
	rec := get(t, s, "/api/blindxss")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/blindxss: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var state blindxssStateResp
	if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode state %q: %v", rec.Body.String(), err)
	}
	return state
}

// listeningServer is a server with a real blind-XSS listener bound on an ephemeral loopback port.
func listeningServer(t *testing.T) *Server {
	t.Helper()
	listener, err := blindxss.NewListener(t.Context(), blindxss.Options{})
	if err != nil {
		t.Fatalf("bind a loopback blind-XSS listener: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	return newTestServer().WithBlindXSS(listener, nil)
}

// The defect this endpoint exists to avoid: an unwired channel answering with an empty hit list, which
// a reader would take as "a payload was planted and nothing came back".
func TestBlindXSSWithNoChannelSaysSoRatherThanReturningAnEmptyResult(t *testing.T) {
	state := blindxssState(t, newTestServer())

	if state.Configured || state.Listening {
		t.Errorf("configured = %v, listening = %v; a server given no listener must claim neither",
			state.Configured, state.Listening)
	}
	if state.Reason == "" {
		t.Fatal("no reason was given for an absent channel; an empty payload list with no reason is " +
			"indistinguishable from a channel that heard nothing")
	}
	if !strings.Contains(state.Reason, "-blindxss") {
		t.Errorf("reason does not name the flag that would wire one: %q", state.Reason)
	}
	// The verdict is what a surface renders when it renders nothing else, so it has to carry the whole
	// claim: not that the target is clean, but that no claim is available.
	if !strings.Contains(state.Verdict, "not a statement about any target") {
		t.Errorf("verdict does not disclaim a verdict about the target: %q", state.Verdict)
	}
	if state.Payloads == nil {
		t.Error("payloads decoded as null; the field must serialise as [] so a client cannot confuse " +
			"an absent field with an empty one")
	}
}

// A bind failure is the case internal/blindxss's honest-failure contract is written for: the channel
// was asked for and could not be had, which is not the same fact as never asking.
func TestBlindXSSAFailedBindIsReportedAsAReasonNotAsSilence(t *testing.T) {
	s := newTestServer().WithBlindXSS(nil, errors.New("cannot listen on \"0.0.0.0:80\": permission denied"))
	state := blindxssState(t, s)

	if !state.Configured {
		t.Error("configured = false for a channel that was requested and failed; the operator did ask")
	}
	if state.Listening {
		t.Error("listening = true with no listener")
	}
	if !strings.Contains(state.Reason, "permission denied") {
		t.Errorf("the bind failure did not survive into the reason: %q", state.Reason)
	}
	if !strings.Contains(state.Verdict, "not a statement about any target") {
		t.Errorf("verdict does not disclaim a verdict about the target: %q", state.Verdict)
	}
}

// Minting against no listener would produce a token planted in a real application and correlated
// against a channel that cannot hear it — an outstanding finding that can never resolve either way.
func TestBlindXSSMintingWithoutAListenerIsRefused(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/blindxss/payload", map[string]any{})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "-blindxss") {
		t.Errorf("the refusal does not say how to wire a channel: %q", rec.Body.String())
	}
	if n := blindxssState(t, s).Counts.Payloads; n != 0 {
		t.Errorf("a refused mint recorded %d payload(s); it must record none", n)
	}
}

// A minted payload with no callback is outstanding, and the word has to be on the wire: "hits: []" is
// one careless sentence away from "no blind XSS found".
func TestBlindXSSAMintedPayloadIsOutstandingUntilItFires(t *testing.T) {
	s := listeningServer(t)

	rec := postJSON(t, s, "/api/blindxss/payload", map[string]any{})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/blindxss/payload: status = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
	var minted struct {
		Payload struct {
			Token     string `json:"token"`
			ScriptURL string `json:"script_url"`
			ScriptTag string `json:"script_tag"`
		} `json:"payload"`
		Caveat string `json:"caveat"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}
	if !strings.HasPrefix(minted.Payload.Token, "bsy") {
		t.Errorf("token = %q, want the bsy-prefixed correlation shape", minted.Payload.Token)
	}
	if !strings.Contains(minted.Payload.ScriptTag, minted.Payload.ScriptURL) {
		t.Errorf("script tag %q does not carry the script URL %q", minted.Payload.ScriptTag, minted.Payload.ScriptURL)
	}
	// The caveat travels with the payload, where the operator is about to plant it, rather than only
	// with the result they read days later.
	if !strings.Contains(minted.Caveat, "outstanding") {
		t.Errorf("mint response does not warn that an unfired payload is outstanding: %q", minted.Caveat)
	}

	state := blindxssState(t, s)
	if !state.Listening {
		t.Fatalf("a bound listener reported listening = false (%s)", state.Reason)
	}
	if state.Counts.Payloads != 1 || state.Counts.Outstanding != 1 || state.Counts.Fired != 0 {
		t.Errorf("counts = %+v, want one payload, one outstanding, none fired", state.Counts)
	}
	if len(state.Payloads) != 1 || !state.Payloads[0].Outstanding {
		t.Errorf("payload list = %+v, want one entry marked outstanding", state.Payloads)
	}
	if !strings.Contains(state.Verdict, "Outstanding is not clean") {
		t.Errorf("verdict lets an unfired payload read as a clean result: %q", state.Verdict)
	}
}

// The whole channel, end to end, against the real listener: it serves the capture script for a token
// it minted, records the callback that script would post, and the API attributes it to that token.
//
// The two URLs are derived from the mint response rather than hand-built from the path scheme, except
// for the ".js" → "/report" step, which is the one piece of internal/blindxss's routing this test
// knows. That coupling is deliberate: a change to the report path should fail here rather than leave
// the endpoint silently unable to see any callback.
func TestBlindXSSACallbackIsRecordedAgainstItsToken(t *testing.T) {
	s := listeningServer(t)

	rec := postJSON(t, s, "/api/blindxss/payload", map[string]any{})
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint: status = %d (%s)", rec.Code, rec.Body.String())
	}
	var minted struct {
		Payload struct {
			Token     string `json:"token"`
			ScriptURL string `json:"script_url"`
		} `json:"payload"`
	}
	json.Unmarshal(rec.Body.Bytes(), &minted)

	// The script has to be served for a minted token, or nothing would ever execute to call home.
	scriptResp, err := http.Get(minted.Payload.ScriptURL)
	if err != nil {
		t.Fatalf("GET the served payload script: %v", err)
	}
	scriptResp.Body.Close()
	if scriptResp.StatusCode != http.StatusOK {
		t.Fatalf("the listener answered %d for a token it minted", scriptResp.StatusCode)
	}

	reportURL := strings.TrimSuffix(minted.Payload.ScriptURL, ".js") + "/report"
	body := `{"token":"` + minted.Payload.Token + `","cookies":"session=abc","dom":"<div>admin panel</div>",` +
		`"truncated":false,"location":"https://admin.target.test/tickets/9","referrer":"","userAgent":"probe"}`
	callback, err := http.Post(reportURL, "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST the callback: %v", err)
	}
	callback.Body.Close()
	if callback.StatusCode != http.StatusNoContent {
		t.Fatalf("the listener answered %d for a well-formed callback", callback.StatusCode)
	}

	state := blindxssState(t, s)
	if state.Counts.Hits != 1 || state.Counts.Fired != 1 || state.Counts.Outstanding != 0 {
		t.Fatalf("counts = %+v, want one hit on one fired payload and nothing outstanding", state.Counts)
	}
	if len(state.Payloads) != 1 || len(state.Payloads[0].Hits) != 1 {
		t.Fatalf("payloads = %+v, want one payload carrying one hit", state.Payloads)
	}
	hit := state.Payloads[0].Hits[0]
	if hit.Token != minted.Payload.Token {
		t.Errorf("hit token = %q, want %q — a callback filed under the wrong token is fabricated evidence",
			hit.Token, minted.Payload.Token)
	}
	// Where it executed is the fact a blind finding turns on; it must survive to the wire.
	if hit.Location != "https://admin.target.test/tickets/9" {
		t.Errorf("hit location = %q, want the URL the payload reported", hit.Location)
	}
	if state.Payloads[0].Outstanding {
		t.Error("a payload with a recorded callback is still marked outstanding")
	}
}

// A callback quoting a token this listener never minted is not filed at all. Without this, anyone who
// could reach the listener could manufacture the evidence a finding would be written from.
func TestBlindXSSACallbackForAnUnmintedTokenIsNotRecorded(t *testing.T) {
	s := listeningServer(t)
	state := blindxssState(t, s)
	if state.BaseURL == "" {
		t.Fatal("a listening channel reported no base URL, so this test cannot address the listener")
	}

	forged := "bsyaaaaaaaaaaaaa"
	resp, err := http.Post(state.BaseURL+"/bxss/"+forged+"/report", "text/plain",
		strings.NewReader(`{"token":"`+forged+`","location":"https://invented.test/"}`))
	if err != nil {
		t.Fatalf("POST a forged callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("the listener answered %d for a token it never minted, want 404", resp.StatusCode)
	}
	if n := blindxssState(t, s).Counts.Hits; n != 0 {
		t.Errorf("counts.hits = %d after a forged callback; it must be 0", n)
	}
}

// GET is the only verb the state route answers, and the mint is the only thing that changes state. A
// GET that minted would be a state change on a safe verb — the defect the sequencer's stop route had.
func TestBlindXSSMintIsNotReachableByGET(t *testing.T) {
	s := listeningServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/blindxss/payload", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/blindxss/payload answered %d, want 405 (%s)", rec.Code, rec.Body.String())
	}
	if n := blindxssState(t, s).Counts.Payloads; n != 0 {
		t.Errorf("a GET minted %d payload(s)", n)
	}
}
