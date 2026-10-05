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
	"go.uber.org/zap"
)

// Sequencer analysis settings (burpsy-react-ui-nm81) and the per-analysis test switch
// (burpsy-react-ui-3iao), asserted on the marshalled wire shape — what the console actually reads.

func seqRequest(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// seqTokens is a sample large enough that both batteries answer every test, so a row marked
// not-run is the operator's decision rather than a battery that declined anyway.
func seqTokens() []string {
	tokens := make([]string, 0, 4096)
	const alphabet = "0123456789abcdef"
	for i := 0; i < 4096; i++ {
		var b [8]byte
		for j := range b {
			b[j] = alphabet[(i*7+j*3)%len(alphabet)]
		}
		tokens = append(tokens, string(b[:]))
	}
	return tokens
}

type seqWireTest struct {
	ID            string `json:"id"`
	Disabled      bool   `json:"disabled"`
	DisableReason string `json:"disable_reason"`
}

type seqWireReport struct {
	Grade json.RawMessage `json:"grade"`
	Fips  struct {
		Tests []seqWireTest `json:"tests"`
	} `json:"fips"`
	Advanced struct {
		Tests []seqWireTest `json:"tests"`
	} `json:"advanced"`
}

func analyseSeq(t *testing.T, s *Server, extra string) seqWireReport {
	t.Helper()
	raw, _ := json.Marshal(seqTokens())
	body := `{"tokens":` + string(raw) + extra + `}`
	rec := seqRequest(t, s, http.MethodPost, "/api/sequencer/analyse", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyse = %d: %s", rec.Code, rec.Body.String())
	}
	var rep seqWireReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	return rep
}

func seqRow(t *testing.T, tests []seqWireTest, id string) seqWireTest {
	t.Helper()
	for _, x := range tests {
		if x.ID == id {
			return x
		}
	}
	t.Fatalf("the report carries no %q row at all — a switched-off test must be present and marked, "+
		"not silently absent", id)
	return seqWireTest{}
}

// Criterion 1 and 3: every one of the ten keys is readable, and the defaults are Burp's — all
// analyses on, base64 decoding off.
func TestSequencerSettingsReadEveryBurpKeyAtItsDefault(t *testing.T) {
	s := newTestServer()
	rec := seqRequest(t, s, http.MethodGet, "/api/sequencer/settings", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d", rec.Code)
	}
	var view struct {
		TokenAnalysis map[string]bool `json:"token_analysis"`
		TokenHandling map[string]bool `json:"token_handling"`
		Keys          []string        `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []string{"count", "transitions", "fips_monobit", "fips_poker", "fips_runs", "fips_long_run",
		"spectral", "correlation", "compression"}
	for _, k := range want {
		on, present := view.TokenAnalysis[k]
		if !present {
			t.Errorf("sequencer.token_analysis.%s is not readable", k)
		} else if !on {
			t.Errorf("sequencer.token_analysis.%s defaults off; Burp runs every analysis by default", k)
		}
	}
	if len(view.TokenAnalysis) != len(want) {
		t.Errorf("token_analysis carries %d keys, want %d: %v", len(view.TokenAnalysis), len(want), view.TokenAnalysis)
	}
	b64, present := view.TokenHandling["base_64_decode_before_analyzing"]
	if !present || b64 {
		t.Errorf("base_64_decode_before_analyzing = %v (present %v), want false — Burp's default", b64, present)
	}
	if len(view.Keys) != len(want) {
		t.Errorf("keys lists %d, want %d", len(view.Keys), len(want))
	}
}

// Criterion 4, end to end through the settings surface: switching fips_poker off changes which rows
// are marked not-run in the next analysis, and the grade does not move.
func TestTurningFipsPokerOffInSettingsChangesTheRowsAndNotTheGrade(t *testing.T) {
	s := newTestServer()
	before := analyseSeq(t, s, "")
	if seqRow(t, before.Fips.Tests, "poker").Disabled {
		t.Fatal("poker is marked not-run before anything was switched off")
	}

	if rec := seqRequest(t, s, http.MethodPut, "/api/sequencer/settings", `{"token_analysis":{"fips_poker":false}}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	after := analyseSeq(t, s, "")

	poker := seqRow(t, after.Fips.Tests, "poker")
	if !poker.Disabled || poker.DisableReason == "" {
		t.Errorf("poker row = %+v, want disabled with a reason (criterion 2: not-run WITH its name)", poker)
	}
	if seqRow(t, after.Fips.Tests, "monobit").Disabled {
		t.Error("switching poker off also marked monobit not-run")
	}
	if string(before.Grade) != string(after.Grade) {
		t.Errorf("the grade moved when a test was switched off:\nbefore %s\nafter  %s", before.Grade, after.Grade)
	}
}

// 3iao: one analysis can leave a test out without touching the saved settings, and "Redo analysis"
// is the same request with a different list.
func TestADisabledTestsListAppliesToOneAnalysisOnly(t *testing.T) {
	s := newTestServer()
	redo := analyseSeq(t, s, `,"disabled_tests":["compression"]`)
	if !seqRow(t, redo.Advanced.Tests, "compression").Disabled {
		t.Error("disabled_tests:[compression] did not mark the compression test not-run")
	}
	// The next analysis, naming nothing, runs it again: the list was for that run only.
	if seqRow(t, analyseSeq(t, s, "").Advanced.Tests, "compression").Disabled {
		t.Error("a per-analysis disable leaked into the saved settings")
	}
	// An explicit empty list overrides saved switches: every test runs.
	seqRequest(t, s, http.MethodPut, "/api/sequencer/settings", `{"token_analysis":{"spectral":false}}`)
	if seqRow(t, analyseSeq(t, s, `,"disabled_tests":[]`).Advanced.Tests, "spectral").Disabled {
		t.Error("an explicit empty disabled_tests did not override the saved switch")
	}
}

// Refusals name what is accepted and change nothing.
func TestSequencerSettingsRefuseWhatTheyCannotMean(t *testing.T) {
	s := newTestServer()

	rec := seqRequest(t, s, http.MethodPut, "/api/sequencer/settings", `{"token_analysis":{"fips_pokr":false}}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "fips_poker") {
		t.Errorf("an unknown key = %d %q, want 400 naming the accepted keys", rec.Code, rec.Body.String())
	}
	rec = seqRequest(t, s, http.MethodPut, "/api/sequencer/settings", `{"token_analysis":{"count":false,"spectral":false}}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("count:false = %d, want 400 — a switch that changed nothing would be a control that lies", rec.Code)
	}
	// The refused PUT changed nothing — spectral, in the same body, is still on.
	if seqRow(t, analyseSeq(t, s, "").Advanced.Tests, "spectral").Disabled {
		t.Error("a refused PUT partially applied: spectral was switched off by a body that was refused")
	}

	raw, _ := json.Marshal(seqTokens())
	rec = seqRequest(t, s, http.MethodPost, "/api/sequencer/analyse", `{"tokens":`+string(raw)+`,"disabled_tests":["chi_square"]}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "compression") {
		t.Errorf("an unknown disabled test = %d %q, want 400 naming the tests", rec.Code, rec.Body.String())
	}
}

// The settings are saved with the project: they survive a restart, and a different project that never
// saved any reads as Burp's defaults rather than inheriting the first project's switches.
func TestSequencerSettingsAreSavedWithTheProject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.db")
	store, err := persist.Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s := NewServer(core.NewTrafficStore(), core.NewScope()).WithLogger(zap.NewNop()).WithPersist(store)
	if rec := seqRequest(t, s, http.MethodPut, "/api/sequencer/settings",
		`{"token_analysis":{"correlation":false},"token_handling":{"base_64_decode_before_analyzing":true}}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	store.Close()

	reopened, err := persist.Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	s2 := NewServer(core.NewTrafficStore(), core.NewScope()).WithLogger(zap.NewNop()).WithPersist(reopened)
	got := s2.sequencerSettings()
	if got.TokenAnalysis["correlation"] {
		t.Error("correlation:false did not survive the restart")
	}
	if !got.TokenHandling.Base64DecodeBeforeAnalyzing {
		t.Error("base_64_decode_before_analyzing:true did not survive the restart")
	}

	other, err := persist.Open(filepath.Join(dir, "b.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open b: %v", err)
	}
	defer other.Close()
	s2.WithPersist(other) // what a project switch does
	if !s2.sequencerSettings().TokenAnalysis["correlation"] {
		t.Error("a project with no saved settings inherited the previous project's correlation:false")
	}
}
