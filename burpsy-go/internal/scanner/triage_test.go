package scanner

// The LLM post-scan triage pass (burpsy-react-ui-ei0v). The tests pin the contracts that
// make the feature honest rather than magical:
//
//   - the gate is Burp's Standard profile: High any-confidence, Medium tentative-or-better,
//     Low never swept, Collaborator never (no transcript to read);
//   - the verdict parses from the model's answer — JSON preferred, vocabulary fallback,
//     anything else investigate-further with the raw answer carried so the operator sees
//     what the model actually said;
//   - ADVICE NEVER PROMOTION: a triage note lands beside Confidence and Severity and moves
//     neither — the property the enrich rule already guards for catalog severities;
//   - an unparseable answer refuses rather than inventing a verdict;
//   - an endpoint error leaves NO note: a triage that did not happen must not leave a
//     marker that looks like one.
import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTheStandardProfileGateBoundsTheSweep(t *testing.T) {
	cases := []struct {
		name       string
		severity   string
		confidence string
		want       bool
	}{
		{"SQL injection", "high", "tentative", true},
		{"SQL injection", "high", "firm", true},
		{"Stored XSS", "critical", "certain", true},
		{"Open redirect", "medium", "tentative", true},
		{"Open redirect", "medium", "firm", true},
		{"Some finding", "medium", "info", false},    // medium at info-confidence: below tentative
		{"Frameable response", "low", "firm", false}, // Low is never swept under Standard
		{"Info disclosure", "info", "certain", false},
	}
	for _, tc := range cases {
		f := &Finding{Name: tc.name, Severity: tc.severity, Confidence: tc.confidence}
		if got := TriageEligible(f); got != tc.want {
			t.Errorf("TriageEligible(%q, %s/%s) = %v, want %v", tc.name, tc.severity, tc.confidence, got, tc.want)
		}
	}
}

func TestCollaboratorFindingsAreExcludedEntirely(t *testing.T) {
	// Burp's own exclusion: out-of-band findings carry an interaction id, not a transcript
	// — there is nothing for the model to read, at any severity.
	f := &Finding{Name: "External service interaction (HTTP Collaborator)", Severity: "high", Confidence: "certain"}
	if TriageEligible(f) {
		t.Fatal("a Collaborator finding was gated in — the model would be reading an interaction id and inventing a verdict")
	}
}

func TestTheVerdictParsesFromJSONAndVocabulary(t *testing.T) {
	// The prompt's asked shape
	note := parseTriageAnswer(`{"verdict":"real-risk","reasoning":"the reflected value lands unescaped in a text node"}`, "gpt-x")
	if note == nil || note.Verdict != TriageVerdictRealRisk {
		t.Fatalf("JSON answer = %+v, want real-risk", note)
	}
	if note.Model != "gpt-x" {
		t.Errorf("the note does not name the model that produced it: %+v", note.Model)
	}
	// Prose wrapping the vocabulary: still readable
	note = parseTriageAnswer("Based on the evidence, this looks like a FALSE-POSITIVE-LIKELY issue because the parameter is type-checked server-side.", "gpt-x")
	if note == nil || note.Verdict != TriageVerdictFalsePositiveLikely {
		t.Fatalf("vocabulary fallback = %+v, want false-positive-likely", note)
	}
	// A fenced JSON answer (the habit every model has)
	note = parseTriageAnswer("```json\n{\"verdict\":\"investigate-further\",\"reasoning\":\"the response is truncated\"}\n```", "gpt-x")
	if note == nil || note.Verdict != TriageVerdictInvestigateFurther {
		t.Fatalf("fenced JSON = %+v, want investigate-further", note)
	}
}

func TestAnOutOfVocabularyAnswerBecomesInvestigateFurtherWithTheRawWords(t *testing.T) {
	// The verdict that spends an operator's attention rather than guessing — and carries
	// what the model actually said, so a refusal or an off-topic answer is visible as
	// itself, never as an invented clean bill.
	answer := "I cannot assess this finding without more context."
	note := parseTriageAnswer(answer, "gpt-x")
	if note == nil {
		t.Fatal("an out-of-vocabulary answer produced no note at all")
	}
	if note.Verdict != TriageVerdictInvestigateFurther {
		t.Errorf("verdict = %q, want investigate-further — the safe direction", note.Verdict)
	}
	if !strings.Contains(note.Reasoning, answer) {
		t.Errorf("the note's reasoning %q drops the model's own words", note.Reasoning)
	}
}

func TestANoteNeverMovesTheFindingGrades(t *testing.T) {
	// THE honest-counting property: advice rides beside grades, never over them.
	f := &Finding{Name: "SQL injection", Severity: "high", Confidence: "tentative"}
	note := parseTriageAnswer(`{"verdict":"false-positive-likely","reasoning":"the error string is the framework's, not the database's"}`, "gpt-x")
	f.Triage = note
	if f.Severity != "high" || f.Confidence != "tentative" {
		t.Fatalf("attaching a triage note moved the finding's own grades: %s/%s — advice must never be promotion", f.Severity, f.Confidence)
	}
}

// triageStubEndpoint answers one canned chat completion, so TriageFinding is driven
// end-to-end without a real LLM.
func triageStubEndpoint(t *testing.T, answer string) (TriageEndpointConfig, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusBadRequest)
			return
		}
		var req struct {
			Model    string `json:"model"`
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if req.Model == "" || len(req.Messages) == 0 {
			http.Error(w, "model and messages are required", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": answer}},
			},
		})
	}))
	t.Cleanup(srv.Close)
	return TriageEndpointConfig{BaseURL: srv.URL, Model: "test-model", APIKey: "k"}, srv
}

func TestTriageFindingAttachesTheNoteEndToEnd(t *testing.T) {
	cfg, _ := triageStubEndpoint(t, `{"verdict":"real-risk","reasoning":"unescaped reflection in a text node"}`)
	f := &Finding{
		Name: "SQL injection", Severity: "high", Confidence: "tentative",
		URL: "/search?q=1", Evidence: "error signature", Solution: "parameterise",
	}
	note, err := TriageFinding(context.Background(), f, cfg)
	if err != nil {
		t.Fatalf("TriageFinding: %v", err)
	}
	if note.Verdict != TriageVerdictRealRisk {
		t.Fatalf("verdict = %q", note.Verdict)
	}
	if f.Triage == nil {
		t.Fatal("the note was not attached to the finding")
	}
	if f.Confidence != "tentative" || f.Severity != "high" {
		t.Fatal("the pass moved the finding's grades — advice must never be promotion")
	}
	if !note.InvestigatedAt.After(time.Time{}) {
		t.Error("the note carries no timestamp — a stale note is indistinguishable from a fresh one")
	}
}

func TestAnEndpointErrorLeavesNoNote(t *testing.T) {
	// A pass that did not happen must not leave a marker that looks like one.
	cfg, _ := triageStubEndpoint(t, "") // the stub still answers 200 with the empty content
	// drive a hard error instead: an unreachable base URL
	cfg.BaseURL = "http://127.0.0.1:1"
	f := &Finding{Name: "SQL injection", Severity: "high", Confidence: "tentative"}
	note, err := TriageFinding(context.Background(), f, cfg)
	if err == nil {
		t.Fatal("an unreachable endpoint answered")
	}
	if note != nil {
		t.Fatalf("an errored pass returned a note %+v — a triage that did not happen must not leave a marker", note)
	}
	if f.Triage != nil {
		t.Fatal("the errored pass attached a note to the finding")
	}
}

func TestOutsideTheGateIsRefusedWithTheReason(t *testing.T) {
	cfg, _ := triageStubEndpoint(t, `{"verdict":"real-risk","reasoning":"x"}`)
	f := &Finding{Name: "Frameable response", Severity: "low", Confidence: "firm"}
	_, err := TriageFinding(context.Background(), f, cfg)
	if err == nil {
		t.Fatal("a Low finding was swept — the Standard profile bounds the pass")
	}
	if !strings.Contains(err.Error(), "outside the Standard profile gate") {
		t.Errorf("refusal = %q, want it to name the gate", err)
	}
}
