package scanner

// The LLM post-scan triage pass (burpsy-react-ui-ei0v) — Burp AI's shape: after a scan
// finishes, a second look at selected findings that "checks each issue to determine
// whether it represents a real and exploitable risk" and writes evidence + reasoning.
// It does not affect crawl or audit phases, and it NEVER promotes a finding past the
// evidence its checks earned.
//
// # What is deliberately NOT here
//
// No ML in the engine core — Burp has none, the statistical niche is covered by the
// sequencer's classical battery, and a nondeterministic verdict is at odds with honest
// counting. The triage verdict is ADVICE attached to the finding (TriageNote), never a
// move of Confidence or Severity.
//
// # The gate (Burp's Standard profile)
//
// High at any confidence, plus Medium at tentative or better. Low findings are left alone
// under Standard (an operator can still triage one finding directly). Collaborator /
// out-of-band findings are excluded: their evidence is an interaction id, and there is no
// request transcript for the model to read.
//
// # The dial
//
// One OpenAI-compatible chat completion call per finding, with the finding's own fields
// (name, severity, confidence, evidence, the request/response excerpt) rendered into a
// prompt that asks for a verdict and reasoning. The response is parsed into one of three
// verdicts; anything the model answers outside the vocabulary — or refuses, or errors — is
// investigate-further, the verdict that spends an operator's attention rather than
// guessing. A refusal note is carried as reasoning, so an operator sees what happened.
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TriageEndpointConfig is what the pass dials: the operator-supplied endpoint, per the
// recorded decision on the bead. No default, no compiled-in fallback.
type TriageEndpointConfig struct {
	BaseURL string
	Model   string
	APIKey  string
	// HTTPClient is optional; nil uses a client with a hard 60s timeout — one finding's
	// second look must not hang a scan session.
	HTTPClient *http.Client
}

// TriageEligible reports whether one finding is in the Standard-profile gate: High at any
// confidence, or Medium at tentative-or-better. Collaborator findings are refused by name
// (out-of-band: no transcript to read).
func TriageEligible(f *Finding) bool {
	if f == nil {
		return false
	}
	if strings.Contains(strings.ToLower(f.Name), "collaborator") {
		return false
	}
	switch f.Severity {
	case "high", "critical":
		return true
	case "medium":
		return f.Confidence == "tentative" || f.Confidence == "firm" || f.Confidence == "certain"
	}
	return false
}

// triagePrompt renders one finding into the second-look prompt. The model sees exactly
// what the operator sees; nothing about other findings, the target's name beyond the row,
// or burpsy's internals.
func triagePrompt(f *Finding) string {
	var b strings.Builder
	b.WriteString("You are reviewing a web application security scanner finding to decide whether it represents a real and exploitable risk.\n\n")
	fmt.Fprintf(&b, "Issue name: %s\n", f.Name)
	fmt.Fprintf(&b, "Severity (as assessed by the scanner): %s\n", f.Severity)
	fmt.Fprintf(&b, "Confidence (as assessed by the scanner): %s\n", f.Confidence)
	if f.URL != "" {
		fmt.Fprintf(&b, "URL: %s\n", f.URL)
	}
	if f.Method != "" {
		fmt.Fprintf(&b, "Method: %s\n", f.Method)
	}
	if f.Param != "" {
		fmt.Fprintf(&b, "Parameter: %s\n", f.Param)
	}
	fmt.Fprintf(&b, "\nEvidence the scanner recorded:\n%s\n", f.Evidence)
	fmt.Fprintf(&b, "\nRemediation the scanner suggests:\n%s\n", f.Solution)
	b.WriteString("\nAnswer in exactly this JSON shape, with no other text:\n")
	b.WriteString(`{"verdict":"real-risk"|"investigate-further"|"false-positive-likely","reasoning":"one or two sentences of concrete reasoning grounded in the evidence"}`)
	return b.String()
}

// TriageFinding runs the second look on one finding. The note is attached and returned;
// the finding's own grades are never touched. An error is returned to the caller (who
// counts it) AND leaves the finding without a note — a triage that did not happen must
// not leave a marker that looks like one.
func TriageFinding(ctx context.Context, f *Finding, cfg TriageEndpointConfig) (*TriageNote, error) {
	if f == nil {
		return nil, fmt.Errorf("triage: no finding")
	}
	if !TriageEligible(f) {
		return nil, fmt.Errorf("triage: %q (severity %s, confidence %s) is outside the Standard profile gate", f.Name, f.Severity, f.Confidence)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	body, err := json.Marshal(map[string]any{
		"model":    cfg.Model,
		"messages": []map[string]string{{"role": "user", "content": triagePrompt(f)}},
		// temperature 0 for reproducibility; the verdict is advice but not a coin flip.
		"temperature": 0,
	})
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("triage endpoint answered %d: %.200s", res.StatusCode, string(raw))
	}
	var completion struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &completion); err != nil {
		return nil, fmt.Errorf("triage: decode completion: %w", err)
	}
	if len(completion.Choices) == 0 {
		return nil, fmt.Errorf("triage: the endpoint returned no choices")
	}
	note := parseTriageAnswer(completion.Choices[0].Message.Content, cfg.Model)
	if note == nil {
		return nil, fmt.Errorf("triage: unparseable answer: %.200s", completion.Choices[0].Message.Content)
	}
	f.Triage = note
	return note, nil
}

// parseTriageAnswer reads the model's answer into a note. Anything outside the verdict
// vocabulary becomes investigate-further with the raw answer carried as reasoning — the
// verdict that spends an operator's attention rather than guessing, with the evidence of
// what the model actually said.
func parseTriageAnswer(content, model string) *TriageNote {
	content = strings.TrimSpace(content)
	// The prompt asks for JSON; accept a fenced or bare object, and fall back to scanning
	// for the vocabulary if the model wrapped the object in prose.
	verdict := ""
	reasoning := ""
	if i := strings.Index(content, "{"); i >= 0 {
		if j := strings.LastIndex(content, "}"); j > i {
			var out struct {
				Verdict   string `json:"verdict"`
				Reasoning string `json:"reasoning"`
			}
			if err := json.Unmarshal([]byte(content[i:j+1]), &out); err == nil && out.Verdict != "" {
				verdict, reasoning = out.Verdict, out.Reasoning
			}
		}
	}
	if verdict == "" {
		lower := strings.ToLower(content)
		for _, v := range []struct{ needle, name string }{
			{"false-positive-likely", TriageVerdictFalsePositiveLikely},
			{"false positive", TriageVerdictFalsePositiveLikely},
			{"real-risk", TriageVerdictRealRisk},
			{"real risk", TriageVerdictRealRisk},
			{"exploitable", TriageVerdictRealRisk},
			{"investigate", TriageVerdictInvestigateFurther},
		} {
			if strings.Contains(lower, v.needle) {
				verdict = v.name
				break
			}
		}
		if reasoning == "" {
			reasoning = content
		}
	}
	switch verdict {
	case TriageVerdictRealRisk, TriageVerdictFalsePositiveLikely, TriageVerdictInvestigateFurther:
	default:
		// An out-of-vocabulary or refused answer: investigate-further, the model's own
		// words carried so the operator sees what happened rather than an invented verdict.
		verdict = TriageVerdictInvestigateFurther
		if reasoning == "" {
			reasoning = content
		}
	}
	if reasoning == "" {
		reasoning = content
	}
	return &TriageNote{
		Verdict:        verdict,
		Reasoning:      reasoning,
		Model:          model,
		InvestigatedAt: time.Now(),
	}
}
