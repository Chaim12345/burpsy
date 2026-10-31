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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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

// CheckTriageEndpointURL is the engine's own policy for where the configured API key may go:
// https anywhere, or http only to loopback (127.0.0.0/8, ::1, localhost exactly - no other
// aliases). The key travels as a bearer token, so a remote cleartext URL would expose it on
// the wire. userinfo/query/fragment forms are rejected without echoing their values: the
// engine appends /chat/completions to the configured value verbatim, so credentials or
// parameters hidden in the URL would ride every call unreviewed.
func CheckTriageEndpointURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("triage: the base URL is not a full URL (scheme and host are required)")
	}
	if u.User != nil {
		return fmt.Errorf("triage: base URLs with embedded credentials are not accepted - configure the key in the API key field")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("triage: base URLs with a query string or fragment are not accepted")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		h := u.Hostname()
		if ip := net.ParseIP(h); h == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
		return fmt.Errorf("triage: the base URL must be https for a remote endpoint - http would send the API key in cleartext (loopback http is allowed for local endpoints)")
	}
	return fmt.Errorf("triage: the base URL scheme must be https (or http to loopback)")
}

// triagePort normalizes the port for an origin comparison: an explicit port wins, otherwise
// the scheme's default. Same host on a DIFFERENT port is a different endpoint.
func triagePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// withCredentialRedirectGuard clones the client (transport, timeout, jar preserved) and
// composes its CheckRedirect with the credential rule: a redirect that would carry the
// Authorization header to a changed origin - scheme, hostname, OR port - fails the call
// instead of following. Hard error, not strip-and-follow: silently continuing unauthenticated
// to a changed destination still runs the reviewed call against an endpoint the operator never
// reviewed. Go's default policy keeps the header on subdomains and on an https->http same-host
// downgrade (pinned in triage_redirect_test.go); this guard refuses both. The 10-redirect cap
// the default policy had is kept when the caller supplied no policy of its own.
func withCredentialRedirectGuard(c *http.Client) *http.Client {
	out := *c
	prev := c.CheckRedirect
	out.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if prev != nil {
			if err := prev(req, via); err != nil {
				return err
			}
		} else if len(via) >= 10 {
			return fmt.Errorf("triage: stopped after 10 redirects")
		}
		if len(via) == 0 || req.Header.Get("Authorization") == "" {
			return nil
		}
		last := via[len(via)-1].URL
		if req.URL.Scheme != last.Scheme || req.URL.Hostname() != last.Hostname() || triagePort(req.URL) != triagePort(last) {
			return fmt.Errorf("triage: redirect would carry the API key to a changed origin (scheme/host/port) - refused")
		}
		return nil
	}
	return &out
}

// scrubTriageSecret is the final net on every operator-facing error the pass returns:
// the configured key is replaced BY VALUE, whatever an endpoint, a redirect target or a
// transport put into the underlying text. Unwrapping or static messages alone cannot
// guarantee this - an arbitrary RoundTripper or TLS error can carry request material.
// An empty key changes nothing (there is nothing to leak).
func scrubTriageSecret(err error, apiKey string) error {
	if err == nil || apiKey == "" {
		return err
	}
	s := err.Error()
	if !strings.Contains(s, apiKey) {
		return err
	}
	return errors.New(strings.ReplaceAll(s, apiKey, "[redacted-api-key]"))
}

// scrubTriageText is the same by-value net for operator-facing text that is not an
// error: the triage note carries the model's own words verbatim, and those words can
// reflect the request's credentials back.
func scrubTriageText(s, apiKey string) string {
	if apiKey == "" {
		return s
	}
	return strings.ReplaceAll(s, apiKey, "[redacted-api-key]")
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
	// Revalidate at dispatch, not only where the config is loaded: a stored config written
	// before the policy existed, or by a caller that skipped it, gets the same refusal here.
	if err := CheckTriageEndpointURL(cfg.BaseURL); err != nil {
		return nil, err
	}
	base := cfg.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: 60 * time.Second}
	}
	// The guard wraps the caller's client too (clone + composed CheckRedirect): the injection
	// seam is for transports in tests, not a credential-security exemption.
	client := withCredentialRedirectGuard(base)
	body, err := json.Marshal(map[string]any{
		"model":    cfg.Model,
		"messages": []map[string]string{{"role": "user", "content": triagePrompt(f)}},
		// temperature 0 for reproducibility; the verdict is advice but not a coin flip.
		"temperature": 0,
	})
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	res, err := client.Do(req)
	if err != nil {
		// Drop the outer url.Error: its text embeds the request/redirect-target URL, which is
		// attacker-influenced text on a redirect refusal. The inner error carries the reason.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, scrubTriageSecret(fmt.Errorf("triage: the endpoint request failed: %w", err), cfg.APIKey)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		// A failing body reader can carry request material in its error - same net.
		return nil, scrubTriageSecret(fmt.Errorf("triage: reading the endpoint answer failed: %w", err), cfg.APIKey)
	}
	if res.StatusCode != http.StatusOK {
		// No response-body bytes: an endpoint can reflect the request's Authorization header
		// into its error page, and remote content is never operator-facing here.
		return nil, scrubTriageSecret(fmt.Errorf("triage endpoint answered %d (the response body is not echoed - it can reflect request credentials)", res.StatusCode), cfg.APIKey)
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
		return nil, scrubTriageSecret(fmt.Errorf("triage: unparseable answer (the answer text is not echoed - it can reflect request credentials)"), cfg.APIKey)
	}
	// The note carries the model's words verbatim to the operator; an endpoint that
	// reflects the request's Authorization header into its answer must not see them
	// land on the finding.
	note.Reasoning = scrubTriageText(note.Reasoning, cfg.APIKey)
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
