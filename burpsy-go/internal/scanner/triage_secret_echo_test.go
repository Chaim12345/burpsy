package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Operator-facing triage errors must never carry remote content or the configured key:
// an endpoint can reflect the request's Authorization header into an error page or an
// answer, a redirect target's URL is attacker-influenced text in the outer url.Error,
// and an arbitrary transport error can carry request material. These probes pin the
// reviewer-required behaviour: the key value survives NO return path of TriageFinding.

type triageRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f triageRoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTriageErrorNeverEchoesKeyNon200(t *testing.T) {
	// Header-reflecting endpoint: bounces the request's Authorization header into its
	// 500 body. The returned error must carry the status and NOT the body, NOT the key.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "gateway error, your request said Authorization: %s", r.Header.Get("Authorization"))
	}))
	defer srv.Close()
	cfg := TriageEndpointConfig{BaseURL: srv.URL, Model: "fixture", APIKey: triageSecKey}
	_, err := TriageFinding(context.Background(), triageSecFinding(), cfg)
	if err == nil {
		t.Fatal("expected an error from a 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("status missing from error: %v", err)
	}
	if strings.Contains(err.Error(), triageSecKey) {
		t.Fatalf("KEY LEAK via non-200 body echo: %v", err)
	}
}

func TestTriageErrorNeverEchoesKeyUnparseable(t *testing.T) {
	// The endpoint embeds the key in a 200 answer that fails to parse as a verdict.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"choices":[{"message":{"content":"unrecognized answer, key was %s"}}]}`, triageSecKey)
	}))
	defer srv.Close()
	cfg := TriageEndpointConfig{BaseURL: srv.URL, Model: "fixture", APIKey: triageSecKey}
	f := triageSecFinding()
	note, err := TriageFinding(context.Background(), f, cfg)
	// Out-of-vocabulary answers become an investigate-further note carrying the model's
	// words - the note is the operator-facing surface that must not carry the key.
	if err != nil {
		if strings.Contains(err.Error(), triageSecKey) {
			t.Fatalf("KEY LEAK via unparseable answer echo: %v", err)
		}
		return
	}
	if note == nil || f.Triage == nil {
		t.Fatal("expected a note on the finding")
	}
	if strings.Contains(note.Reasoning, triageSecKey) || strings.Contains(f.Triage.Reasoning, triageSecKey) {
		t.Fatalf("KEY LEAK via note reasoning echo: %q", note.Reasoning)
	}
	if !strings.Contains(note.Reasoning, "[redacted-api-key]") {
		t.Fatalf("expected the redaction marker in the carried reasoning: %q", note.Reasoning)
	}
}

func TestTriageErrorNeverEchoesRedirectTarget(t *testing.T) {
	// The redirect target's URL is attacker text riding the outer url.Error. The final
	// error must carry the refusal reason without the destination's userinfo/host/path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://junkuser:junkpw@attacker.invalid/harvest?next=triage", http.StatusFound)
	}))
	defer srv.Close()
	cfg := TriageEndpointConfig{BaseURL: srv.URL, Model: "fixture", APIKey: triageSecKey}
	_, err := TriageFinding(context.Background(), triageSecFinding(), cfg)
	if err == nil {
		t.Fatal("expected the redirect refusal")
	}
	// Go strips Authorization on the cross-host redirect, so the guard lets the dial
	// happen and it fails (attacker.invalid does not resolve). The reviewer minimum:
	// no secrets and no credential-shaped destination text - userinfo, query junk, the
	// key. The unresolved host name in the dial error is diagnostic, not a secret.
	for _, junk := range []string{triageSecKey, "junkuser", "junkpw", "next=triage", "harvest"} {
		if strings.Contains(err.Error(), junk) {
			t.Fatalf("redirect-target text %q leaked into error: %v", junk, err)
		}
	}
}

func TestTriageErrorNeverEchoesKeyTransport(t *testing.T) {
	// Arbitrary transport error carrying request material: unwrapping shapes cannot
	// help here - only by-value scrubbing removes the key.
	cfg := TriageEndpointConfig{
		BaseURL: "http://127.0.0.1:1/v1", Model: "fixture", APIKey: triageSecKey,
		HTTPClient: &http.Client{Transport: triageRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed while sending Authorization: Bearer " + triageSecKey)
		})},
	}
	_, err := TriageFinding(context.Background(), triageSecFinding(), cfg)
	if err == nil {
		t.Fatal("expected the transport error")
	}
	if strings.Contains(err.Error(), triageSecKey) {
		t.Fatalf("KEY LEAK via transport error: %v", err)
	}
	if !strings.Contains(err.Error(), "[redacted-api-key]") || !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("expected the redacted reason to survive: %v", err)
	}
}

type triageFailBody struct{ n int }

func (b *triageFailBody) Read(p []byte) (int, error) {
	if b.n == 0 {
		b.n++
		return copy(p, `{"partial":`), nil
	}
	return 0, errors.New("stream reset while answering Authorization: Bearer " + triageSecKey)
}
func (b *triageFailBody) Close() error { return nil }

func TestTriageErrorNeverEchoesKeyBodyRead(t *testing.T) {
	// The body fails mid-read with an error carrying request material: the ReadAll
	// return path must pass through the same by-value net, not a bare err.
	cfg := TriageEndpointConfig{
		BaseURL: "http://127.0.0.1:1/v1", Model: "fixture", APIKey: triageSecKey,
		HTTPClient: &http.Client{Transport: triageRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Status: "200 OK", Body: &triageFailBody{}, Request: r}, nil
		})},
	}
	_, err := TriageFinding(context.Background(), triageSecFinding(), cfg)
	if err == nil {
		t.Fatal("expected the body-read error")
	}
	if strings.Contains(err.Error(), triageSecKey) {
		t.Fatalf("KEY LEAK via body-read error: %v", err)
	}
	if !strings.Contains(err.Error(), "reading the endpoint answer failed") {
		t.Fatalf("expected the read-failure reason: %v", err)
	}
}

func TestTriageScrubEmptyKeyHarmless(t *testing.T) {
	// Empty key: nothing to leak, errors pass through untouched.
	base := errors.New("plain failure")
	if got := scrubTriageSecret(base, ""); got != base {
		t.Fatalf("empty key changed the error: %v", got)
	}
	if got := scrubTriageSecret(nil, ""); got != nil {
		t.Fatalf("nil error changed: %v", got)
	}
}
