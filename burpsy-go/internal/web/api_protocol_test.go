package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// programBody is a decidable frame program addressing one path, in the shape the endpoint accepts.
func programBody(host string, port uint16, path string, lie bool) []byte {
	enc := http2.NewEncoder(4096)
	block := enc.Encode([]http2.HeaderField{
		http2.NewHeaderField(":method", "GET"),
		http2.NewHeaderField(":scheme", "https"),
		http2.NewHeaderField(":authority", host),
		http2.NewHeaderField(":path", path),
	})
	headers := map[string]any{
		"type":           http2.TypeHeaders,
		"flags":          http2.FlagEndHeaders | http2.FlagEndStream,
		"stream":         1,
		"payload_base64": base64.StdEncoding.EncodeToString(block),
	}
	if lie {
		headers["declared_len"] = len(block) - 3
	}
	body, _ := json.Marshal(map[string]any{
		"host":        host,
		"port":        port,
		"tls":         true,
		"preface":     true,
		"read_for_ms": 50,
		"frames": []map[string]any{
			{"type": http2.TypeSettings, "flags": 0, "stream": 0},
			headers,
		},
	})
	return body
}

func TestProtocolsEndpointReportsEveryDowngradeReason(t *testing.T) {
	s := NewServer(core.NewTrafficStore(), core.NewScope())
	cfg := sender.DefaultSenderConfig()
	cfg.TLSVerify = false
	s.WithSender(sender.NewSender(cfg))

	rec := httptest.NewRecorder()
	s.handleProtocols(rec, httptest.NewRequest(http.MethodGet, "/api/protocols", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body struct {
		Enabled     bool `json:"enabled"`
		SentAsHTTP2 int  `json:"sent_as_http2"`
		SentAsHTTP1 int  `json:"sent_as_http1"`
		Downgrades  []struct {
			Reason string `json:"reason"`
			Count  int    `json:"count"`
		} `json:"downgrades"`
		Rewrites []struct {
			Rewrite string `json:"rewrite"`
		} `json:"rewrites"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Enabled {
		t.Fatal("a wired sender must report as enabled")
	}
	// Every reason is present with a zero count, so a pane can render the whole vocabulary rather than only
	// the reasons that happen to have fired.
	if len(body.Downgrades) != len(sender.DowngradeReasonAll) {
		t.Fatalf("want %d reasons, got %d", len(sender.DowngradeReasonAll), len(body.Downgrades))
	}
	if len(body.Rewrites) != len(sender.RewriteKindAll) {
		t.Fatalf("want %d rewrite kinds, got %d", len(sender.RewriteKindAll), len(body.Rewrites))
	}
	for _, d := range body.Downgrades {
		if d.Reason == "" {
			t.Fatal("a reason with no text cannot be read by anyone")
		}
	}
}

// NewServer builds a sender of its own, so the only way here is a caller that explicitly cleared it —
// which api_session.go's handlers guard against too. Tested rather than assumed unreachable: a handler
// that would nil-panic on an operator's process is worse than one that says what is missing.
func TestProtocolsEndpointSaysSoWhenNoSenderIsWired(t *testing.T) {
	s := NewServer(core.NewTrafficStore(), core.NewScope())
	s.WithSender(nil)
	rec := httptest.NewRecorder()
	s.handleProtocols(rec, httptest.NewRequest(http.MethodGet, "/api/protocols", nil))
	if !strings.Contains(rec.Body.String(), "no sender is wired") {
		t.Fatalf("want the absence explained, got %s", rec.Body.String())
	}
}

// H2-03 through the API: an undecidable program is refused with the construct named, and nothing is sent.
func TestTheFrameProgramEndpointRefusesAnUndecidableProgramByName(t *testing.T) {
	store := core.NewTrafficStore()
	s := NewServer(store, core.NewScopeAllowEverything())
	cfg := sender.DefaultSenderConfig()
	cfg.TLSVerify = false
	s.WithSender(sender.NewSender(cfg))

	// A port nothing listens on: if the classifier let this through, the failure would be a dial error and
	// the status would be 502 rather than 403.
	body := programBody("127.0.0.1", 1, "/allowed", true)
	rec := httptest.NewRecorder()
	s.handleHTTP2Program(rec, httptest.NewRequest(http.MethodPost, "/api/http2/program", bytes.NewReader(body)))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 for a refusal, got %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Verdict  string   `json:"verdict"`
		Refusals []string `json:"refusals"`
		Sent     struct {
			Octets int `json:"octets"`
		} `json:"sent"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Verdict != "not authorisable" {
		t.Fatalf("verdict %q", got.Verdict)
	}
	if len(got.Refusals) != 1 || !strings.Contains(got.Refusals[0], "declares") {
		t.Fatalf("want the construct named, got %v", got.Refusals)
	}
	if !strings.Contains(got.Refusals[0], "frames by the declared length") {
		t.Fatalf("want the undecidability explained, got %v", got.Refusals)
	}
	if got.Sent.Octets != 0 {
		t.Fatalf("a refused program must write nothing, got %d octets", got.Sent.Octets)
	}
	if len(store.Exchanges()) != 0 {
		t.Fatalf("a refused program must not be captured, got %d exchanges", len(store.Exchanges()))
	}
}

// An out-of-scope program is refused by the same gate every other send passes.
func TestTheFrameProgramEndpointRefusesAnOutOfScopePath(t *testing.T) {
	scope := core.NewScope()
	scope.Add(core.NewScopeRuleWithPath(core.ScopeInclude, "127.0.0.1", "/allowed"))
	s := NewServer(core.NewTrafficStore(), scope)
	cfg := sender.DefaultSenderConfig()
	cfg.TLSVerify = false
	s.WithSender(sender.NewSender(cfg))

	rec := httptest.NewRecorder()
	s.handleHTTP2Program(rec, httptest.NewRequest(http.MethodPost, "/api/http2/program",
		bytes.NewReader(programBody("127.0.0.1", 1, "/secret", false))))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "refused") {
		t.Fatalf("want a refusal, got %s", rec.Body.String())
	}
}

// The named bounds refuse rather than truncate: a truncated frame program is a different program.
func TestTheFrameProgramEndpointRefusesAnOversizedProgramByName(t *testing.T) {
	s := NewServer(core.NewTrafficStore(), core.NewScopeAllowEverything())
	s.WithSender(sender.NewSender(sender.DefaultSenderConfig()))

	frames := make([]map[string]any, 0, maxProgramFrames+1)
	for i := 0; i <= maxProgramFrames; i++ {
		frames = append(frames, map[string]any{"type": http2.TypePing, "stream": 0})
	}
	body, _ := json.Marshal(map[string]any{
		"host": "127.0.0.1", "port": 1, "tls": true, "preface": true, "frames": frames,
	})
	rec := httptest.NewRecorder()
	s.handleHTTP2Program(rec, httptest.NewRequest(http.MethodPost, "/api/http2/program", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "may carry 512 frames") {
		t.Fatalf("want the bound named, got %s", rec.Body.String())
	}
}

func TestTheFrameProgramEndpointNeedsAnAuthorityToAuthoriseAgainst(t *testing.T) {
	s := NewServer(core.NewTrafficStore(), core.NewScopeAllowEverything())
	s.WithSender(sender.NewSender(sender.DefaultSenderConfig()))
	rec := httptest.NewRecorder()
	s.handleHTTP2Program(rec, httptest.NewRequest(http.MethodPost, "/api/http2/program",
		bytes.NewReader([]byte(`{"frames":[]}`))))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "needs a host and a port") {
		t.Fatalf("want the reason named, got %s", rec.Body.String())
	}
}
