package dominvader

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/domexec"
)

const ProbeLimitations = "workers/OOPIF not exercised; popups blocked; fetch/XHR/WebSocket/WebTransport network blocked, sink arguments observed only; JSON limited to document-parsed data, not AJAX; finite property vocabulary and wrapped sinks only; no gadget observation is not proof of safety; fresh isolated context does not inherit operator login"

type ScanResult struct {
	Hits        []*Hit   `json:"hits"`
	Blocked     []string `json:"blocked"`
	Limitations string   `json:"limitations"`
	Probes      int      `json:"probes"`
	Errors      []string `json:"errors"`
}

type probeSpec struct {
	Marker    string `json:"marker"`
	Proof     string `json:"proof"`
	Property  string `json:"property"`
	Technique string `json:"technique"`
	Nested    bool   `json:"nested"`
}

// Scan uses the crawl renderer's isolated, gated Session rather than the
// operator browser's pass-through proxy. Each technique/property gets a fresh
// context and RANDOM proof marker. The gate must check current scope, including
// same-origin, on every request. No source is manufactured by this runner.
func Scan(ctx context.Context, b *domexec.Browser, p PollutionConfig, gate domexec.ScopeGate) (ScanResult, error) {
	out := ScanResult{Hits: []*Hit{}, Blocked: []string{}, Errors: []string{}, Limitations: ProbeLimitations}
	if err := p.Validate(); err != nil {
		return out, err
	}
	if !p.Enabled {
		return out, fmt.Errorf("pollution scan is off")
	}
	if gate == nil {
		return out, fmt.Errorf("pollution scan requires a scope gate")
	}
	u, _ := url.Parse(p.Target)
	if err := gate.AllowURL(u); err != nil {
		return out, err
	}
	techniques := []string{}
	if p.Query {
		techniques = append(techniques, "query-bracket", "query-dot")
	}
	if p.Hash {
		techniques = append(techniques, "hash-bracket", "hash-dot")
	}
	if p.JSON {
		techniques = append(techniques, "json")
	}
	if p.Nested {
		if p.Query {
			techniques = append(techniques, "query-constructor")
		}
		if p.Hash {
			techniques = append(techniques, "hash-constructor")
		}
	}
	script, err := extensionFS.ReadFile("extension/pollution.js")
	if err != nil {
		return out, err
	}
	for _, property := range p.Properties {
		for _, technique := range techniques {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			var random [16]byte
			if _, err := rand.Read(random[:]); err != nil {
				return out, fmt.Errorf("cannot create fresh probe marker: %w", err)
			}
			marker := "burpsyDI" + hex.EncodeToString(random[:])
			spec := probeSpec{Marker: marker, Proof: "__burpsyProof" + marker, Property: property, Technique: technique, Nested: p.Nested}
			target := probeURL(p.Target, spec)
			blob, _ := json.Marshal(spec)
			preload := `window.__burpsyDI_probe=` + string(blob) + `;window.__burpsyDI_probeHits=[];document.addEventListener('__burpsyDI_hit',function(e){window.__burpsyDI_probeHits.push(JSON.parse(e.detail));},true);` + string(script)
			sess, err := b.NewSession(gate)
			if err != nil {
				return out, err
			}
			probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			raw, err := sess.Probe(probeCtx, target, preload, `(window.__burpsyDI_checkPollution ? (window.__burpsyDI_checkPollution(),JSON.stringify(window.__burpsyDI_probeHits)) : "probe instrumentation unavailable")`)
			cancel()
			out.Blocked = append(out.Blocked, sess.RenderBlocked()...)
			sess.Close()
			out.Probes++
			if err != nil {
				out.Errors = append(out.Errors, technique+"/"+property+": "+err.Error())
				continue
			}
			var hits []*Hit
			if err := json.Unmarshal([]byte(raw), &hits); err != nil {
				out.Errors = append(out.Errors, technique+": cannot collect probe evidence")
				continue
			}
			for _, h := range hits {
				h.Limitations = ProbeLimitations
				out.Hits = append(out.Hits, h)
			}
		}
	}
	return out, nil
}

func probeURL(raw string, p probeSpec) string {
	if p.Technique == "json" {
		return raw
	}
	u, _ := url.Parse(raw)
	values := url.Values{}
	for _, prop := range []string{p.Proof, p.Property} {
		key := "__proto__[" + prop + "]"
		if strings.HasSuffix(p.Technique, "-dot") {
			key = "__proto__." + prop
		}
		if strings.HasSuffix(p.Technique, "-constructor") {
			key = "constructor[prototype][" + prop + "]"
		}
		values.Set(key, p.Marker)
	}
	if strings.HasPrefix(p.Technique, "query-") {
		q := u.Query()
		for k, v := range values {
			q[k] = v
		}
		u.RawQuery = q.Encode()
	} else {
		u.Fragment = values.Encode()
	}
	return u.String()
}
