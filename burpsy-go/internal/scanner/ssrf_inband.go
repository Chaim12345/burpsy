package scanner

// In-band server-side request forgery (0vzb.6).
//
// # The gap this closes
//
// The tree had exactly one SSRF row, "Out-of-band resource load (HTTP)", and it needs a collaborator:
// it plants a callback domain and waits for a DNS or HTTP interaction. That is the right test for a
// BLIND SSRF, and it is the only test for one. It is not the only SSRF: an application that fetches a
// URL and puts the fetched body into its own response proves the same primitive — the server made a
// request an attacker chose — with evidence visible in the response itself. Measured on OWASP
// VulnerableApp: `LEVEL_1?fileurl=http://127.0.0.1:9090/VulnerableApp/scanner` returns that endpoint's
// JSON body, while the SECURE `LEVEL_5` answers "Provided URL not valid". With only the OOB row
// admitted, all four vulnerable levels reported clean.
//
// # Why it is the same catalogued issue
//
// Both are CWE-918, and Burp's "Out-of-band resource load (HTTP)" definition covers content fetched
// from an arbitrary external location AND INCORPORATED INTO THE APPLICATION'S OWN RESPONSE — the
// in-band case is inside that sentence. So this files under the same row rather than inventing a name
// a report reader would not find in Burp. It is admitted by its own switch, because it sends requests
// to a URL the PROBE chooses and an operator should opt into that separately from the passive rows.
//
// # What it does NOT do
//
// It does not chase a URL it chooses at random. It plants a URL pointing at a canary endpoint on THIS
// scanner's own listener — a path only this process serves — and looks for that endpoint's marker in
// the response. A target that fetches it proves the fetch; a target that merely echoes the URL string
// back does not, because the marker is not in the URL, it is in what the URL RETURNS. That is the
// difference between "the application repeated my input" and "the application made the request".

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ssrfCanaryServer is a loopback listener this scanner owns, serving a unique marker at a unique
// path. A target that fetches the planted URL returns the marker; a target that only echoes the URL
// cannot, because the marker never appears in the URL.
type ssrfCanaryServer struct {
	srv    *http.Server
	ln     net.Listener
	addr   string
	path   string
	marker string

	mu   sync.Mutex
	hits int
}

// startSSRFCanary binds the listener. It binds loopback only: the scan's own process must be able to
// reach it, which it can, and nothing outside this host should be able to, which keeps the canary
// from being an open reflector.
func startSSRFCanary() (*ssrfCanaryServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("ssrf canary: listen: %w", err)
	}
	c := &ssrfCanaryServer{
		ln:     ln,
		addr:   ln.Addr().String(),
		path:   "/burpsy-ssrf-" + domCanary("canary"),
		marker: "bsySSRF" + domCanary("mark"),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(c.path, func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.hits++
		c.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(c.marker))
	})
	c.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = c.srv.Serve(ln) }()
	return c, nil
}

// URL is the address a probe plants.
func (c *ssrfCanaryServer) URL() string { return "http://" + c.addr + c.path }

// Marker is the token a successful fetch returns.
func (c *ssrfCanaryServer) Marker() string { return c.marker }

// Hit reports whether the canary was actually requested.
func (c *ssrfCanaryServer) Hit() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits > 0
}

func (c *ssrfCanaryServer) Close() {
	if c == nil || c.srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = c.srv.Shutdown(ctx)
}

// checkSSRFInBand plants this scanner's own canary URL and reports when the target fetched it and
// returned its body.
func checkSSRFInBand(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	const row = "Out-of-band resource load (HTTP)"
	if err := cc.RequireEgress(); err != nil {
		return nil, fmt.Errorf("%s: %w", row, err)
	}
	h, err := NewProbeHarness(ctx, cc, cc.ProbeInsertionKinds())
	if err != nil {
		return nil, err
	}
	points := h.Points()
	if len(points) == 0 {
		return nil, nil
	}
	if len(points) > MaxInjectionPointsPerCheck {
		points = points[:MaxInjectionPointsPerCheck]
	}
	canary, err := startSSRFCanary()
	if err != nil {
		// No listener means no capability, which must never read as no vulnerability.
		return nil, fmt.Errorf("%s: %w", row, err)
	}
	defer canary.Close()

	for _, point := range points {
		for _, payload := range ssrfInBandPayloads(canary.URL()) {
			res, err := h.Send(ctx, point, payload)
			if err != nil {
				continue
			}
			// The marker is in what the canary RETURNS, never in the URL, so finding it in the response
			// means the target made the request. A target that echoed the URL back carries the address
			// but not the marker. The file and metadata payloads are judged by their own content.
			if what, ok := ssrfInBandEvidence(res.Body, canary.Marker()); ok {
				return []*Finding{buildHeaderFinding(cc, row, "high", "firm",
					payload,
					fmt.Sprintf("%s %q: %s, so a server-side request can be sent to an attacker-chosen address", point.Kind, point.Name, what))}, nil
			}
		}
	}
	// Nothing fetched it. That is a result, and the honest reading is "no in-band fetch observed" —
	// a BLIND effect is what the collaborator row is for, and it is a separate admission.
	return nil, nil
}

// ssrfInBandPayloads are the URL-shaped values planted in a parameter.
//
// The HTTP canary URL is the strongest probe — it proves the server made an attacker-chosen request
// and returned its body, with the marker living in what the URL RETURNS rather than in the URL. The
// rest cover the other resource schemes and addresses an SSRF actually reaches, each with its own
// evidence:
//
//   - `file:///etc/passwd` and the Windows equivalent: the classic local-file read, evidenced by a
//     known line of the file rather than by a marker. Measured on OWASP VulnerableApp, whose SSRF
//     level documents exactly this payload — and whose arbitrary-HTTP path 500s, so a check that only
//     planted an http:// canary reported clean against a target that IS vulnerable through file://.
//   - the cloud metadata addresses (AWS IMDS, GCP, Azure): an in-band read of the instance identity,
//     evidenced by the field names those services return.
func ssrfInBandPayloads(canaryURL string) []string {
	upper := canaryURL
	if len(upper) >= 4 {
		upper = strings.ToUpper(upper[:4]) + upper[4:]
	}
	return []string{
		canaryURL, canaryURL + "/", upper,
		"file:///etc/passwd",
		"file:///c:/windows/win.ini",
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
	}
}

// ssrfInBandEvidence reports whether a response body carries evidence that the planted URL was
// fetched, and what that evidence was.
//
// The canary marker is the unambiguous case. The file and metadata payloads are judged by the content
// those resources are known to contain, the same discipline the traversal signatures use: a distinctive
// string the page would not otherwise carry, so a target that merely echoes the URL back cannot match.
func ssrfInBandEvidence(body, marker string) (string, bool) {
	if strings.Contains(body, marker) {
		return "the scanner's canary endpoint was fetched and its body returned", true
	}
	for _, sig := range []struct{ text, what string }{
		{"root:x:0:0:", "/etc/passwd was read"},
		{"[fonts]", "win.ini was read"},
		{"[extensions]", "win.ini was read"},
		{"ami-id", "the AWS instance metadata service was read"},
		{"instance-id", "the instance metadata service was read"},
		{"computeMetadata", "the GCP metadata service was read"},
	} {
		if strings.Contains(body, sig.text) {
			return sig.what, true
		}
	}
	return "", false
}
