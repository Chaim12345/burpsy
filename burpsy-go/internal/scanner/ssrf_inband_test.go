package scanner

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

const ssrfRow = "Out-of-band resource load (HTTP)"

// ssrfTarget serves /fetch?url=… with the given handler for the url value.
func ssrfTarget(t *testing.T, answer func(u string) string) (string, uint16) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, answer(r.URL.Query().Get("url")))
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	return host, uint16(port)
}

// auditSSRFInBandOnly audits /fetch?url=seed with ONLY the in-band SSRF switch (and its family
// switch) on — CheckOutOfBand is off, so no collaborator is involved.
func auditSSRFInBandOnly(t *testing.T, host string, port uint16) []*Finding {
	t.Helper()
	return auditSSRFInBandPath(t, host, port, "/fetch?url=seed")
}

// auditSSRFInBandPath is auditSSRFInBandOnly for an arbitrary seeded path.
func auditSSRFInBandPath(t *testing.T, host string, port uint16, path string) []*Finding {
	t.Helper()
	store := core.NewTrafficStore()
	id := seedAuditExchange(t, store, host, port, path, "nothing fetched")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: 30 * time.Second,
			CheckExtendedActive: true, CheckSSRFInBand: true})
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, DefaultAuditConfig())
	return findings
}

// TestInBandSSRFRunsWithoutTheOutOfBandSwitch pins that CheckSSRFInBand admits the row on its own. The
// row used to be gated on CheckOutOfBand, so turning only the in-band switch on ran nothing and an
// application that fetches and returns an attacker-chosen URL reported clean.
func TestInBandSSRFRunsWithoutTheOutOfBandSwitch(t *testing.T) {
	host, port := ssrfTarget(t, func(u string) string {
		// Fetch only this host's loopback, which is where the canary lives; nothing else is reached.
		if !strings.HasPrefix(strings.ToLower(u), "http://127.0.0.1:") {
			return "nothing fetched"
		}
		resp, err := http.Get(u)
		if err != nil {
			return "fetch failed"
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "fetched: " + string(b)
	})
	if !hasFinding(auditSSRFInBandOnly(t, host, port), ssrfRow) {
		t.Fatal("a target that fetched the canary and returned its body was not reported with only the in-band switch on")
	}
}

// TestInBandSSRFDoesNotFireOnAnEcho is the negative control for the echo false positive: a target that
// repeats the URL it was given, and fetches nothing, must not be reported. The GCP payload's URL
// contains "computeMetadata", which used to be accepted as evidence of a metadata read.
func TestInBandSSRFDoesNotFireOnAnEcho(t *testing.T) {
	host, port := ssrfTarget(t, func(u string) string { return "you asked for " + u })
	if hasFinding(auditSSRFInBandOnly(t, host, port), ssrfRow) {
		t.Fatal("an application that only echoed the planted URL was reported as fetching it")
	}
}

// TestInBandSSRFEvidenceRules pins the evidence rules on their own: a signature that is part of the
// payload, or already in the baseline, is not evidence.
func TestInBandSSRFEvidenceRules(t *testing.T) {
	listing := "ami-id\nami-launch-index\nami-manifest-path\ninstance-id\ninstance-type\n"
	const imds = "http://169.254.169.254/latest/meta-data/"
	if _, ok := ssrfInBandEvidence(listing, "", imds, "mk"); !ok {
		t.Error("an IMDS listing was not accepted")
	}
	if _, ok := ssrfInBandEvidence(listing, listing, imds, "mk"); ok {
		t.Error("an IMDS listing already in the baseline was accepted")
	}
	if _, ok := ssrfInBandEvidence("echo: "+imds+"instance-id", "", imds+"instance-id", "mk"); ok {
		t.Error("an echoed URL naming instance-id was accepted")
	}
	gcp := "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true"
	if _, ok := ssrfInBandEvidence("echo: "+gcp, "", gcp, "mk"); ok {
		t.Error("an echoed GCP metadata URL was accepted")
	}
	if _, ok := ssrfInBandEvidence(`{"machineType":"projects/1/machineTypes/e2"}`, "", gcp, "mk"); !ok {
		t.Error("a GCP instance document was not accepted")
	}
	if _, ok := ssrfInBandEvidence("[fonts]\r\n[extensions]\r\n", "[fonts]\r\n[extensions]\r\n", "file:///c:/windows/win.ini", "mk"); ok {
		t.Error("win.ini sections already in the baseline were accepted")
	}
}

// ssrfVulnappTarget serves the vulnapp fixtures in-process and returns where.
func ssrfVulnappTarget(t *testing.T) (string, uint16) {
	t.Helper()
	srv := httptest.NewServer(vulnapp.Handler())
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	return host, uint16(port)
}

// ssrfFindingFor returns the SSRF row's finding, or nil.
func ssrfFindingFor(fs []*Finding) *Finding {
	for _, f := range fs {
		if f.Name == ssrfRow {
			return f
		}
	}
	return nil
}

// TestInBandSSRFBypassesTheFixtureFilters audits the vulnapp SSRF pairs (j1mk.9) on their own. The
// vulnerable halves refuse the plain canary URL — one blocks the literal loopback names, one accepts
// only image-looking URLs and follows redirects — so each is found only through a bypass spelling.
// The safe halves echo every refused URL, which a detector matching its own URL would report.
//
// Negative controls, run by hand: with ssrfLoopbackSpellings returning nil /ssrf/preview is missed;
// with the image-extension redirect hop removed from ssrfInBandProbes /ssrf/thumbnail is missed; with
// ssrfURLValueRE never matching, /ssrf/thumbnail is missed too (its parameter name says nothing).
func TestInBandSSRFBypassesTheFixtureFilters(t *testing.T) {
	host, port := ssrfVulnappTarget(t)
	for _, e := range vulnapp.Vulnerabilities() {
		if !strings.HasPrefix(e.Path, "/ssrf/") {
			continue
		}
		t.Run(e.Path, func(t *testing.T) {
			f := ssrfFindingFor(auditSSRFInBandPath(t, host, port, e.Path))
			switch {
			case e.Safe && f != nil:
				t.Fatalf("safe twin reported: %s", f.Description+" | "+f.Evidence)
			case !e.Safe && f == nil:
				t.Fatal("vulnerable endpoint not reported")
			case f != nil:
				t.Logf("evidence: %s", f.Description+" | "+f.Evidence)
			}
		})
	}
}

// TestInBandSSRFIsNotFooledByAnOpenRedirect: a target that answers 302 to whatever URL it is given
// makes no server-side request. If the probe sender followed that redirect, the SCANNER would fetch
// its own canary and read the marker as the target's doing.
func TestInBandSSRFIsNotFooledByAnOpenRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("url"); u != "" && u != "seed" {
			w.Header().Set("Location", u)
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "nothing fetched")
	}))
	t.Cleanup(srv.Close)
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	if f := ssrfFindingFor(auditSSRFInBandOnly(t, host, uint16(port))); f != nil {
		t.Fatalf("an open redirect was reported as a server-side fetch: %s", f.Description+" | "+f.Evidence)
	}
}

// TestInBandSSRFEvidenceSurvivesWrapping pins the two shapes a fetched IMDS listing takes when the
// application wraps it: JSON-escaped newlines, and lines joined with nothing between them. Echoes of
// the URL in either shape stay non-evidence.
func TestInBandSSRFEvidenceSurvivesWrapping(t *testing.T) {
	const imds = "http://169.254.169.254/latest/meta-data/"
	escaped := `{"content":"ami-id\nami-launch-index\nami-manifest-path\nhostname"}`
	if _, ok := ssrfInBandEvidence(escaped, `{"content":"hello"}`, imds, "mk"); !ok {
		t.Error("a JSON-escaped IMDS listing was not accepted")
	}
	if _, ok := ssrfInBandEvidence(escaped, escaped, imds, "mk"); ok {
		t.Error("a JSON-escaped IMDS listing already in the baseline was accepted")
	}
	if _, ok := ssrfInBandEvidence("ami-idami-launch-indexami-manifest-pathhostname", "", imds, "mk"); !ok {
		t.Error("an IMDS listing with its lines joined was not accepted")
	}
	if _, ok := ssrfInBandEvidence(`{"error":"refused http:\/\/169.254.169.254\/latest\/meta-data\/"}`, "", imds, "mk"); ok {
		t.Error("a JSON-escaped echo of the metadata URL was accepted")
	}
	ecs := `{"Cluster":"c","TaskARN":"arn:aws:ecs:us-east-1:1:task/x"}`
	if _, ok := ssrfInBandEvidence(ecs, "", "http://169.254.170.2/v2/metadata", "mk"); !ok {
		t.Error("an ECS task metadata document was not accepted")
	}
}

// TestSSRFURLLikePoint pins which parameters get the bypass spellings: by name or by value.
func TestSSRFURLLikePoint(t *testing.T) {
	cases := []struct {
		name, value string
		want        bool
	}{
		{"imageurl", "x", true},
		{"imageUri", "x", true},
		{"callback_url", "", true},
		{"server_ip", "", true},
		{"src", "a", true},
		{"item", "https%3A%2F%2Fcdn.example.test%2Flogo.png", true},
		{"item", "//cdn.example.test/logo.png", true},
		{"item", "cdn.example.test/logo.png", true},
		{"item", "10.0.0.1:8080/x", true},
		{"q", "shoes", false},
		{"security", "high", false},
		{"recipient", "bob", false},
		{"id", "42", false},
		{"during", "1.5", false},
	}
	for _, c := range cases {
		got := ssrfURLLikePoint(bcheck.InsertionPoint{Name: c.name, BaseValue: c.value})
		if got != c.want {
			t.Errorf("ssrfURLLikePoint(%q=%q) = %v, want %v", c.name, c.value, got, c.want)
		}
	}
}

// TestSSRFLoopbackSpellingsAreLoopback: every alternate loopback host planted must be loopback (or
// unspecified) wherever Go's parser reads it as an address, and must not be a public address under a
// decimal reading. A spelling that is neither stays a host NAME, which only a resolver can answer.
func TestSSRFLoopbackSpellingsAreLoopback(t *testing.T) {
	c := &ssrfCanaryServer{addr: "127.0.0.1:1", port: "1", addr6: "[::1]:2", path: "/p"}
	for _, p := range ssrfLoopbackSpellings(c) {
		u, err := url.Parse(p.value)
		if err != nil {
			t.Fatalf("%q: %v", p.value, err)
		}
		h := u.Hostname()
		if ip := net.ParseIP(h); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			t.Errorf("%q plants a non-loopback address %s", p.value, ip)
		}
	}
}

func TestSSRFURLLikePointSplitsNames(t *testing.T) {
	for _, n := range []string{"serverIP", "target_host", "next", "img2", "returnTo", "SRC"} {
		if !ssrfURLLikePoint(bcheck.InsertionPoint{Name: n, BaseValue: "x"}) {
			t.Errorf("%q not treated as URL-like", n)
		}
	}
}
