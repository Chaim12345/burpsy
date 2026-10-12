package scanner

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
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
	store := core.NewTrafficStore()
	id := seedAuditExchange(t, store, host, port, "/fetch?url=seed", "nothing fetched")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: 30 * time.Second,
			CheckExtendedActive: true, CheckSSRFInBand: true})
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, DefaultAuditConfig())
	return findings
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
