//go:build tlsx_live

// Live end-to-end check against badssl.com, matching the oob_live convention.
// Run: go test -tags tlsx_live ./internal/tlsprobe/... -count=1 -v
package tlsprobe

import (
	"context"
	"testing"
	"time"
)

func TestLiveBadSSLDefectsAreDetected(t *testing.T) {
	if !Available("") {
		t.Skip("tlsx not on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	res := Probe(ctx, []string{
		"expired.badssl.com",
		"self-signed.badssl.com",
		"wrong.host.badssl.com",
		"untrusted-root.badssl.com",
	}, Options{})

	if res.Outcome != OutcomeCompleted {
		t.Fatalf("Outcome = %v, err = %v", res.Outcome, res.Err)
	}
	t.Logf("argv: %v", res.Command)

	want := map[string]func(Host) bool{
		"expired.badssl.com":        func(h Host) bool { return h.Expired },
		"self-signed.badssl.com":    func(h Host) bool { return h.SelfSigned },
		"wrong.host.badssl.com":     func(h Host) bool { return h.Mismatched },
		"untrusted-root.badssl.com": func(h Host) bool { return h.Untrusted },
	}
	seen := map[string]bool{}
	for _, h := range res.Hosts {
		t.Logf("%s ver=%s expired=%v selfsigned=%v mismatched=%v untrusted=%v",
			h.Host, h.TLSVersion, h.Expired, h.SelfSigned, h.Mismatched, h.Untrusted)
		if pred, ok := want[h.Host]; ok {
			if !pred(h) {
				t.Errorf("%s: expected defect flag not set: %+v", h.Host, h)
			}
			if !h.HasCertificateDefect() {
				t.Errorf("%s: HasCertificateDefect() = false", h.Host)
			}
			seen[h.Host] = true
		}
	}
	for host := range want {
		if !seen[host] {
			t.Errorf("%s produced no record", host)
		}
	}
}
