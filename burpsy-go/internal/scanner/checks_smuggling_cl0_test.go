package scanner

// CL.0 / client-side desync tests (burpsy-react-ui-0vzb.40).

import (
	"context"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

func runCL0(t *testing.T, listener string) ([]*Finding, error) {
	t.Helper()
	l, err := vulnapp.StartListener(listener)
	if err != nil {
		t.Fatalf("start %s: %v", listener, err)
	}
	t.Cleanup(func() { l.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cc := smugglingAt(l.Host, l.Port, l.TLS)
	cc.Config = &ScanConfig{CheckRequestSmuggling: true, CheckExtendedActive: true}
	return checkRequestSmuggling(ctx, cc)
}

func runClientSideDesync(t *testing.T, listener string) ([]*Finding, error) {
	t.Helper()
	l, err := vulnapp.StartListener(listener)
	if err != nil {
		t.Fatalf("start %s: %v", listener, err)
	}
	t.Cleanup(func() { l.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return checkClientSideDesync(ctx, smugglingAt(l.Host, l.Port, l.TLS))
}

func TestCL0ReportsTheSmuggledPrefixAnswer(t *testing.T) {
	fs, err := runCL0(t, "desync-cl0")
	if err != nil {
		t.Fatalf("check errored: %v", err)
	}
	var f *Finding
	for _, x := range fs {
		if x.Name == smugglingRow {
			f = x
		}
	}
	if f == nil {
		t.Fatalf("no smuggling finding (got %v)", fs)
	}
	if f.Param != "CL.0" || f.Severity != "high" || f.Confidence != "firm" {
		t.Fatalf("param/severity/confidence = %q/%s/%s", f.Param, f.Severity, f.Confidence)
	}
}

func TestCL0StaysQuietWhenTheBodyIsRead(t *testing.T) {
	fs, err := runCL0(t, "desync-cl0-safe")
	if err != nil {
		t.Fatalf("check errored: %v", err)
	}
	for _, x := range fs {
		if x.Name == smugglingRow {
			t.Fatalf("safe twin reported: %+v", x)
		}
	}
}

func TestClientSideDesyncReportsTheSmuggledPrefixAnswer(t *testing.T) {
	fs, err := runClientSideDesync(t, "desync-client-side")
	if err != nil {
		t.Fatalf("check errored: %v", err)
	}
	var f *Finding
	for _, x := range fs {
		if x.Name == "Client-side desync" {
			f = x
		}
	}
	if f == nil {
		t.Fatalf("no client-side desync finding (got %v)", fs)
	}
	if f.Severity != "high" || f.Confidence != "firm" {
		t.Fatalf("severity/confidence = %s/%s", f.Severity, f.Confidence)
	}
}

func TestClientSideDesyncStaysQuietOnTheSafeTwin(t *testing.T) {
	fs, err := runClientSideDesync(t, "desync-csd-safe")
	if err != nil {
		t.Fatalf("check errored: %v", err)
	}
	for _, x := range fs {
		if x.Name == "Client-side desync" {
			t.Fatalf("safe twin reported: %+v", x)
		}
	}
}

// CL.0 can leave a response on a shared back-end connection, so the smuggling switch alone (whose
// promise is that nothing is queued) does not run it: only the extended-active opt-in does.
func TestCL0NeedsTheExtendedActiveOptIn(t *testing.T) {
	l, err := vulnapp.StartListener("desync-cl0")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cc := smugglingAt(l.Host, l.Port, l.TLS)
	cc.Config = &ScanConfig{CheckRequestSmuggling: true}
	fs, err := checkRequestSmuggling(ctx, cc)
	if err != nil {
		t.Fatalf("check errored: %v", err)
	}
	for _, x := range fs {
		if x.Param == "CL.0" {
			t.Fatalf("CL.0 ran under CheckRequestSmuggling alone: %+v", x)
		}
	}
}

// The smuggling row and "Client-side desync" share one CL.0 probe per endpoint: the risky prefix
// is sent once however many rows read it. The listener is closed after the first row, so the
// second can only report from the shared result, never from a probe of its own.
func TestCL0ProbeIsSentOncePerEndpoint(t *testing.T) {
	l, err := vulnapp.StartListener("desync-cl0")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cc := smugglingAt(l.Host, l.Port, l.TLS)
	cc.Config = &ScanConfig{CheckRequestSmuggling: true, CheckExtendedActive: true}
	if fs, err := checkRequestSmuggling(ctx, cc); err != nil || len(fs) == 0 {
		t.Fatalf("smuggling row: %v %v", fs, err)
	}
	l.Close()
	fs, err := checkClientSideDesync(ctx, cc)
	if err != nil || len(fs) != 1 {
		t.Fatalf("client-side desync did not reuse the endpoint's CL.0 result: %v %v", fs, err)
	}
}
