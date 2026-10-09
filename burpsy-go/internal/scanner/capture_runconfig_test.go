package scanner

import (
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Capture-time scanning honours the engagement's run configuration (burpsy-react-ui-saq3.3.3). The test
// drives Capture.Record, the path every proxied, crawled and Repeater exchange takes, with a source that
// stands in for the ActiveScanner. The response raises built-in passive findings, which are outside the
// catalogue, and a catalogued static-DOM finding: Cross-site scripting (DOM-based), 0x00200310.

type stubRunConfig struct {
	cfg      AuditConfig
	scanWide []uint32
}

func (s stubRunConfig) AuditConfig() AuditConfig   { return s.cfg }
func (s stubRunConfig) ConfigSnapshot() ScanConfig { return ScanConfig{IssueTypes: s.scanWide} }

const domXSSType = 0x00200310

func capturedNames(t *testing.T, src RunConfigSource) []string {
	t.Helper()
	c, _, fs := newTestCapture()
	if src != nil {
		c.Scanner.WithRunConfigSource(src)
	}
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=1\r\n\r\n" +
		"<html><script>document.write(location.hash);</script></html>"
	if _, err := c.Record(CapturedExchange{Host: "h", Port: 80, Method: "GET", Path: "/p",
		Request: []byte(testRequest), Response: []byte(resp), Started: time.Now()}); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range fs.All() {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	return names
}

func has(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

func Test_capture_honours_the_run_configuration(t *testing.T) {
	const dom = "Cross-site scripting (DOM-based)"
	const passive = "Cookie Missing HttpOnly Flag"

	base := capturedNames(t, nil)
	if !has(base, dom) || !has(base, passive) {
		t.Fatalf("control: an unconfigured capture raised %v, want both families", base)
	}
	if got := capturedNames(t, stubRunConfig{cfg: DefaultAuditConfig()}); strings.Join(got, "|") != strings.Join(base, "|") {
		t.Errorf("the default run configuration changed what capture raises: %v vs %v", got, base)
	}

	cases := []struct {
		name               string
		src                stubRunConfig
		wantDOM, wantPassv bool
	}{
		{"scan_type_passive false", stubRunConfig{cfg: func() AuditConfig {
			c := DefaultAuditConfig()
			c.PassiveChecks = SomeUint32(0)
			return c
		}()}, true, false},
		{"use_static_analysis false", stubRunConfig{cfg: func() AuditConfig {
			c := DefaultAuditConfig()
			c.JavaScriptStaticAnalysis = SomeUint32(0)
			return c
		}()}, false, true},
		{"issue type deselected", stubRunConfig{cfg: func() AuditConfig {
			c := DefaultAuditConfig()
			c.DisabledIssueTypes = []uint32{domXSSType}
			return c
		}()}, false, true},
		{"static method disabled for the type", stubRunConfig{cfg: func() AuditConfig {
			c := DefaultAuditConfig()
			c.DisabledDetectionMethods = []IssueDetectionMethod{{TypeIndex: domXSSType, Method: MethodJavaScriptStatic}}
			return c
		}()}, false, true},
		{"a different method disabled leaves it", stubRunConfig{cfg: func() AuditConfig {
			c := DefaultAuditConfig()
			c.DisabledDetectionMethods = []IssueDetectionMethod{{TypeIndex: domXSSType, Method: MethodJavaScriptDynamic}}
			return c
		}()}, true, true},
		{"scan-wide whitelist excludes it", stubRunConfig{cfg: DefaultAuditConfig(), scanWide: []uint32{0x00100100}}, false, true},
		{"run whitelist includes it", stubRunConfig{cfg: func() AuditConfig {
			c := DefaultAuditConfig()
			c.IssueTypes = []uint32{domXSSType}
			return c
		}()}, true, true},
	}
	for _, tc := range cases {
		got := capturedNames(t, tc.src)
		if has(got, dom) != tc.wantDOM || has(got, passive) != tc.wantPassv {
			t.Errorf("%s: captured %v, want DOM=%v passive=%v", tc.name, got, tc.wantDOM, tc.wantPassv)
		}
	}
}

// max_static_time_per_item bounds the capture-time DOM pass as it bounds the audit's.
func Test_capture_static_pass_obeys_the_per_item_time_limit(t *testing.T) {
	start := time.Now()
	var reads atomic.Int64
	old := domNow
	domNow = func() time.Time {
		if reads.Add(1) == 1 {
			return start
		}
		return start.Add(time.Hour)
	}
	defer func() { domNow = old }()

	limited := DefaultAuditConfig()
	limited.MaxStaticTimePerItem = SomeUint32(1)
	if has(capturedNames(t, stubRunConfig{cfg: limited}), "Cross-site scripting (DOM-based)") {
		t.Error("a static pass whose time limit ran out before its first statement still reported a flow")
	}
	domNow = old
	if !has(capturedNames(t, stubRunConfig{cfg: limited}), "Cross-site scripting (DOM-based)") {
		t.Error("control: within its limit the pass found nothing")
	}
}
