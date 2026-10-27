package archtest

import (
	"os/exec"
	"sort"
	"strings"
	"testing"
)

const module = "github.com/burpsy-go/burpsy/"

// layerRules says which internal packages a package (and its subpackages) must not import directly.
// The layering in prose (docs/adr, the architecture review of 2026-10-27): the wire and capture
// layers sit below the tools, the tools below the console, and the console's clients (mcp, agent)
// talk to it over HTTP rather than linking it. core and sender carry their own transitive tests.
var layerRules = []struct {
	from      string
	forbidden []string
}{
	{"internal/httputil", []string{"internal/sender", "internal/proxy", "internal/scanner", "internal/web"}},
	{"internal/bcheck", []string{"internal/scanner", "internal/intruder", "internal/web"}},
	{"internal/intruder", []string{"internal/scanner", "internal/proxy", "internal/web"}},
	{"internal/scanner", []string{"internal/proxy", "internal/crawler", "internal/web"}},
	{"internal/proxy", []string{"internal/scanner", "internal/intruder", "internal/crawler", "internal/web"}},
	{"internal/crawler", []string{"internal/scanner", "internal/intruder", "internal/proxy", "internal/web"}},
	{"internal/pool", []string{"internal/intruder", "internal/scanner", "internal/web"}},
	{"internal/persist", []string{"internal/scanner", "internal/web"}},
	{"internal/mcp", []string{"internal/web"}},
	{"internal/agent", []string{"internal/web"}},
}

// knownViolations are the edges that break a rule today, each with the bead that removes it. The
// test fails on any edge NOT listed (a new violation) and on any listed edge that no longer exists
// (fixed: delete the line so it cannot quietly come back).
var knownViolations = map[string]string{
	"internal/proxy -> internal/scanner":   "misplaced-primitives (core.ExchangeSink for scanner.Capture)",
	"internal/crawler -> internal/scanner": "misplaced-primitives (core.ExchangeSink for scanner.Capture)",
	"internal/persist -> internal/scanner": "scanconfig-wire-keys (persist the wire view, not scanner.ScanConfig)",
	"internal/mcp -> internal/web":         "route-statements (manifest leaf package)",
}

func under(pkg, prefix string) bool { return pkg == prefix || strings.HasPrefix(pkg, prefix+"/") }

func TestTheLayeringHoldsBeyondTheKnownViolations(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{.ImportPath}} {{join .Imports \" \"}}", module+"...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	found := map[string]bool{}
	packages := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], module) {
			continue
		}
		packages++
		pkg := strings.TrimPrefix(fields[0], module)
		for _, rule := range layerRules {
			if !under(pkg, rule.from) {
				continue
			}
			for _, imp := range fields[1:] {
				imp = strings.TrimPrefix(imp, module)
				for _, f := range rule.forbidden {
					if under(imp, f) {
						found[rule.from+" -> "+f] = true
					}
				}
			}
		}
	}
	// A listing that saw a handful of packages has not searched the module.
	if packages < 40 {
		t.Fatalf("go list returned %d module packages; the listing is incomplete", packages)
	}
	var fresh, gone []string
	for edge := range found {
		if _, ok := knownViolations[edge]; !ok {
			fresh = append(fresh, edge)
		}
	}
	for edge := range knownViolations {
		if !found[edge] {
			gone = append(gone, edge)
		}
	}
	sort.Strings(fresh)
	sort.Strings(gone)
	if len(fresh) > 0 {
		t.Errorf("new layering violations (move the shared piece down a layer instead):\n  %s", strings.Join(fresh, "\n  "))
	}
	if len(gone) > 0 {
		t.Errorf("fixed violations still listed in knownViolations — delete them so they cannot come back:\n  %s", strings.Join(gone, "\n  "))
	}
}
