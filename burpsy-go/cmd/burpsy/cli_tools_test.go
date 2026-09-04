package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The CLI's -tools allowlist is what makes a `run tool` corpus check
// dispatchable. Without it the check is counted at load (LoadReport.Tools)
// and excluded from the audit set; with it, the same check joins the set. The
// comparison is against the no-tools context rather than against zero, because
// the default ScanConfig ships the built-in table — what proves the wiring is
// that the allowlist context has *more* active checks than the plain one.
func TestCLIContextWiresToolAllowlistIntoActiveScanner(t *testing.T) {
	dir := t.TempDir()
	corpus := `metadata:
  language: v1-beta
  name: "tool wiring probe"
  description: "tool wiring probe"

given request then
  run tool sqlmap called probe:
    args: "-u", "{base.request.url}"
`
	if err := os.WriteFile(filepath.Join(dir, "tool.bcheck"), []byte(corpus), 0o644); err != nil {
		t.Fatal(err)
	}

	noTools, err := newCLIContext("", 1<<20, "*", "", "", dir, "", "", nil)
	if err != nil {
		t.Fatalf("newCLIContext (no -tools): %v", err)
	}
	withTools, err := newCLIContext("", 1<<20, "*", "", "", dir, "sqlmap=/usr/bin/sqlmap", "", nil)
	if err != nil {
		t.Fatalf("newCLIContext (with -tools): %v", err)
	}
	if withTools.scanner.ActiveCheckCount() <= noTools.scanner.ActiveCheckCount() {
		t.Fatalf("expected -tools to add the tool check to the audit set: noTools=%d withTools=%d",
			noTools.scanner.ActiveCheckCount(), withTools.scanner.ActiveCheckCount())
	}
}

// A malformed -tools entry refuses construction rather than surfacing mid-scan
// as a tool that silently never ran.
func TestParseToolAllowlistRefusesMalformedEntries(t *testing.T) {
	for _, bad := range []string{"sqlmap", "=path", "sqlmap=", "sqlmap=/a,sqlmap=/b"} {
		if _, err := parseToolAllowlist(bad); err == nil {
			t.Errorf("parseToolAllowlist(%q) succeeded, want an error", bad)
		}
	}
	got, err := parseToolAllowlist(" sqlmap=/usr/bin/sqlmap , jwt_tool=/opt/jwt/jwt_tool ")
	if err != nil {
		t.Fatalf("parseToolAllowlist: %v", err)
	}
	if got["sqlmap"] != "/usr/bin/sqlmap" || got["jwt_tool"] != "/opt/jwt/jwt_tool" {
		t.Errorf("allowlist = %v, want both entries trimmed", got)
	}
}
