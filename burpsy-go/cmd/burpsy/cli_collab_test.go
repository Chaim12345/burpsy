package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// The CLI's -collab-base flag is what makes a corpus check whose verdict needs
// `<type> interactions` dispatchable. Without it the check is counted at load
// (LoadReport.Collaborator) and excluded from the audit set; with it, the same
// check joins the set. The comparison is against the no-server context rather
// than against zero, because the default ScanConfig ships the built-in table —
// what proves the wiring is that the server context has *more* active checks
// than the plain one, exactly like the -tools allowlist test.
func TestCLIContextWiresCollaboratorServerIntoActiveScanner(t *testing.T) {
	dir := t.TempDir()
	corpus := `metadata:
  language: v1-beta
  name: "collaborator wiring probe"
  description: "collaborator wiring probe"

define:
    url_ssrf = ` + "`http://{generate_collaborator_address()}/url`" + `
given request then
  send request:
    appending queries: ` + "`url={url_ssrf}`\n" + `
  if http interactions then
    report issue:
      severity: high
      confidence: certain
  end if
`
	if err := os.WriteFile(filepath.Join(dir, "collab.bcheck"), []byte(corpus), 0o644); err != nil {
		t.Fatal(err)
	}

	noServer, err := newCLIContext("", 1<<20, "*", "", "", dir, "", "", "", "", "")
	if err != nil {
		t.Fatalf("newCLIContext (no -collab-base): %v", err)
	}
	withServer, err := newCLIContext("", 1<<20, "*", "", "", dir, "", "burpsy.test", "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("newCLIContext (with -collab-base): %v", err)
	}
	defer withServer.collab.Close()
	if withServer.scanner.ActiveCheckCount() <= noServer.scanner.ActiveCheckCount() {
		t.Fatalf("expected -collab-base to add the blind check to the audit set: noServer=%d withServer=%d",
			noServer.scanner.ActiveCheckCount(), withServer.scanner.ActiveCheckCount())
	}
}

// A -collab-base that cannot bind its listeners refuses construction rather
// than surfacing mid-scan as checks that silently cannot verdict.
func TestNewCLIContextRefusesAnUnbindableInteractionServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got, err := newCLIContext("", 1<<20, "*", "", "", "", "", "x.test", ln.Addr().String(), "", "")
	if err == nil {
		got.collab.Close()
		t.Fatalf("newCLIContext succeeded on an occupied collab-http port %s", ln.Addr())
	}
}
