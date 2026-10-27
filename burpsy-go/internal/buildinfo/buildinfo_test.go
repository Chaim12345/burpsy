package buildinfo

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAStampedVersionWins(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "v9.9.9"
	if got := String(); got != "v9.9.9" {
		t.Errorf("String() = %q, want the stamp", got)
	}
	Version = ""
	if got := String(); got == "" {
		t.Error("an unstamped build reported an empty version")
	}
}

// The release workflow's -X path must name this variable exactly: a typo links silently and every
// release reports "dev".
func TestTheReleaseWorkflowStampsThisVariable(t *testing.T) {
	wf, err := os.ReadFile(filepath.Join("..", "..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Skip("release workflow not present in this checkout")
	}
	if !strings.Contains(string(wf), "-X github.com/burpsy-go/burpsy/internal/buildinfo.Version=") {
		t.Error("release.yml does not stamp internal/buildinfo.Version")
	}
	if testing.Short() {
		return
	}
	out := filepath.Join(t.TempDir(), "mcp")
	build := exec.Command("go", "build", "-ldflags", "-X github.com/burpsy-go/burpsy/internal/buildinfo.Version=v0.0.0-stamp", "-o", out, "../../cmd/burpsy-mcp")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	got, err := exec.Command(out, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(got), "v0.0.0-stamp") {
		t.Errorf("burpsy-mcp --version = %q (%v), want the stamp", got, err)
	}
}
