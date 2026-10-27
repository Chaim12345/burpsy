package tlsprobe

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeTLSX writes a stand-in tlsx that records its argv and runs body.
func fakeTLSX(t *testing.T, body string) (bin, argvFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stand-in")
	}
	dir := t.TempDir()
	argvFile = filepath.Join(dir, "argv")
	bin = filepath.Join(dir, "tlsx")
	script := "#!/bin/sh\necho \"$@\" > " + argvFile + "\n" + body + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, argvFile
}

func TestProbeKeepsRecordsFromANonZeroExitAndPassesTheOptions(t *testing.T) {
	bin, argvFile := fakeTLSX(t, "echo '"+selfSignedRecord+"'\nexit 1")
	res := Probe(context.Background(), []string{"a.test", "b.test"}, Options{Binary: bin, EnumerateCiphers: true, MinVersion: "tls10"})
	if res.Outcome != OutcomeCompleted || len(res.Hosts) != 1 || !res.Hosts[0].SelfSigned {
		t.Fatalf("result = %+v", res)
	}
	argv, _ := os.ReadFile(argvFile)
	for _, want := range []string{"-u a.test,b.test", "-ce -ct all", "-min-version tls10"} {
		if !strings.Contains(string(argv), want) {
			t.Errorf("argv %q lacks %q", argv, want)
		}
	}
}

func TestProbeWithNoRecordsAndAFailedRunIsFailed(t *testing.T) {
	bin, _ := fakeTLSX(t, "echo 'handshake refused' >&2\nexit 2")
	res := Probe(context.Background(), []string{"a.test"}, Options{Binary: bin})
	if res.Outcome != OutcomeFailed || res.Err == nil || !strings.Contains(res.Err.Error(), "handshake refused") {
		t.Fatalf("result = %+v", res)
	}
}
