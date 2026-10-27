//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAWrittenReportIsOwnerOnly(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	dir := t.TempDir()
	fresh := filepath.Join(dir, "fresh.sarif")
	existing := filepath.Join(dir, "existing.html")
	if err := os.WriteFile(existing, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{fresh, existing} {
		if err := writeReport(p, []byte("evidence")); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is %v: a report of findings must be owner-only", filepath.Base(p), st.Mode().Perm())
		}
	}
}
