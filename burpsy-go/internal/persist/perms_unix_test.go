//go:build unix

package persist

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// burpsy-react-ui-data-at-rest-perms: the capture segments and the project database hold every
// request and response burpsy recorded — session cookies, bearer tokens, credentials typed into a
// target. Created 0755/0644 they were readable by every other account on the machine.
//
// The umask is pinned to the common 022 for the whole test. Under a stricter umask (077) every file
// would come out owner-only whatever the code asked for, and this test would pass against the bug.
func TestCaptureAndProjectFilesAreOwnerOnly(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })

	root := t.TempDir()
	ownerOnly := func(t *testing.T, path string) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s is %#o; captured traffic must be owner-only (mode&0o077 == 0)", path, perm)
		}
	}

	t.Run("capture segments", func(t *testing.T) {
		dir := filepath.Join(root, "capture", "segments")
		sl, err := core.NewSegmentLog(dir, 1<<20)
		if err != nil {
			t.Fatalf("NewSegmentLog: %v", err)
		}
		if _, err := sl.Append(1, core.DirectionRequest, []byte("GET / HTTP/1.1\r\nCookie: s=secret\r\n\r\n")); err != nil {
			t.Fatalf("Append: %v", err)
		}
		if err := sl.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		ownerOnly(t, dir)
		segs, _ := filepath.Glob(filepath.Join(dir, "*"))
		if len(segs) == 0 {
			t.Fatal("no segment file was written, so nothing about its mode was checked")
		}
		for _, seg := range segs {
			ownerOnly(t, seg)
		}

		// A segment written by an earlier build is 0644; resuming it tightens it.
		if err := os.Chmod(segs[len(segs)-1], 0o644); err != nil {
			t.Fatal(err)
		}
		sl, err = core.NewSegmentLog(dir, 1<<20)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		sl.Close()
		ownerOnly(t, segs[len(segs)-1])
	})

	t.Run("project database with its WAL and SHM", func(t *testing.T) {
		db := filepath.Join(root, "project.db")
		s, err := Open(db, zap.NewNop())
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		// A write, so the WAL holds something and both companions exist while the store is open
		// (SQLite removes them on the last close).
		s.SaveScope([]*core.ScopeRule{{Kind: core.ScopeInclude, Pattern: "owner-only.test"}})
		for _, p := range []string{db, db + "-wal", db + "-shm"} {
			ownerOnly(t, p)
		}

		// The snapshot is the same data, so it is owner-only too.
		backup := filepath.Join(root, "backup.db")
		if err := s.Backup(backup); err != nil {
			t.Fatalf("Backup: %v", err)
		}
		ownerOnly(t, backup)
		s.Close()

		// A project created by an earlier build is tightened on its next open.
		if err := os.Chmod(db, 0o644); err != nil {
			t.Fatal(err)
		}
		s, err = Open(db, zap.NewNop())
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		defer s.Close()
		ownerOnly(t, db)
	})
}
