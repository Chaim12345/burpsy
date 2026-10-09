//go:build unix

// Package proctest holds the test helpers that check a contained command's
// descendants really died (burpsy-react-ui-9bzh). Test scripts write the pid of
// the child they start to a file; these read it back and watch it exit.
package proctest

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ChildPID reads the pid a test script wrote, waiting briefly for it.
func ChildPID(t testing.TB, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && strings.HasSuffix(string(b), "\n") {
			pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil {
				t.Fatalf("pid file %q: %v", b, err)
			}
			return pid
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the script never wrote its child's pid")
	return 0
}

// processGone reports whether pid has exited. A killed orphan is reparented and
// may sit as a zombie until its new parent reaps it, and a zombie still answers
// signal 0, so on Linux a zombie counts as gone (it is not running anything).
func processGone(pid int) bool {
	if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
		return true
	}
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return os.IsNotExist(err)
	}
	// /proc/<pid>/stat: "pid (comm) S ..." — the state follows the last ')'.
	s := string(stat)
	if i := strings.LastIndexByte(s, ')'); i >= 0 && i+2 < len(s) {
		return s[i+2] == 'Z' || s[i+2] == 'X'
	}
	return false
}

// WaitGone polls processGone, since SIGKILL delivery is asynchronous.
func WaitGone(pid int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for {
		if processGone(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}
