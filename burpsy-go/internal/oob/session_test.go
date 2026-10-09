package oob

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A client identity that outlives the process (burpsy-react-ui-d657): Burp's restoreClient(SecretKey).
// The fake below behaves as interactsh-client does with -sf: it resumes the correlation id from the
// session file when one exists, and writes the file only when it exits on SIGINT.

func sessionFakeBinary(t *testing.T, saveOnInterrupt bool) string {
	t.Helper()
	save := `printf '%s' "$cid" > "$sf"; exit 0`
	if !saveOnInterrupt {
		save = `exit 0`
	}
	script := `#!/bin/sh
out=""; sf=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -sf) sf="$2"; shift ;;
  esac
  shift
done
if [ -f "$sf" ]; then cid=$(cat "$sf"); else cid="cid$$abcdefghijklmnop"; fi
runs="$sf.runs"; n=$(( $(cat "$runs" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$runs"
trap '` + save + `' INT TERM
echo '[INF] Current interactsh version 1.3.1 (latest)' >&2
echo "[INF] ${cid}n$$.oast.me" >&2
printf '{"protocol":"http","raw-request":"GET /run-%s HTTP/1.1"}\n' "$n" >> "$out"
while :; do sleep 0.05; done
`
	path := filepath.Join(t.TempDir(), "fake-interactsh-client")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func cidOf(domain string) string { return strings.SplitN(domain, "n", 2)[0] }

func Test_a_new_session_is_saved_at_once_and_resumed_by_the_next_process(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	bin := sessionFakeBinary(t, true)
	first, err := NewClient(context.Background(), Options{BinaryPath: bin, StateDir: dir, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	// Saved before any payload can be handed out, so a crash from here on cannot lose it.
	if _, err := os.Stat(filepath.Join(dir, sessionFileName)); err != nil || !first.Resumed() {
		t.Fatalf("new session not saved on registration: stat=%v resumed=%v", err, first.Resumed())
	}
	cid := cidOf(first.Domain())
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := NewClient(context.Background(), Options{BinaryPath: bin, StateDir: dir, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if got := cidOf(second.Domain()); got != cid || !second.Resumed() {
		t.Errorf("second process registered %q (resumed=%v), want the saved identity %q", got, second.Resumed(), cid)
	}
	// Three runs (register, save-restart, next process), three logs, all read: the earlier runs' logs
	// are the only record of what they received, because each run truncates its own.
	all, err := second.Interactions()
	if err != nil {
		t.Fatal(err)
	}
	var runs []string
	for _, in := range all {
		runs = append(runs, strings.Fields(in.RawRequest)[1])
	}
	if strings.Join(runs, ",") != "/run-1,/run-2,/run-3" {
		t.Errorf("interactions across runs = %v, want /run-1,/run-2,/run-3", runs)
	}
}

func Test_a_client_that_does_not_save_its_session_is_refused(t *testing.T) {
	old := gracefulStopWait
	gracefulStopWait = 300 * time.Millisecond
	defer func() { gracefulStopWait = old }()
	dir := filepath.Join(t.TempDir(), "state")
	_, err := NewClient(context.Background(), Options{BinaryPath: sessionFakeBinary(t, false), StateDir: dir, Timeout: 5 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "did not write") {
		t.Fatalf("err = %v, want a refusal: a session that cannot be saved cannot keep minted payloads polled", err)
	}
}

func Test_forget_deletes_the_identity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	c, err := NewClient(context.Background(), Options{BinaryPath: sessionFakeBinary(t, true), StateDir: dir, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Forget(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("state directory still exists after Forget: %v", err)
	}
}

func Test_state_dirs_are_per_server(t *testing.T) {
	if StateDirFor("", "x") != "" {
		t.Error("no base must mean no persistence")
	}
	a, b := StateDirFor("/b", ""), StateDirFor("/b", "https://oast.Example:8443/")
	if a != "/b/public" || b != "/b/server-https___oast.example_8443_" || a == b {
		t.Errorf("state dirs %q %q", a, b)
	}
}
