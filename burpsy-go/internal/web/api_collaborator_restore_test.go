package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Collaborator identity across a restart (burpsy-react-ui-d657), through the real routes and the
// real lazy provider, with a stand-in interactsh-client that resumes its correlation id from -sf the
// way the real one does. Payloads minted before the "restart" are listed after it, and a callback to
// one of them that arrived while burpsy was down is attributed to it, not lost.

func sessionClientScript(t *testing.T) string {
	t.Helper()
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
trap 'printf "%s" "$cid" > "$sf"; exit 0' INT TERM
echo "[INF] ${cid}n$$.oast.me" >&2
: > "$out"
while :; do sleep 0.05; done
`
	path := filepath.Join(t.TempDir(), "fake-interactsh-client")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// bootCollaborator is one burpsy process: a server with the state base, configured from the console.
func bootCollaborator(t *testing.T, base, client string) *Server {
	t.Helper()
	s := newTestServerWithScanner(t).WithCollaboratorStateDir(base)
	body := fmt.Sprintf(`{"server":"https://oast.example","client_path":%q}`, client)
	if rec := postCollaboratorServer(t, s, body); rec.Code != http.StatusOK {
		t.Fatalf("configure: %d %s", rec.Code, rec.Body.String())
	}
	return s
}

func mint(t *testing.T, s *Server, count int) []string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/collaborator/payload",
		strings.NewReader(fmt.Sprintf(`{"count":%d}`, count))))
	if rec.Code != http.StatusOK {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Markers []string `json:"markers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Markers
}

func Test_minted_payloads_survive_a_restart_and_keep_their_late_callbacks(t *testing.T) {
	base, client := t.TempDir(), sessionClientScript(t)

	first := bootCollaborator(t, base, client)
	before := mint(t, first, 2)
	if err := first.scanner.CloseOOBChannel(); err != nil { // the process shuts down
		t.Fatal(err)
	}

	// While burpsy was down, the target called back to the first payload. The resumed client delivers
	// it on its first poll; here it is written to a log in the state directory, which is where that
	// delivery lands.
	state := filepath.Join(base, "server-https___oast.example")
	late := fmt.Sprintf(`{"protocol":"http","raw-request":"GET / HTTP/1.1\r\nHost: %s.cidxoast.me\r\n"}`, before[0])
	if err := os.WriteFile(filepath.Join(state, "interactions-0.jsonl"), []byte(late+"\n"), 0o600); err != nil {
		t.Fatalf("state directory %s missing or unwritable: %v", state, err)
	}

	second := bootCollaborator(t, base, client)
	after := mint(t, second, 1) // the first mint opens the resumed channel
	defer second.scanner.CloseOOBChannel()

	rec := httptest.NewRecorder()
	second.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/collaborator/poll", nil))
	var status struct {
		Payloads []collaboratorPayloadView `json:"payloads"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	hits := map[string]int{}
	for _, p := range status.Payloads {
		hits[p.Marker] = p.Interactions
	}
	for _, m := range append(before, after...) {
		if _, ok := hits[m]; !ok {
			t.Errorf("payload %s not listed after the restart: %s", m, rec.Body.String())
		}
	}
	if hits[before[0]] != 1 {
		t.Errorf("the late callback to %s was not attributed after the restart (interactions=%d)", before[0], hits[before[0]])
	}

	// "Don't use Collaborator" with confirmation forgets the identity, so nothing resumes it.
	if rec := deleteCollaboratorServer(second, `{"discard_open_channel":true}`); rec.Code != http.StatusOK {
		t.Fatalf("unset: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Errorf("state directory kept after a confirmed discard: %v", err)
	}
}
