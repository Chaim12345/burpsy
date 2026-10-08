package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/extscan"
)

// The content-discovery session (burpsy-react-ui-dgbi): built-in lists, recursion, observed
// names, derivations and variant extensions. These tests drive the whole session through the
// real route with a FAKE ffuf — a script that records its argv, copies the wordlist it was
// handed, and answers canned JSON by URL — because what is being tested is the session driver:
// which runs happen, in what order, against which directories, and what each level reports.
// One real-tool run is already covered by the tests above; the session driver is a claim about
// this process, and the fake makes it deterministic.
//
// The canned answers:
//   - ORIGIN/FUZZ finds the directory /admin (301 to /admin/);
//   - ORIGIN/admin/FUZZ finds the directory /admin/deep (301 to /admin/deep/) and the file
//     /admin/report.txt (200);
//   - ORIGIN/admin/deep/FUZZ finds the file /admin/deep/notes.txt (200);
//   - anything else finds nothing.
func fakeFFUF(t *testing.T, dir string) string {
	t.Helper()
	script := `#!/usr/bin/env bash
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
printf '%s\n' "$*" >> "$here/argv.log"
n="$(ls "$here" 2>/dev/null | grep -c '^wordlist-.*\.copy$' || true)"
out="" url="" wl="" prev=""
for a in "$@"; do
  case "$prev" in
    -o) out="$a" ;;
    -u) url="$a" ;;
    -w) wl="$a" ;;
  esac
  prev="$a"
done
cp "$wl" "$here/wordlist-$n.copy"
base="${url%FUZZ}"
case "$url" in
  */admin/deep/FUZZ)
    printf '{"results":[{"url":"%snotes.txt","input":{"FUZZ":"notes.txt"},"status":200,"length":5,"words":1,"lines":1,"content-type":"text/plain","redirectlocation":"","host":"127.0.0.1"}]}' "$base" > "$out"
    ;;
  */admin/FUZZ)
    printf '{"results":[{"url":"%sdeep","input":{"FUZZ":"deep"},"status":301,"length":10,"words":2,"lines":1,"content-type":"text/html","redirectlocation":"%sdeep/","host":"127.0.0.1"},{"url":"%sreport.txt","input":{"FUZZ":"report.txt"},"status":200,"length":6,"words":1,"lines":1,"content-type":"text/plain","redirectlocation":"","host":"127.0.0.1"}]}' "$base" "$base" "$base" > "$out"
    ;;
  */FUZZ)
    printf '{"results":[{"url":"%sadmin","input":{"FUZZ":"admin"},"status":301,"length":10,"words":2,"lines":1,"content-type":"text/html","redirectlocation":"%sadmin/","host":"127.0.0.1"}]}' "$base" "$base" > "$out"
    ;;
  *)
    printf '{"results":[]}' > "$out"
    ;;
esac
`
	path := filepath.Join(dir, "ffuf")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake ffuf: %v", err)
	}
	return path
}

// startDiscoverySession posts one session and waits for it to finish. The
// target is a real httptest origin (its host is what scope authorises); the
// body needs no target of its own. preSeed, when given, runs before the POST —
// the merged wordlist is built inside the POST handler, so seeding after it
// would race the merge.
func startDiscoverySession(t *testing.T, body map[string]any, preSeed func(s *Server, origin string), extraScope func(s *Server, host string)) (*Server, uint64, string) {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	t.Cleanup(target.Close)
	host := mustHostname(t, target.URL)

	dir := t.TempDir()
	fake := fakeFFUF(t, dir)
	s := newTestServer().WithExternalTools(map[string]string{extscan.ToolFFUF: fake})
	s.scope.AddInclude(host)
	if preSeed != nil {
		preSeed(s, target.URL)
	}
	if extraScope != nil {
		extraScope(s, host)
	}
	body["target"] = target.URL + "/"

	rec := postJSON(t, s, "/api/discovery", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/discovery: status = %d (%s)", rec.Code, rec.Body.String())
	}
	var start struct {
		TaskID uint64 `json:"task_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	return s, start.TaskID, dir
}

// argvLog reads the fake's invocation log: one line per ffuf run.
func argvLog(t *testing.T, dir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "argv.log"))
	if err != nil {
		t.Fatalf("the fake ffuf recorded no argv: %v", err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// argvURL pulls the argument after -u off one recorded argv line.
func argvURL(argv string) string {
	parts := strings.Fields(argv)
	for i, p := range parts {
		if p == "-u" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// rawRun fetches the run's wire body, for the assertions that must see the JSON
// itself (arrays are [], never null).
func rawRun(t *testing.T, s *Server, taskID uint64) string {
	t.Helper()
	rec := get(t, s, "/api/discovery?task="+strconv.FormatUint(taskID, 10))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET run %d: %d (%s)", taskID, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// Depth 2 issues exactly the expected runs — one per directory per level, nothing
// more — and every level reports what it found.
func TestDiscoveryRecursionDepthTwoIssuesExactlyTheExpectedRuns(t *testing.T) {
	s, taskID, dir := startDiscoverySession(t, map[string]any{
		"lists":         []string{"builtin-short-directories"},
		"recurse_depth": 2,
		"threads":       1,
	}, nil, nil)
	run := waitForDiscovery(t, s, taskID)
	if run.State != "done" || run.Outcome != "completed" {
		t.Fatalf("run state = %q outcome = %q error = %q; want a completed session", run.State, run.Outcome, run.Error)
	}

	log := argvLog(t, dir)
	if len(log) != 3 {
		t.Fatalf("depth 2 issued %d ffuf run(s), want exactly 3 (base, /admin/, /admin/deep/):\n%s",
			len(log), strings.Join(log, "\n"))
	}
	// The order is breadth-first: the target, then the directory it found, then
	// the directory that found.
	for i, want := range []string{"/FUZZ", "/admin/FUZZ", "/admin/deep/FUZZ"} {
		if got := argvURL(log[i]); !strings.HasSuffix(got, want) {
			t.Errorf("run %d swept %q, want the directory ending %q", i, got, want)
		}
	}
	if len(run.Levels) != 2 {
		t.Fatalf("levels = %+v, want one entry per recursion depth", run.Levels)
	}
	if run.Levels[0].Level != 1 || run.Levels[0].Discovered != 2 || run.Levels[0].Runs != 1 || run.Levels[0].Skipped != 0 {
		t.Errorf("level 1 = %+v, want two discoveries (the subdirectory and the file), one run, nothing skipped", run.Levels[0])
	}
	if run.Levels[1].Level != 2 || run.Levels[1].Discovered != 1 || run.Levels[1].Runs != 1 {
		t.Errorf("level 2 = %+v, want one discovery (the file), one run", run.Levels[1])
	}
	// The whole session's discoveries: the base directory, level 1's two, and
	// level 2's file — all four, deduplicated.
	paths := map[string]bool{}
	for _, d := range run.Discoveries {
		paths[d.Path] = true
	}
	for _, want := range []string{"/admin", "/admin/deep", "/admin/report.txt", "/admin/deep/notes.txt"} {
		if !paths[want] {
			t.Errorf("the session did not report %s; reported %v", want, paths)
		}
	}
	if !strings.Contains(rawRun(t, s, taskID), `"levels":[`) {
		t.Error("the run does not serialise levels as an array")
	}
}

// A subdirectory the engagement scope refuses is counted as skipped and never
// fetched: egress stays scope-checked per directory, which is the reason ffuf's
// own -recursion is not used.
func TestDiscoverySkipsOutOfScopeSubdirectoriesRatherThanRunningThem(t *testing.T) {
	// The exclude carries a trailing slash: it refuses everything beneath
	// /admin/ while the discovery of /admin itself (no slash) still passes the
	// post-run filter — the shape that puts the directory in the frontier and
	// the pre-launch gate to work.
	s, taskID, dir := startDiscoverySession(t, map[string]any{
		"lists":         []string{"builtin-short-directories"},
		"recurse_depth": 1,
		"threads":       1,
	}, nil, func(s *Server, host string) {
		s.scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, host, "/admin/"))
	})

	run := waitForDiscovery(t, s, taskID)
	if run.Outcome != "completed" {
		t.Fatalf("outcome = %q error = %q", run.Outcome, run.Error)
	}
	if log := argvLog(t, dir); len(log) != 1 {
		t.Fatalf("an out-of-scope subdirectory was fetched: %d run(s) issued, want only the base sweep:\n%s",
			len(log), strings.Join(log, "\n"))
	}
	if len(run.Levels) != 1 {
		t.Fatalf("levels = %+v, want the one recursion depth asked for", run.Levels)
	}
	if run.Levels[0].Skipped != 1 || run.Levels[0].Runs != 0 {
		t.Errorf("level 1 = %+v, want skipped=1 (scope refused the subdirectory before launch) and runs=0", run.Levels[0])
	}
	// The directory itself was still reported by the base sweep: refusing to
	// fetch beneath it is not refusing to know it exists.
	found := false
	for _, d := range run.Discoveries {
		if d.Path == "/admin" {
			found = true
		}
	}
	if !found {
		t.Errorf("the base sweep's /admin discovery was dropped; the skip is the level's, not the base's (discoveries: %+v)", run.Discoveries)
	}
}

// The merged wordlist carries the selected built-in list and the names observed
// on the target site, deduplicated — Burp's two name sources in one file.
func TestTheMergedWordlistCarriesTheBuiltinsAndTheObservedNames(t *testing.T) {
	s, taskID, dir := startDiscoverySession(t, map[string]any{
		"lists":          []string{"builtin-short-directories"},
		"observed_names": true,
		"threads":        1,
	}, func(s *Server, origin string) {
		// An exchange on the target's host is what "observed names" reads: a
		// directory segment and a filename stem the site really uses. Seeded
		// before the POST so the merge reads it.
		reqID, err := s.store.Put([]byte("GET /products/widget HTTP/1.1\r\nHost: h\r\n\r\n"), core.DirectionRequest)
		if err != nil {
			t.Fatalf("put: %v", err)
		}
		s.store.AddExchange(&core.Exchange{Host: "127.0.0.1", Port: 1, Method: "GET", Path: "/products/widget", Request: core.MsgPtr(reqID)})
	}, nil)

	run := waitForDiscovery(t, s, taskID)
	if run.Outcome != "completed" {
		t.Fatalf("outcome = %q error = %q", run.Outcome, run.Error)
	}

	// The fake copied the merged wordlist it was handed; the copy is the file
	// ffuf read, which is the strongest form of "the merged wordlist contains".
	raw, err := os.ReadFile(filepath.Join(dir, "wordlist-0.copy"))
	if err != nil {
		t.Fatalf("the fake ffuf copied no wordlist: %v", err)
	}
	merged := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		merged[strings.TrimSpace(line)] = true
	}
	if !merged["admin"] {
		t.Errorf("the merged wordlist lacks 'admin' from the built-in short directory list:\n%s", raw)
	}
	if !merged["products"] || !merged["widget"] {
		t.Errorf("the merged wordlist lacks the observed names 'products'/'widget':\n%s", raw)
	}
}

// A flat run — no recursion, no lists, just the operator's wordlist — reports
// levels as the empty array, never null, and issues exactly the one run it
// always did.
func TestAFlatRunStillReportsEmptyLevelsAndOneRun(t *testing.T) {
	own := filepath.Join(t.TempDir(), "own.txt")
	if err := os.WriteFile(own, []byte("admin\n"), 0o644); err != nil {
		t.Fatalf("write own list: %v", err)
	}
	s, taskID, dir := startDiscoverySession(t, map[string]any{
		"wordlist": own,
		"threads":  1,
	}, nil, nil)

	run := waitForDiscovery(t, s, taskID)
	if run.Outcome != "completed" {
		t.Fatalf("outcome = %q error = %q", run.Outcome, run.Error)
	}
	if len(run.Levels) != 0 {
		t.Errorf("levels = %+v; a flat run recursed", run.Levels)
	}
	if log := argvLog(t, dir); len(log) != 1 {
		t.Errorf("the flat run issued %d invocations, want exactly one", len(log))
	}
	if !strings.Contains(rawRun(t, s, taskID), `"levels":[]`) {
		t.Error("levels must serialise as [], not null")
	}
}

// The variant-extension pass and the derivation pass each add exactly one run
// per directory that found something, and their hits count into the level.
func TestTheVariantAndDerivationPassesRunOverWhatWasDiscovered(t *testing.T) {
	s, taskID, dir := startDiscoverySession(t, map[string]any{
		"lists":              []string{"builtin-short-directories"},
		"recurse_depth":      1,
		"variant_extensions": "bak",
		"derivations":        true,
		"threads":            1,
	}, nil, nil)

	run := waitForDiscovery(t, s, taskID)
	if run.Outcome != "completed" {
		t.Fatalf("outcome = %q error = %q", run.Outcome, run.Error)
	}
	// Base sweep and its derivation pass over what it found (admin → admin_old,
	// ...; it found no file, so no variant pass), then /admin/'s three: the
	// sweep, the variant pass over the file stem it found (report), and the
	// derivation pass (deep_old, deep.bak, DEEP, report.txt_old, ...).
	log := argvLog(t, dir)
	if len(log) != 5 {
		t.Fatalf("the variant and derivation passes issued %d run(s) total, want 5:\n%s", len(log), strings.Join(log, "\n"))
	}
	if len(run.Levels) != 2 || run.Levels[0].Level != 0 || run.Levels[0].Runs != 1 || run.Levels[1].Runs != 3 {
		t.Errorf("levels = %+v, want level 0 with the base derivation run and level 1 with 3 runs", run.Levels)
	}
	if second := argvURL(log[1]); strings.Contains(second, "/admin/") {
		t.Errorf("the base derivation pass swept %q, want the target root", second)
	}
	third, fourth := argvURL(log[3]), argvURL(log[4])
	if !strings.HasSuffix(third, "/admin/FUZZ") {
		t.Errorf("the variant pass swept %q, want /admin/", third)
	}
	if !strings.HasSuffix(fourth, "/admin/FUZZ") {
		t.Errorf("the derivation pass swept %q, want /admin/", fourth)
	}
	// The variant pass asked for the .bak extension; the derivation pass's
	// wordlist is the derived names. Both are visible in the recorded argv.
	if !strings.Contains(log[3], "-e bak") {
		t.Errorf("the variant pass did not carry the variant extensions: %q", log[3])
	}
}

// The new parameters are validated before anything is registered or run.
func TestDiscoverySessionParameterValidation(t *testing.T) {
	s := newTestServer()
	for _, body := range []map[string]any{
		{"target": "https://target.test/", "lists": []string{"builtin-short-files", "builtin-made-up"}},
		{"target": "https://target.test/", "recurse_depth": -1},
		{"target": "https://target.test/", "lists": []string{"builtin-short-files"}, "recurse_depth": MaxDiscoveryRecurseDepth + 1},
		{"target": "https://target.test/"},
	} {
		rec := postJSON(t, s, "/api/discovery", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST %v: status = %d, want 400 (%s)", body, rec.Code, rec.Body.String())
		}
	}
	if n := len(s.tasks.Snapshot()); n != 0 {
		t.Errorf("a malformed request registered %d task(s)", n)
	}
}

// The passes run over the BASE sweep too (review finding): with no recursion, a file the base sweep
// found is still variant-tested in the directory it was found in.
func TestTheVariantPassRunsOverTheBaseSweepWithoutRecursion(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "origin") }))
	t.Cleanup(origin.Close)
	dir := t.TempDir()
	s := newTestServer().WithExternalTools(map[string]string{extscan.ToolFFUF: fakeFFUF(t, dir)})
	s.scope.AddInclude(mustHostname(t, origin.URL))
	own := filepath.Join(t.TempDir(), "own.txt")
	if err := os.WriteFile(own, []byte("report\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := postJSON(t, s, "/api/discovery", map[string]any{"target": origin.URL + "/admin/", "wordlist": own,
		"variant_extensions": "bak", "threads": 1})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST = %d %s", rec.Code, rec.Body.String())
	}
	var start struct {
		TaskID uint64 `json:"task_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &start)
	run := waitForDiscovery(t, s, start.TaskID)
	log := argvLog(t, dir)
	if len(log) != 2 || !strings.Contains(log[1], "-e bak") || !strings.HasSuffix(argvURL(log[1]), "/admin/FUZZ") {
		t.Fatalf("with recurse_depth 0 the runs were:\n%s\nwant the base sweep then a variant pass in /admin/", strings.Join(log, "\n"))
	}
	if len(run.Levels) != 1 || run.Levels[0].Level != 0 {
		t.Errorf("levels = %+v, want the base level recording the variant pass", run.Levels)
	}
}

// A directory found under a target with a path prefix is swept at its own path, not at the prefix
// doubled (review finding: /app/ + /app/admin made /app/app/admin/).
func TestSessionDirectoriesUseTheOriginNotTheParentPath(t *testing.T) {
	got := sessionDirectories(extscan.Target{URL: "https://h.test/app/"}, []extscan.Discovery{{Path: "/app/admin/"}})
	if len(got) != 1 || got[0].url != "https://h.test/app/admin/" {
		t.Errorf("directories = %+v, want https://h.test/app/admin/", got)
	}
}

// Observed names are path segments only: a query string is not a name, and an escape is decoded.
func TestObservedNamesIgnoreQueryStrings(t *testing.T) {
	s := newTestServer()
	req, _ := s.store.Put([]byte("GET /search%20page/list.php?q=a/b HTTP/1.1\r\nHost: h.test\r\n\r\n"), core.DirectionRequest)
	s.store.AddExchange(&core.Exchange{Request: core.MsgPtr(req), Host: "h.test", Port: 443, TLS: true, Method: "GET",
		Path: "/search%20page/list.php?q=a/b"})
	names := s.observedNames(extscan.Target{Host: "h.test"})
	if strings.Join(names, ",") != "list,search page" {
		t.Errorf("observed names = %q, want [list search page]", names)
	}
}

// Derived numeric names keep their zero padding (review finding: report009 derived report0010).
func TestDerivedNumbersKeepTheirWidth(t *testing.T) {
	got := deriveDiscoveryNames(extscan.Discovery{Path: "/report009"})
	if len(got) < 2 || got[0] != "report010" || got[1] != "report011" {
		t.Errorf("derived = %q, want report010 and report011 first", got)
	}
}
