package web

// Compare site maps (burpsy-react-ui-k3a7) — the HTTP surface. What these tests pin is the
// operator's question and the honest refusals, in the same style sitemap_delete_test.go drives
// DELETE /api/sitemap:
//
//   - two runs over one target: the rows say which side each path is on, and only_a/only_b/both
//     are the summary an operator reports;
//   - a task id of 0 is refused, because 0 is the stored "no task owns this" sentinel and no
//     operator can name a run that does not exist;
//   - the same run twice is refused — a site map diffed with itself answers nothing and would
//     report every path as "both";
//   - exchanges no other run owns stay out: the diff is between the two named runs and nothing
//     else, which is what makes it a comparison rather than a dump.
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// compareSitemaps posts the two task ids and decodes the answer.
func compareSitemaps(t *testing.T, s *Server, taskA, taskB uint64) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"task_a": taskA, "task_b": taskB})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/tools/compare-sitemaps", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode compare-sitemaps: %v", err)
		}
	}
	return rec.Code, out
}

// addAttributedTraffic records one exchange through the store — the same way addTraffic does,
// which is also the way the proxy and the crawler capture paths write — then stamps it with the
// run that owns it, exactly as crawler.WithTaskID stamps cfg.Capture.TaskID at launch.
func addAttributedTraffic(t *testing.T, s *Server, task uint64, host, method, path string, status int) *core.Exchange {
	t.Helper()
	ex := addTraffic(t, s.store, host, method, path)
	st := uint16(status)
	ex.Status = &st
	ex.TaskID = task
	return ex
}

func TestCompareSitemapsNamesWhichRunReachedEachPath(t *testing.T) {
	s := newTestServer()
	// Run 1 saw the anonymous surface; run 2 saw that plus the admin branch.
	addAttributedTraffic(t, s, 1, "app.test", "GET", "/index.html", 200)
	addAttributedTraffic(t, s, 1, "app.test", "GET", "/login", 200)
	addAttributedTraffic(t, s, 2, "app.test", "GET", "/index.html", 200)
	addAttributedTraffic(t, s, 2, "app.test", "GET", "/login", 200)
	addAttributedTraffic(t, s, 2, "app.test", "GET", "/admin", 200)
	// Traffic another run owns, and traffic nobody owns: neither belongs in this diff.
	addAttributedTraffic(t, s, 9, "app.test", "GET", "/elsewhere", 200)
	addAttributedTraffic(t, s, 0, "app.test", "GET", "/own-browsing", 200)

	code, out := compareSitemaps(t, s, 1, 2)
	if code != http.StatusOK {
		t.Fatalf("POST /api/tools/compare-sitemaps = %d: %s", code, "body unread")
	}
	if got := out["only_a"]; got != float64(0) {
		t.Errorf("only_a = %v, want 0 — nothing was reached by run 1 alone", got)
	}
	if got := out["only_b"]; got != float64(1) {
		t.Errorf("only_b = %v, want 1 — /admin is the access-control finding this feature exists to surface", got)
	}
	if got := out["both"]; got != float64(2) {
		t.Errorf("both = %v, want 2 (index.html and login)", got)
	}
	rows := out["rows"].([]any)
	byPath := map[string]map[string]any{}
	for _, raw := range rows {
		row := raw.(map[string]any)
		byPath[row["path"].(string)] = row
	}
	if side := byPath["/admin"]["side"]; side != "b" {
		t.Errorf("/admin side = %v, want b", side)
	}
	if side := byPath["/index.html"]["side"]; side != "both" {
		t.Errorf("/index.html side = %v, want both", side)
	}
	// The rows another run owns must not appear as either side.
	for _, p := range []string{"/elsewhere", "/own-browsing"} {
		if _, present := byPath[p]; present {
			t.Errorf("%s appears in the diff, but neither named run reached it — the comparison is between the two runs and nothing else", p)
		}
	}
}

func TestCompareSitemapsRefusesAZeroTask(t *testing.T) {
	s := newTestServer()
	code, _ := compareSitemaps(t, s, 1, 0)
	if code != http.StatusBadRequest {
		t.Errorf("task_b = 0 answered %d, want 400 — 0 is the stored sentinel for \"no task owns this\", not a run an operator can name", code)
	}
}

func TestCompareSitemapsRefusesTheSameRunTwice(t *testing.T) {
	s := newTestServer()
	code, _ := compareSitemaps(t, s, 4, 4)
	if code != http.StatusBadRequest {
		t.Errorf("comparing run 4 with itself answered %d, want 400 — every path would read \"both\" and the operator would learn nothing", code)
	}
}

func TestCompareSitemapsEmptyRunsAnswerEmptyNotError(t *testing.T) {
	s := newTestServer()
	code, out := compareSitemaps(t, s, 2, 3)
	if code != http.StatusOK {
		t.Fatalf("two runs with no traffic answered %d, want 200 — an empty diff is the honest answer for empty runs", code)
	}
	if rows := out["rows"].([]any); len(rows) != 0 {
		t.Errorf("rows = %v, want none", rows)
	}
	if got := out["only_a"]; got != float64(0) {
		t.Errorf("only_a = %v, want 0", got)
	}
}
