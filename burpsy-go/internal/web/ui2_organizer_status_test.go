package web

import (
	"encoding/json"
	"github.com/burpsy-go/burpsy/internal/organizer"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func workflowPost(s *Server, action string, f url.Values) string {
	r := httptest.NewRequest("POST", "/ui2/organizer/status/"+action, strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w.Body.String()
}
func workflowForm(it organizer.Item, status string) url.Values {
	return url.Values{"op": {"status"}, "item_id": {strconv.Itoa(it.ID)}, "form_base": {ui2WorkflowDigest(it)}, "status": {status}}
}
func workflowReview(t *testing.T, s *Server, f url.Values) (url.Values, string) {
	t.Helper()
	out := workflowPost(s, "confirm", f)
	run := url.Values{}
	for _, k := range []string{"review_id", "token"} {
		m := regexp.MustCompile(`name="` + k + `" value="([^"]+)"`).FindStringSubmatch(out)
		if len(m) != 2 {
			t.Fatalf("missing %s: %s", k, out)
		}
		run.Set(k, m[1])
	}
	return run, out
}
func workflowRefuse(t *testing.T, s *Server, f url.Values, word string) {
	t.Helper()
	out := workflowPost(s, "confirm", f)
	if !strings.Contains(out, word) || strings.Contains(out, `name="token"`) {
		t.Fatalf("expected refusal %s: %s", word, out)
	}
}
func TestUI2WorkflowFlowAndPreservation(t *testing.T) {
	s := organizerTestServer(t)
	c, _ := s.organizer.NewCollection("group")
	it := s.organizer.Add(999999)
	s.organizer.Update(it.ID, "<b>title</b>", "private note", "red")
	s.organizer.MoveToCollection([]int{it.ID}, c.ID)
	s.organizer.Add(999998)
	collections, _ := json.Marshal(s.organizer.Collections())
	for _, status := range []string{"in_progress", "postponed", "done", "ignored", "new"} {
		before := s.organizer.List()
		it = before[0]
		run, sheet := workflowReview(t, s, workflowForm(it, status))
		if strings.Contains(sheet, "<b>title</b>") || !strings.Contains(sheet, "&lt;b&gt;title&lt;/b&gt;") || strings.Contains(sheet, "private note") || strings.Contains(sheet, "999999") {
			t.Fatal("review exposes traffic/context or unsafe markup")
		}
		pending, _ := json.Marshal(s.organizer.List())
		b, _ := json.Marshal(before)
		if string(pending) != string(b) {
			t.Fatal("mint mutated")
		}
		if out := workflowPost(s, "run", run); !strings.Contains(out, "workflow status saved") {
			t.Fatal(out)
		}
		expected := append([]organizer.Item{}, before...)
		expected[0].Status = organizer.Status(status)
		want, _ := json.Marshal(expected)
		got, _ := json.Marshal(s.organizer.List())
		if string(want) != string(got) {
			t.Fatalf("non-status fields changed: %s != %s", want, got)
		}
		afterC, _ := json.Marshal(s.organizer.Collections())
		if string(afterC) != string(collections) {
			t.Fatal("collections changed")
		}
		if out := workflowPost(s, "run", run); !strings.Contains(out, "already used") {
			t.Fatal("replay accepted")
		}
	}
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest("GET", "/ui2/organizer", nil))
	page := w.Body.String()
	for _, word := range []string{"HTTP status", "Workflow status", "unavailable", "&lt;b&gt;title&lt;/b&gt;", "value=\"new\""} {
		if !strings.Contains(page, word) {
			t.Fatal("page missing " + word)
		}
	}
	if strings.Contains(page, "<b>title</b>") {
		t.Fatal("unsafe page markup")
	}
	// The form base is the stored item, never the traffic-resolved wrapper.
	if !strings.Contains(page, ui2WorkflowDigest(s.organizer.List()[0])) {
		t.Fatal("wrong form digest")
	}
}
func TestUI2WorkflowRefusals(t *testing.T) {
	s := organizerTestServer(t)
	it := s.organizer.Add(9999)
	workflowRefuse(t, s, workflowForm(it, "invented"), "new, in_progress, postponed, done or ignored")
	workflowRefuse(t, s, workflowForm(it, "new"), "already new")
	for _, k := range []string{"foreign", "op", "item_id", "form_base", "status"} {
		f := workflowForm(it, "done")
		f.Add(k, "bad")
		workflowRefuse(t, s, f, "single permitted")
	}
	for _, k := range []string{"op", "item_id", "form_base", "status"} {
		f := workflowForm(it, "done")
		f.Del(k)
		workflowRefuse(t, s, f, "single permitted")
	}
	f := workflowForm(it, "done")
	f.Set("form_base", "stale")
	workflowRefuse(t, s, f, "changed since this form")
	run, _ := workflowReview(t, s, workflowForm(it, "done"))
	s.organizer.Update(it.ID, "changed", "note", "blue")
	out := workflowPost(s, "run", run)
	if !strings.Contains(out, "changed since review") {
		t.Fatal("stale install accepted: " + out)
	}
	if s.organizer.List()[0].Status != organizer.StatusNew {
		t.Fatal("stale write changed state")
	}
	it = s.organizer.List()[0]
	run, _ = workflowReview(t, s, workflowForm(it, "done"))
	s.organizer.Remove(it.ID)
	if out := workflowPost(s, "run", run); !strings.Contains(out, "no longer exists") {
		t.Fatal("deleted install accepted")
	}
}
func TestUI2WorkflowBindingExpiryAndLimit(t *testing.T) {
	s := organizerTestServer(t)
	it := s.organizer.Add(9999)
	run, _ := workflowReview(t, s, workflowForm(it, "done"))
	v, _ := s.ui2WorkflowReviews.Load(run.Get("review_id"))
	e := v.(ui2CollectionReview)
	e.body = []byte(`{"workflow_status":"ignored"}`)
	s.ui2WorkflowReviews.Store(run.Get("review_id"), e)
	if out := workflowPost(s, "run", run); !strings.Contains(out, "does not match") {
		t.Fatal("tamper accepted")
	}
	run, _ = workflowReview(t, s, workflowForm(it, "done"))
	v, _ = s.ui2WorkflowReviews.Load(run.Get("review_id"))
	e = v.(ui2CollectionReview)
	e.expires = time.Now().Add(-time.Second)
	s.ui2WorkflowReviews.Store(run.Get("review_id"), e)
	if out := workflowPost(s, "run", run); !strings.Contains(out, "expired") {
		t.Fatal("expiry accepted")
	}
	// Re-signed invalid held payload exercises install enum validation independently of mint.
	run, _ = workflowReview(t, s, workflowForm(it, "done"))
	v, _ = s.ui2WorkflowReviews.Load(run.Get("review_id"))
	e = v.(ui2CollectionReview)
	e.body, _ = json.Marshal(ui2WorkflowChange{Before: it, Status: "invalid"})
	token, _ := s.confirms.issue("ui2-workflow", newCallBinding("POST", "/ui2/organizer/status/install", "", e.body))
	s.ui2WorkflowReviews.Store(run.Get("review_id"), e)
	run.Set("token", token)
	if out := workflowPost(s, "run", run); !strings.Contains(out, "workflow status must be") {
		t.Fatal("install enum accepted")
	}
	if s.organizer.List()[0] != it {
		t.Fatal("refusal mutated")
	}
	for i := 0; i < 8; i++ {
		workflowReview(t, s, workflowForm(it, "done"))
	}
	workflowRefuse(t, s, workflowForm(it, "done"), "too many workflow")
}

func TestUI2WorkflowEveryStoredFieldStales(t *testing.T) {
	mutations := map[string]func(*organizer.Item){
		"exchange":   func(it *organizer.Item) { it.Exchange++ },
		"title":      func(it *organizer.Item) { it.Title = "outside" },
		"note":       func(it *organizer.Item) { it.Note = "outside" },
		"highlight":  func(it *organizer.Item) { it.Highlight = "blue" },
		"status":     func(it *organizer.Item) { it.Status = organizer.StatusIgnored },
		"collection": func(it *organizer.Item) { it.Collection = 12 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s := organizerTestServer(t)
			it := s.organizer.Add(9999)
			run, _ := workflowReview(t, s, workflowForm(it, "done"))
			outside := it
			mutate(&outside)
			s.organizer.Restore([]organizer.Item{outside}, nil)
			workflowRefuse(t, s, workflowForm(it, "done"), "changed since this form")
			if out := workflowPost(s, "run", run); !strings.Contains(out, "changed since review") {
				t.Fatal("stale install accepted: " + out)
			}
			if s.organizer.List()[0] != outside {
				t.Fatal("outside change overwritten")
			}
		})
	}
}
