package web

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/organizer"
)

func itemOpPost(s *Server, action string, f url.Values) string {
	r := httptest.NewRequest("POST", "/ui2/organizer/items/"+action, strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w.Body.String()
}
func itemOpForm(it organizer.Item, op string, dest int) url.Values {
	return url.Values{"op": {op}, "item_id": {strconv.Itoa(it.ID)}, "form_base": {ui2WorkflowDigest(it)}, "collection_id": {strconv.Itoa(dest)}}
}
func itemOpReview(t *testing.T, s *Server, f url.Values) (url.Values, string) {
	t.Helper()
	sheet := itemOpPost(s, "confirm", f)
	run := url.Values{}
	for _, k := range []string{"review_id", "token"} {
		m := regexp.MustCompile(`name="` + k + `" value="([^"]+)"`).FindStringSubmatch(sheet)
		if len(m) != 2 {
			t.Fatalf("missing %s: %s", k, sheet)
		}
		run.Set(k, m[1])
	}
	return run, sheet
}
func itemOpRefuse(t *testing.T, s *Server, f url.Values, word string) {
	t.Helper()
	sheet := itemOpPost(s, "confirm", f)
	if !strings.Contains(sheet, word) || strings.Contains(sheet, `name="token"`) {
		t.Fatalf("expected refusal %s: %s", word, sheet)
	}
}

func TestUI2ItemOpsFlowAndPreservation(t *testing.T) {
	s := organizerTestServer(t)
	a, _ := s.organizer.NewCollection("alpha")
	b, _ := s.organizer.NewCollection("beta")
	it := s.organizer.Add(999999)
	s.organizer.Update(it.ID, "<b>title</b>", "private note", "red")
	s.organizer.MoveToCollection([]int{it.ID}, a.ID)
	s.organizer.Add(999998)

	// Move: only membership changes; the review sheet never shows the note or raw markup.
	before, _ := json.Marshal(s.organizer.List())
	run, sheet := itemOpReview(t, s, itemOpForm(s.organizer.List()[0], "move", b.ID))
	if strings.Contains(sheet, "<b>title</b>") || !strings.Contains(sheet, "&lt;b&gt;title&lt;/b&gt;") || strings.Contains(sheet, "private note") {
		t.Fatal("move review exposes note or unsafe markup")
	}
	if !strings.Contains(sheet, "beta") {
		t.Fatal("move review hides the reviewed destination")
	}
	pending, _ := json.Marshal(s.organizer.List())
	if string(pending) != string(before) {
		t.Fatal("mint mutated")
	}
	if out := itemOpPost(s, "run", run); !strings.Contains(out, "moved to beta") {
		t.Fatal(out)
	}
	moved := s.organizer.List()
	if moved[0].Collection != b.ID || len(moved) != 2 {
		t.Fatal("move not applied")
	}
	moved[0].Collection = a.ID
	want, _ := json.Marshal(moved)
	if string(want) != string(before) {
		t.Fatal("move changed more than membership")
	}
	if out := itemOpPost(s, "run", run); !strings.Contains(out, "already used") {
		t.Fatal("replay accepted")
	}

	// Copy into the same collection is the duplicate: fresh id, reviewed fields, source untouched.
	before, _ = json.Marshal(s.organizer.List())
	run, sheet = itemOpReview(t, s, itemOpForm(s.organizer.List()[0], "copy", a.ID))
	if strings.Contains(sheet, "private note") {
		t.Fatal("copy review exposes note")
	}
	if out := itemOpPost(s, "run", run); !strings.Contains(out, "copied to alpha") {
		t.Fatal(out)
	}
	grown := s.organizer.List()
	if len(grown) != 3 || grown[0] != s.organizer.List()[0] {
		t.Fatal("copy changed the source")
	}
	dup := grown[2]
	if dup.ID <= grown[1].ID || dup.Collection != a.ID || dup.Title != "<b>title</b>" || dup.Note != "private note" || dup.Highlight != "red" || dup.Status != grown[0].Status || dup.Exchange != grown[0].Exchange {
		t.Fatalf("copy not a reviewed duplicate: %+v", dup)
	}
	_ = before

	// Delete removes only the saved item; collections and the other item stay.
	run, sheet = itemOpReview(t, s, itemOpForm(s.organizer.List()[2], "delete", 0))
	if strings.Contains(sheet, "private note") {
		t.Fatal("delete review exposes note")
	}
	collections, _ := json.Marshal(s.organizer.Collections())
	if out := itemOpPost(s, "run", run); !strings.Contains(out, "deleted; its exchange and history are kept") {
		t.Fatal(out)
	}
	if len(s.organizer.List()) != 2 {
		t.Fatal("delete removed more than the item")
	}
	afterC, _ := json.Marshal(s.organizer.Collections())
	if string(afterC) != string(collections) {
		t.Fatal("delete changed collections")
	}
	if out := itemOpPost(s, "run", run); !strings.Contains(out, "already used") {
		t.Fatal("delete replay accepted")
	}
}

func TestUI2ItemOpsRefusals(t *testing.T) {
	s := organizerTestServer(t)
	a, _ := s.organizer.NewCollection("alpha")
	it := s.organizer.Add(999999)
	s.organizer.MoveToCollection([]int{it.ID}, a.ID)
	it = s.organizer.List()[0]

	itemOpRefuse(t, s, itemOpForm(it, "rename", a.ID), "unknown item operation")
	itemOpRefuse(t, s, itemOpForm(it, "move", 999), "no longer exists")
	itemOpRefuse(t, s, itemOpForm(it, "copy", 999), "no longer exists")
	itemOpRefuse(t, s, itemOpForm(it, "move", a.ID), "already in that collection")
	itemOpRefuse(t, s, itemOpForm(organizer.Item{ID: 999}, "move", a.ID), "no longer exists")
	f := itemOpForm(it, "move", a.ID)
	f.Set("form_base", "stale")
	itemOpRefuse(t, s, f, "changed since this form")
	f = itemOpForm(it, "delete", 0)
	f.Set("collection_id", strconv.Itoa(a.ID))
	itemOpRefuse(t, s, f, "delete takes no destination")
	for _, k := range []string{"foreign", "op", "item_id", "form_base", "collection_id"} {
		f = itemOpForm(it, "move", 0)
		f.Add(k, "bad")
		itemOpRefuse(t, s, f, "single permitted")
	}

	// A changed item between review and install is refused; nothing applied.
	run, _ := itemOpReview(t, s, itemOpForm(it, "move", 0))
	s.organizer.Update(it.ID, "changed", "note", "blue")
	if out := itemOpPost(s, "run", run); !strings.Contains(out, "changed since review") {
		t.Fatal("stale install accepted")
	}
	// A renamed destination between review and install is refused.
	it = s.organizer.List()[0]
	b2, _ := s.organizer.NewCollection("target")
	run, _ = itemOpReview(t, s, itemOpForm(it, "move", b2.ID))
	s.organizer.RenameCollection(b2.ID, "drifted")
	if out := itemOpPost(s, "run", run); !strings.Contains(out, "renamed since review") {
		t.Fatal("renamed destination accepted")
	}
	// A deleted destination between review and install is refused.
	run, _ = itemOpReview(t, s, itemOpForm(it, "move", b2.ID))
	s.organizer.DeleteCollection(b2.ID, false)
	if out := itemOpPost(s, "run", run); !strings.Contains(out, "no longer exists") {
		t.Fatal("deleted destination accepted")
	}
	// A removed item between review and install is refused.
	run, _ = itemOpReview(t, s, itemOpForm(it, "delete", 0))
	s.organizer.Remove(it.ID)
	if out := itemOpPost(s, "run", run); !strings.Contains(out, "no longer exists") {
		t.Fatal("removed item accepted")
	}
	// Review cap: the ninth pending review is refused.
	it = s.organizer.Add(1)
	for i := 0; i < 8; i++ {
		itemOpReview(t, s, itemOpForm(it, "move", a.ID))
	}
	itemOpRefuse(t, s, itemOpForm(it, "move", a.ID), "too many item reviews")
}

func TestUI2AnnotateHighlightPrefill(t *testing.T) {
	s := organizerTestServer(t)
	it := s.organizer.Add(4242)
	s.organizer.Update(it.ID, "title", "note", "red")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest("GET", "/ui2/organizer", nil))
	page := w.Body.String()
	if !strings.Contains(page, `value="red" checked`) {
		t.Fatal("current highlight not pre-checked; a title-only edit is browser-blocked")
	}
	if strings.Contains(page, `value="none" checked`) {
		t.Fatal("none pre-checked over the current red highlight")
	}
	// A title-only edit with the pre-checked highlight keeps the highlight unchanged.
	run, _ := annotateReview(t, s, annotateForm(s.organizer.List()[0], "retitled", "note", "red"))
	if out := annotatePost(s, "run", run); !strings.Contains(out, "annotations saved") {
		t.Fatal(out)
	}
	if got := s.organizer.List()[0]; got.Highlight != "red" || got.Title != "retitled" {
		t.Fatalf("title-only edit changed highlight: %+v", got)
	}
	// A default item pre-checks the none literal.
	s2 := organizerTestServer(t)
	s2.organizer.Add(4242)
	w2 := httptest.NewRecorder()
	s2.mux.ServeHTTP(w2, httptest.NewRequest("GET", "/ui2/organizer", nil))
	if !strings.Contains(w2.Body.String(), `value="none" checked`) {
		t.Fatal("none not pre-checked for a default item")
	}
}
