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

func annotatePost(s *Server, action string, f url.Values) string {
	r := httptest.NewRequest("POST", "/ui2/organizer/annotate/"+action, strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w.Body.String()
}
func annotateForm(it organizer.Item, title, note, highlight string) url.Values {
	return url.Values{"op": {"annotate"}, "item_id": {strconv.Itoa(it.ID)}, "form_base": {ui2WorkflowDigest(it)}, "title": {title}, "note": {note}, "highlight": {highlight}}
}
func annotateReview(t *testing.T, s *Server, f url.Values) (url.Values, string) {
	t.Helper()
	out := annotatePost(s, "confirm", f)
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
func annotateRefuse(t *testing.T, s *Server, f url.Values, word string) {
	t.Helper()
	out := annotatePost(s, "confirm", f)
	if !strings.Contains(out, word) || strings.Contains(out, `name="token"`) {
		t.Fatalf("expected refusal %s: %s", word, out)
	}
}

func TestUI2AnnotateFlowAndPreservation(t *testing.T) {
	s := organizerTestServer(t)
	c, _ := s.organizer.NewCollection("group")
	it := s.organizer.Add(999999)
	s.organizer.Update(it.ID, "<b>title</b>", "private note", "red")
	s.organizer.MoveToCollection([]int{it.ID}, c.ID)
	s.organizer.Add(999998)
	collections, _ := json.Marshal(s.organizer.Collections())

	// Review discloses only the item's own annotation fields, escaped; no request content.
	it = s.organizer.List()[0]
	run, sheet := annotateReview(t, s, annotateForm(it, "renamed", "new note", "blue"))
	if strings.Contains(sheet, "<b>title</b>") || !strings.Contains(sheet, "&lt;b&gt;title&lt;/b&gt;") {
		t.Fatal("review title not escaped")
	}
	if !strings.Contains(sheet, "private note") || !strings.Contains(sheet, "new note") || strings.Contains(sheet, "999999") {
		t.Fatal("review leaks note or exchange")
	}
	if !strings.Contains(sheet, "red") || !strings.Contains(sheet, "blue") {
		t.Fatal("review omits highlight change")
	}
	if out := annotatePost(s, "run", run); !strings.Contains(out, "annotations saved") {
		t.Fatal(out)
	}
	got := s.organizer.List()[0]
	want := it
	want.Title, want.Note, want.Highlight = "renamed", "new note", "blue"
	if got != want {
		t.Fatalf("non-annotation fields changed: %+v != %+v", want, got)
	}
	marsh, _ := json.Marshal(s.organizer.List()[0])
	wantm, _ := json.Marshal(want)
	if string(marsh) != string(wantm) {
		t.Fatal("marshal mismatch")
	}
	afterC, _ := json.Marshal(s.organizer.Collections())
	if string(afterC) != string(collections) {
		t.Fatal("collections changed")
	}
	if out := annotatePost(s, "run", run); !strings.Contains(out, "already used") {
		t.Fatal("replay accepted")
	}

	// Blank title renders explicitly; verbatim bytes preserved (no trimming).
	it = s.organizer.List()[0]
	padded := "  padded  "
	run, sheet = annotateReview(t, s, annotateForm(it, "", padded, "none"))
	if !strings.Contains(sheet, "(blank)") {
		t.Fatal("blank title not named")
	}
	annotatePost(s, "run", run)
	if got := s.organizer.List()[0]; got.Title != "" || got.Note != padded {
		t.Fatal("values trimmed or blank not stored")
	}

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest("GET", "/ui2/organizer", nil))
	page := w.Body.String()
	for _, word := range []string{"Annotation editors", "Edit annotations for item #", "current highlight:", "value=\"none\""} {
		if !strings.Contains(page, word) {
			t.Fatal("page missing " + word)
		}
	}
	if strings.Contains(page, "<b>title</b>") {
		t.Fatal("unsafe page markup")
	}
	if !strings.Contains(page, ui2WorkflowDigest(s.organizer.List()[0])) {
		t.Fatal("wrong form digest")
	}
}

func TestUI2AnnotateRefusals(t *testing.T) {
	s := organizerTestServer(t)
	it := s.organizer.Add(9999)
	annotateRefuse(t, s, annotateForm(it, "t", "n", "invented"), "none, red, orange, yellow, green, cyan, blue, pink, magenta or gray")
	annotateRefuse(t, s, annotateForm(it, "t", "n", ""), "must be none, red")
	annotateRefuse(t, s, annotateForm(it, it.Title, it.Note, it.Highlight), "unchanged")
	annotateRefuse(t, s, annotateForm(it, strings.Repeat("x", 513), "n", "red"), "512 UTF-8 bytes")
	annotateRefuse(t, s, annotateForm(it, "t", strings.Repeat("x", 4097), "red"), "4096 UTF-8 bytes")
	for _, k := range []string{"foreign", "op", "item_id", "form_base", "title", "note", "highlight"} {
		f := annotateForm(it, "t", "n", "red")
		f.Add(k, "bad")
		annotateRefuse(t, s, f, "single permitted")
	}
	for _, k := range []string{"op", "item_id", "form_base", "title", "note", "highlight"} {
		f := annotateForm(it, "t", "n", "red")
		f.Del(k)
		annotateRefuse(t, s, f, "single permitted")
	}
	f := annotateForm(it, "t", "n", "red")
	f.Set("form_base", "stale")
	annotateRefuse(t, s, f, "changed since this form")
	run, _ := annotateReview(t, s, annotateForm(it, "t", "n", "red"))
	s.organizer.Update(it.ID, "changed", "note", "blue")
	if out := annotatePost(s, "run", run); !strings.Contains(out, "changed since review") {
		t.Fatal("stale install accepted: " + out)
	}
	if s.organizer.List()[0].Title != "changed" {
		t.Fatal("stale write changed state")
	}
	it = s.organizer.List()[0]
	run, _ = annotateReview(t, s, annotateForm(it, "t2", "n2", "gray"))
	s.organizer.Remove(it.ID)
	if out := annotatePost(s, "run", run); !strings.Contains(out, "no longer exists") {
		t.Fatal("deleted install accepted")
	}
}

func TestUI2AnnotateBindingExpiryAndLimit(t *testing.T) {
	s := organizerTestServer(t)
	it := s.organizer.Add(9999)
	run, _ := annotateReview(t, s, annotateForm(it, "t", "n", "red"))
	v, _ := s.ui2AnnotateReviews.Load(run.Get("review_id"))
	e := v.(ui2CollectionReview)
	e.body = []byte(`{"highlight":"ignored"}`)
	s.ui2AnnotateReviews.Store(run.Get("review_id"), e)
	if out := annotatePost(s, "run", run); !strings.Contains(out, "does not match") {
		t.Fatal("tamper accepted")
	}
	run, _ = annotateReview(t, s, annotateForm(it, "t", "n", "red"))
	v, _ = s.ui2AnnotateReviews.Load(run.Get("review_id"))
	e = v.(ui2CollectionReview)
	e.expires = time.Now().Add(-time.Second)
	s.ui2AnnotateReviews.Store(run.Get("review_id"), e)
	if out := annotatePost(s, "run", run); !strings.Contains(out, "expired") {
		t.Fatal("expiry accepted")
	}
	// Re-signed invalid held payload exercises install validation independently of mint.
	run, _ = annotateReview(t, s, annotateForm(it, "t", "n", "red"))
	v, _ = s.ui2AnnotateReviews.Load(run.Get("review_id"))
	e = v.(ui2CollectionReview)
	e.body, _ = json.Marshal(ui2AnnotationChange{Before: it, Title: "t", Note: "n", Highlight: "invented"})
	token, _ := s.confirms.issue("ui2-annotate", newCallBinding("POST", "/ui2/organizer/annotate/install", "", e.body))
	s.ui2AnnotateReviews.Store(run.Get("review_id"), e)
	run.Set("token", token)
	if out := annotatePost(s, "run", run); !strings.Contains(out, "must be none, red") {
		t.Fatal("install enum accepted")
	}
	if s.organizer.List()[0] != it {
		t.Fatal("refusal mutated")
	}
	for i := 0; i < 8; i++ {
		annotateReview(t, s, annotateForm(it, "t", "n", "red"))
	}
	annotateRefuse(t, s, annotateForm(it, "t", "n", "red"), "too many annotation")
}

func TestUI2AnnotateEveryStoredFieldStales(t *testing.T) {
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
			run, _ := annotateReview(t, s, annotateForm(it, "t", "n", "red"))
			outside := it
			mutate(&outside)
			s.organizer.Restore([]organizer.Item{outside}, nil)
			annotateRefuse(t, s, annotateForm(it, "t", "n", "red"), "changed since this form")
			if out := annotatePost(s, "run", run); !strings.Contains(out, "changed since review") {
				t.Fatal("stale install accepted: " + out)
			}
			if s.organizer.List()[0] != outside {
				t.Fatal("outside change overwritten")
			}
		})
	}
}
