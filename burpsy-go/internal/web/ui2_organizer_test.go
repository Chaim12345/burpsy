package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/organizer"
)

func collectionPost(s *Server, action string, f url.Values) string {
	r := httptest.NewRequest(http.MethodPost, "/ui2/organizer/collections/"+action, strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w.Body.String()
}
func collectionForm(c organizer.Collection, name, note string) url.Values {
	return url.Values{"op": {"edit"}, "collection_id": {strconv.Itoa(c.ID)}, "form_base": {ui2CollectionDigest(c)}, "name": {name}, "note": {note}}
}
func collectionReview(t *testing.T, s *Server, f url.Values) (url.Values, string) {
	t.Helper()
	sheet := collectionPost(s, "confirm", f)
	out := url.Values{}
	for _, key := range []string{"review_id", "token"} {
		m := regexp.MustCompile(`name="` + key + `" value="([^"]+)"`).FindStringSubmatch(sheet)
		if len(m) != 2 {
			t.Fatalf("missing %s: %s", key, sheet)
		}
		out.Set(key, m[1])
	}
	return out, sheet
}
func collectionRefuse(t *testing.T, s *Server, f url.Values, word string) {
	t.Helper()
	sheet := collectionPost(s, "confirm", f)
	if !strings.Contains(sheet, word) || strings.Contains(sheet, `name="token"`) {
		t.Fatalf("expected refusal %s: %s", word, sheet)
	}
}
func TestUI2OrganizerCollectionFlowAndPreservation(t *testing.T) {
	s := organizerTestServer(t)
	c, _ := s.organizer.NewCollection("before")
	it := s.organizer.Add(0)
	s.organizer.MoveToCollection([]int{it.ID}, c.ID)
	before, _ := json.Marshal(s.organizer.List())
	f := collectionForm(c, "after", "<script>canary()</script>")
	run, sheet := collectionReview(t, s, f)
	if strings.Contains(sheet, "<script>canary()") || !strings.Contains(sheet, `\u003cscript\u003e`) {
		t.Fatal("collection review markup escaping failed")
	}
	if s.organizer.Collections()[0] != c {
		t.Fatal("review mutated collection")
	}
	if out := collectionPost(s, "run", run); !strings.Contains(out, "collection saved") {
		t.Fatal(out)
	}
	after, _ := json.Marshal(s.organizer.List())
	if string(before) != string(after) {
		t.Fatal("collection edit moved or changed items")
	}
	got := s.organizer.Collections()[0]
	if got.Name != "after" || got.Note != "<script>canary()</script>" {
		t.Fatal("edit not applied")
	}
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest("GET", "/ui2/organizer", nil))
	page := w.Body.String()
	if strings.Contains(page, "<script>canary()") || !strings.Contains(page, "&lt;script&gt;canary()") {
		t.Fatal("collection page markup escaping failed")
	}
	if out := collectionPost(s, "run", run); !strings.Contains(out, "already used") {
		t.Fatal("review replay accepted")
	}
	run, _ = collectionReview(t, s, url.Values{"op": {"create"}, "name": {"new"}})
	if out := collectionPost(s, "run", run); !strings.Contains(out, "collection saved") {
		t.Fatal(out)
	}
}
func TestUI2OrganizerCollectionRefusals(t *testing.T) {
	s := organizerTestServer(t)
	c, _ := s.organizer.NewCollection("first")
	s.organizer.NewCollection("taken")
	f := collectionForm(c, "changed", "")
	f.Set("form_base", "stale")
	collectionRefuse(t, s, f, "changed since this form")
	collectionRefuse(t, s, collectionForm(c, "taken", ""), "already exists")
	for _, name := range []string{"Inbox", " inbox ", "INBOX"} {
		collectionRefuse(t, s, collectionForm(c, name, ""), "reserved")
	}
	collectionRefuse(t, s, collectionForm(c, strings.Repeat("x", 121), ""), "120 UTF-8")
	collectionRefuse(t, s, collectionForm(c, "valid", strings.Repeat("n", 4097)), "4096 UTF-8")
	collectionRefuse(t, s, collectionForm(c, " ", ""), "nonblank")
	for _, key := range []string{"foreign", "name", "op", "form_base", "collection_id", "note"} {
		f = collectionForm(c, "changed", "")
		f.Add(key, "bad")
		collectionRefuse(t, s, f, "single permitted")
	}
	collectionRefuse(t, s, collectionForm(organizer.Collection{ID: 0}, "new", ""), "not Inbox")
	for _, field := range []string{"name", "note"} {
		run, _ := collectionReview(t, s, collectionForm(c, "edited", "note"))
		if field == "name" {
			s.organizer.RenameCollection(c.ID, "external")
		} else {
			s.organizer.SetCollectionNote(c.ID, "external note")
		}
		if out := collectionPost(s, "run", run); !strings.Contains(out, "name or note changed") {
			t.Fatal("stale install accepted " + field)
		}
		c = s.organizer.Collections()[0]
	}
	run, _ := collectionReview(t, s, collectionForm(c, "newclash", ""))
	s.organizer.NewCollection("newclash")
	if out := collectionPost(s, "run", run); !strings.Contains(out, "already exists") {
		t.Fatal("duplicate edit install accepted")
	}
	run, _ = collectionReview(t, s, url.Values{"op": {"create"}, "name": {"createclash"}})
	s.organizer.NewCollection("createclash")
	if out := collectionPost(s, "run", run); !strings.Contains(out, "already exists") {
		t.Fatal("duplicate create install accepted")
	}
	run, _ = collectionReview(t, s, collectionForm(c, "valid", ""))
	s.organizer.DeleteCollection(c.ID, false)
	if out := collectionPost(s, "run", run); !strings.Contains(out, "no longer exists") {
		t.Fatal("deleted install accepted")
	}
}
func TestUI2OrganizerCollectionPayloadBinding(t *testing.T) {
	s := organizerTestServer(t)
	run, _ := collectionReview(t, s, url.Values{"op": {"create"}, "name": {"bound"}})
	v, _ := s.ui2CollectionReviews.Load(run.Get("review_id"))
	entry := v.(ui2CollectionReview)
	entry.body = []byte(`{"op":"create","name":"tampered"}`)
	s.ui2CollectionReviews.Store(run.Get("review_id"), entry)
	if out := collectionPost(s, "run", run); !strings.Contains(out, "does not match") {
		t.Fatal("payload tamper accepted")
	}
	if len(s.organizer.Collections()) != 0 {
		t.Fatal("payload tamper mutated")
	}
	// A valid held payload remains subject to install-time reserved-name and cap checks.
	for _, name := range []string{"Inbox", strings.Repeat("x", 121)} {
		run, _ = collectionReview(t, s, url.Values{"op": {"create"}, "name": {"valid"}})
		v, _ = s.ui2CollectionReviews.Load(run.Get("review_id"))
		e := v.(ui2CollectionReview)
		e.body, _ = json.Marshal(ui2CollectionChange{Op: "create", Name: name})
		token, _ := s.confirms.issue("ui2-collection", newCallBinding("POST", "/ui2/organizer/collections/install", "", e.body))
		e.token = token
		s.ui2CollectionReviews.Store(run.Get("review_id"), e)
		run.Set("token", token)
		out := collectionPost(s, "run", run)
		if !strings.Contains(out, "reserved") && !strings.Contains(out, "120 UTF-8") {
			t.Fatal("install validation skipped")
		}
	}
}
