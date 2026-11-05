package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func orgGet(s *Server, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func orgPost(s *Server, path string, f url.Values) string {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w.Body.String()
}

func orgRun(t *testing.T, sheet string) url.Values {
	t.Helper()
	out := url.Values{}
	for _, key := range []string{"review_id", "token"} {
		m := regexp.MustCompile(`name="` + key + `" value="([^"]+)"`).FindStringSubmatch(sheet)
		if len(m) != 2 {
			t.Fatalf("missing %s: %s", key, sheet)
		}
		out.Set(key, m[1])
	}
	return out
}

func TestUI2OrganizerFiltersAndDetail(t *testing.T) {
	s := organizerTestServer(t)
	ok := captureExchange(t, s, "a.test", "/ok.js", 200, "text/javascript")
	bad := captureExchange(t, s, "a.test", "/missing", 404, "text/html")
	s.organizer.Add(ok)
	it := s.organizer.Add(bad)
	s.organizer.Update(it.ID, "the-404", "why", "red")
	s.organizer.Add(99999) // unresolved: exempt from every filter
	page := orgGet(s, "/ui2/organizer?status=4xx").Body.String()
	if !strings.Contains(page, "the-404") || strings.Contains(page, "/ok.js") || !strings.Contains(page, "1 shown unjudged") {
		t.Fatalf("status filter: %s", page)
	}
	page = orgGet(s, "/ui2/organizer?q=OK%5C.JS&regex=1").Body.String()
	if !strings.Contains(page, "/ok.js") || strings.Contains(page, "the-404") {
		t.Fatal("case-insensitive regex search did not select /ok.js")
	}
	page = orgGet(s, "/ui2/organizer?q=ok&negative=1&ext=js").Body.String()
	if strings.Contains(page, "the-404") || strings.Contains(page, "a.test/ok.js") {
		t.Fatal("negative search combined with extension should leave only the unjudged row")
	}
	page = orgGet(s, "/ui2/organizer?annotated=1&item="+strconv.Itoa(it.ID)).Body.String()
	for _, want := range []string{`id="org-detail"`, "Show in history", "GET", "Revert edits", `data-copy="why"`, "Review move to destination"} {
		if !strings.Contains(page, want) {
			t.Fatalf("detail missing %q", want)
		}
	}
	if strings.Contains(page, "a.test/ok.js") {
		t.Fatal("annotated filter kept an unannotated row")
	}
}

func TestUI2OrganizerExportCSV(t *testing.T) {
	s := organizerTestServer(t)
	it := s.organizer.Add(1)
	s.organizer.Update(it.ID, "=HYPERLINK(\"x\")", "plain", "")
	w := orgGet(s, "/ui2/organizer/export.csv")
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("export: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	want := `"ID","Title","Note","Highlight","Status","Exchange"` + "\n" + `"1","'=HYPERLINK(""x"")","plain","none","new","1"`
	if w.Body.String() != want {
		t.Fatalf("csv:\n%s\nwant\n%s", w.Body.String(), want)
	}
	if body := orgGet(s, "/ui2/organizer/export.csv?workflow=done").Body.String(); strings.Contains(body, "HYPERLINK") {
		t.Fatal("export ignored the filter")
	}
}

func TestUI2OrganizerAddExchange(t *testing.T) {
	s := organizerTestServer(t)
	id := captureExchange(t, s, "b.test", "/x", 200, "text/plain")
	sheet := orgPost(s, "/ui2/organizer/add/confirm", url.Values{"exchange": {strconv.Itoa(id)}})
	if len(s.organizer.List()) != 0 {
		t.Fatal("review saved an item")
	}
	out := orgPost(s, "/ui2/organizer/add/run", orgRun(t, sheet))
	if !strings.Contains(out, "saved to the Inbox") || len(s.organizer.List()) != 1 || s.organizer.List()[0].Exchange != id {
		t.Fatalf("add run: %s", out)
	}
	if out := orgPost(s, "/ui2/organizer/add/run", orgRun(t, sheet)); !strings.Contains(out, "already used") {
		t.Fatal("replay accepted")
	}
}

func TestUI2OrganizerAddExchangeRefusals(t *testing.T) {
	s := organizerTestServer(t)
	for _, f := range []url.Values{{"exchange": {"-1"}}, {"exchange": {""}}, {"exchange": {"424242"}}, {"exchange": {"0"}, "extra": {"1"}}} {
		if out := orgPost(s, "/ui2/organizer/add/confirm", f); !strings.Contains(out, "Not saved") || strings.Contains(out, `name="token"`) {
			t.Fatalf("refusal expected for %v: %s", f, out)
		}
	}
}

func TestUI2OrganizerCollectionDuplicateAndDelete(t *testing.T) {
	s := organizerTestServer(t)
	c, _ := s.organizer.NewCollection("src")
	it := s.organizer.Add(5)
	s.organizer.MoveToCollection([]int{it.ID}, c.ID)
	base := url.Values{"collection_id": {strconv.Itoa(c.ID)}, "form_base": {ui2CollectionDigest(c)}, "members_base": {ui2MembersDigest(s.organizer.Members(c.ID))}}
	dup := url.Values{"op": {"duplicate"}, "name": {"src (copy)"}}
	for k, v := range base {
		dup[k] = v
	}
	out := orgPost(s, "/ui2/organizer/collections/run", orgRun(t, orgPost(s, "/ui2/organizer/collections/confirm", dup)))
	if !strings.Contains(out, "duplicated") || len(s.organizer.Collections()) != 2 || len(s.organizer.List()) != 2 {
		t.Fatalf("duplicate: %s", out)
	}
	del := url.Values{"op": {"delete"}, "items": {"inbox"}}
	for k, v := range base {
		del[k] = v
	}
	out = orgPost(s, "/ui2/organizer/collections/run", orgRun(t, orgPost(s, "/ui2/organizer/collections/confirm", del)))
	if !strings.Contains(out, "moved to the Inbox") || len(s.organizer.Collections()) != 1 || s.organizer.List()[0].Collection != 0 {
		t.Fatalf("delete keep items: %s", out)
	}
	copyC := s.organizer.Collections()[0]
	del = url.Values{"op": {"delete"}, "items": {"delete"}, "collection_id": {strconv.Itoa(copyC.ID)}, "form_base": {ui2CollectionDigest(copyC)}, "members_base": {ui2MembersDigest(s.organizer.Members(copyC.ID))}}
	out = orgPost(s, "/ui2/organizer/collections/run", orgRun(t, orgPost(s, "/ui2/organizer/collections/confirm", del)))
	if !strings.Contains(out, "deleted with its 1") || len(s.organizer.List()) != 1 || len(s.organizer.Collections()) != 0 {
		t.Fatalf("delete with items: %s", out)
	}
}

func TestUI2OrganizerCollectionDuplicateDeleteRefusals(t *testing.T) {
	s := organizerTestServer(t)
	c, _ := s.organizer.NewCollection("src")
	members := ui2MembersDigest(s.organizer.Members(c.ID))
	s.organizer.MoveToCollection([]int{s.organizer.Add(1).ID}, c.ID) // membership drifts after the form rendered
	for _, f := range []url.Values{
		{"op": {"duplicate"}, "name": {"x"}, "collection_id": {strconv.Itoa(c.ID)}, "form_base": {ui2CollectionDigest(c)}, "members_base": {members}},
		{"op": {"delete"}, "items": {"inbox"}, "collection_id": {strconv.Itoa(c.ID)}, "form_base": {ui2CollectionDigest(c)}, "members_base": {members}},
		{"op": {"delete"}, "items": {"maybe"}, "collection_id": {strconv.Itoa(c.ID)}, "form_base": {ui2CollectionDigest(c)}, "members_base": {ui2MembersDigest(s.organizer.Members(c.ID))}},
		{"op": {"delete"}, "items": {"inbox"}, "name": {"x"}, "collection_id": {strconv.Itoa(c.ID)}, "form_base": {ui2CollectionDigest(c)}, "members_base": {ui2MembersDigest(s.organizer.Members(c.ID))}},
	} {
		if out := orgPost(s, "/ui2/organizer/collections/confirm", f); !strings.Contains(out, "Not saved") || strings.Contains(out, `name="token"`) {
			t.Fatalf("refusal expected for %v: %s", f, out)
		}
	}
	// A membership change between review and confirm refuses the held delete.
	f := url.Values{"op": {"delete"}, "items": {"delete"}, "collection_id": {strconv.Itoa(c.ID)}, "form_base": {ui2CollectionDigest(c)}, "members_base": {ui2MembersDigest(s.organizer.Members(c.ID))}}
	run := orgRun(t, orgPost(s, "/ui2/organizer/collections/confirm", f))
	s.organizer.MoveToCollection([]int{s.organizer.Add(2).ID}, c.ID)
	if out := orgPost(s, "/ui2/organizer/collections/run", run); !strings.Contains(out, "items changed") || len(s.organizer.List()) != 2 {
		t.Fatalf("stale delete applied: %s", out)
	}
}
