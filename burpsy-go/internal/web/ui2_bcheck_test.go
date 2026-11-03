package web

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var ui2BCheckHidden = regexp.MustCompile(`name="(review_id|token)" value="([^"]*)"`)

// ui2BCheckReviewFields pulls the run form's hidden review id and token out of a review sheet.
func ui2BCheckReviewFields(t *testing.T, html string) url.Values {
	t.Helper()
	out := url.Values{}
	for _, m := range ui2BCheckHidden.FindAllStringSubmatch(html, -1) {
		out.Set(m[1], m[2])
	}
	if out.Get("review_id") == "" || out.Get("token") == "" {
		t.Fatalf("no review form in: %.400s", html)
	}
	return out
}

func ui2BCheckHas(t *testing.T, rec *httptest.ResponseRecorder, want ...string) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %.300s", rec.Code, rec.Body.String())
	}
	for _, w := range want {
		if !strings.Contains(rec.Body.String(), w) {
			t.Errorf("missing %q in: %.600s", w, rec.Body.String())
		}
	}
}

func TestUI2BChecksPageListsTheCorpus(t *testing.T) {
	s, _, _ := authoringServer(t)
	rec := getUI2(t, s, "/ui2/bchecks")
	ui2BCheckHas(t, rec, "<!doctype html", "Custom scan checks", "from file", "file.bcheck", "always on",
		`href="/ui2/bchecks/editor?name=from%20file"`, `href="/ui2/bchecks/export?name=from%20file"`)
	// A file check is view-only: no delete form.
	if strings.Contains(rec.Body.String(), `aria-label="Delete from file"`) {
		t.Error("a file check offers Delete")
	}
}

func TestUI2BCheckEditorOpensATemplateAndALoadedCheck(t *testing.T) {
	s, _, _ := authoringServer(t)
	ui2BCheckHas(t, getUI2(t, s, "/ui2/bchecks/editor?template=host"), "New host check", "Review save to corpus", "Review test run")
	rec := getUI2(t, s, "/ui2/bchecks/editor?name=from+file")
	ui2BCheckHas(t, rec, "View custom scan check — file.bcheck", "secret-token", " readonly>")
	if strings.Contains(rec.Body.String(), "Review save to corpus") {
		t.Error("a file check offers Save")
	}
}

func TestUI2BCheckExportDownloadsTheSource(t *testing.T) {
	s, _, _ := authoringServer(t)
	rec := getUI2(t, s, "/ui2/bchecks/export?name=from+file")
	ui2BCheckHas(t, rec, "secret-token")
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="file.bcheck"` {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if rec := getUI2(t, s, "/ui2/bchecks/export"); rec.Code != http.StatusBadRequest {
		t.Errorf("export without a name = %d, want 400", rec.Code)
	}
}

func TestUI2BCheckValidateRendersDiagnostics(t *testing.T) {
	s, _, _ := authoringServer(t)
	bad := postUI2Form(t, s, "/ui2/bchecks/validate", url.Values{"source": {draft("x", "given host then\n  frobnicate\n")}})
	ui2BCheckHas(t, bad, "invalid", "line ")
	ok := postUI2Form(t, s, "/ui2/bchecks/validate", url.Values{"source": {draft("x", activeBody)}})
	ui2BCheckHas(t, ok, "valid</span> x · active")
}

func TestUI2BCheckUploadOpensTheFileAsADraft(t *testing.T) {
	s, _, _ := authoringServer(t)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "up.bcheck")
	_, _ = fw.Write([]byte(draft("uploaded", passiveBody)))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/ui2/bchecks/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	ui2BCheckHas(t, rec, "Import custom scan check — up.bcheck", "uploaded")
	if strings.Contains(strings.Join(corpusNames(s), "|"), "uploaded") {
		t.Error("an upload loaded the check without a reviewed Save")
	}
}

// Save is a held review: nothing loads on the review step, the run loads exactly the reviewed
// draft, and the review cannot be spent twice.
func TestUI2BCheckSaveReviewThenRun(t *testing.T) {
	s, _, _ := authoringServer(t)
	review := postUI2Form(t, s, "/ui2/bchecks/review/save", url.Values{"source": {draft("ui2 active", activeBody)}})
	ui2BCheckHas(t, review, "Review before saving", "POST /api/scanner/checks/import", "Confirm and save", "disabled data-arm-on-load")
	if strings.Contains(strings.Join(corpusNames(s), "|"), "ui2 active") {
		t.Fatal("the review step loaded the check")
	}
	fields := ui2BCheckReviewFields(t, review.Body.String())
	ui2BCheckHas(t, postUI2Form(t, s, "/ui2/bchecks/run", fields), "ui2 active", "no project database")
	if !strings.Contains(strings.Join(corpusNames(s), "|"), "ui2 active") {
		t.Fatal("the run did not load the check")
	}
	ui2BCheckHas(t, postUI2Form(t, s, "/ui2/bchecks/run", fields), "unknown or was already used")
}

func TestUI2BCheckSaveRefusesAForgedToken(t *testing.T) {
	s, _, _ := authoringServer(t)
	review := postUI2Form(t, s, "/ui2/bchecks/review/save", url.Values{"source": {draft("forged", activeBody)}})
	fields := ui2BCheckReviewFields(t, review.Body.String())
	fields.Set("token", strings.Repeat("0", 32))
	ui2BCheckHas(t, postUI2Form(t, s, "/ui2/bchecks/run", fields), "does not match this confirmation")
	if strings.Contains(strings.Join(corpusNames(s), "|"), "forged") {
		t.Error("a forged token loaded the check")
	}
	// A file check's name is refused at review, before anything is held.
	clash := postUI2Form(t, s, "/ui2/bchecks/review/save", url.Values{"source": {draft("from file", passiveBody)}})
	ui2BCheckHas(t, clash, "Not applied", "Save would be refused")
}

func TestUI2BCheckEnableSwitchesAnActiveCheck(t *testing.T) {
	s, _, _ := authoringServer(t)
	if rec := postJSON(t, s, "/api/scanner/checks/import", map[string]any{"source": draft("sw", activeBody)}); rec.Code != http.StatusCreated {
		t.Fatalf("import = %d", rec.Code)
	}
	ui2BCheckHas(t, postUI2Form(t, s, "/ui2/bchecks/enable", url.Values{"name": {"sw"}, "enabled": {"false"}}), "is now disabled")
	if !s.wiredScanner().CheckDisabled("sw") {
		t.Error("the switch did not disable the check")
	}
	ui2BCheckHas(t, postUI2Form(t, s, "/ui2/bchecks/enable", url.Values{"name": {"nope"}, "enabled": {"false"}}), "Not changed", "no check named nope")
}

func TestUI2BCheckReloadReportsAndRefuses(t *testing.T) {
	s, _, _ := authoringServer(t)
	ui2BCheckHas(t, postUI2Form(t, s, "/ui2/bchecks/reload", nil), "Reloaded:")
	ui2BCheckHas(t, postUI2Form(t, newTestServer(), "/ui2/bchecks/reload", nil), "Reload refused")
}

func TestUI2BCheckDeleteReviewThenRun(t *testing.T) {
	s, _, _ := authoringServer(t)
	if rec := postJSON(t, s, "/api/scanner/checks/import", map[string]any{"source": draft("gone soon", activeBody)}); rec.Code != http.StatusCreated {
		t.Fatalf("import = %d", rec.Code)
	}
	review := postUI2Form(t, s, "/ui2/bchecks/review/delete", url.Values{"name": {"gone soon"}})
	ui2BCheckHas(t, review, "Review before deleting", "DELETE /api/scanner/checks/source?name=gone&#43;soon")
	ui2BCheckHas(t, postUI2Form(t, s, "/ui2/bchecks/run", ui2BCheckReviewFields(t, review.Body.String())), "Deleted")
	if strings.Contains(strings.Join(corpusNames(s), "|"), "gone soon") {
		t.Error("the run did not delete the check")
	}
	// A file check: the API's 409 is the outcome, and the check stays.
	review = postUI2Form(t, s, "/ui2/bchecks/review/delete", url.Values{"name": {"from file"}})
	ui2BCheckHas(t, postUI2Form(t, s, "/ui2/bchecks/run", ui2BCheckReviewFields(t, review.Body.String())), "Not applied")
}

// Run test is riskAttack: the review mints a gate token for the exact body and the run spends it.
func TestUI2BCheckTestReviewThenRun(t *testing.T) {
	s, _, _ := authoringServer(t)
	id := seedUI2Exchange(t, s, "GET /t HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nsecret-token")
	form := url.Values{"source": {draft("probe", passiveBody)}, "exchange_ids": {strconv.FormatUint(uint64(id), 10)}}
	review := postUI2Form(t, s, "/ui2/bchecks/review/test", form)
	ui2BCheckHas(t, review, "Review before testing", "attack, confirmation-gated", "sends nothing")
	out := postUI2Form(t, s, "/ui2/bchecks/run", ui2BCheckReviewFields(t, review.Body.String()))
	ui2BCheckHas(t, out, "Test run — probe (passive)", "#"+strconv.FormatUint(uint64(id), 10), "0 sent")
	if !strings.Contains(out.Body.String(), "sev-low") {
		t.Errorf("no finding rendered: %.600s", out.Body.String())
	}
	// No ids: refused before anything is held.
	ui2BCheckHas(t, postUI2Form(t, s, "/ui2/bchecks/review/test", url.Values{"source": {draft("probe", passiveBody)}}), "Not applied", "at least one exchange id")
}
