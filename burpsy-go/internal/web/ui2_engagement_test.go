package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The PoC is attacker-shaped HTML: the page shows it escaped, the download is an inert attachment,
// and "test in browser" links the PoC host, never this origin.
func TestUI2EngagementCSRFRendersEscapedPoC(t *testing.T) {
	s := newTestServer()
	id := seedUI2Exchange(t, s,
		"POST /transfer HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 30\r\n\r\nto=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
		"HTTP/1.1 200 OK\r\n\r\n")
	body := getUI2(t, s, fmt.Sprintf("/ui2/engagement/csrf?id=%d&technique=form&auto_submit=false", id)).Body.String()
	if !strings.Contains(body, `id="csrf-poc"`) || !strings.Contains(body, "&lt;form") {
		t.Fatalf("no escaped PoC: %s", body)
	}
	if strings.Contains(body, "<script>alert(1)") || strings.Contains(body, `<form action="http://bank.test`) {
		t.Fatal("the PoC reached the console as live markup")
	}

	dl := getUI2(t, s, fmt.Sprintf("/ui2/engagement/csrf/%d/download?technique=form&auto_submit=true", id))
	if dl.Code != http.StatusOK || !strings.HasPrefix(dl.Header().Get("Content-Disposition"), "attachment") ||
		dl.Header().Get("Content-Security-Policy") != "sandbox" || !strings.Contains(dl.Body.String(), "bank.test/transfer") {
		t.Fatalf("download = %d %v: %s", dl.Code, dl.Header(), dl.Body.String())
	}
	if rec := getUI2(t, s, "/ui2/engagement/csrf/1/download?technique=evil"); rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown technique downloaded: %d", rec.Code)
	}

	test := postUI2Form(t, s, "/ui2/engagement/csrf/test", url.Values{"id": {fmt.Sprint(id)}, "technique": {"auto"}, "auto_submit": {"true"}}).Body.String()
	if !strings.Contains(test, `id="csrf-test-url" class="btn" href="http://`) {
		t.Fatalf("no one-shot PoC host URL: %s", test)
	}
}

// Hidden-input guessing launches only through review -> token, then shows the run.
func TestUI2EngagementHiddenInputsReviewAndRun(t *testing.T) {
	hf := newHiddenFixture(t, "")
	id := hf.seed(t, "/hidden/account")
	form := url.Values{"exchange_id": {fmt.Sprint(id)}, "kinds": {"header"}, "max_requests": {"200"}}
	review := postUI2Form(t, hf.s, "/ui2/engagement/hidden-inputs/confirm", form).Body.String()
	if !strings.Contains(review, "POST /api/hidden-inputs") || !strings.Contains(review, "&#34;max_requests&#34;:200") {
		t.Fatalf("review: %s", review)
	}
	run := url.Values{"exchange_id": form["exchange_id"], "kinds": {"header"}, "max_requests": {"200"}, "token": {"bogus"}}
	if body := postUI2Form(t, hf.s, "/ui2/engagement/hidden-inputs/run", run).Body.String(); !strings.Contains(body, "role=\"alert\"") || hf.hits.Load() != 0 {
		t.Fatalf("a bogus token launched (hits %d): %s", hf.hits.Load(), body)
	}
	if body := postUI2Form(t, hf.s, "/ui2/engagement/hidden-inputs/confirm", url.Values{"exchange_id": form["exchange_id"], "max_requests": {"9999"}, "kinds": {"query"}}).Body.String(); !strings.Contains(body, "Not started") {
		t.Fatalf("an over-budget run was reviewed: %s", body)
	}
	run.Set("token", ui2HiddenValue(review, "token"))
	page := postUI2Form(t, hf.s, "/ui2/engagement/hidden-inputs/run", run).Body.String()
	const marker = "<h3>Run "
	i := strings.Index(page, marker)
	if !strings.Contains(page, `id="hidden-run"`) || i < 0 {
		t.Fatalf("no live run panel: %s", page)
	}
	task := page[i+len(marker):]
	task = task[:strings.IndexByte(task, ' ')]
	for i := 0; i < 400; i++ {
		frag := getUI2(t, hf.s, "/ui2/engagement/hidden-inputs?task="+task+"&frag=run").Body.String()
		if !strings.Contains(frag, "every 2s") {
			if !strings.Contains(frag, "requests sent") {
				t.Fatalf("finished run panel: %s", frag)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("the run never finished")
}

func TestUI2EngagementClickbanditShowsScriptAsText(t *testing.T) {
	s := newTestServer()
	body := getUI2(t, s, "/ui2/engagement/clickbandit").Body.String()
	if !strings.Contains(body, `id="clickbandit-script"`) || !strings.Contains(body, "copy-btn") {
		t.Fatalf("clickbandit page: %s", body[:ui2Min(400, len(body))])
	}
}
