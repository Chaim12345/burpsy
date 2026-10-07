package domexec

import (
	"context"
	"strings"
	"testing"
	"time"
)

// burpsy-react-ui-hzzl: a render records the requests the page itself issues at run time — the API
// calls a single-page app makes, which appear in no served byte and no rendered link.
func TestARenderRecordsTheRequestsThePageIssues(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	url := servePage(t, `<html><body><script>
		fetch('/api/items?page=1');
		var x = new XMLHttpRequest(); x.open('POST', '/api/track'); x.send('{}');
	</script></body></html>`)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, outcome, err := b.RenderedDOMWithOptions(ctx, url, RenderOptions{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	got := map[string]string{}
	for _, r := range outcome.Requests {
		got[r.URL[strings.Index(r.URL, "/api/"):]] = r.Method
	}
	if got["/api/items?page=1"] != "GET" {
		t.Errorf("the fetch was not recorded as a GET: %+v", outcome.Requests)
	}
	if got["/api/track"] != "POST" {
		t.Errorf("the XHR POST was not recorded with its method: %+v", outcome.Requests)
	}
}
