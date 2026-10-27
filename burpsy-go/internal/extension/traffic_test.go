package extension

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// ieg3: read access to the traffic store. traffic.query and scope.check are grant-gated like
// every other plugin->host method, and answer from an injected TrafficReader.

type fakeTraffic struct {
	queries []TrafficQuery
	items   []TrafficItem
	scoped  map[string]bool
}

func (f *fakeTraffic) Query(_ context.Context, plugin string, q TrafficQuery) (TrafficPage, error) {
	f.queries = append(f.queries, q)
	end := q.Offset + q.Limit
	if end > len(f.items) {
		end = len(f.items)
	}
	start := q.Offset
	if start > end {
		start = end
	}
	return TrafficPage{Items: f.items[start:end], Total: len(f.items)}, nil
}
func (f *fakeTraffic) InScope(_ context.Context, url string) (bool, error) { return f.scoped[url], nil }

func trafficHost(t *testing.T, f *fakeTraffic, grants ...string) *Host {
	return testHost(t, "host-caller", func(c *Config) {
		c.Services = Services{Traffic: f}
		c.Grants = map[string][]string{"probe": grants}
	})
}

func Test_traffic_query_needs_its_own_grant(t *testing.T) {
	f := &fakeTraffic{}
	h := trafficHost(t, f, "scope.check")
	got := callHost(t, h, "traffic.query", map[string]any{"source": "proxy"})
	if got.Error == nil || got.Error.Code != CodeNoGrant || len(f.queries) != 0 {
		t.Errorf("ungranted traffic.query = %+v (queries %d)", got, len(f.queries))
	}
}

func Test_traffic_query_returns_a_bounded_page_of_the_chosen_source(t *testing.T) {
	f := &fakeTraffic{}
	for i := 0; i < 300; i++ {
		f.items = append(f.items, TrafficItem{ID: i, Method: "GET", URL: "http://a.test/", Status: 200})
	}
	h := trafficHost(t, f, "traffic.query")
	got := callHost(t, h, "traffic.query", map[string]any{"source": "sitemap", "host": "a.test", "limit": 5000, "offset": 2})
	if got.Error != nil {
		t.Fatalf("error: %+v", got.Error)
	}
	if len(f.queries) != 1 || f.queries[0].Source != TrafficSitemap || f.queries[0].Host != "a.test" {
		t.Fatalf("service saw %+v", f.queries)
	}
	if f.queries[0].Limit != MaxTrafficPage {
		t.Errorf("limit = %d, want the %d cap applied to a request for 5000", f.queries[0].Limit, MaxTrafficPage)
	}
	var page struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(got.Result, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != MaxTrafficPage || page.Total != 300 || page.Items[0]["id"] != float64(2) {
		t.Errorf("page = %d items total %d first %v", len(page.Items), page.Total, page.Items[0])
	}
	// Defaults when the plugin names no limit.
	callHost(t, h, "traffic.query", map[string]any{"source": "proxy"})
	if f.queries[1].Limit != DefaultTrafficPage {
		t.Errorf("default limit = %d, want %d", f.queries[1].Limit, DefaultTrafficPage)
	}
}

func Test_traffic_query_refuses_an_unknown_source_and_a_negative_offset(t *testing.T) {
	f := &fakeTraffic{}
	h := trafficHost(t, f, "traffic.query")
	for _, params := range []map[string]any{{"source": "cookies"}, {"source": "proxy", "offset": -1}, {}} {
		got := callHost(t, h, "traffic.query", params)
		if got.Error == nil || got.Error.Code != CodeInvalidParams {
			t.Errorf("%v answered %+v, want invalid params", params, got)
		}
	}
	if len(f.queries) != 0 {
		t.Errorf("an invalid query reached the store: %v", f.queries)
	}
}

func Test_an_oversized_traffic_answer_is_an_error_not_a_hung_plugin(t *testing.T) {
	f := &fakeTraffic{items: []TrafficItem{{ID: 1, Method: "GET", URL: "http://a/", Request: strings.Repeat("x", 600<<10)}}}
	h := testHost(t, "host-caller", func(c *Config) {
		c.MaxMessageBytes = 64 << 10
		c.Services = Services{Traffic: f}
		c.Grants = map[string][]string{"probe": {"traffic.query"}}
	})
	got := callHost(t, h, "traffic.query", map[string]any{"source": "proxy", "include_bodies": true})
	if got.Error == nil || got.Error.Code != CodeServiceFailed {
		t.Errorf("an answer past the message bound = %+v, want CodeServiceFailed", got)
	}
}

func Test_traffic_bodies_are_omitted_unless_asked_for(t *testing.T) {
	f := &fakeTraffic{items: []TrafficItem{{ID: 1, Method: "GET", URL: "http://a/", Request: "GET / HTTP/1.1", Response: "HTTP/1.1 200 OK"}}}
	h := trafficHost(t, f, "traffic.query")
	got := callHost(t, h, "traffic.query", map[string]any{"source": "proxy"})
	if strings.Contains(string(got.Result), "HTTP/1.1") {
		t.Errorf("bodies leaked without include_bodies: %s", got.Result)
	}
	got = callHost(t, h, "traffic.query", map[string]any{"source": "proxy", "include_bodies": true})
	if !strings.Contains(string(got.Result), `"request":"GET / HTTP/1.1"`) {
		t.Errorf("include_bodies dropped the request: %s", got.Result)
	}
}

func Test_scope_check_answers_from_the_engagement_scope(t *testing.T) {
	f := &fakeTraffic{scoped: map[string]bool{"http://in.test/": true}}
	h := trafficHost(t, f, "scope.check")
	in := callHost(t, h, "scope.check", map[string]any{"url": "http://in.test/"})
	out := callHost(t, h, "scope.check", map[string]any{"url": "http://out.test/"})
	if !strings.Contains(string(in.Result), `"in_scope":true`) || !strings.Contains(string(out.Result), `"in_scope":false`) {
		t.Errorf("in = %s, out = %s", in.Result, out.Result)
	}
	if bad := callHost(t, h, "scope.check", map[string]any{"url": ""}); bad.Error == nil || bad.Error.Code != CodeInvalidParams {
		t.Errorf("empty url answered %+v", bad)
	}
}

func Test_traffic_methods_are_grantable_and_unwired_says_so(t *testing.T) {
	if err := ValidateGrants(map[string][]string{"p": {"traffic.query", "scope.check"}}); err != nil {
		t.Errorf("ValidateGrants: %v", err)
	}
	h := testHost(t, "host-caller", func(c *Config) { c.Grants = map[string][]string{"probe": {"traffic.query"}} })
	got := callHost(t, h, "traffic.query", map[string]any{"source": "proxy"})
	if got.Error == nil || got.Error.Code != CodeNotWired {
		t.Errorf("unwired traffic.query = %+v", got)
	}
}
