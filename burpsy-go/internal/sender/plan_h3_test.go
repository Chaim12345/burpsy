package sender

// PlanH3 is the exported carriability seam the proxy's Alt-Svc leg consumes (vln3 ruling B): one
// planner, one home. These tests pin the exported contract only - planH2's construct-by-construct
// bar is already pinned exhaustively by the h2 planning tests.

import (
	"strings"
	"testing"
)

// A carriable request comes back as the pseudo-header parts the h3 leg re-expresses from.
func TestPlanH3ReturnsTheRequestParts(t *testing.T) {
	plan, err := PlanH3([]byte("POST /h3?q=1 HTTP/1.1\r\nHost: example.test\r\nX-Op: burpsy\r\nContent-Length: 5\r\n\r\nhello"))
	if err != nil {
		t.Fatalf("PlanH3: %v", err)
	}
	if plan.Method != "POST" || plan.Path != "/h3?q=1" || plan.Authority != "example.test" {
		t.Fatalf("plan = %+v", plan)
	}
	if string(plan.Body) != "hello" {
		t.Fatalf("body = %q", plan.Body)
	}
	found := false
	for _, h := range plan.Headers {
		if h.Name == "x-op" && h.Value == "burpsy" {
			found = true
		}
	}
	if !found {
		t.Fatalf("headers = %+v, want x-op carried", plan.Headers)
	}
}

// An uncarriable request is an error naming the construct - the strict answer the Alt-Svc leg
// falls back on, never a mangled send.
func TestPlanH3NamesTheUncarriableConstruct(t *testing.T) {
	_, err := PlanH3([]byte("POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"))
	if err == nil {
		t.Fatal("a chunked request planned onto h3 instead of failing")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "transfer-encoding") {
		t.Fatalf("error = %v, want the construct named", err)
	}
}
