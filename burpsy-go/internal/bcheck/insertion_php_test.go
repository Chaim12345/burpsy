package bcheck

import (
	"strings"
	"testing"
)

// Burp's PHP file-request point (burpsy-react-ui-i7i5): a .php URL gets a bare parameter-name point
// "1" after the path; any other extension does not.
func TestAPHPURLGetsABareParameterNamePoint(t *testing.T) {
	php := []byte("GET /index.PHP?page=2 HTTP/1.1\r\nHost: h\r\n\r\n")
	points, _ := Enumerate(php, []string{"param_name_url"})
	var bare *InsertionPoint
	for i := range points {
		if points[i].Kind == IpParamNameURL && points[i].Name == "1" {
			bare = &points[i]
		}
	}
	if bare == nil {
		t.Fatalf("no bare-name point on a .php URL: %v", names(points))
	}
	got, err := bare.Apply(php, "x'y", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), "GET /index.PHP?page=2&x'y HTTP/1.1") {
		t.Errorf("applied = %q, want the payload as a bare name after the existing query", got)
	}
	plain := []byte("GET /index.html HTTP/1.1\r\nHost: h\r\n\r\n")
	points, _ = Enumerate(plain, []string{"param_name_url"})
	for _, p := range points {
		if p.Kind == IpParamNameURL && p.Name == "1" {
			t.Error("a non-PHP URL got the PHP bare-name point")
		}
	}
	noQuery := []byte("GET /a.php HTTP/1.1\r\nHost: h\r\n\r\n")
	points, _ = Enumerate(noQuery, []string{"param_name_url"})
	for i := range points {
		if points[i].Kind == IpParamNameURL && points[i].Name == "1" {
			got, _ := points[i].Apply(noQuery, "1", true)
			if !strings.HasPrefix(string(got), "GET /a.php?11 HTTP/1.1") {
				t.Errorf("appending on a query-less URL = %q", got)
			}
		}
	}
}
