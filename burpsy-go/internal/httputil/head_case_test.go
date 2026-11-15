package httputil

import "testing"

// Methods are case-sensitive: only "HEAD" has a bodiless answer. Treating "head" the same left a
// real body on the connection, read as the next response.
func TestOnlyExactHEADHasNoResponseBody(t *testing.T) {
	head := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
	if ResponseHasBodyFor("HEAD", head) {
		t.Error("a HEAD answer was given a body")
	}
	for _, m := range []string{"head", "Head", "GET"} {
		if !ResponseHasBodyFor(m, head) {
			t.Errorf("the answer to %q lost its body", m)
		}
	}
}
