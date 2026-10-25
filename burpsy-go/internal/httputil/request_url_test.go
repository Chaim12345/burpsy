package httputil

// burpsy-react-ui-swqq: the url.Parse fast path ACCEPTS-then-TRANSFORMS - '/a#b' loses its
// fragment, '/a b' comes back '%20'-encoded - and only parse failures used to reach the
// byte-preserving Opaque path. The target IS the probe, on h2 and h3 alike: verbatim carry,
// never re-encode.

import "testing"

// A target url.Parse accepts but would transform takes the byte-preserving path: RequestURI
// after RequestURL is exactly what the operator wrote.
func TestRequestURLCarriesTransformedShapesVerbatim(t *testing.T) {
	for _, target := range []string{"/a#b", "/a?x=1#frag", "/a#b?c=d", "/a b"} {
		u, err := RequestURL("example.test", target)
		if err != nil {
			t.Fatalf("RequestURL(%q): %v", target, err)
		}
		if got := u.RequestURI(); got != target {
			t.Errorf("RequestURL(%q).RequestURI() = %q - the wire would not carry what was written", target, got)
		}
	}
}
