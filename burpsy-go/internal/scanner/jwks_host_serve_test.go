package scanner

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
)

// The jku/x5u material is swapped in on the listener that the forged header already names. The
// port is never let go in between: closing it and listening again let another listener in the
// process take it, and the row then failed with no fetch (a red scanner-rest shard on master).
func TestHostedMaterialIsReplacedWithoutReleasingItsPort(t *testing.T) {
	h, err := hostMaterial("application/json", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	u, err := url.Parse(h.url)
	if err != nil {
		t.Fatal(err)
	}

	h.Serve("application/x-pem-file", []byte("CERT"))

	// Still ours: nothing else can listen on the port the header names.
	if ln, err := net.Listen("tcp", ":"+u.Port()); err == nil {
		ln.Close()
		t.Fatalf("port %s was free after the material was replaced; another listener could have taken it", u.Port())
	}
	resp, err := http.Get("http://127.0.0.1:" + u.Port() + u.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "CERT" || resp.Header.Get("Content-Type") != "application/x-pem-file" {
		t.Fatalf("served %q (%s), want the replaced material", body, resp.Header.Get("Content-Type"))
	}
	if !h.Fetched() {
		t.Fatal("a fetch of the replaced material was not recorded")
	}
}
