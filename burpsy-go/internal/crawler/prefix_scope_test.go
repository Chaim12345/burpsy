package crawler

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func TestSeedDirectoryPrefixAndPrefixScopeNarrowBothGates(t *testing.T) {
	dir, err := SeedDirectoryPrefix("https://Shop.test/app/page.html?x=1")
	if err != nil || dir != "https://shop.test:443/app/" {
		t.Fatalf("seed dir = %q %v", dir, err)
	}
	base := core.NewScope()
	base.AddInclude("shop.test")
	ex, _ := NormalisePrefix("https://shop.test/app/admin")
	p := &PrefixScope{Base: base, Include: []string{dir}, Exclude: []string{ex}}
	for _, c := range []struct {
		path string
		want bool
	}{{"/app/", true}, {"/app/a?q=1", true}, {"/apple", false}, {"/other/x", false}, {"/app/admin/users", false}} {
		if got := p.Contains("shop.test", 443, c.path, true); got != c.want {
			t.Errorf("Contains(%s) = %v, want %v", c.path, got, c.want)
		}
	}
	if err := p.AuthoriseRaw("shop.test", 443, true, []byte("GET /other/x HTTP/1.1\r\nHost: shop.test\r\n\r\n")); err == nil || !strings.Contains(err.Error(), "crawl's scope") {
		t.Errorf("the send gate let a request outside the prefix out: %v", err)
	}
	if err := p.AuthoriseRaw("shop.test", 443, true, []byte("GET /app/b HTTP/1.1\r\nHost: shop.test\r\n\r\n")); err != nil {
		t.Errorf("an in-prefix request was refused: %v", err)
	}
	if engagementScope(p) != Scope(base) {
		t.Error("the session's re-login must use the engagement scope beneath the crawl's")
	}
}
