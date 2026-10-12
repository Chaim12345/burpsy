package advisory

import (
	"strings"
	"testing"
	"testing/fstest"
)

// The native set is burpsy's own and must not change any count of Burp's catalogue.
func TestNativeDefinitionsStayOutOfTheBurpCounts(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Len() != 183 || len(c.All()) != 183 {
		t.Fatalf("Len=%d All=%d, want Burp's 183", c.Len(), len(c.All()))
	}
	if c.IndexedLen()+len(c.ShadowedByIndex()) != c.Len() {
		t.Errorf("IndexedLen %d + shadowed %d != Len %d: a native row leaked into the Burp count",
			c.IndexedLen(), len(c.ShadowedByIndex()), c.Len())
	}
	for _, d := range c.All() {
		if d.IsNative() {
			t.Errorf("%q is native but listed among Burp's definitions", d.Name)
		}
	}
	if len(c.Native()) == 0 {
		t.Fatal("no native definitions loaded")
	}
}

func TestInsecureDirectObjectReferenceResolvesToItsNativeRow(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d, why := c.Resolve("Insecure direct object reference")
	if d == nil {
		t.Fatalf("no advisory: %q", why)
	}
	if !d.IsNative() || d.HexIndex() != "b5000100" || d.Severity != SeverityHigh {
		t.Errorf("got native=%v index=%s severity=%s", d.IsNative(), d.HexIndex(), d.Severity)
	}
	var cwe bool
	for _, cl := range d.Classification {
		cwe = cwe || strings.HasPrefix(cl.Title, "CWE-639:")
	}
	if !cwe {
		t.Errorf("classifications %v lack CWE-639", d.Classification)
	}
	if got, ok := c.ByIndex(0xb5000100); !ok || got != d {
		t.Error("the native row is not reachable by its index")
	}
}

// A native row may not take a Burp index or name, nor sit outside the native range.
func TestNativeDefinitionsRefuseCollisions(t *testing.T) {
	base := func() *Catalogue {
		c, err := loadFS(bundled, "definitions")
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		return c
	}
	cases := map[string]string{
		"b5000200_X.json": `{"typeIndex": 3036676608, "name": "SQL injection"}`,
		"00100200_X.json": `{"typeIndex": 1049088, "name": "Something new"}`,
		"b5000300_X.json": `{"typeIndex": 3036676352, "name": "Filename disagrees"}`,
	}
	for file, body := range cases {
		fsys := fstest.MapFS{"n/" + file: {Data: []byte(body)}}
		if err := base().addNative(fsys, "n"); err == nil {
			t.Errorf("%s %s was accepted", file, body)
		}
	}
	ok := fstest.MapFS{"n/b5000200_X.json": {Data: []byte(`{"typeIndex": 3036676608, "name": "Something new"}`)}}
	if err := base().addNative(ok, "n"); err != nil {
		t.Errorf("a well-formed native row was refused: %v", err)
	}
}
