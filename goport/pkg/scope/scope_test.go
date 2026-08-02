package scope

import (
	"testing"
)

func TestScopeBasicIncludeExclude(t *testing.T) {
	s := NewScope()
	s.AddRule(NewIncludeRule("*.target.test"))

	rBlock := NewExcludeRule("admin.target.test")
	s.AddRule(rBlock)

	if !s.Contains("app.target.test", 443, "/", true) {
		t.Errorf("expected app.target.test to be in scope")
	}
	if s.Contains("admin.target.test", 443, "/", true) {
		t.Errorf("expected admin.target.test to be excluded")
	}
}

func TestScopeHostMatchesWildcard(t *testing.T) {
	if !hostMatches("*.target.test", "app.target.test") {
		t.Errorf("expected app.target.test to match wildcard")
	}
	if hostMatches("*.target.test", "target.test") {
		t.Errorf("wildcard should not match apex host")
	}
	if hostMatches("*.target.test", "eviltarget.test") {
		t.Errorf("wildcard should not match eviltarget.test")
	}
}

func TestRequestPathParsing(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"GET /a?b=1 HTTP/1.1\r\n", "/a", true},
		{"GET http://h.test/a?b=1 HTTP/1.1\r\n", "/a", true},
		{"GET http://h.test HTTP/1.1\r\n", "/", true},
		{"POST /x HTTP/1.1", "/x", true},
		{"", "", false},
	}

	for _, tc := range cases {
		got, ok := RequestPath([]byte(tc.raw))
		if ok != tc.ok {
			t.Errorf("RequestPath(%q) ok got %v, want %v", tc.raw, ok, tc.ok)
		}
		if got != tc.want {
			t.Errorf("RequestPath(%q) got %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestValidateHostPattern(t *testing.T) {
	bads := []string{
		"a*.test",
		"*.*.test",
		"",
		"http://h.test/a",
		"h.test/admin",
		"h.test internalspace",
	}
	for _, bad := range bads {
		if err := ValidateHostPattern(bad); err == nil {
			t.Errorf("ValidateHostPattern(%q) should have failed", bad)
		}
	}

	goods := []string{
		"*.ok.test",
		"api.test",
	}
	for _, good := range goods {
		if err := ValidateHostPattern(good); err != nil {
			t.Errorf("ValidateHostPattern(%q) unexpected error: %v", good, err)
		}
	}
}
