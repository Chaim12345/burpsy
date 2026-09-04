package core

import (
	"slices"
	"testing"
)

func TestCookieNamesCollectsSetCookieNamesInOrder(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc; Path=/\r\nContent-Type: text/html\r\nSet-Cookie: theme=dark; Secure\r\nSet-Cookie: sid=def; Path=/\r\n\r\n<body>")
	got := CookieNames(raw)
	if !slices.Equal(got, []string{"sid", "theme"}) {
		t.Errorf("CookieNames = %q, want [sid theme]", got)
	}
}

func TestCookieNamesIgnoresBareFlagsAndEmpty(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nSet-Cookie: justaflag\r\nSet-Cookie: =noname\r\n\r\n")
	if got := CookieNames(raw); len(got) != 0 {
		t.Errorf("CookieNames = %q, want empty: a flag and a nameless value name no cookie", got)
	}
}

func TestCookieNamesReadsNothingWithoutAResponse(t *testing.T) {
	if got := CookieNames(nil); len(got) != 0 {
		t.Errorf("CookieNames(nil) = %q, want empty", got)
	}
}

func TestResponseTitleReadsTheTitle(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><head><title>  Shop — cart </title></head><body>x")
	if got := ResponseTitle(raw); got != "Shop — cart" {
		t.Errorf("ResponseTitle = %q, want trimmed title text", got)
	}
}

func TestResponseTitleRefusesNonHTML(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"title\": \"not a page title\"}")
	if got := ResponseTitle(raw); got != "" {
		t.Errorf("ResponseTitle = %q, want empty: JSON has no title element", got)
	}
}

func TestResponseTitleIgnoresCommentsAndScripts(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!-- <title>comment</title> --><script>var t = \"<title>script</title>\";</script><title>Real</title>")
	if got := ResponseTitle(raw); got != "Real" {
		t.Errorf("ResponseTitle = %q, want the real title element", got)
	}
}

func TestResponseTitleEmptyWithoutOne(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>no head</body></html>")
	if got := ResponseTitle(raw); got != "" {
		t.Errorf("ResponseTitle = %q, want empty", got)
	}
}
