package main

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
)

// The webview's writes carry its own origin; the console must see them as its own, and a foreign
// origin must reach the console unchanged so the same-origin check still refuses it.
func TestTheDesktopDirectorRewritesOnlyTheWebviewOrigin(t *testing.T) {
	target, _ := url.Parse("http://127.0.0.1:8081")
	d := consoleDirector(httputil.NewSingleHostReverseProxy(target).Director, target.Host)
	for origin, want := range map[string]string{
		"wails://wails":          "http://127.0.0.1:8081",
		"http://wails.localhost": "http://127.0.0.1:8081",
		"https://evil.example":   "https://evil.example",
		"":                       "",
	} {
		r := httptest.NewRequest(http.MethodPost, "http://wails.localhost/api/scope", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		d(r)
		if r.Host != "127.0.0.1:8081" {
			t.Errorf("Host = %q, want the console's", r.Host)
		}
		if got := r.Header.Get("Origin"); got != want {
			t.Errorf("Origin %q forwarded as %q, want %q", origin, got, want)
		}
	}
}
