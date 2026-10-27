package bcheck

import "testing"

// A parameter Fixed on one API operation is exempt there and only there (burpsy-react-ui-8yjj).
func TestSkipAllTestsForParametersAtIsScopedToItsEndpoint(t *testing.T) {
	opts := EnumerateOptions{SkipAllTestsForParametersAt: []ParameterAt{{Method: "GET", Template: "/users/{id}", Name: "token"}}}
	has := func(req string) bool {
		pts, _ := EnumerateWith([]byte(req), []string{"query"}, opts)
		for _, p := range pts {
			if p.Name == "token" {
				return true
			}
		}
		return false
	}
	if has("GET /api/v1/users/7?token=a&q=1 HTTP/1.1\r\nHost: h\r\n\r\n") {
		t.Error("token was audited on the endpoint it is Fixed on")
	}
	for _, other := range []string{
		"GET /api/v1/orders/7?token=a HTTP/1.1\r\nHost: h\r\n\r\n",
		"POST /api/v1/users/7?token=a HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /api/v1/users/7/orders?token=a HTTP/1.1\r\nHost: h\r\n\r\n",
	} {
		if !has(other) {
			t.Errorf("token was dropped on another endpoint: %q", other)
		}
	}
}

func TestParameterAtMatches(t *testing.T) {
	p := ParameterAt{Method: "post", Template: "/users/{id}/orders", Name: "x"}
	for path, want := range map[string]bool{
		"/users/7/orders":        true,
		"/api/v2/users/7/orders": true,
		"/users/orders":          false,
		"/users/7/orders/9":      false,
		"/users//orders":         false,
	} {
		if got := p.Matches("POST", path); got != want {
			t.Errorf("Matches(POST, %q) = %v, want %v", path, got, want)
		}
	}
	if p.Matches("GET", "/users/7/orders") {
		t.Error("another method matched")
	}
}
