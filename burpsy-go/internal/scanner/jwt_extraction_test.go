package scanner

import "testing"

// j1mk.7. A JWT does not arrive as a field of its own — it is the VALUE in an Authorization header,
// a cookie, a query parameter or a form body, glued to a name by `=`, `:`, a space or an `&`. The
// extractor used to split the raw bytes on whitespace, so it found `Authorization: Bearer <jwt>`
// (the token is its own whitespace-delimited field) and missed `?JWT=<jwt>` (the token is glued to
// the path by `?JWT=`), which meant every JWT row reported clean on a query-parameter endpoint
// without sending a single probe. These pin each carrier.

func jwtInAResult(t *testing.T, raw string) (string, bool) {
	t.Helper()
	cc := postureFixture(t, raw, htmlResponse("<html><body>ok</body></html>"), true)
	got, _, ok := jwtFromExchange(cc)
	return got, ok
}

func TestAJWTIsFoundInEveryCarrierARequestNamesItIn(t *testing.T) {
	tok := testJWT()
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"authorization bearer header",
			"GET /api HTTP/1.1\r\nHost: app.test\r\nAuthorization: Bearer " + tok + "\r\n\r\n"},
		{"authorization bare header",
			"GET /api HTTP/1.1\r\nHost: app.test\r\nAuthorization: " + tok + "\r\n\r\n"},
		{"cookie",
			"GET /api HTTP/1.1\r\nHost: app.test\r\nCookie: session=" + tok + "\r\n\r\n"},
		{"query parameter",
			"GET /api?JWT=" + tok + " HTTP/1.1\r\nHost: app.test\r\n\r\n"},
		{"query parameter, not the first",
			"GET /api?id=1&token=" + tok + " HTTP/1.1\r\nHost: app.test\r\n\r\n"},
		{"form body",
			"POST /api HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ntoken=" + tok},
		{"json body",
			"POST /api HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\n\r\n{\"token\":\"" + tok + "\"}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := jwtInAResult(t, tc.raw)
			if !ok {
				t.Fatalf("no JWT found in a request that carries one in its %s; the JWT rows would "+
					"return early and report clean without probing", tc.name)
			}
			if got != tok {
				t.Fatalf("found %q, want the token %q", got, tok)
			}
		})
	}
}

// A request with no JWT is genuinely nothing to do — the extractor must not invent one from an
// arbitrary dotted string, or a non-JWT endpoint would be probed as though it carried a token.
func TestARequestWithNoJWTYieldsNone(t *testing.T) {
	for _, raw := range []string{
		"GET /api HTTP/1.1\r\nHost: app.test\r\n\r\n",
		"GET /api?q=1.2.3 HTTP/1.1\r\nHost: app.test\r\n\r\n",              // dots but not base64 JSON
		"GET /a/b.c/d HTTP/1.1\r\nHost: app.test\r\n\r\n",                  // path dots
		"GET /api?x=eyJub3QiOiJqd3QifQ HTTP/1.1\r\nHost: app.test\r\n\r\n", // one segment
	} {
		if got, ok := jwtInAResult(t, raw); ok {
			t.Errorf("found a JWT %q in a request with none: %q", got, raw)
		}
	}
}
