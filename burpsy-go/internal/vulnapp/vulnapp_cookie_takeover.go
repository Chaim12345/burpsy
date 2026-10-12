package vulnapp

// Cookie prefix and SameSite weaknesses (0vzb.19) and subdomain takeover (0vzb.17).
//
// The cookie endpoints write their Set-Cookie headers verbatim (net/http's SetCookie would normalise
// them), each vulnerable one breaking exactly one rule, each safe one keeping it.
//
// The takeover endpoints are reached under a hostname of their own, sent as the Host header; the
// scanner reads that name because the connection target is an IP literal. TakeoverResolver is the
// DNS those names live in, so no fixture asks real DNS. Every name is under .test (RFC 6761), and the
// CNAME targets name real service domains only inside this fake.
//
// Corresponding scanner checks: checkCookiePrefixViolated and checkSessionCookieSameSite
// (checks_cookie_attrs.go), checkSubdomainTakeover (checks_takeover.go).

import (
	"context"
	"net"
	"net/http"
	"strings"
)

func cookieTakeoverEndpoints() []Endpoint {
	const prefix = "Cookie prefix requirements not met"
	const samesite = "Session cookie without SameSite protection"
	const takeover = "Subdomain takeover"
	host := func(h string) map[string]string { return map[string]string{"Host": h} }
	return []Endpoint{
		// --- cookie prefixes ---
		{Path: "/cookie/prefix/host-insecure", Row: prefix, Note: "__Host- cookie without Secure"},
		{Path: "/cookie/prefix/host-path", Row: prefix, Note: "__Host- cookie with Path=/account"},
		{Path: "/cookie/prefix/host-nopath", Row: prefix, Note: "__Host- cookie with Secure but no Path attribute"},
		{Path: "/cookie/prefix/host-domain", Row: prefix, Note: "__Host- cookie with a Domain attribute"},
		{Path: "/cookie/prefix/secure-insecure", Row: prefix, Note: "__Secure- cookie without Secure"},
		{Path: "/cookie/prefix/upper", Row: prefix, Note: "__HOST- (browsers match prefixes case-insensitively) without Secure"},
		{Path: "/cookie/prefix/logout", Row: prefix,
			Note: "logout deletes a __Host- cookie without Secure: the browser ignores the deletion, the session survives"},
		{Path: "/cookie/safe/prefix/host", Row: prefix, Safe: true, Note: "__Host- cookie with Secure, Path=/ and no Domain"},
		{Path: "/cookie/safe/prefix/secure", Row: prefix, Safe: true, Note: "__Secure- cookie with Secure, a Domain and a narrow Path"},
		{Path: "/cookie/safe/prefix/lookalike", Row: prefix, Safe: true,
			Note: "_Host-sid and Host-sid are not prefixes; they carry no attributes and no promise"},
		{Path: "/cookie/safe/prefix/empty-domain", Row: prefix, Safe: true,
			Note: "__Host- cookie with an empty Domain attribute, which the storage model ignores (still host-only)"},

		// --- SameSite on session cookies ---
		{Path: "/cookie/samesite/missing", Row: samesite, Note: "sessionid without SameSite"},
		{Path: "/cookie/samesite/none-insecure", Row: samesite, Note: "auth_token with SameSite=None and no Secure"},
		{Path: "/cookie/samesite/jwt", Row: samesite,
			Note: "an innocuously named cookie holding a signed JWT, with an unrecognised SameSite value"},
		{Path: "/cookie/safe/samesite/lax", Row: samesite, Safe: true, Note: "sessionid with SameSite=Lax"},
		{Path: "/cookie/safe/samesite/none-secure", Row: samesite, Safe: true, Note: "sessionid with SameSite=None; Secure"},
		{Path: "/cookie/safe/samesite/nonsession", Row: samesite, Safe: true,
			Note: "theme, consent and csrftoken cookies without SameSite: none is a session credential"},
		{Path: "/cookie/safe/samesite/logout", Row: samesite, Safe: true, Note: "sessionid deleted with Max-Age=0"},

		// --- subdomain takeover ---
		{Path: "/takeover/s3", Row: takeover, RequestHeaders: host("assets.takeover.test"),
			Note: "CNAME to an S3 bucket endpoint, answering 404 NoSuchBucket"},
		{Path: "/takeover/azure", Row: takeover, RequestHeaders: host("app.takeover.test"),
			Note: "CNAME to an azurewebsites.net name that does not resolve"},
		{Path: "/takeover/safe/s3-live", Row: takeover, Safe: true, RequestHeaders: host("static.takeover.test"),
			Note: "CNAME to an S3 bucket endpoint that serves a live page"},
		{Path: "/takeover/safe/s3-docs", Row: takeover, Safe: true, RequestHeaders: host("help.takeover.test"),
			Note: "CNAME to an S3 website endpoint whose live 200 page documents the NoSuchBucket error"},
		{Path: "/takeover/safe/s3-nokey", Row: takeover, Safe: true, RequestHeaders: host("media.takeover.test"),
			Note: "CNAME to a live S3 bucket answering 404 NoSuchKey: the bucket exists, one object does not"},
		{Path: "/takeover/safe/no-cname", Row: takeover, Safe: true, RequestHeaders: host("plain.takeover.test"),
			Note: "the NoSuchBucket page, on a host with no CNAME at all"},
		{Path: "/takeover/safe/lookalike", Row: takeover, Safe: true, RequestHeaders: host("docs.takeover.test"),
			Note: "the NoSuchBucket page, CNAME to bucket.s3.amazonaws.com.cdn.test: the service domain only as a substring"},
		{Path: "/takeover/safe/azure-live", Row: takeover, Safe: true, RequestHeaders: host("api.takeover.test"),
			Note: "CNAME to an azurewebsites.net name that resolves"},
		{Path: "/takeover/safe/azure-flaky", Row: takeover, Safe: true, RequestHeaders: host("jobs.takeover.test"),
			Note: "CNAME to an azurewebsites.net name whose lookup fails temporarily: no answer is not NXDOMAIN"},
	}
}

func registerCookieTakeover(mux *http.ServeMux) {
	cookies := map[string][]string{
		"/cookie/prefix/host-insecure":   {"__Host-sid=f81d4fae7dec; Path=/; HttpOnly; SameSite=Lax"},
		"/cookie/prefix/host-path":       {"__Host-sid=f81d4fae7dec; Secure; Path=/account; HttpOnly; SameSite=Lax"},
		"/cookie/prefix/host-nopath":     {"__Host-sid=f81d4fae7dec; Secure; HttpOnly; SameSite=Lax"},
		"/cookie/prefix/host-domain":     {"__Host-sid=f81d4fae7dec; Secure; Path=/; Domain=takeover.test; HttpOnly; SameSite=Lax"},
		"/cookie/prefix/secure-insecure": {"__Secure-sid=f81d4fae7dec; Path=/; HttpOnly; SameSite=Lax"},
		"/cookie/prefix/upper":           {"__HOST-sid=f81d4fae7dec; Path=/; HttpOnly; SameSite=Lax"},
		"/cookie/prefix/logout":          {"__Host-sid=; Max-Age=0"},
		"/cookie/safe/prefix/host":       {"__Host-sid=f81d4fae7dec; Secure; Path=/; HttpOnly; SameSite=Lax"},
		"/cookie/safe/prefix/secure":     {"__Secure-sid=f81d4fae7dec; Secure; Domain=takeover.test; Path=/account; HttpOnly; SameSite=Lax"},
		"/cookie/safe/prefix/lookalike": {"_Host-sid=f81d4fae7dec; Path=/app; SameSite=Lax",
			"Host-sid=f81d4fae7dec; Domain=takeover.test; SameSite=Lax"},
		"/cookie/safe/prefix/empty-domain": {"__Host-sid=f81d4fae7dec; Secure; Path=/; Domain=; HttpOnly; SameSite=Lax"},

		"/cookie/samesite/missing":       {"sessionid=8b1a9953c4611296; Path=/; Secure; HttpOnly"},
		"/cookie/samesite/none-insecure": {"auth_token=8b1a9953c4611296; Path=/; HttpOnly; SameSite=None"},
		"/cookie/samesite/jwt": {"pref=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSJ9." +
			"Tq3Xh0cpzY7uAp6d7ZbQe4dJjzGv2lWkXcfmHbRj1Ks; Path=/; Secure; HttpOnly; SameSite=Relaxed"},
		"/cookie/safe/samesite/lax":         {"sessionid=8b1a9953c4611296; Path=/; Secure; HttpOnly; SameSite=Lax"},
		"/cookie/safe/samesite/none-secure": {"sessionid=8b1a9953c4611296; Path=/; Secure; HttpOnly; SameSite=None"},
		"/cookie/safe/samesite/nonsession": {"theme=dark; Path=/", "consent=yes; Path=/; Max-Age=31536000",
			"csrftoken=0f3c9a1b; Path=/; Secure"},
		"/cookie/safe/samesite/logout": {"sessionid=; Path=/; Max-Age=0"},
	}
	for path, set := range cookies {
		set := set
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			for _, c := range set {
				w.Header().Add("Set-Cookie", c)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<!doctype html><title>Account</title><p>Welcome back.</p>"))
		})
	}

	noSuchBucket := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
			`<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>` +
			`<BucketName>assets.takeover.test</BucketName><RequestId>4442587FB7D0A2F9</RequestId></Error>`))
	}
	livePage := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><title>Static assets</title><p>Downloads and documentation.</p>"))
	}
	mux.HandleFunc("/takeover/s3", noSuchBucket)
	mux.HandleFunc("/takeover/azure", livePage)
	mux.HandleFunc("/takeover/safe/s3-live", livePage)
	mux.HandleFunc("/takeover/safe/s3-docs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><title>Troubleshooting</title><h2>NoSuchBucket</h2>" +
			"<p>The specified bucket does not exist: check the bucket name in your upload settings.</p>"))
	})
	mux.HandleFunc("/takeover/safe/s3-nokey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
			`<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message>` +
			`<Key>takeover/safe/s3-nokey</Key><RequestId>9F1C0E2A6B7D4C11</RequestId></Error>`))
	})
	mux.HandleFunc("/takeover/safe/no-cname", noSuchBucket)
	mux.HandleFunc("/takeover/safe/lookalike", noSuchBucket)
	mux.HandleFunc("/takeover/safe/azure-live", livePage)
	mux.HandleFunc("/takeover/safe/azure-flaky", livePage)
}

// TakeoverResolver is the fake DNS the takeover fixtures live in. It satisfies the scanner's
// DNSResolver. Hosts it does not know are NXDOMAIN, so it can never send a test to real DNS.
type TakeoverResolver struct {
	// CNAME maps a hostname to its CNAME target; a host listed in Plain has no CNAME.
	CNAME map[string]string
	Plain map[string]bool
	// Live are the names that resolve to an address; Flaky fail with a temporary error.
	Live  map[string]bool
	Flaky map[string]bool
}

// NewTakeoverResolver returns the resolver for the fixtures above.
func NewTakeoverResolver() *TakeoverResolver {
	return &TakeoverResolver{
		CNAME: map[string]string{
			"assets.takeover.test": "burpsy-gone-assets.s3.amazonaws.com.",
			"app.takeover.test":    "burpsy-gone-app.azurewebsites.net.",
			"static.takeover.test": "burpsy-live-static.s3.amazonaws.com.",
			"docs.takeover.test":   "burpsy-gone-assets.s3.amazonaws.com.cdn.test.",
			"api.takeover.test":    "burpsy-live-api.azurewebsites.net.",
			"jobs.takeover.test":   "burpsy-flaky-jobs.azurewebsites.net.",
			"help.takeover.test":   "burpsy-live-help.s3-website-us-east-1.amazonaws.com.",
			"media.takeover.test":  "burpsy-live-media.s3.eu-west-1.amazonaws.com.",
		},
		Plain: map[string]bool{"plain.takeover.test": true},
		Live: map[string]bool{
			"burpsy-live-static.s3.amazonaws.com": true, "burpsy-gone-assets.s3.amazonaws.com": true,
			"burpsy-live-api.azurewebsites.net": true, "burpsy-live-help.s3-website-us-east-1.amazonaws.com": true,
			"burpsy-live-media.s3.eu-west-1.amazonaws.com": true, "plain.takeover.test": true,
		},
		Flaky: map[string]bool{"burpsy-flaky-jobs.azurewebsites.net": true},
	}
}

func takeoverFold(h string) string { return strings.ToLower(strings.TrimSuffix(h, ".")) }

// LookupCNAME answers like net.Resolver: the CNAME target, or the name itself when it has none.
func (r *TakeoverResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	h := takeoverFold(host)
	if t, ok := r.CNAME[h]; ok {
		return t, nil
	}
	if r.Plain[h] {
		return h + ".", nil
	}
	return "", &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// LookupHost answers with a documentation address for a live name.
func (r *TakeoverResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	h := takeoverFold(host)
	switch {
	case r.Live[h]:
		return []string{"192.0.2.10"}, nil
	case r.Flaky[h]:
		return nil, &net.DNSError{Err: "server misbehaving", Name: host, IsTemporary: true}
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}
