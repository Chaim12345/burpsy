package crawler

// A crawl's own scope (burpsy-react-ui-501u): Burp's "By default, the scope of the crawl is
// restricted to the configured URLs, ending with the final directory", and its "Detailed scope
// configuration" of URL prefixes to include and exclude. It only ever NARROWS the engagement scope:
// a URL must be in the engagement scope AND match this crawl's prefixes, at both gates — Contains
// (what the frontier admits) and AuthoriseRaw (what the sender lets out) — so a redirect or a form
// cannot carry the crawl outside the directory it was told to stay in.

import (
	"bytes"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// PrefixScope narrows a Scope to URLs under Include and outside Exclude. An empty Include admits
// every URL the base scope does.
type PrefixScope struct {
	Base    Scope
	Include []string
	Exclude []string
}

// NormalisePrefix turns a URL into the canonical prefix form: lower-case scheme and host, an explicit
// port, and a path that starts with "/". It refuses anything that is not an http(s) URL with a host.
func NormalisePrefix(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("scope prefix %q must be an http or https URL with a host", raw)
	}
	return urlKey(strings.ToLower(u.Scheme), u.Hostname(), portOf(u), u.EscapedPath()), nil
}

// SeedDirectoryPrefix is a seed's final directory: everything up to and including the last "/" of its
// path — https://a.test/app/page.html scopes the crawl to https://a.test:443/app/.
func SeedDirectoryPrefix(seed string) (string, error) {
	p, err := NormalisePrefix(seed)
	if err != nil {
		return "", err
	}
	scheme, rest, _ := strings.Cut(p, "://")
	if i := strings.Index(rest, "/"); i >= 0 {
		path := rest[i:]
		path = path[:strings.LastIndexByte(path, '/')+1]
		return scheme + "://" + rest[:i] + path, nil
	}
	return p + "/", nil
}

func urlKey(scheme, host string, port uint16, path string) string {
	if path == "" {
		path = "/"
	}
	return scheme + "://" + strings.ToLower(host) + ":" + strconv.Itoa(int(port)) + path
}

func (p *PrefixScope) allows(host string, port uint16, path string, isTLS bool) bool {
	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	if q := strings.IndexByte(path, '?'); q >= 0 {
		path = path[:q]
	}
	key := urlKey(scheme, host, port, path)
	for _, ex := range p.Exclude {
		if strings.HasPrefix(key, ex) {
			return false
		}
	}
	if len(p.Include) == 0 {
		return true
	}
	for _, in := range p.Include {
		if strings.HasPrefix(key, in) {
			return true
		}
	}
	return false
}

// Contains is the frontier's question: in the engagement scope and in this crawl's.
func (p *PrefixScope) Contains(host string, port uint16, path string, isTLS bool) bool {
	return p.Base.Contains(host, port, path, isTLS) && p.allows(host, port, path, isTLS)
}

// AuthoriseRaw is the send gate's: the engagement scope's answer, then this crawl's prefixes against
// the request line's own target.
func (p *PrefixScope) AuthoriseRaw(host string, port uint16, isTLS bool, raw []byte) error {
	if err := p.Base.AuthoriseRaw(host, port, isTLS, raw); err != nil {
		return err
	}
	line, _, _ := bytes.Cut(raw, []byte("\n"))
	parts := strings.Fields(string(line))
	if len(parts) < 2 {
		return nil // the base gate already judged the bytes; nothing more to read here
	}
	target := parts[1]
	if u, err := url.Parse(target); err == nil && u.IsAbs() {
		target = u.EscapedPath()
	}
	if !p.allows(host, port, target, isTLS) {
		return fmt.Errorf("outside this crawl's scope: %s", p.Explain(host, port, target, isTLS))
	}
	return nil
}

// Explain says which scope refused a URL, so the crawl report can tell "the engagement excludes it"
// from "this crawl was told to stay under a prefix".
func (p *PrefixScope) Explain(host string, port uint16, path string, isTLS bool) string {
	if !p.Base.Contains(host, port, path, isTLS) {
		if e, ok := p.Base.(interface {
			Explain(string, uint16, string, bool) string
		}); ok {
			return e.Explain(host, port, path, isTLS)
		}
		return "outside the engagement scope"
	}
	if len(p.Include) > 0 {
		return "outside this crawl's scope prefixes (" + strings.Join(p.Include, ", ") + ")"
	}
	return "matches one of this crawl's excluded prefixes (" + strings.Join(p.Exclude, ", ") + ")"
}

// engagementScope unwraps a crawl's own scope to the engagement scope beneath it, for the requests a
// crawl makes on the session's behalf rather than the site map's.
func engagementScope(s Scope) Scope {
	if p, ok := s.(*PrefixScope); ok && p.Base != nil {
		return p.Base
	}
	return s
}
