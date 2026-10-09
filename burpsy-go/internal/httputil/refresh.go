package httputil

// Declarative refresh (burpsy-react-ui-z9zi, q0qr): the URL a Refresh response header or a
// <meta http-equiv="refresh"> element names. Shared by the sender, which follows such redirects when
// the network settings allow them, and the crawler, which discovers them as delayed-redirect edges, so
// both read the same grammar.

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// RefreshTarget reads the URL out of a refresh value, HTML's "shared declarative refresh steps": a
// delay, then ';' or ',', then an optional "url=", then the URL, optionally quoted. A value that is
// only a delay reloads the page itself and names no new location, so it reports false.
func RefreshTarget(value string) (string, bool) {
	v := strings.TrimSpace(value)
	i := 0
	for i < len(v) && (v[i] >= '0' && v[i] <= '9' || v[i] == '.') {
		i++
	}
	if i == 0 {
		return "", false
	}
	v = strings.TrimLeft(v[i:], " \t")
	if v == "" || (v[0] != ';' && v[0] != ',') {
		return "", false
	}
	v = strings.TrimLeft(v[1:], " \t")
	if len(v) >= 3 && strings.EqualFold(v[:3], "url") {
		rest := strings.TrimLeft(v[3:], " \t")
		if strings.HasPrefix(rest, "=") {
			v = strings.TrimLeft(rest[1:], " \t")
		}
	}
	if v != "" && (v[0] == '\'' || v[0] == '"') {
		q := v[0]
		v = v[1:]
		if j := strings.IndexByte(v, q); j >= 0 {
			v = v[:j]
		}
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	return v, true
}

// metaRefreshScanBytes bounds how much of a body is tokenised looking for a meta refresh. The element
// belongs in <head>, and a page that puts it past the first 64 KiB is not one a browser treats as a
// redirect either.
const metaRefreshScanBytes = 64 * 1024

// MetaRefreshTarget returns the URL of the first <meta http-equiv="refresh"> in an HTML body.
func MetaRefreshTarget(body []byte) (string, bool) {
	if len(body) > metaRefreshScanBytes {
		body = body[:metaRefreshScanBytes]
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		switch z.Next() {
		case html.ErrorToken:
			return "", false
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			if atom.Lookup(name) != atom.Meta || !hasAttr {
				continue
			}
			var equiv, content string
			for {
				k, v, more := z.TagAttr()
				switch strings.ToLower(string(k)) {
				case "http-equiv":
					equiv = string(v)
				case "content":
					content = string(v)
				}
				if !more {
					break
				}
			}
			if strings.EqualFold(strings.TrimSpace(equiv), "refresh") {
				if target, ok := RefreshTarget(content); ok {
					return target, true
				}
			}
		}
	}
}
