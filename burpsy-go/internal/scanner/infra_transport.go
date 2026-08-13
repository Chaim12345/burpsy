package scanner

// Transport and caching posture analysers: unencrypted communications, HSTS enforcement,
// cacheable HTTPS responses and mixed content. These are the rows that shared the TLS
// reason text but are answered by headers and subresources, not by the handshake.

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// IsUnencryptedCommunication reports a request carried over cleartext HTTP.
func IsUnencryptedCommunication(requestURL string) bool {
	u, err := url.Parse(requestURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "http")
}

// HSTS is a parsed Strict-Transport-Security header.
type HSTS struct {
	Present           bool
	MaxAge            int64
	MaxAgePresent     bool
	IncludeSubDomains bool
	Preload           bool
}

// Enforced requires a max-age above zero. A header with max-age=0 is an instruction to
// forget the policy, so treating its mere presence as enforcement inverts its meaning.
func (h HSTS) Enforced() bool { return h.Present && h.MaxAgePresent && h.MaxAge > 0 }

func ParseHSTS(header string) HSTS {
	if strings.TrimSpace(header) == "" {
		return HSTS{}
	}
	h := HSTS{Present: true}
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		name, value, hasValue := strings.Cut(part, "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "max-age":
			if hasValue {
				v := strings.Trim(strings.TrimSpace(value), `"`)
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					h.MaxAge, h.MaxAgePresent = n, true
				}
			}
		case "includesubdomains":
			h.IncludeSubDomains = true
		case "preload":
			h.Preload = true
		}
	}
	return h
}

// StrictTransportSecurityNotEnforced reports the row's condition: an HTTPS response that
// does not commit the browser to HTTPS. It is scoped to TLS responses because the header
// is defined to be ignored over cleartext.
func StrictTransportSecurityNotEnforced(overTLS bool, headers http.Header) bool {
	if !overTLS {
		return false
	}
	return !ParseHSTS(headers.Get("Strict-Transport-Security")).Enforced()
}

// ResponseIsCacheable reports whether a response lacks any directive that would stop a
// browser writing it to disk.
//
// no-cache is treated as insufficient on purpose: it requires revalidation but still
// permits storage, so a copy can remain on disk for another user of the machine to
// recover. Only no-store, or private for a shared cache, actually prevent that.
func ResponseIsCacheable(headers http.Header) bool {
	cc := strings.ToLower(headers.Get("Cache-Control"))
	for _, directive := range strings.Split(cc, ",") {
		switch strings.TrimSpace(directive) {
		case "no-store":
			return false
		}
	}
	return true
}

// CacheableHTTPSResponse reports the row's condition: content delivered over TLS that the
// browser is free to store.
func CacheableHTTPSResponse(overTLS bool, headers http.Header) bool {
	return overTLS && ResponseIsCacheable(headers)
}

// MixedContentRef is one subresource loaded over cleartext by a TLS page.
type MixedContentRef struct {
	Tag       string
	Attribute string
	URL       string
	// Active is true for subresources that can execute or restyle — script, iframe, link
	// stylesheets, form actions. Passive references (images, media) are a weaker finding,
	// and collapsing the two would overstate the passive case.
	Active bool
}

var mixedContentTargets = []struct {
	selector  string
	attribute string
	active    bool
}{
	{"script[src]", "src", true},
	{"iframe[src]", "src", true},
	{"link[href]", "href", true},
	{"object[data]", "data", true},
	{"embed[src]", "src", true},
	{"form[action]", "action", true},
	{"img[src]", "src", false},
	{"audio[src]", "src", false},
	{"video[src]", "src", false},
	{"source[src]", "src", false},
}

// MixedContent reports cleartext subresources referenced by an HTTPS page. A non-TLS page
// yields nothing: mixed content is defined relative to a secure context.
func MixedContent(pageURL string, overTLS bool, body []byte) ([]MixedContentRef, error) {
	if !overTLS {
		return nil, nil
	}
	page, err := url.Parse(pageURL)
	if err != nil {
		return nil, err
	}
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}

	var refs []MixedContentRef
	seen := make(map[string]struct{})
	for _, target := range mixedContentTargets {
		doc.Find(target.selector).Each(func(_ int, s *goquery.Selection) {
			raw, _ := s.Attr(target.attribute)
			if strings.TrimSpace(raw) == "" {
				return
			}
			ref, err := page.Parse(raw)
			if err != nil || !strings.EqualFold(ref.Scheme, "http") {
				return
			}
			key := target.selector + "|" + ref.String()
			if _, dup := seen[key]; dup {
				return
			}
			seen[key] = struct{}{}
			refs = append(refs, MixedContentRef{
				Tag:       strings.Split(target.selector, "[")[0],
				Attribute: target.attribute,
				URL:       ref.String(),
				Active:    target.active,
			})
		})
	}
	return refs, nil
}

// HasActiveMixedContent separates the executable cases from images and media.
func HasActiveMixedContent(refs []MixedContentRef) bool {
	for _, r := range refs {
		if r.Active {
			return true
		}
	}
	return false
}
