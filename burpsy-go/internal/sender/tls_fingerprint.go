package sender

// Per-target browser TLS fingerprints (burpsy-react-ui-63pf): the operator-facing setting
// behind alpn.Dialer.Fingerprint. Rules are matched like netauth's client-certificate
// bindings (matchHost: "*" matches everything, "*.example.com" matches the suffix and the
// apex, anything else is exact), first binding wins - one glob dialect, not two.

import (
	"strings"

	"github.com/burpsy-go/burpsy/internal/alpn"
)

// TLSFingerprints is the ordered set of host-pattern to fingerprint bindings.
type TLSFingerprints struct {
	entries []fingerprintBinding
}

type fingerprintBinding struct {
	pattern     string
	fingerprint alpn.Fingerprint
}

// Add binds a fingerprint to a host pattern, replacing any binding the pattern already had.
func (f *TLSFingerprints) Add(pattern string, fingerprint alpn.Fingerprint) {
	for i, e := range f.entries {
		if e.pattern == pattern {
			f.entries[i].fingerprint = fingerprint
			return
		}
	}
	f.entries = append(f.entries, fingerprintBinding{pattern, fingerprint})
}

// Remove drops a pattern's binding, reporting whether there was one.
func (f *TLSFingerprints) Remove(pattern string) bool {
	for i, e := range f.entries {
		if e.pattern == pattern {
			f.entries = append(f.entries[:i], f.entries[i+1:]...)
			return true
		}
	}
	return false
}

// For returns the fingerprint bound to host, or FingerprintGo (Go's own hello) when nothing
// matches. Nil receiver is the default: no bindings, Go's hello.
func (f *TLSFingerprints) For(host string) alpn.Fingerprint {
	if f == nil {
		return alpn.FingerprintGo
	}
	for _, e := range f.entries {
		if fingerprintMatchHost(e.pattern, host) {
			return e.fingerprint
		}
	}
	return alpn.FingerprintGo
}

// fingerprintMatchHost mirrors netauth.matchHost exactly: same patterns, same meaning.
func fingerprintMatchHost(pattern, host string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(host, suffix) || host == pattern[2:]
	}
	return pattern == host
}
