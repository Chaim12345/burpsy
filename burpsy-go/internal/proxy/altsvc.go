package proxy

// The Alt-Svc table (burpsy-react-ui-vln3): the proxy's record of which origins have advertised
// an HTTP/3 endpoint on responses burpsy itself received. Browsers keep the same record; burpsy
// keeps it so a later forward to the origin can ride QUIC - and so the exchange row can say why
// it did.
//
// Only what the origin said, for exactly as long as it said it: advertisements come from
// forwarded response heads, never invented; ma= bounds their life; clear withdraws them. The
// exact h3 token only - draft identifiers (h3-29) and other protocols are not HTTP/3.

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// altSvcOrigin keys the table: the scheme is always https (Alt-Svc's h3 is only meaningful on
// encrypted origins), so host:port identifies the origin.
type altSvcOrigin struct {
	host string
	port uint16
}

type altSvcEntry struct {
	endpointPort uint16
	expires      time.Time
}

type altSvcTable struct {
	mu      sync.Mutex
	entries map[altSvcOrigin]altSvcEntry
}

func newAltSvcTable() *altSvcTable {
	return &altSvcTable{entries: make(map[altSvcOrigin]altSvcEntry)}
}

// learn records one response's Alt-Svc header value for the origin it came from.
func (t *altSvcTable) learn(host string, port uint16, headerValue string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	origin := altSvcOrigin{host, port}
	for _, part := range strings.Split(headerValue, ",") {
		part = strings.TrimSpace(part)
		if part == "clear" {
			delete(t.entries, origin)
			continue
		}
		token, params, _ := strings.Cut(part, ";")
		// The alternative itself is one token: h3=":8443". Only the port is carried - the host
		// is the origin's own (alternate hosts are a footgun burpsy does not dial).
		name, authority, _ := strings.Cut(strings.TrimSpace(token), "=")
		if name != "h3" {
			continue
		}
		var endpointPort uint16
		authority = strings.Trim(authority, `"`)
		if p, err := strconv.Atoi(strings.TrimPrefix(authority, ":")); err == nil && p > 0 && p <= 65535 {
			endpointPort = uint16(p)
		}
		var maxAge int64 = 86400 // RFC 7838's default when ma= is absent.
		for _, param := range strings.Split(params, ";") {
			key, value, _ := strings.Cut(strings.TrimSpace(param), "=")
			value = strings.Trim(value, `"`)
			if key == "ma" {
				if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
					maxAge = seconds
				}
			}
		}
		if endpointPort == 0 {
			continue
		}
		if maxAge <= 0 {
			delete(t.entries, origin)
			continue
		}
		t.entries[origin] = altSvcEntry{endpointPort: endpointPort, expires: now.Add(time.Duration(maxAge) * time.Second)}
	}
}

// h3Endpoint reports the origin's advertised h3 dial address while its advertisement lives.
func (t *altSvcTable) h3Endpoint(host string, port uint16, now time.Time) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.entries[altSvcOrigin{host, port}]
	if !ok || !now.Before(entry.expires) {
		return "", false
	}
	return host + ":" + strconv.Itoa(int(entry.endpointPort)), true
}
