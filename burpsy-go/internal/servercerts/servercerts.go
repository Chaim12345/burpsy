// Package servercerts records the X.509 certificates target servers present (burpsy-react-ui-t75m):
// Burp's Settings → Network → TLS → "Server TLS certificates", an "information-only panel [that]
// contains details of all X509 certificates received from web servers" (settings/network/tls.html).
//
// The sender's TLS dials, its typed transport, and the proxy's upstream leg each hand the chain they
// received to one Store. A certificate is one entry however often it is seen, keyed by the SHA-256 of
// its DER, with every authority it was presented on (bounded) and when it was first and last seen.
// The store is bounded too; past the bound the least recently seen certificate goes first.
package servercerts

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	// MaxCertificates bounds the store.
	MaxCertificates = 512
	// maxSeenOn bounds the authorities kept per certificate.
	maxSeenOn = 16
)

// Entry is one certificate as the panel shows it.
type Entry struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	DNSNames     []string  `json:"dns_names"`
	IPAddresses  []string  `json:"ip_addresses"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SHA256       string    `json:"sha256"`
	// Leaf is true when the certificate was presented as the server's own (first in the chain) on at
	// least one connection; false for an intermediate or root a server sent along.
	Leaf bool `json:"leaf"`
	// SeenOn is every host:port the certificate was presented on, oldest first, bounded.
	SeenOn    []string  `json:"seen_on"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Store is the bounded, deduplicated record. The zero value is not usable; use New.
type Store struct {
	mu      sync.Mutex
	entries map[string]*Entry
	now     func() time.Time
}

// New returns an empty store.
func New() *Store { return &Store{entries: map[string]*Entry{}, now: time.Now} }

// Record notes the chain a server presented on host:port. Nil-safe, so a caller without a store
// simply records nothing.
func (s *Store) Record(host string, port uint16, chain []*x509.Certificate) {
	if s == nil || len(chain) == 0 {
		return
	}
	authority := net.JoinHostPort(host, strconv.Itoa(int(port)))
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, cert := range chain {
		if cert == nil {
			continue
		}
		sum := sha256.Sum256(cert.Raw)
		key := hex.EncodeToString(sum[:])
		e, ok := s.entries[key]
		if !ok {
			if len(s.entries) >= MaxCertificates {
				s.evictLocked()
			}
			e = &Entry{
				Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), SerialNumber: cert.SerialNumber.String(),
				DNSNames: append([]string{}, cert.DNSNames...), IPAddresses: []string{},
				NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, SHA256: key,
				SeenOn: []string{}, FirstSeen: now,
			}
			for _, ip := range cert.IPAddresses {
				e.IPAddresses = append(e.IPAddresses, ip.String())
			}
			s.entries[key] = e
		}
		e.Count++
		e.LastSeen = now
		if i == 0 {
			e.Leaf = true
		}
		seen := false
		for _, a := range e.SeenOn {
			if a == authority {
				seen = true
				break
			}
		}
		if !seen && len(e.SeenOn) < maxSeenOn {
			e.SeenOn = append(e.SeenOn, authority)
		}
	}
}

func (s *Store) evictLocked() {
	var oldest string
	for k, e := range s.entries {
		if oldest == "" || e.LastSeen.Before(s.entries[oldest].LastSeen) {
			oldest = k
		}
	}
	delete(s.entries, oldest)
}

// List returns every recorded certificate, most recently seen first. Never nil.
func (s *Store) List() []Entry {
	if s == nil {
		return []Entry{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		c := *e
		c.DNSNames = append([]string{}, e.DNSNames...)
		c.IPAddresses = append([]string{}, e.IPAddresses...)
		c.SeenOn = append([]string{}, e.SeenOn...)
		out = append(out, c)
	}
	sort.SliceStable(out, func(a, b int) bool {
		if !out[a].LastSeen.Equal(out[b].LastSeen) {
			return out[a].LastSeen.After(out[b].LastSeen)
		}
		return out[a].SHA256 < out[b].SHA256
	})
	return out
}

// Clear forgets every certificate.
func (s *Store) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = map[string]*Entry{}
}
