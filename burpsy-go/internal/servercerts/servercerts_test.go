package servercerts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func makeCert(t *testing.T, cn string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		DNSNames: []string{cn}, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
		NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(1_800_000_000, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestACertificateIsOneEntryWithEveryAuthorityItWasSeenOn(t *testing.T) {
	s := New()
	leaf, inter := makeCert(t, "app.test", 1), makeCert(t, "Issuing CA", 2)
	s.Record("app.test", 443, []*x509.Certificate{leaf, inter})
	s.Record("app.test", 8443, []*x509.Certificate{leaf, inter})
	s.Record("app.test", 443, []*x509.Certificate{leaf})
	list := s.List()
	if len(list) != 2 {
		t.Fatalf("%d entries, want 2 (one per certificate)", len(list))
	}
	var gotLeaf, gotInter *Entry
	for i := range list {
		if list[i].Leaf {
			gotLeaf = &list[i]
		} else {
			gotInter = &list[i]
		}
	}
	if gotLeaf == nil || gotInter == nil {
		t.Fatalf("leaf flags wrong: %+v", list)
	}
	if gotLeaf.Count != 3 || len(gotLeaf.SeenOn) != 2 || gotLeaf.SeenOn[0] != "app.test:443" || gotLeaf.SeenOn[1] != "app.test:8443" {
		t.Errorf("leaf = %+v", gotLeaf)
	}
	if gotLeaf.Subject != "CN=app.test" || gotLeaf.DNSNames[0] != "app.test" || gotLeaf.IPAddresses[0] != "10.0.0.1" || len(gotLeaf.SHA256) != 64 {
		t.Errorf("leaf details = %+v", gotLeaf)
	}
}

func TestTheStoreIsBoundedAndListIsNeverNil(t *testing.T) {
	var none *Store
	if none.List() == nil || New().List() == nil {
		t.Fatal("List returned nil")
	}
	s := New()
	clock := time.Unix(0, 0)
	s.now = func() time.Time { clock = clock.Add(time.Second); return clock }
	first := makeCert(t, "first.test", 1)
	s.Record("first.test", 443, []*x509.Certificate{first})
	for i := 0; i < MaxCertificates; i++ {
		s.Record("h.test", 443, []*x509.Certificate{makeCert(t, "h.test", int64(i+10))})
	}
	list := s.List()
	if len(list) != MaxCertificates {
		t.Fatalf("%d entries, want the bound %d", len(list), MaxCertificates)
	}
	for _, e := range list {
		if e.Subject == "CN=first.test" {
			t.Error("the least recently seen certificate was not the one evicted")
		}
	}
	s.Clear()
	if len(s.List()) != 0 {
		t.Error("Clear left entries")
	}
}
