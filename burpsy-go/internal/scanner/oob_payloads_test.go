package scanner

import (
	"strings"
	"testing"
)

// The SMTP row shares oobCheck with the DNS and HTTP rows, and for a while shared their
// payloads too. A URL never asks an application to send mail, so the SMTP row was wired but
// could realistically only fire if something treated a bare hostname as a mail domain — a
// check that is present, counted as coverage, and almost never able to fire. The protocol
// therefore has to change the payload shape.
func TestSMTPOutOfBandProbesUseAddressShapedPayloads(t *testing.T) {
	const host = "abc123.oast.test"

	smtp := oobPayloadsFor("smtp", host)
	if len(smtp) == 0 {
		t.Fatal("no SMTP payloads; the row could never provoke a callback")
	}
	var addressed int
	for _, p := range smtp {
		if strings.Contains(p, "@"+host) {
			addressed++
		}
		if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "//") {
			t.Errorf("SMTP payload %q is URL-shaped; a URL does not ask an application to send mail", p)
		}
	}
	if addressed == 0 {
		t.Error("no SMTP payload carries a local part; nothing would cause mail to be addressed to the collaborator")
	}

	// The bare host stays, because some applications append their own local part.
	var bare bool
	for _, p := range smtp {
		if p == host {
			bare = true
		}
	}
	if !bare {
		t.Error("the bare collaborator host was dropped; applications that supply their own local part would be missed")
	}
}

// The HTTP and DNS rows must keep the URL shapes — an address-shaped payload does not make a
// server fetch anything, so swapping the two would break them in the mirror-image way.
func TestNonSMTPOutOfBandProbesStayURLShaped(t *testing.T) {
	const host = "abc123.oast.test"
	for _, protocol := range []string{"http", "dns"} {
		payloads := oobPayloadsFor(protocol, host)
		if len(payloads) == 0 {
			t.Fatalf("%s: no payloads", protocol)
		}
		var absolute bool
		for _, p := range payloads {
			if p == "http://"+host+"/" {
				absolute = true
			}
			if strings.Contains(p, "@") {
				t.Errorf("%s payload %q is address-shaped; that does not cause a fetch", protocol, p)
			}
		}
		if !absolute {
			t.Errorf("%s payloads carry no absolute URL: %v", protocol, payloads)
		}
	}
}
