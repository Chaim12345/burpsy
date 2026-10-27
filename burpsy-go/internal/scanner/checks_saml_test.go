package scanner

import (
	"context"
	"encoding/base64"
	"net/url"
	"testing"
)

func TestTheSAMLRowFlagsOnlyUnsignedAssertions(t *testing.T) {
	for xml, want := range map[string]int{
		`<samlp:Response><saml:Assertion ID="a"><saml:Subject/></saml:Assertion></samlp:Response>`: 1,
		`<samlp:Response><saml:Assertion ID="a"><ds:Signature/></saml:Assertion></samlp:Response>`: 0,
		`<samlp:Response><saml:EncryptedAssertion><x/></saml:EncryptedAssertion></samlp:Response>`: 0,
	} {
		req := "POST /acs HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" +
			"RelayState=x&SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(xml)))
		cc := postureFixture(t, req, "HTTP/1.1 302 Found\r\nLocation: /\r\n\r\n", true)
		fs, err := crossDomainPOSTOrSAML(checkCrossDomainPOST)(context.Background(), cc)
		if err != nil || len(fs) != want {
			t.Errorf("%s: %d finding(s) (%v), want %d", xml, len(fs), err, want)
		}
	}
}
