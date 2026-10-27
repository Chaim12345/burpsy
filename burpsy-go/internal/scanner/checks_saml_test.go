package scanner

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestSAMLResponseXMLFlagsOnlyUnsignedAssertions(t *testing.T) {
	req := func(xml string) string {
		return "POST /acs HTTP/1.1\r\nHost: sp\r\n\r\nRelayState=x&SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(xml)))
	}
	unsigned := `<samlp:Response><saml:Assertion ID="a"><saml:Subject/></saml:Assertion></samlp:Response>`
	signed := `<samlp:Response><saml:Assertion ID="a"><ds:Signature/></saml:Assertion></samlp:Response>`
	for xml, want := range map[string]bool{unsigned: true, signed: false} {
		doc := samlResponseXML(req(xml))
		got := doc != "" && samlAssertion.MatchString(doc) && !samlSignature.MatchString(doc)
		if got != want {
			t.Errorf("%s: flagged=%v, want %v", xml, got, want)
		}
	}
}
