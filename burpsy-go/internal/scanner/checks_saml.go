package scanner

import (
	"context"
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
)

// IssueSAMLUnsigned is burpsy's own row (burpsy_rows.go).
const IssueSAMLUnsigned = "SAML assertion not signed"

var (
	samlAssertion  = regexp.MustCompile(`<(\w+:)?Assertion[\s/>]`)
	samlEncrypted  = regexp.MustCompile(`<(\w+:)?EncryptedAssertion[\s/>]`)
	samlSignature  = regexp.MustCompile(`<(\w+:)?Signature[\s/>]`)
	samlWhitespace = strings.NewReplacer("\r", "", "\n", "", " ", "")
)

// samlResponseXML returns the decoded SAMLResponse the request carries, in its query or form body.
func samlResponseXML(raw string) string {
	head, body, _ := strings.Cut(raw, "\r\n\r\n")
	line, _, _ := strings.Cut(head, "\r\n")
	var values []string
	if parts := strings.Fields(line); len(parts) >= 2 {
		if _, q, ok := strings.Cut(parts[1], "?"); ok {
			if v, err := url.ParseQuery(q); err == nil {
				values = append(values, v["SAMLResponse"]...)
			}
		}
	}
	if v, err := url.ParseQuery(body); err == nil {
		values = append(values, v["SAMLResponse"]...)
	}
	for _, s := range values {
		if dec, err := base64.StdEncoding.DecodeString(samlWhitespace.Replace(s)); err == nil && strings.Contains(string(dec), "<") {
			return string(dec)
		}
	}
	return ""
}

func checkSAMLUnsigned(_ context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	doc := samlResponseXML(requestRaw(cc.Scanner, cc.Exchange))
	if doc == "" || !samlAssertion.MatchString(doc) || samlEncrypted.MatchString(doc) || samlSignature.MatchString(doc) {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, IssueSAMLUnsigned, "medium", "tentative",
		"SAMLResponse parameter: an Assertion with no Signature element on it or on the Response",
		"the identity provider sent an unsigned SAML assertion to this endpoint; if the service provider "+
			"accepts it, anyone can forge a login as any user")}, nil
}

// crossDomainPOSTOrSAML runs the SAML row on the Cross-domain POST descriptor, the passive row for
// the cross-site form post that carries a SAMLResponse.
func crossDomainPOSTOrSAML(cdp CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		out, err := cdp(ctx, cc)
		if err != nil {
			return out, err
		}
		s, err := checkSAMLUnsigned(ctx, cc)
		return append(out, s...), err
	}
}
