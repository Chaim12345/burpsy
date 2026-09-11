package scanner

// The remaining rows whose infrastructure is complete: GraphQL, JWT forgery, TLS certificate,
// SMTP header injection, CORS, cross-domain policy files, XXE and entity expansion, file
// upload discovery, passive OpenAPI discovery, out-of-band interaction, React2Shell version
// fingerprinting, and the SQL-statement-in-parameter heuristic.
//
// Rows deliberately NOT here, and why, so the gap is legible rather than looking like an
// oversight:
//
//   - "JWT arbitrary jku header supported" / "...x5u header supported": confirming these
//     requires serving a JWKS or certificate at a URL the target will fetch. The OOB channel
//     registers a callback domain but cannot serve chosen content, so the forged token could
//     be sent but its acceptance could never be proven.
//   - "Broken access control": needs a session.Coordinator on CheckContext to build the
//     authenticated half. AuthContextsFrom exists; the handle does not.
//   - "Cross-site request forgery": ClassifyCSRF needs three probe outcomes including an
//     authenticated session, which is the same missing handle.
//   - The four meta rows ("Extension generated issue" and siblings) are issue-source
//     provenance labels Burp applies when a human or extension files a finding. They are not
//     detections and cannot be wired without fabricating them.

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/oob"
	"github.com/burpsy-go/burpsy/internal/tlsprobe"
	"github.com/burpsy-go/burpsy/pkg/graphqlmap"
)

// remainingChecksEnabled gates this file behind one opt-in switch.
//
// Two of these rows used to hang off CheckSSRF and CheckXXE, which are on by default in the
// web layer's live-audit config. Once they had real evaluators that mattered: the OOB check
// needs a collaborator binary and outbound DNS, and reports their absence as an error, so a
// default scan on a machine without interactsh began failing every sweep. Sending XXE payloads
// on a default scan is the same kind of posture change. Both are now opt-in, which restores
// "a default scan sends nothing it was not asked to send" while keeping the checks available.
func remainingChecksEnabled(c *ScanConfig) bool { return c != nil && c.CheckExtendedActive }

// oobChecksEnabled narrows remainingChecksEnabled to the four rows that need a collaborator: an
// out-of-band callback nothing in this process can synthesise. It is an AND, not an alternative:
// CheckOutOfBand on its own admits nothing.
func oobChecksEnabled(c *ScanConfig) bool { return remainingChecksEnabled(c) && c.CheckOutOfBand }

// tlsProbeChecksEnabled gates the TLS certificate row, which shells out to tlsx.
//
// It used to share oobChecksEnabled with the four collaborator rows, which was wrong in a way that
// cost coverage rather than correctness: this row needs no callback and no collaborator, only a TLS
// port to connect to. Grouping it with rows that wait five seconds for a DNS interaction made it
// undemonstrable for a reason that was never true of it. Still behind the family switch, because it
// spawns a subprocess.
func tlsProbeChecksEnabled(c *ScanConfig) bool { return remainingChecksEnabled(c) }

// ---------------------------------------------------------------------------
// GraphQL
// ---------------------------------------------------------------------------

// The four GraphQL rows run on pkg/graphqlmap, driven through scannerTransport so probes
// leave via the authorised sender. Using the library rather than hand-rolled bodies means the
// scanner and a standalone caller exercise the same introspection documents, the same batching
// wire shape, and the same suggestion parser.

func checkGraphQLEndpointFound(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	client := newGraphQLClient(cc)
	res, err := client.Execute(ctx, "query{__typename}")
	if err != nil {
		return nil, fmt.Errorf("GraphQL endpoint probe: %w", err)
	}
	if !graphqlmap.IsGraphQLEnvelope(res.Body) {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "GraphQL endpoint found", "info", "firm",
		fmt.Sprintf("HTTP %d with a GraphQL envelope", res.Status),
		"the endpoint answers a GraphQL query with a GraphQL data/errors envelope")}, nil
}

func checkGraphQLIntrospection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if err := cc.RequireEgress(); err != nil {
		return nil, fmt.Errorf("GraphQL introspection: %w", err)
	}
	schema, err := newGraphQLClient(cc).Introspect(ctx)
	if err != nil {
		// Both introspection documents were refused or unparseable. That is the expected
		// state on a hardened endpoint, not a scan failure — but only because RequireEgress
		// above has already ruled out the case where nothing was sent at all.
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "GraphQL introspection enabled", "low", "certain",
		fmt.Sprintf("%d types via the %s introspection document", len(schema.Types), schema.Document),
		fmt.Sprintf("the endpoint discloses its schema: %d object types, %d injectable String/ID arguments",
			len(schema.ObjectTypes()), len(schema.StringArguments())))}, nil
}

func checkGraphQLSuggestions(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	res, err := newGraphQLClient(cc).Execute(ctx, graphqlmap.SuggestionProbe(""))
	if err != nil {
		return nil, fmt.Errorf("GraphQL suggestion probe: %w", err)
	}
	suggestions := graphqlmap.FieldSuggestions(res.ErrorMessages())
	if len(suggestions) == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "GraphQL suggestions enabled", "low", "certain",
		strings.Join(suggestions, ", "),
		"the endpoint names valid fields in its error messages, which discloses schema even with introspection disabled")}, nil
}

// checkGraphQLContentType reports an endpoint that answers GraphQL under a content type it
// should reject. That is the precondition for CSRF against a GraphQL endpoint: a form can only
// send urlencoded or plain bodies, so an endpoint that insists on application/json is not
// reachable that way.
func checkGraphQLContentType(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if err := cc.RequireEgress(); err != nil {
		return nil, fmt.Errorf("GraphQL content type: %w", err)
	}
	// Every probe below may legitimately fail (an endpoint that rejects the encoding is the
	// negative result this check looks for), which is only safe to ignore because the egress
	// guard has already separated that from "no probe could be sent".
	var accepted []string
	for _, enc := range []struct {
		name string
		opt  graphqlmap.Option
	}{
		{"application/x-www-form-urlencoded", graphqlmap.WithEncoding(graphqlmap.EncodingForm)},
		{"query string (GET)", graphqlmap.WithEncoding(graphqlmap.EncodingGet)},
	} {
		res, err := newGraphQLClient(cc, enc.opt).Execute(ctx, "query{__typename}")
		if err != nil || res == nil {
			continue
		}
		if graphqlmap.IsGraphQLEnvelope(res.Body) && !res.HasErrors() {
			accepted = append(accepted, enc.name)
		}
	}
	if len(accepted) == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "GraphQL content type not validated", "low", "firm",
		strings.Join(accepted, ", "),
		"the endpoint answers GraphQL sent under content types a browser form can produce, which makes it reachable by CSRF")}, nil
}

// ---------------------------------------------------------------------------
// JWT forgery
// ---------------------------------------------------------------------------

// jwtFromExchange finds the first parseable JWT in the request.
func jwtFromExchange(cc *CheckContext) (string, JWTToken, bool) {
	raw := requestRaw(cc.Scanner, cc.Exchange)
	for _, field := range strings.Fields(strings.ReplaceAll(raw, ";", " ")) {
		field = strings.Trim(field, `"',`)
		if strings.Count(field, ".") != 2 || len(field) < 20 {
			continue
		}
		if t := ParseJWT(field); t.ParseError == "" {
			return field, t, true
		}
	}
	return "", JWTToken{}, false
}

// jwtForgeryAccepted replaces the original token with a forged one and reports whether the
// application still served the authenticated response.
//
// The comparison is against the baseline, not against a status code alone: an endpoint that
// returns 200 with a login page for both is not accepting the forgery.
//
// The error return is separate from the false return on purpose. "The application rejected the
// forgery" and "the forgery was never sent" both used to come back as false with an
// explanatory string the caller discarded, so a scan with no sender reported every JWT row
// clean. Only the first of those is a verdict.
func jwtForgeryAccepted(ctx context.Context, cc *CheckContext, original, forged string) (bool, string, error) {
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if !strings.Contains(raw, original) {
		return false, "", fmt.Errorf("the token was not found in the request bytes, so it could not be replaced")
	}
	h, err := NewProbeHarness(ctx, cc, []string{"header", "cookie"})
	if err != nil {
		return false, "", fmt.Errorf("forged-token probe not prepared: %w", err)
	}
	mutated := strings.Replace(raw, original, forged, 1)
	res, err := h.send(ctx, []byte(mutated))
	if err != nil {
		return false, "", fmt.Errorf("forged-token probe not sent: %w", err)
	}
	base := NewResponseFingerprint(h.Baseline().Status, h.Baseline().Body)
	got := NewResponseFingerprint(res.Status, res.Body)
	if base.SameShape(got) {
		return true, fmt.Sprintf("the forged token produced the same response as the original (HTTP %d)", res.Status), nil
	}
	return false, fmt.Sprintf("the forged token produced a different response (HTTP %d vs baseline %d)",
		res.Status, h.Baseline().Status), nil
}

func jwtCheck(row string, forge func(JWTToken) ([]string, error)) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
			return nil, nil
		}
		// A request with no JWT is genuinely nothing to do, and demanding egress for it would
		// be a false refusal — so the precondition is checked before the capability.
		original, token, ok := jwtFromExchange(cc)
		if !ok {
			return nil, nil
		}
		if err := cc.RequireEgress(); err != nil {
			return nil, fmt.Errorf("%s: %w", row, err)
		}
		forged, err := forge(token)
		if err != nil {
			return nil, fmt.Errorf("%s: could not forge a token to test with: %w", row, err)
		}
		if len(forged) == 0 {
			return nil, fmt.Errorf("%s: no forged token was produced, so nothing was tested", row)
		}
		for _, f := range forged {
			accepted, detail, err := jwtForgeryAccepted(ctx, cc, original, f)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", row, err)
			}
			if accepted {
				return []*Finding{buildHeaderFinding(cc, row, "high", "firm", f, detail)}, nil
			}
		}
		return nil, nil
	}
}

// checkJWTPrivateKeyDisclosed is passive: a JWKS that ships private material.
func checkJWTPrivateKeyDisclosed(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	body := responseBody(responseRaw(cc.Scanner, cc.Exchange))
	if body == "" {
		return nil, nil
	}
	fields := ScanForPrivateKeyInJWKS([]byte(body))
	if len(fields) == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "JWT private key disclosed", "high", "certain",
		strings.Join(fields, ", "),
		"the JWKS response carries private key material, so anyone can mint valid tokens")}, nil
}

// ---------------------------------------------------------------------------
// TLS certificate
// ---------------------------------------------------------------------------

func checkTLSCertificate(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil || !cc.Exchange.TLS {
		// A plaintext capture has no certificate to examine. That is an absence, not a refusal.
		return nil, nil
	}
	// tlsprobe shells out to tlsx and opens its own connection, so it does not pass through
	// probeGate the way every other probe does. That makes this the one check that could touch
	// a host the engagement never authorised, and it would do so before anything noticed. The
	// gate is therefore consulted explicitly here: RequireEgress fails both when no sender is
	// configured and when probeGate refuses this exchange, which is exactly the authorisation
	// question tlsx cannot ask for itself.
	if err := cc.RequireEgress(); err != nil {
		return nil, fmt.Errorf("TLS certificate: %w", err)
	}
	target := net.JoinHostPort(cc.Exchange.Host, strconv.Itoa(int(cc.Exchange.Port)))
	res := tlsprobe.Probe(ctx, []string{target}, tlsprobe.Options{Timeout: 30 * time.Second})
	if res.Outcome != tlsprobe.OutcomeCompleted {
		// Unavailable / failed / not invoked are all "could not look", which must not
		// read as a clean certificate.
		return nil, fmt.Errorf("TLS certificate probe: %s: %v", res.Outcome, res.Err)
	}
	for _, host := range res.Hosts {
		if !host.HasCertificateDefect() {
			continue
		}
		var defects []string
		for name, present := range map[string]bool{
			"expired": host.Expired, "self-signed": host.SelfSigned,
			"hostname mismatch": host.Mismatched, "untrusted issuer": host.Untrusted,
			"revoked": host.Revoked,
		} {
			if present {
				defects = append(defects, name)
			}
		}
		return []*Finding{buildHeaderFinding(cc, "TLS certificate", "medium", "certain",
			strings.Join(defects, ", "),
			fmt.Sprintf("the certificate for %s is not valid for this connection (notAfter %s, issuer %q)",
				host.Host, host.NotAfter, host.IssuerCN))}, nil
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// SMTP header injection
// ---------------------------------------------------------------------------

func checkSMTPHeaderInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	h, err := NewProbeHarness(ctx, cc, cc.ProbeInsertionKinds())
	if err != nil {
		return nil, err
	}
	points := h.Points()
	if len(points) > MaxInjectionPointsPerCheck {
		points = points[:MaxInjectionPointsPerCheck]
	}
	for _, point := range points {
		for _, payload := range MailHeaderPayloads("") {
			res, err := h.Send(ctx, point, payload.Payload)
			if err != nil {
				continue
			}
			ev := ClassifyMailHeaderResponse(h.Baseline().Body, res.Body,
				h.Baseline().Status, res.Status)
			if ev == MailInjectionNone {
				continue
			}
			return []*Finding{buildHeaderFinding(cc, "SMTP header injection", "high", "firm",
				payload.Payload,
				fmt.Sprintf("%s %q: mail-header evidence %d", point.Kind, point.Name, int(ev)))}, nil
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// CORS (the base row; the three risky sub-cases are already native)
// ---------------------------------------------------------------------------

func checkCORSBaseRow(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	acao := strings.TrimSpace(headerValue(respRaw, headerAccessControlAllowOrigin))
	if acao == "" {
		return nil, nil
	}
	credentials := strings.EqualFold(strings.TrimSpace(headerValue(respRaw, headerAccessControlAllowCredentials)), "true")
	detail := "the response defines a cross-origin resource sharing policy, creating a trust relationship that should be reviewed"
	if credentials {
		detail += "; credentials are also permitted"
	}
	return []*Finding{buildHeaderFinding(cc, "Cross-origin resource sharing", "info", "certain",
		headerAccessControlAllowOrigin+": "+acao, detail)}, nil
}

// ---------------------------------------------------------------------------
// cross-domain policy files (host-wide)
// ---------------------------------------------------------------------------

func crossDomainPolicyCheck(row, path string, parse func([]byte) CrossdomainPolicy) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		// This row is decided by fetching a file, so without egress there is no verdict to
		// give. sendTestRequest reports failure as an empty string, which is the same value a
		// host with no policy file produces — the guard is what keeps those apart.
		if err := cc.RequireEgress(); err != nil {
			return nil, fmt.Errorf("%s: %w", row, err)
		}
		body := cc.Scanner.sendTestRequest(ctx, cc.Exchange, path)
		if strings.TrimSpace(body) == "" {
			// Genuinely absent: the request went out and came back with nothing.
			return nil, nil
		}
		policy := parse([]byte(body))
		if policy.ParseError != "" {
			return nil, nil
		}
		if !policy.TrustsArbitraryOrigin() {
			return nil, nil
		}
		return []*Finding{buildHeaderFinding(cc, row, "medium", "certain", path,
			"the policy file trusts an arbitrary origin: "+policy.RiskSummary())}, nil
	}
}

// ---------------------------------------------------------------------------
// XXE and entity expansion
// ---------------------------------------------------------------------------

func checkXXE(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	// entire_body first: an XXE payload is a whole document with its own DOCTYPE, not a value
	// spliced into a parameter. IpBody only enumerates form pairs and JSON string values, so an
	// application/xml request yielded zero points and the check reported clean having tested
	// nothing at all.
	h, err := NewProbeHarness(ctx, cc, []string{"entire_body", "body", "query"})
	if err != nil {
		return nil, err
	}
	points := h.Points()
	if len(points) > MaxInjectionPointsPerCheck {
		points = points[:MaxInjectionPointsPerCheck]
	}
	for _, point := range points {
		for _, payload := range XXEFilePayloads("bsyxxe") {
			res, err := h.Send(ctx, point, payload.Body)
			if err != nil {
				continue
			}
			if DetectXXEEvidence(res.Body, payload) == XXEEvidenceNone {
				continue
			}
			return []*Finding{buildHeaderFinding(cc, "XML external entity injection", "high", "firm",
				payload.Name, fmt.Sprintf("%s %q: the external entity was resolved", point.Kind, point.Name))}, nil
		}
	}
	return nil, nil
}

func checkXMLEntityExpansion(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	h, err := NewProbeHarness(ctx, cc, []string{"entire_body", "body"})
	if err != nil {
		return nil, err
	}
	points := h.Points()
	if len(points) > MaxInjectionPointsPerCheck {
		points = points[:MaxInjectionPointsPerCheck]
	}
	for _, point := range points {
		for _, payload := range EntityExpansionPayloads() {
			res, err := h.Send(ctx, point, payload.Body)
			if err != nil {
				continue
			}
			// An echo is not an expansion. The payload is itself a kilobyte of entity
			// declarations, so "the body grew four times over the baseline" is satisfied by a
			// server that merely reflected it - which is exactly how this row fired against an
			// endpoint that caps expansion. Two discriminators, both required:
			//
			//   - the entity reference must be gone. If the response still contains it
			//     verbatim, nothing expanded it, whatever the response now weighs.
			//   - the growth must exceed what echoing the payload could account for, rather
			//     than exceeding the baseline, which the payload's own length already does.
			if strings.Contains(res.Body, payload.Marker) {
				continue
			}
			if len(res.Body) <= len(h.Baseline().Body)+2*len(payload.Body) {
				continue
			}
			return []*Finding{buildHeaderFinding(cc, "XML entity expansion", "medium", "firm",
				payload.Name,
				fmt.Sprintf("%s %q: the response grew from %d to %d bytes, so the entity was expanded",
					point.Kind, point.Name, len(h.Baseline().Body), len(res.Body)))}, nil
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// passive discovery: file upload, OpenAPI
// ---------------------------------------------------------------------------

func checkFileUploadFunctionality(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	forms, _ := parsedForms(cc)
	for _, f := range forms {
		for _, fl := range f.Fields {
			if strings.EqualFold(fl.Type, "file") {
				return []*Finding{buildHeaderFinding(cc, "File upload functionality", "info", "certain",
					fmt.Sprintf("form action %q, field %q", f.Action, fl.Name),
					"the page exposes a file-upload field, which warrants review of what the server accepts")}, nil
			}
		}
	}
	return nil, nil
}

// openAPIMarkers are the structural keys an OpenAPI/Swagger document always carries.
var openAPIMarkers = []string{`"openapi"`, `"swagger"`, `"paths"`}

func checkOpenAPIDefinitionPassive(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	body := responseBody(responseRaw(cc.Scanner, cc.Exchange))
	if body == "" {
		return nil, nil
	}
	lower := strings.ToLower(body)
	// Both a version key and a paths object are required: "paths" alone appears in plenty
	// of unrelated JSON, and reporting on it would fire on half a site's API responses.
	hasVersion := strings.Contains(lower, `"openapi"`) || strings.Contains(lower, `"swagger"`)
	if !hasVersion || !strings.Contains(lower, `"paths"`) {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "OpenAPI definition found (passive scan check)",
		"info", "firm", strings.Join(openAPIMarkers, " + "),
		"the response body is an OpenAPI/Swagger definition, which discloses the API surface")}, nil
}

// ---------------------------------------------------------------------------
// out-of-band interaction
// ---------------------------------------------------------------------------

// oobCheck builds a runner that plants the collaborator domain in every insertion point and
// then asks the channel whether the target called back.
func oobCheck(row, protocol string) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		// Cheap local preconditions first, expensive external capability second.
		//
		// This used to register the collaborator before looking at whether a probe could be
		// sent at all, which meant every scan with no sender still spawned interactsh-client
		// and waited up to 30s for a domain it would never use. Acquiring an external process
		// and a public DNS registration to answer a question already decided locally is both
		// wasteful and untestable, so the order is now: authorised to send? points to plant?
		// only then open the channel.
		if err := cc.RequireEgress(); err != nil {
			return nil, fmt.Errorf("%s: %w", row, err)
		}
		h, err := NewProbeHarness(ctx, cc, cc.ProbeInsertionKinds())
		if err != nil {
			return nil, err
		}
		if len(h.Points()) == 0 {
			// Nowhere to plant a callback domain. Registering one would prove nothing.
			return nil, nil
		}

		channel, err := cc.Scanner.OOBChannel(ctx)
		if err != nil {
			// No channel means no capability. Zero interactions must never read as zero
			// vulnerabilities, which is exactly why this is an error.
			return nil, fmt.Errorf("%s: %w", row, err)
		}

		points := h.Points()
		if len(points) > MaxInjectionPointsPerCheck {
			points = points[:MaxInjectionPointsPerCheck]
		}
		marker := strings.ToLower(domCanary("oob"))
		payloadHost := marker + "." + channel.Domain()
		var sent int
		for _, point := range points {
			for _, payload := range oobPayloadsFor(protocol, payloadHost) {
				if _, err := h.Send(ctx, point, payload); err != nil {
					continue
				}
				sent++
			}
		}
		if sent == 0 {
			// Nothing left the process, so there is nothing a callback could be a response to.
			return nil, fmt.Errorf("%s: no probe carrying the collaborator domain could be sent: %w",
				row, errCheckInconclusive)
		}

		// The wait belongs to the registry, not to this check.
		//
		// This used to sleep five seconds, poll once, and close the channel on return - so a
		// callback in the sixth second was unrecoverable and the row reported nothing, which reads
		// as clean. A target that queues outbound work is precisely what this row is for.
		deadline := nowUTC().Add(DefaultPendingDeadline)
		if cc.Config != nil && cc.Config.PendingDeadline > 0 {
			deadline = nowUTC().Add(cc.Config.PendingDeadline)
		}
		if err := cc.Scanner.Pending().Register(PendingItem{
			Row:      row,
			Exchange: cc.Exchange.ID,
			Deadline: deadline,
			What: fmt.Sprintf("%d probe(s) carrying %s planted in %s, awaiting a %s callback",
				sent, payloadHost, cc.Exchange.Path, protocol),
		}, func(context.Context) (*Finding, bool, error) {
			interactions, err := channel.InteractionsFor(marker)
			if err != nil {
				// Retryable: the channel being unreadable now says nothing about the target.
				return nil, false, fmt.Errorf("reading out-of-band interactions: %w", err)
			}
			for _, i := range oob.Deduplicate(interactions) {
				if !strings.EqualFold(i.Protocol, protocol) {
					continue
				}
				return buildHeaderFinding(cc, row, "high", "certain",
					fmt.Sprintf("%s interaction from %s", i.Protocol, i.RemoteAddress),
					"the target contacted a domain supplied in a parameter, proving it fetches "+
						"attacker-controlled locations"), true, nil
			}
			// Deliberately never settles negatively. Absence of a callback is not evidence the
			// target does not make one; it is the absence of evidence, and the registry reports
			// that as outstanding rather than clean.
			return nil, false, nil
		}); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%s: collaborator domain planted, awaiting callback: %w",
			row, errCheckInconclusive)
	}
}

// oobPayloadsFor returns the payload shapes that can plausibly provoke a callback over the
// named protocol.
//
// The protocol is not decoration: an SMTP interaction happens because the application sent
// mail to a domain it was handed, which a URL-shaped payload does not ask it to do. Planting
// only `http://host/` and expecting an SMTP callback would leave the row wired but effectively
// silent — the failure mode this codebase treats as worse than an honest decline, because a
// check that cannot fire still counts as coverage. So the SMTP row gets address-shaped
// payloads as well, and keeps the bare host for applications that append their own local part.
func oobPayloadsFor(protocol, host string) []string {
	if strings.EqualFold(protocol, "smtp") {
		return []string{
			"burpsy@" + host,
			"<burpsy@" + host + ">",
			host,
		}
	}
	return []string{
		"http://" + host + "/",
		"//" + host + "/",
		host,
	}
}

// ---------------------------------------------------------------------------
// version fingerprinting and the SQL-in-parameter heuristic
// ---------------------------------------------------------------------------

// react2ShellAffected is the affected range from the catalog's own remediation text: React
// Server Components 19.0.0 through 19.2.1, patched in 19.0.1 / 19.1.2 / 19.2.1.
const react2ShellAffected = ">=19.0.0 <19.2.1"

func checkReact2Shell(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	techs, err := Fingerprint(headerSet(respRaw), []byte(responseBody(respRaw)))
	if err != nil {
		return nil, nil
	}
	for _, name := range []string{"React", "Next.js"} {
		verdict, found := TechnologyInAffectedRange(techs, name, react2ShellAffected)
		if !found || verdict != VersionInRange {
			continue
		}
		tech, _ := FindTechnology(techs, name)
		// Tentative on purpose: this is a version match, not an exploitation. The
		// deserialization probe that would make it certain is not implemented, and saying
		// "certain" from a version string alone would overstate what was tested.
		return []*Finding{buildHeaderFinding(cc,
			"React Server Components remote code execution (React2Shell)", "high", "tentative",
			tech.String(),
			fmt.Sprintf("%s is within the affected range %s. This is a version match only; no deserialization probe was sent, so exploitability was not confirmed.",
				tech.String(), react2ShellAffected))}, nil
	}
	return nil, nil
}

// sqlKeywordsInParameter are the fragments whose presence in a *submitted* value suggests the
// application is passing SQL through the client. Recovered fragments from burp.Ze2s inform the
// shape; the keyword list itself is standard.
var sqlKeywordsInParameter = []string{
	"select ", " from ", " where ", "union select", "insert into", "update ", "delete from",
	" order by ", " group by ", "drop table",
}

func checkSQLStatementInParameter(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	points, _ := bcheck.Enumerate([]byte(raw), []string{"query", "body", "cookie"})
	for _, p := range points {
		value := strings.ToLower(p.BaseValue)
		hits := 0
		var matched []string
		for _, kw := range sqlKeywordsInParameter {
			if strings.Contains(value, kw) {
				hits++
				matched = append(matched, strings.TrimSpace(kw))
			}
		}
		// Two keywords, not one: "update" or "select" alone appears in ordinary values
		// ("update_profile", "selected"), and a single match would fire constantly.
		if hits < 2 {
			continue
		}
		return []*Finding{buildHeaderFinding(cc, "SQL statement in request parameter", "info", "firm",
			fmt.Sprintf("%s %q contains %s", p.Kind, p.Name, strings.Join(matched, ", ")),
			"a request parameter carries what looks like a SQL statement, so the client may be choosing the query")}, nil
	}
	return nil, nil
}

// RemainingCheckDescriptors returns the rows wired by this file.
func RemainingCheckDescriptors() []CheckDescriptor {
	return []CheckDescriptor{
		nativeDescriptor("GraphQL endpoint found", DispatchScopePerUrl, remainingChecksEnabled, checkGraphQLEndpointFound),
		nativeDescriptor("GraphQL introspection enabled", DispatchScopePerUrl, remainingChecksEnabled, checkGraphQLIntrospection),
		nativeDescriptor("GraphQL suggestions enabled", DispatchScopePerUrl, remainingChecksEnabled, checkGraphQLSuggestions),
		nativeDescriptor("GraphQL content type not validated", DispatchScopePerUrl, remainingChecksEnabled, checkGraphQLContentType),

		nativeDescriptor("JWT signature not verified", DispatchScopePerRequest, remainingChecksEnabled,
			jwtCheck("JWT signature not verified", func(t JWTToken) ([]string, error) {
				// An unsigned-but-otherwise-intact token: if it is accepted, the
				// signature was never checked.
				tok, err := ForgeNoneAlg(t)
				if err != nil {
					return nil, err
				}
				return []string{tok}, nil
			})),
		nativeDescriptor("JWT none algorithm supported", DispatchScopePerRequest, remainingChecksEnabled,
			jwtCheck("JWT none algorithm supported", func(t JWTToken) ([]string, error) {
				return ForgeNoneAlgVariants(t), nil
			})),
		nativeDescriptor("JWT self-signed JWK header supported", DispatchScopePerRequest, remainingChecksEnabled,
			jwtCheck("JWT self-signed JWK header supported", func(t JWTToken) ([]string, error) {
				tok, _, err := ForgeSelfSignedJWK(t)
				if err != nil {
					return nil, err
				}
				return []string{tok}, nil
			})),
		nativeDescriptor("JWT private key disclosed", DispatchScopePerUrl, remainingChecksEnabled, checkJWTPrivateKeyDisclosed),

		nativeDescriptor("TLS certificate", DispatchScopePerHost, tlsProbeChecksEnabled, checkTLSCertificate),
		nativeDescriptor("SMTP header injection", DispatchScopePerUrl, remainingChecksEnabled, checkSMTPHeaderInjection),
		nativeDescriptor("Cross-origin resource sharing", DispatchScopePerRequest, remainingChecksEnabled, checkCORSBaseRow),

		nativeDescriptor("Flash cross-domain policy", DispatchScopePerHost, remainingChecksEnabled,
			crossDomainPolicyCheck("Flash cross-domain policy", "/crossdomain.xml", ParseFlashCrossdomainPolicy)),
		nativeDescriptor("Silverlight cross-domain policy", DispatchScopePerHost, remainingChecksEnabled,
			crossDomainPolicyCheck("Silverlight cross-domain policy", "/clientaccesspolicy.xml", ParseSilverlightPolicy)),

		nativeDescriptor("XML external entity injection", DispatchScopePerUrl, remainingChecksEnabled, checkXXE),
		nativeDescriptor("XML entity expansion", DispatchScopePerUrl, remainingChecksEnabled, checkXMLEntityExpansion),

		nativeDescriptor("File upload functionality", DispatchScopePerHost, remainingChecksEnabled, checkFileUploadFunctionality),
		nativeDescriptor("OpenAPI definition found (passive scan check)", DispatchScopePerUrl, remainingChecksEnabled, checkOpenAPIDefinitionPassive),

		nativeDescriptor("Out-of-band resource load (HTTP)", DispatchScopePerUrl, oobChecksEnabled,
			oobCheck("Out-of-band resource load (HTTP)", "http")),
		nativeDescriptor("External service interaction (DNS)", DispatchScopePerUrl, oobChecksEnabled,
			oobCheck("External service interaction (DNS)", "dns")),
		nativeDescriptor("External service interaction (HTTP)", DispatchScopePerUrl, oobChecksEnabled,
			oobCheck("External service interaction (HTTP)", "http")),

		nativeDescriptor("React Server Components remote code execution (React2Shell)", DispatchScopePerUrl, remainingChecksEnabled, checkReact2Shell),
		nativeDescriptor("SQL statement in request parameter", DispatchScopePerUrl, remainingChecksEnabled, checkSQLStatementInParameter),
	}
}
