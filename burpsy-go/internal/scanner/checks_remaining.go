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
	"slices"
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
// Two of these rows used to hang off CheckSSRF and CheckXXE. Once they had real evaluators that
// mattered: the OOB check needs a collaborator binary and outbound DNS, and reports their absence as
// an error, so a default scan on a machine without interactsh began failing every sweep. The OOB row
// stays here. The XXE row answers to CheckXXE again (xxeChecksEnabled): its file-read probe needs
// nothing outside this process, and j1mk.37 put it in the default audit, as Burp's is.
func remainingChecksEnabled(c *ScanConfig) bool { return c != nil && c.CheckExtendedActive }

// oobChecksEnabled narrows remainingChecksEnabled to the four rows that need a collaborator: an
// out-of-band callback nothing in this process can synthesise. It is an AND, not an alternative:
// CheckOutOfBand on its own admits nothing.
func oobChecksEnabled(c *ScanConfig) bool { return remainingChecksEnabled(c) && c.CheckOutOfBand }

// xxeChecksEnabled admits the XML external entity row under its own family switch or under the
// extended family that carried it before CheckXXE had a runner. Only that row: "XML entity
// expansion" is a load test of the parser and keeps the extended switch alone.
func xxeChecksEnabled(c *ScanConfig) bool {
	return c != nil && (c.CheckXXE || remainingChecksEnabled(c))
}

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

// graphQLSuggestionProbe selects near-misses of the root fields GraphQL APIs most often expose
// (user, node, viewer, product, order, search, item, customer, account, me), one edit or two from
// the real name. graphql-js suggests a field within that distance, so a server with suggestions on
// names whichever of those fields it really has. A single nonsense name (the probe this replaced)
// is near nothing, so it drew a suggestion only from a schema that happened to hold a lookalike.
// The names go in one operation: one request, one error per unknown field.
const graphQLSuggestionProbe = "query{bsyNoSuchField usr nod viewr produc ordr serch itm custmer accnt mee}"

var graphQLSuggestionProbeNames = func() map[string]bool {
	m := map[string]bool{}
	for _, f := range strings.Fields(strings.Trim(strings.TrimPrefix(graphQLSuggestionProbe, "query"), "{}")) {
		m[f] = true
	}
	return m
}()

func checkGraphQLSuggestions(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	res, err := newGraphQLClient(cc).Execute(ctx, graphQLSuggestionProbe)
	if err != nil {
		return nil, fmt.Errorf("GraphQL suggestion probe: %w", err)
	}
	// A name the probe itself sent is not a suggestion: an echo of the query must not count.
	var suggestions []string
	for _, name := range graphqlmap.FieldSuggestions(res.ErrorMessages()) {
		if !graphQLSuggestionProbeNames[name] {
			suggestions = append(suggestions, name)
		}
	}
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
		// Asked under a fresh alias and with only the captured cookies, the one credential a
		// cross-site form or link carries: the answer must be data keyed by that alias, which a
		// fixed or cached body cannot be.
		alias := graphQLNonce()
		res, err := newCrossSiteGraphQLClient(cc, enc.opt).Execute(ctx, "query{"+alias+":__typename}")
		if err != nil || res == nil {
			continue
		}
		if graphQLAliasTyped(res, alias) && !res.HasErrors() {
			accepted = append(accepted, enc.name)
		}
	}
	if len(accepted) == 0 {
		return nil, nil
	}
	// A query over GET is the weaker half of CSRF: it changes nothing by itself. Whether the
	// endpoint also EXECUTES A MUTATION OPERATION over GET is what turns a link into a state change,
	// and `mutation{<alias>:__typename}` answers that without running any mutation resolver.
	if slices.Contains(accepted, "query string (GET)") {
		alias := graphQLNonce()
		res, err := newCrossSiteGraphQLClient(cc, graphqlmap.WithEncoding(graphqlmap.EncodingGet)).
			Execute(ctx, "mutation{"+alias+":__typename}")
		if err == nil && graphQLAliasTyped(res, alias) && !res.HasErrors() {
			accepted = append(accepted, "mutation operations over GET")
		}
	}
	return []*Finding{buildHeaderFinding(cc, "GraphQL content type not validated", "low", "firm",
		strings.Join(accepted, ", "),
		"the endpoint answers GraphQL sent under content types a browser form can produce, which makes it reachable by CSRF")}, nil
}

// ---------------------------------------------------------------------------
// JWT forgery
// ---------------------------------------------------------------------------

// jwtFromExchange finds the first parseable JWT in the request.
//
// The token is searched for as a TOKEN SHAPE rather than a whitespace-delimited field, because a JWT
// does not arrive as a field of its own: it is the value in `Authorization: Bearer eyJ…`, in a cookie
// `session=eyJ…`, in a query parameter `?JWT=eyJ…`, or in a form body `token=eyJ…` — glued to a name
// by `=`, `:`, a space, a quote or an `&` in every case. The previous version split the raw bytes on
// whitespace and trimmed a few delimiters, which found a bare token (a body that IS the token) and
// missed every NAMED one. So an endpoint taking its token as a query parameter had no token found,
// jwtCheck returned "nothing to do", and all six JWT rows reported clean without a single probe —
// the silent-skip shape the honest-counting rule forbids, a miss indistinguishable from a pass.
//
// Scanned over `[A-Za-z0-9_-]` and `.`, so `=`/`:`/`&`/quote/space/CR/LF/slash ends a run and
// separates `?JWT=` from its value or `Bearer ` from its token. Each run, and each two-dot window
// inside a longer run, is offered to ParseJWT — which is refuse-by-default, so a dotted string that
// is not a token is rejected rather than mistaken for one.
func jwtFromExchange(cc *CheckContext) (string, JWTToken, bool) {
	raw := requestRaw(cc.Scanner, cc.Exchange)
	for _, candidate := range jwtCandidatesIn(string(raw)) {
		if t := ParseJWT(candidate); t.ParseError == "" {
			return candidate, t, true
		}
	}
	return "", JWTToken{}, false
}

// jwtCandidatesIn returns the plausible JWT substrings of a request, in the order they appear.
//
// A candidate is a maximal run of token characters (`[A-Za-z0-9_-]` and `.`) with exactly two dots and
// at least minLen bytes. Every delimiter a request uses to name a token — `=`, `:`, `&`, a quote, a
// space, CR, LF, `/`, `?` — is outside that set, so `?JWT=eyJ…` yields the bare token as its own run.
// No window splitting is needed: the delimiters already do it.
func jwtCandidatesIn(raw string) []string {
	const minLen = 20
	isTok := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.'
	}
	var out []string
	seen := map[string]bool{}
	for i := 0; i < len(raw); {
		if !isTok(raw[i]) {
			i++
			continue
		}
		j := i
		for j < len(raw) && isTok(raw[j]) {
			j++
		}
		run := raw[i:j]
		if len(run) >= minLen && strings.Count(run, ".") == 2 && !seen[run] {
			seen[run] = true
			out = append(out, run)
		}
		i = j
	}
	return out
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

// checkSMTPHeaderInjection reports a value whose line break reached a mail library.
//
// It used to report ANY response ClassifyMailHeaderResponse did not call "none" — including a body
// that merely differed from the baseline (MailInjectionStatusOrBodyDivergence, which infra_smtp.go
// itself calls "a weak signal only") and a payload printed back verbatim (MailInjectionReflectedVerbatim,
// documented there as evidence AGAINST a split). Every page with a timestamp or a nonce differs from
// its own baseline, so the row fired on the User-Agent header of every endpoint of a benchmark that
// sends no mail at all (burpsy-react-ui-j1mk.41).
//
// What is accepted now is the one class that can be attributed to a mail layer, and only with two
// controls behind it:
//
//   - the probe response carries a mail-library error (mailLibraryErrorSignatures) the baseline does
//     not;
//   - the same value with the separator replaced by a space does NOT carry it, so the error is caused
//     by the line break and not by an input the library rejects whatever it contains (an address
//     validator throwing AddressException on any punctuation is the case this rules out);
//   - a fresh canary through the same separator raises it again.
//
// "tentative": no mail was observed being sent with the injected header. Seeing the Bcc reach a
// mailbox, or an SMTP interaction at a collaborator, is what would make it certain.
func checkSMTPHeaderInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	h, err := NewProbeHarness(ctx, cc, cc.ProbeInsertionKinds())
	if err != nil {
		return nil, err
	}
	points := h.Points()
	if len(points) > MaxInjectionPointsPerCheck {
		points = points[:MaxInjectionPointsPerCheck]
	}
	base := h.Baseline()
	mailError := func(res ProbeResponse) bool {
		return ClassifyMailHeaderResponse(base.Body, res.Body, base.Status, res.Status) == MailInjectionMailLibraryError
	}
	for _, point := range points {
		for _, payload := range MailHeaderPayloads("") {
			res, err := h.Send(ctx, point, payload.Payload)
			if err != nil || !mailError(res) {
				continue
			}
			control := strings.Replace(payload.Payload, smtpEncodedSeparator(payload), " ", 1)
			if control == payload.Payload {
				continue
			}
			ctl, err := h.Send(ctx, point, control)
			if err != nil || mailError(ctl) {
				continue
			}
			again := MailHeaderPayloads("")
			var repeat *MailHeaderInjection
			for i := range again {
				if again[i].Separator == payload.Separator && again[i].Encoding == payload.Encoding {
					repeat = &again[i]
				}
			}
			if repeat == nil {
				continue
			}
			res2, err := h.Send(ctx, point, repeat.Payload)
			if err != nil || !mailError(res2) {
				continue
			}
			return []*Finding{buildHeaderFinding(cc, "SMTP header injection", "high", "tentative",
				payload.Payload,
				fmt.Sprintf("%s %q: a line break (%s, %s) followed by a Bcc header raised a mail-library error the "+
					"baseline does not show; the same value with a space in place of the line break did not, and a "+
					"fresh canary raised it again. The separator reached the mail-composition layer. No mail carrying "+
					"the injected header was observed.", point.Kind, point.Name, strconv.Quote(payload.Separator), payload.Encoding))}, nil
		}
	}
	return nil, nil
}

// smtpEncodedSeparator is the separator exactly as it was written into the payload.
func smtpEncodedSeparator(p MailHeaderInjection) string {
	switch p.Encoding {
	case mailEncodingPercent:
		return encodeHeaderInjectionSeparator(p.Separator, 1)
	case mailEncodingPercentDoubled:
		return percentDoubleEncodedSeparator(p.Separator)
	default:
		return p.Separator
	}
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

// xxeExternalSubstitution is the XXE differential's discriminator. It reports the value the external
// entity was expanded to, and ok=true only when that value is the ONLY thing distinguishing the
// external answer from the internal-entity control's answer.
//
// The two documents differ in exactly one place, the entity declaration (`<!ENTITY e SYSTEM "uri">`
// against `<!ENTITY e "marker">`), so a parser that expands both produces two answers that differ in
// exactly two places: the echoed declaration, if the application echoes the document, and the
// substituted value. The declaration is normalised out of both answers first; the control's answer
// is then split at its single copy of the marker, and the external answer must carry the SAME prefix
// and the SAME suffix around a non-empty value. Anything weaker is not evidence:
//
//   - "the bodies differ", or "the external answer is longer", is true of a safe parser that answers a
//     SYSTEM entity with an error page or a stack trace — a longer 500 is a refusal, not a read;
//   - an expansion to the empty string is a parser that blanked the reference (measured on OWASP
//     VulnerableApp's secure levels), which is the safe behaviour;
//   - an answer whose status class differs from the control's, or that is an error status at all,
//     came from a different code path than the one the control established, so its content says
//     nothing about what the entity resolved to.
func xxeExternalSubstitution(external, control ProbeResponse, entity, uri, marker string) (string, bool) {
	if external.Status/100 != control.Status/100 || external.Status >= 400 || control.Status >= 400 {
		return "", false
	}
	const decl = "\x00bsy-xxe-decl\x00"
	ext := strings.ReplaceAll(external.Body, `<!ENTITY `+entity+` SYSTEM "`+uri+`">`, decl)
	ctl := strings.ReplaceAll(control.Body, `<!ENTITY `+entity+` "`+marker+`">`, decl)
	if strings.Count(ctl, marker) != 1 {
		return "", false
	}
	i := strings.Index(ctl, marker)
	prefix, suffix := ctl[:i], ctl[i+len(marker):]
	if len(ext) <= len(prefix)+len(suffix) || !strings.HasPrefix(ext, prefix) || !strings.HasSuffix(ext, suffix) {
		return "", false
	}
	value := ext[len(prefix) : len(ext)-len(suffix)]
	if strings.TrimSpace(value) == "" || strings.Contains(value, marker) || strings.Contains(value, entity) || strings.Contains(value, uri) {
		return "", false
	}
	return value, true
}

// bodyOfRawRequest returns the body of a raw HTTP request: everything after the header/body
// separator. It exists for a check that needs the request's own shape — XXE keeps the base body's XML
// element names so an entity reference lands where the target's schema expects one.
func bodyOfRawRequest(raw string) string {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return raw[i+4:]
	}
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return raw[i+2:]
	}
	return ""
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
	// The base body, so the payload keeps its XML shape: a JAXB-bound endpoint rejects a synthetic
	// `<foo>` root before entity resolution, and the payload must land inside an element its schema
	// already knows. See XXEFilePayloadsFor.
	baseBody := bodyOfRawRequest(string(h.reqBytes))
	for _, point := range points {
		// The internal-entity control is the same for every payload at this point, so it is sent at
		// most once, and only when a payload's own signature did not already decide.
		var control *ProbeResponse
		controlSent := false
		for _, payload := range XXEFilePayloadsFor(baseBody, xxeEntityMarker) {
			res, err := h.Send(ctx, point, payload.Body)
			if err != nil {
				continue
			}
			// Positive(), not `!= XXEEvidenceNone`: the latter fires on
			// XXEEvidenceReflectedVerbatim, which means the payload came back as INERT TEXT —
			// evidence the entity was NOT resolved. Testing the negation reported the four SECURE
			// VulnerableApp levels as "the external entity was resolved".
			if DetectXXEEvidence(res.Body, payload).Positive() {
				return []*Finding{buildHeaderFinding(cc, "XML external entity injection", "high", "firm",
					payload.Name, fmt.Sprintf("%s %q: the external entity was resolved", point.Kind, point.Name))}, nil
			}
			// No recognised content signature. That is the normal case for a file whose content has
			// no fixed marker — /etc/hostname is the machine's own name — so fall back to a
			// differential that holds the document identical and varies only what the entity points at:
			//   control  — an INTERNAL entity holding a known marker
			//   external — the same document with `SYSTEM "file:///…"` in its place
			// An internal-entity reference is substitution with no file access, which every XML parser
			// does and no XXE defence blocks, so the control establishes that this document reaches the
			// parser and that a reference in THIS element is expanded. xxeExternalSubstitution then
			// accepts the external answer only when it is the control's answer with the marker replaced
			// by a non-empty value, under the same non-error status class.
			if !controlSent {
				controlSent = true
				if c, cerr := h.Send(ctx, point, xxeInternalEntityDocument(baseBody, xxeControlMarker)); cerr == nil {
					control = &c
				}
			}
			if control == nil || !strings.Contains(control.Body, xxeControlMarker) {
				// The control did not come back substituted, so this target does not expand an entity
				// reference in this element at all — the external probe's silence proves nothing.
				continue
			}
			value, ok := xxeExternalSubstitution(res, *control, xxeEntityName, payload.Marker, xxeControlMarker)
			if !ok {
				continue
			}
			if len(value) > 64 {
				value = value[:64] + "…"
			}
			return []*Finding{buildHeaderFinding(cc, "XML external entity injection", "high", "tentative",
				payload.Name, fmt.Sprintf("%s %q: the external entity expanded to %q where the same document's "+
					"internal-entity control expanded to its marker, with the rest of the answer identical, so "+
					"the file was read", point.Kind, point.Name, value))}, nil
		}
	}
	// No general entity resolved. A parser with only external GENERAL entities disabled still loads
	// an external DTD through a parameter entity (xxe_param_entity.go); that probe makes the target
	// fetch a URL this scanner serves, so it runs under the in-band SSRF opt-in.
	if inBandSSRFOn(cc.Config) {
		f, err := xxeParameterEntityProbe(ctx, cc, h, points, baseBody)
		if err != nil {
			return nil, fmt.Errorf("XML external entity injection: %w", err)
		}
		if f != nil {
			return []*Finding{f}, nil
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
//
// oobOrInBandSSRF runs the SSRF row's two techniques, each behind its own switch.
//
// The row is one catalogued issue (CWE-918) with two ways to prove it: a collaborator callback for a
// BLIND fetch, and a canary URL this scanner serves for an IN-BAND one. They are admitted separately
// because they need different capabilities (an interactsh binary versus a local listener) and because
// an operator may reasonably want one without the other. Both file under the same row so a report
// reader finds the name Burp uses.
func oobOrInBandSSRF() CheckRunner {
	oob := oobCheck("Out-of-band resource load (HTTP)", "http")
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		var cfg *ScanConfig
		if cc != nil && cc.Scanner != nil {
			cfg = cc.Scanner.config
		}
		var inBandErr error
		if inBandSSRFOn(cfg) {
			// The in-band technique first: it is local, fast, and needs no external registration, so
			// when it confirms there is nothing for the collaborator to add.
			f, err := checkSSRFInBand(ctx, cc)
			if err == nil && len(f) > 0 {
				return f, nil
			}
			inBandErr = err
		}
		if oobChecksEnabled(cfg) {
			return oob(ctx, cc)
		}
		// Only the in-band technique was admitted: its own verdict is the row's, including a refusal
		// (no egress, no listener), which must not read as a clean endpoint.
		return nil, inBandErr
	}
}

// inBandSSRFOn reports whether the in-band technique is admitted: the family switch plus its own. It
// does NOT require CheckOutOfBand — the in-band technique needs no collaborator, and the row is
// admitted by ssrfRowEnabled when either technique is on.
func inBandSSRFOn(c *ScanConfig) bool {
	return remainingChecksEnabled(c) && c.CheckSSRFInBand
}

// ssrfRowEnabled admits the "Out-of-band resource load (HTTP)" row when either of its techniques is
// on: the collaborator (CheckOutOfBand) or the in-band canary (CheckSSRFInBand). The two DNS/HTTP
// external-interaction rows keep oobChecksEnabled; they have no in-band technique.
func ssrfRowEnabled(c *ScanConfig) bool { return oobChecksEnabled(c) || inBandSSRFOn(c) }

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
		hostVehiclesApply := oobHostVehiclesApply(row, protocol)
		if len(h.Points()) == 0 && !hostVehiclesApply {
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
		var routed int
		hostMarker := strings.ToLower(domCanary("oobh"))
		if hostVehiclesApply {
			routed = plantOOBHostVehicles(ctx, h, cc, hostMarker+"."+channel.Domain())
		}
		if sent == 0 && routed == 0 {
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
		if routed > 0 {
			if err := registerOOBHostVehicles(cc, channel, row, protocol, hostMarker, routed, deadline); err != nil {
				return nil, err
			}
		}
		if sent == 0 {
			return nil, fmt.Errorf("%s: collaborator domain planted in the Host header, awaiting callback: %w",
				row, errCheckInconclusive)
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

// oobHostVehiclesApply says which out-of-band rows also plant the collaborator domain as the host of
// the request: the two external-service-interaction rows over DNS and HTTP. That is routing-based
// SSRF (PortSwigger, "HTTP Host header attacks"): a front end that forwards a request to whatever host
// its Host header — or its absolute-form request target — names will resolve and contact the
// collaborator. Burp's scanner plants Collaborator payloads in the Host header insertion point and
// files the interaction under these same rows.
func oobHostVehiclesApply(row, protocol string) bool {
	return strings.HasPrefix(row, "External service interaction") &&
		(strings.EqualFold(protocol, "http") || strings.EqualFold(protocol, "dns"))
}

// plantOOBHostVehicles sends the request with host as its Host header, and again with an absolute-form
// target naming the real authority and host in the Host header. Both go to the exchange's own
// authorised authority — the scope gate never reads the Host header — so the only party that could
// contact the collaborator is the target itself. It returns how many were sent.
func plantOOBHostVehicles(ctx context.Context, h *ProbeHarness, cc *CheckContext, host string) int {
	base := h.RequestBytes()
	authority := requestHostHeader(base)
	if authority == "" {
		authority = hostPort(cc.Exchange.Host, cc.Exchange.Port, cc.Exchange.TLS)
	}
	sent := 0
	for _, raw := range [][]byte{
		withHostHeaders(base, host),
		withAbsoluteTarget(withHostHeaders(base, host), authority),
	} {
		if _, err := h.SendRequestHTTP1(ctx, withCacheBuster(raw)); err == nil {
			sent++
		}
	}
	return sent
}

// registerOOBHostVehicles waits for an interaction carrying the Host-vehicle marker, which can only be
// the target acting on a Host header it should have refused.
func registerOOBHostVehicles(cc *CheckContext, channel OOBChannel, row, protocol, marker string, sent int,
	deadline time.Time) error {
	return cc.Scanner.Pending().Register(PendingItem{
		Row:      row,
		Exchange: cc.Exchange.ID,
		Deadline: deadline,
		What: fmt.Sprintf("%d probe(s) naming %s.%s as the request's host sent to %s, awaiting a %s callback",
			sent, marker, channel.Domain(), cc.Exchange.Path, protocol),
	}, func(context.Context) (*Finding, bool, error) {
		interactions, err := channel.InteractionsFor(marker)
		if err != nil {
			return nil, false, fmt.Errorf("reading out-of-band interactions: %w", err)
		}
		for _, i := range oob.Deduplicate(interactions) {
			if !strings.EqualFold(i.Protocol, protocol) {
				continue
			}
			return buildHeaderFinding(cc, row, "high", "certain",
				fmt.Sprintf("%s interaction from %s after the request named the collaborator as its host",
					i.Protocol, i.RemoteAddress),
				"routing-based SSRF: the target contacted the host named in the request's Host header (or "+
					"absolute-form target), so a front end routes requests by a value the client controls and "+
					"can be pointed at internal systems"), true, nil
		}
		// Never settles negatively, like the parameter-planted item: no callback is not evidence of none.
		return nil, false, nil
	})
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
		// The GraphQL hardening rows (checks_graphql_hardening.go) ride this one, behind their own switch.
		nativeDescriptor("GraphQL endpoint found", DispatchScopePerUrl,
			func(c *ScanConfig) bool { return remainingChecksEnabled(c) || graphQLHardeningEnabled(c) },
			graphQLEndpointWithHardening(checkGraphQLEndpointFound)),
		nativeDescriptor("GraphQL introspection enabled", DispatchScopePerUrl, remainingChecksEnabled, checkGraphQLIntrospection),
		nativeDescriptor("GraphQL suggestions enabled", DispatchScopePerUrl, remainingChecksEnabled, checkGraphQLSuggestions),
		nativeDescriptor("GraphQL content type not validated", DispatchScopePerUrl, remainingChecksEnabled, checkGraphQLContentType),

		// The three forgery rows decide by jwt_attacks.go's two-control differential.
		// The credential-exposure row (jwt_exposure.go) rides the signature row behind its own switch,
		// check_jwt_exposure: it is decided by the same differential.
		nativeDescriptor("JWT signature not verified", DispatchScopePerRequest,
			func(c *ScanConfig) bool { return jwtForgeryEnabled(c) || jwtExposureEnabled(c) },
			jwtSignatureOrExposure(jwtSignatureCheck)),
		nativeDescriptor("JWT none algorithm supported", DispatchScopePerRequest, jwtForgeryEnabled,
			jwtForgeryRow("JWT none algorithm supported", func(t JWTToken) ([]string, error) {
				return ForgeNoneAlgVariants(t), nil
			})),
		nativeDescriptor("JWT self-signed JWK header supported", DispatchScopePerRequest, jwtForgeryEnabled,
			jwtForgeryRow("JWT self-signed JWK header supported", func(t JWTToken) ([]string, error) {
				tok, _, err := ForgeSelfSignedJWK(t)
				if err != nil {
					return nil, err
				}
				return []string{tok}, nil
			})),
		nativeDescriptor("JWT private key disclosed", DispatchScopePerUrl, remainingChecksEnabled, checkJWTPrivateKeyDisclosed),

		nativeDescriptor("TLS certificate", DispatchScopePerHost, tlsProbeChecksEnabled, checkTLSCertificate),
		// The password-reset checks (checks_pwreset.go) ride this row behind their own switch: their
		// findings are burpsy's own rows (BurpsyNativeRows), and the registry admits one descriptor per
		// Burp catalogue type. Both are aimed at endpoints that send mail.
		nativeDescriptor("SMTP header injection", DispatchScopePerUrl,
			func(c *ScanConfig) bool { return remainingChecksEnabled(c) || pwresetEnabled(c) },
			smtpOrPasswordReset(checkSMTPHeaderInjection)),
		nativeDescriptor("Cross-origin resource sharing", DispatchScopePerRequest, remainingChecksEnabled, checkCORSBaseRow),

		nativeDescriptor("Flash cross-domain policy", DispatchScopePerHost, remainingChecksEnabled,
			crossDomainPolicyCheck("Flash cross-domain policy", "/crossdomain.xml", ParseFlashCrossdomainPolicy)),
		nativeDescriptor("Silverlight cross-domain policy", DispatchScopePerHost, remainingChecksEnabled,
			crossDomainPolicyCheck("Silverlight cross-domain policy", "/clientaccesspolicy.xml", ParseSilverlightPolicy)),

		// The XXE row also answers to its own family switch, CheckXXE (on by default, j1mk.37): it reads
		// a local file through an entity and proves it by content or by an internal-entity control.
		// Entity expansion below stays behind CheckExtendedActive alone: it is intrusive.
		nativeDescriptor("XML external entity injection", DispatchScopePerUrl, xxeChecksEnabled, checkXXE),
		intrusiveDescriptor("XML entity expansion", DispatchScopePerUrl, remainingChecksEnabled, checkXMLEntityExpansion),

		nativeDescriptor("File upload functionality", DispatchScopePerHost, remainingChecksEnabled, checkFileUploadFunctionality),
		nativeDescriptor("OpenAPI definition found (passive scan check)", DispatchScopePerUrl, remainingChecksEnabled, checkOpenAPIDefinitionPassive),

		descriptorWithTier("Out-of-band resource load (HTTP)", DispatchScopePerUrl, ssrfRowEnabled,
			oobOrInBandSSRF(), TierIntrusive, ""),
		descriptorWithTier("External service interaction (DNS)", DispatchScopePerUrl, oobChecksEnabled,
			oobCheck("External service interaction (DNS)", "dns"), TierIntrusive, ""),
		descriptorWithTier("External service interaction (HTTP)", DispatchScopePerUrl, oobChecksEnabled,
			oobCheck("External service interaction (HTTP)", "http"), TierIntrusive, ""),

		// The insecure-deserialization check (checks_deserialization.go) rides this row behind its own
		// switch: React2Shell is the only active Burp row classified CWE-502, and the registry admits one
		// descriptor per Burp type.
		nativeDescriptor("React Server Components remote code execution (React2Shell)", DispatchScopePerUrl,
			func(c *ScanConfig) bool { return remainingChecksEnabled(c) || insecureDeserializationEnabled(c) },
			react2ShellOrDeserialization(checkReact2Shell)),
		nativeDescriptor("SQL statement in request parameter", DispatchScopePerUrl, remainingChecksEnabled, checkSQLStatementInParameter),
	}
}
