// checks_reflection2.go ports six catalog issues whose Java evidence sends a single active probe
// (or, for input reflection, no probe at all) and reads back the immediate response — the same
// shape as sqli.go/xss.go: a pure classifier deciding on already-observed evidence, plus a thin
// CheckRunner that gathers the evidence and calls it. None of these six needs a stored-exchange
// thread, a headless browser, or an OOB channel — the capabilities checks_headers.go/
// checks_cache.go/check_registry_declined.go name as missing for their siblings — which is why
// they are ported here while their siblings (stored/DOM-based/second-order variants) stay declined.
//
// # Real evidence and its limits
//
// java_check_inventory.json's live-scan trace confirmed all six firing (Zr02, Zuag, Zb_5, Zwi,
// Zsn3, Zexx). Beyond that, /root/burp-re/out/clean/root gave three checks enough recoverable
// evidence to port faithfully rather than reinvent:
//
//   - Zr02 (input reflection) sends no probe of its own: it inspects Zwe8.PLAIN_REFLECTION_TYPES
//     evidence already collected from the exchange's own baseline request/response. checkInputReflection
//     below mirrors that: no new request, just a check of the exchange's own captured query values
//     against its own captured response body.
//   - Zuag (open redirection) builds crafted-domain payloads and confirms via
//     `location.startsWith(payload)` (its Zq() helper) — out/strings/map_root.tsv recovered the
//     literal prefixes it uses: "http://a", "https://a", "//a", "Http://a" (case-bypass, THOROUGH
//     mode only), "/\\a" and "\\a" (backslash-as-slash bypass). checkOpenRedirect below sends
//     exactly those prefixes and applies the same startsWith comparison.
//   - Zwi (HTTP response header injection) splices one of three separators ("\r\n", "\r", "\n")
//     into a random token via three encodings selected by Zw9s.Ze: raw, percent-encode every
//     non-alphanumeric byte, or a leading NUL byte. checkHeaderInjection below reproduces that
//     3-separator x 3-encoding matrix exactly.
//
// Zsn3 (code injection) and Zexx (SSI injection) only yielded where they probe — the same
// map_root.tsv strings show both target the User-Agent and Referer headers, not just the query
// string, which checkCodeInjection/checkSSIInjection also do — not what literal template payload
// they send: PhpCodeInjectionIssue001/RubyCodeInjectionIssue001/SsiInjectionIssue002's static
// payload-array fields decode to empty (ZKM stripped the literal-only initialisers once ast_rename
// substituted what little it could recover; see out/clean/renamed_v4's "ZKM ciphertext residue"
// notes from the deobfuscation session). Rather than invent Burp-specific strings and label them as
// recovered, checkCodeInjection/checkSSIInjection use publicly documented, industry-standard
// SSTI/code-injection and SSI probe syntaxes and a differential (arithmetic-evaluation /
// true-vs-false-branch) evidence model, which is the same evidence *shape* Java uses without
// claiming Java's exact bytes.
//
// Zb_5 (link manipulation) is not a probe-and-classify check at all: its Z_() method reuses the
// shared XSS breakout-evidence buckets (IssueType.XSS_REFLECTED / CSS_INJECTION_REFLECTED /
// FORM_ACTION_HIJACKING_REFLECTED / LINK_MANIPULATION_REFLECTED) and re-labels a positive breakout
// as one issue or another depending on the insertion point's kind (HOST vs PATH_FILENAME_PARAM vs
// PATH_FOLDER_PARAM). Porting that bucket-sharing architecture is out of scope here; checkLinkManipulation
// instead detects the specific, catalog-matching sub-case Java's shared evidence is standing in
// for: an attacker-controlled value landing unescaped inside an href/src/action/formaction
// attribute, which is exactly what the catalog description ("application embeds user input into
// the path or domain of URLs that appear within application responses") names.
package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// newProbeCanary returns a per-probe unique token. A fixed test value would let a static page that
// happens to contain the literal string produce a false positive; a fresh token per probe makes
// reflection unambiguous, mirroring xss.go's newXSSCanary.
func newProbeCanary(prefix string) string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return prefix + "zzzzzz"
	}
	return prefix + hex.EncodeToString(buf)
}

// buildProbeFinding assembles a Finding for one of this file's six checks, pulling severity and
// remediation from the catalog entry resolved by name — the same shape as checks_headers.go's
// buildHeaderFinding.
func buildProbeFinding(cc *CheckContext, name, confidence, evidenceText, detail string) *Finding {
	exchange := cc.Exchange
	severity, remediation := "info", ""
	if def, ok := ByName(name); ok {
		severity = def.TypicalSeverity
		remediation = def.Remediation
	}
	return &Finding{
		Name:        name,
		Severity:    severity,
		Confidence:  confidence,
		Description: detail,
		URL:         exchangeURL(exchange),
		Method:      exchange.Method,
		Evidence:    evidenceText,
		Solution:    remediation,
		ExchangeID:  exchange.ID,
		Timestamp:   time.Now(),
	}
}

// ---------------------------------------------------------------------------
// Input returned in response (reflected) — Zr02
// ---------------------------------------------------------------------------

const inputReflectionIssue = "Input returned in response (reflected)"

// checkInputReflection is a direct port of Zr02: it sends no probe. Zr02's Zw() only reads
// Zwe8.PLAIN_REFLECTION_TYPES evidence that Java's insertion-point tracker already computed for
// the exchange as captured; there is no equivalent tracker here, so this reproduces the same
// observable outcome directly — do any of the exchange's own existing query values (length >= 4,
// to avoid trivial single-character coincidences) already appear verbatim in its own response body.
func checkInputReflection(_ context.Context, cc *CheckContext) ([]*Finding, error) {
	exchange := cc.Exchange
	values := existingQueryValues(exchange.Path)
	if len(values) == 0 {
		return nil, nil
	}
	body := responseRaw(cc.Scanner, exchange)
	if body == "" {
		return nil, nil
	}
	for _, v := range values {
		if len(v) < 4 {
			continue
		}
		if strings.Contains(body, v) {
			return []*Finding{buildProbeFinding(cc, inputReflectionIssue, "certain",
				"query parameter value \""+v+"\" from the captured request reappeared verbatim in the captured response body",
				"the exchange's own request carries a value that is echoed unmodified in its own response — a prerequisite for reflected XSS, open redirection, and similar client-side issues")}, nil
		}
	}
	return nil, nil
}

// existingQueryValues returns the non-empty query parameter values already present on path,
// without sending anything — Zr02 inspects existing evidence, not a fresh probe.
func existingQueryValues(path string) []string {
	i := strings.IndexByte(path, '?')
	if i < 0 || i == len(path)-1 {
		return nil
	}
	var values []string
	for _, pair := range strings.Split(path[i+1:], "&") {
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}
		values = append(values, parts[1])
	}
	return values
}

// ---------------------------------------------------------------------------
// Open redirection (reflected) — Zuag
// ---------------------------------------------------------------------------

const openRedirectIssue = "Open redirection (reflected)"

// openRedirectPrefixes are the literal crafted-domain prefixes recovered from
// out/strings/map_root.tsv for burp.Zuag: the two base schemes its ZW() helper uses, the
// protocol-relative variant, its THOROUGH-mode case-bypass ("Http://a"), and the two
// backslash-as-slash bypass forms browsers normalise to a new authority.
var openRedirectPrefixes = [...]string{
	"http://a", "https://a", "//a", "Http://a", "/\\a", "\\a",
}

// checkOpenRedirect ports Zuag's confirmation logic: build url = prefix + token + "/", place it in
// each enumerated insertion point, and confirm a 3xx whose Location header (lowercased) starts with
// the payload (lowercased) — Zuag's own Zq() comparison.
//
// It used to append a parameter literally named "redirect", described in this comment as "the same
// simplification sqli.go/xss.go make". Those two turned out to be undetectable in practice for
// exactly that reason: an application whose redirect parameter is called `url`, `next`, `return_to`
// or anything else never saw the payload, and the row reported nothing while looking like a target
// that does not redirect. Zuag itself mutates whichever insertion point already looks like a URL;
// enumerating points is the closest honest equivalent.
func checkOpenRedirect(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	h, err := NewProbeHarness(ctx, cc, []string{"query", "body"})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", openRedirectIssue, err)
	}
	points := h.Points()
	if len(points) > MaxInjectionPointsPerCheck {
		points = points[:MaxInjectionPointsPerCheck]
	}

	for _, point := range points {
		for _, prefix := range openRedirectPrefixes {
			token := newProbeCanary("")
			payload := prefix + token + "/"
			res, err := h.Send(ctx, point, payload)
			if err != nil {
				continue
			}
			if res.Status < 300 || res.Status >= 400 {
				continue
			}
			location := rawHeaderValue(string(res.Raw), "Location")
			if location == "" {
				continue
			}
			// Prefix, not contains: a Location that merely mentions the payload somewhere is a
			// reflection, whereas one that STARTS with it is where the browser will actually go.
			if !strings.HasPrefix(strings.ToLower(location), strings.ToLower(payload)) {
				continue
			}
			return []*Finding{buildProbeFinding(cc, openRedirectIssue, "firm",
				strconv.Itoa(res.Status)+" redirect Location header started with the injected external target "+payload,
				fmt.Sprintf("%s %q controlled the target of a server-issued redirect to an attacker-chosen external origin",
					point.Kind, point.Name))}, nil
		}
	}
	return nil, nil
}

// rawHeaderValue reads one header value out of a raw HTTP response.
//
// The harness returns raw bytes rather than a parsed header map, and parsing the whole response to
// read one header would allocate for every probe. Headers end at the first blank line; anything
// after it is body and must not be searched, or a body that happens to contain "Location:" would be
// read as a redirect target.
func rawHeaderValue(raw, name string) string {
	// Split on bare LF, then strip a trailing CR.
	//
	// Splitting on "\r\n" only was wrong for the one caller that matters most. Two of the three
	// headerInjectionSeparators are a bare CR and a bare LF, so six of the nine probes per insertion
	// point produce a header block whose injected line ends in LF alone. On a "\r\n" split those
	// arrive as one long line, the injected header is never seen, and the row cannot confirm the
	// majority of its own payloads. RFC 9112 §2.2 allows a recipient to recognise a bare LF as a
	// line terminator, and Go's net/textproto does, so a server that emits one really has split the
	// header.
	head := raw
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		head = raw[:i]
	} else if i := strings.Index(raw, "\n\n"); i >= 0 {
		head = raw[:i]
	}
	prefix := strings.ToLower(name) + ":"
	// Last match, not first: when response splitting has injected a second Location or a duplicate
	// header, the injected one comes after the legitimate one, and it is the injected one this
	// caller is asking about.
	found := ""
	for _, line := range strings.Split(head, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			found = strings.TrimSpace(line[len(prefix):])
		}
	}
	return found
}

// ---------------------------------------------------------------------------
// Link manipulation (reflected) — Zb_5 (see file header for the scope-narrowing note)
// ---------------------------------------------------------------------------

const linkManipulationIssue = "Link manipulation (reflected)"

var linkManipulationAttributes = [...]string{"href", "src", "action", "formaction"}

// checkLinkManipulation detects the catalog-matching sub-case of Zb_5's shared breakout evidence:
// an attacker-controlled absolute URL reflected unescaped as the value of a link/resource/form
// target attribute, giving an attacker control over where a link or form points without needing a
// full HTML/script breakout.
// It walks the request's real insertion points. The predecessor appended a parameter named
// "burpsy_link", which only an application that happens to read that name could ever reflect - so
// the check was silent on every real target and nobody noticed, because silence is what a clean
// endpoint looks like.
func checkLinkManipulation(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	h, err := NewProbeHarness(ctx, cc, DefaultProbeInsertionKinds)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", linkManipulationIssue, err)
	}
	points := h.Points()
	if len(points) > MaxInjectionPointsPerCheck {
		points = points[:MaxInjectionPointsPerCheck]
	}
	for _, point := range points {
		canary := newProbeCanary("brpl")
		payload := "https://" + canary + ".invalid/x"
		res, err := h.Send(ctx, point, payload)
		if err != nil || res.Body == "" {
			continue
		}
		if attr := linkAttributeReflection(res.Body, payload); attr != "" {
			return []*Finding{buildProbeFinding(cc, linkManipulationIssue, "firm",
				"submitted external URL "+payload+" was reflected unescaped as the value of an "+attr+
					" attribute (via "+string(point.Kind)+" "+point.Name+")",
				"the injected external URL became the target of a link, resource, or form action in the response")}, nil
		}
	}
	return nil, nil
}

func linkAttributeReflection(body, payload string) string {
	for _, attr := range linkManipulationAttributes {
		for _, quote := range [...]string{`"`, `'`} {
			if strings.Contains(body, attr+"="+quote+payload) {
				return attr
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// HTTP response header injection — Zwi
// ---------------------------------------------------------------------------

const headerInjectionIssue = "HTTP response header injection"

// headerInjectionSeparators are Zwi's three CRLF-family separators (Zy static field: a decoded
// combined form plus the two bare characters). The combined form is a runtime-only XOR decode this
// port cannot execute statically, but Zy's shape — one element alongside bare "\r" and "\n" — leaves
// only one plausible value for it.
var headerInjectionSeparators = [...]string{"\r\n", "\r", "\n"}

// encodeHeaderInjectionSeparator is a direct port of burp.Zw9s.Ze(String, int): bit 0 selects
// percent-encoding of every non-alphanumeric byte, bit 1 prepends a NUL byte, and 0 leaves the
// separator raw. Zwi calls this with variant 0, 1, and 2 for every separator.
func encodeHeaderInjectionSeparator(sep string, variant int) string {
	if variant&1 == 1 {
		return percentEncodeNonAlnum(sep)
	}
	if variant&2 == 2 {
		return "\x00" + sep
	}
	return sep
}

func percentEncodeNonAlnum(s string) string {
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		hexStr := strconv.FormatInt(int64(c), 16)
		if len(hexStr) < 2 {
			b.WriteByte('0')
		}
		b.WriteString(hexStr)
	}
	return b.String()
}

const headerInjectionMarkerName = "X-Burpsy-Canary"

// checkHeaderInjection ports Zwi's separator x encoding matrix (9 probes: 3 separators x 3
// encodings). Each probe splices one encoded separator plus a full marker header line into a fresh
// random token, submitted as a query parameter value (Zwi mutates an existing insertion point via
// REPLACE/APPEND; this port uses a fixed parameter name, the same simplification as elsewhere in
// this file). Confirmation reads the actual response: either the marker landed as a real header, or
// the injection broke straight through into the body.
func checkHeaderInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	h, err := NewProbeHarness(ctx, cc, []string{"query", "body"})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", headerInjectionIssue, err)
	}
	points := h.Points()
	if len(points) > MaxInjectionPointsPerCheck {
		points = points[:MaxInjectionPointsPerCheck]
	}

	for _, point := range points {
		for _, sep := range headerInjectionSeparators {
			for variant := range 3 {
				token := newProbeCanary("brph")
				markerValue := token[:4]
				encoded := encodeHeaderInjectionSeparator(sep, variant)
				payload := token[4:] + encoded + headerInjectionMarkerName + ": " + markerValue

				res, err := h.Send(ctx, point, payload)
				if err != nil {
					continue
				}
				// Read the header block of the raw response: a split header is a new line in the
				// header block, which a parsed header map on the client side may already have
				// normalised away.
				if v := rawHeaderValue(string(res.Raw), headerInjectionMarkerName); strings.Contains(v, markerValue) {
					return []*Finding{buildProbeFinding(cc, headerInjectionIssue, "certain",
						"a CRLF-family separator injected into "+string(point.Kind)+" "+point.Name+
							" produced a new response header "+headerInjectionMarkerName+": "+v,
						"the parameter value was terminated with an injected line break, allowing an attacker-controlled HTTP response header to be added")}, nil
				}
				if strings.Contains(res.Body, headerInjectionMarkerName+": "+markerValue) {
					return []*Finding{buildProbeFinding(cc, headerInjectionIssue, "firm",
						"a CRLF-family separator injected into "+string(point.Kind)+" "+point.Name+
							" broke out of the response headers into the body",
						"the parameter value was terminated with an injected line break, and the injected content reached the raw response")}, nil
				}
			}
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// Unidentified code injection — Zsn3
// ---------------------------------------------------------------------------

const codeInjectionIssue = "Unidentified code injection"

// codeInjectionSyntaxes are publicly documented server-side template/code-evaluation syntaxes
// (Java EL / Spring, ERB, Jinja2/Twig, FreeMarker). Zsn3's own literal payload templates are ZKM
// ciphertext residue with no recoverable value (see file header); these are standard, not
// Burp-specific, and the evidence model below (arithmetic evaluation, not mere reflection) is what
// makes a hit meaningful regardless of which syntax a target happens to support.
var codeInjectionSyntaxes = [...]func(expr string) string{
	func(e string) string { return "${" + e + "}" },
	func(e string) string { return "#{" + e + "}" },
	func(e string) string { return "{{" + e + "}}" },
	func(e string) string { return "<%= " + e + " %>" },
}

// codeInjectionHeaders are the two insertion points out/strings/map_root.tsv recovered for Zsn3
// ("user-agent", "referer"), tried in addition to the query string.
var codeInjectionHeaders = [...]string{"User-Agent", "Referer"}

// checkCodeInjection probes the query string plus the User-Agent and Referer headers (Zsn3's real
// insertion points) with each templating syntax wrapped around a two-factor arithmetic expression
// using freshly randomised operands, and confirms only when the response contains the *evaluated
// product* while not containing the literal payload — evidence the server evaluated the expression
// rather than merely echoing it back.
func checkCodeInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	h, err := NewProbeHarness(ctx, cc, DefaultProbeInsertionKinds)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", codeInjectionIssue, err)
	}
	points := h.Points()
	if len(points) > MaxInjectionPointsPerCheck {
		points = points[:MaxInjectionPointsPerCheck]
	}
	// Operands are randomised per run so a page that happens to contain the product of a previous
	// scan's payload cannot stand in for evaluation.
	a := secureRandN(9000) + 1000
	b := secureRandN(9000) + 1000
	want := strconv.Itoa(a * b)
	expr := strconv.Itoa(a) + "*" + strconv.Itoa(b)
	for _, wrap := range codeInjectionSyntaxes {
		payload := wrap(expr)

		// The request's own parameters, rather than a parameter named "burpsy_ci" that only an
		// application reading that exact name could ever have evaluated.
		for _, point := range points {
			res, err := h.Send(ctx, point, payload)
			if err != nil {
				continue
			}
			if evaluatedNotReflected(res.Body, want, payload) {
				return []*Finding{buildProbeFinding(cc, codeInjectionIssue, "firm",
					"template expression "+payload+" evaluated to "+want+" in the response body (via "+
						string(point.Kind)+" "+point.Name+")",
					"the response contained the evaluated arithmetic result of an injected template expression rather than the literal payload, indicating server-side evaluation of user input")}, nil
			}
		}
		for _, header := range codeInjectionHeaders {
			resp := cc.Scanner.sendTestRequestFull(ctx, cc.Exchange, cc.Exchange.Path, map[string]string{header: payload})
			if resp == nil {
				continue
			}
			if evaluatedNotReflected(string(resp.Body), want, payload) {
				return []*Finding{buildProbeFinding(cc, codeInjectionIssue, "firm",
					header+" header template expression "+payload+" evaluated to "+want+" in the response body",
					"the response contained the evaluated arithmetic result of a template expression injected via the "+header+" header rather than the literal payload, indicating server-side evaluation of user input")}, nil
			}
		}
	}
	return nil, nil
}

func evaluatedNotReflected(body, want, payload string) bool {
	return body != "" && strings.Contains(body, want) && !strings.Contains(body, payload)
}

func secureRandN(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

// ---------------------------------------------------------------------------
// SSI injection — Zexx
// ---------------------------------------------------------------------------

const ssiInjectionIssue = "SSI injection"

// checkSSIInjection probes the query string plus the User-Agent and Referer headers (the same two
// insertion points out/strings/map_root.tsv recovered for Zexx) with a standard SSI #if/#else/
// #endif directive. Zexx's own literal directive templates are ZKM ciphertext residue with no
// recoverable value (see file header); #if/#else/#endif is documented SSI syntax, not
// Burp-specific. Confirmation requires the true-branch token to appear while the false-branch
// token and the literal directive syntax do not — a server that left the directive unprocessed
// would reflect all three or none, so seeing only the true branch is evidence of SSI evaluation.
func checkSSIInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	h, err := NewProbeHarness(ctx, cc, DefaultProbeInsertionKinds)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ssiInjectionIssue, err)
	}
	points := h.Points()
	if len(points) > MaxInjectionPointsPerCheck {
		points = points[:MaxInjectionPointsPerCheck]
	}
	// The request's own parameters, not one named "burpsy_ssi": a directive placed in a parameter
	// the application never reads is never processed, so the predecessor could only ever be silent.
	for _, point := range points {
		trueToken := newProbeCanary("brpt")
		falseToken := newProbeCanary("brpf")
		payload := `<!--#if expr="1 = 1" -->` + trueToken + `<!--#else-->` + falseToken + `<!--#endif-->`
		res, err := h.Send(ctx, point, payload)
		if err != nil {
			continue
		}
		if ssiEvaluated(res.Body, trueToken, falseToken) {
			return []*Finding{buildProbeFinding(cc, ssiInjectionIssue, "firm",
				"injected SSI #if/#else/#endif directive evaluated to its true branch ("+trueToken+
					") with no literal directive or false-branch token present",
				"the "+string(point.Kind)+" parameter "+point.Name+
					" reached a Server-Side Includes processor that parsed and evaluated the injected directive")}, nil
		}
	}

	// The two headers Zexx was recovered probing. These stay header-addressed rather than going
	// through insertion points, because the recovered evidence names them specifically.
	trueToken := newProbeCanary("brpt")
	falseToken := newProbeCanary("brpf")
	payload := `<!--#if expr="1 = 1" -->` + trueToken + `<!--#else-->` + falseToken + `<!--#endif-->`
	for _, header := range codeInjectionHeaders {
		resp := cc.Scanner.sendTestRequestFull(ctx, cc.Exchange, cc.Exchange.Path, map[string]string{header: payload})
		if resp == nil {
			continue
		}
		if ssiEvaluated(string(resp.Body), trueToken, falseToken) {
			return []*Finding{buildProbeFinding(cc, ssiInjectionIssue, "firm",
				header+" header SSI #if/#else/#endif directive evaluated to its true branch ("+trueToken+") with no literal directive or false-branch token present",
				"the "+header+" header reached a Server-Side Includes processor that parsed and evaluated the injected directive")}, nil
		}
	}
	return nil, nil
}

func ssiEvaluated(body, trueToken, falseToken string) bool {
	return body != "" &&
		strings.Contains(body, trueToken) &&
		!strings.Contains(body, falseToken) &&
		!strings.Contains(body, "<!--#if")
}

// ---------------------------------------------------------------------------

// reflectionProbeChecksEnabled gates the whole family behind ScanConfig.CheckReflectionProbes, off
// by default like every other per-family switch.
func reflectionProbeChecksEnabled(c *ScanConfig) bool { return c != nil && c.CheckReflectionProbes }

// ReflectionProbeCheckDescriptors returns the six native checks this file owns. The coordinating
// registry aggregates this with the other per-family descriptor functions into NativeCheckRegistry.
func ReflectionProbeCheckDescriptors() []CheckDescriptor {
	return []CheckDescriptor{
		nativeDescriptor(inputReflectionIssue, DispatchScopePerUrl, reflectionProbeChecksEnabled, checkInputReflection),
		nativeDescriptor(openRedirectIssue, DispatchScopePerUrl, reflectionProbeChecksEnabled, checkOpenRedirect),
		nativeDescriptor(linkManipulationIssue, DispatchScopePerUrl, reflectionProbeChecksEnabled, checkLinkManipulation),
		nativeDescriptor(headerInjectionIssue, DispatchScopePerUrl, reflectionProbeChecksEnabled, checkHeaderInjection),
		nativeDescriptor(codeInjectionIssue, DispatchScopePerUrl, reflectionProbeChecksEnabled, checkCodeInjection),
		nativeDescriptor(ssiInjectionIssue, DispatchScopePerUrl, reflectionProbeChecksEnabled, checkSSIInjection),
	}
}
