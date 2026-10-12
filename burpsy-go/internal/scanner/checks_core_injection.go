package scanner

// The three original catalog rows — SQL injection, reflected XSS, file path traversal — driven
// through enumerated insertion points.
//
// # What these replace, and why it mattered
//
// These rows were the scanner's first checks, written before ProbeHarness existed. Each built its
// probe by appending a parameter with a GUESSED name to the request:
//
//	appendQueryParam(exchange.Path, "test", payload)   // SQL injection
//	appendQueryParam(exchange.Path, "xss",  payload)   // reflected XSS
//	appendQueryParam(exchange.Path, "file", payload)   // file path traversal
//
// Two things follow, and a runtime scan against a deliberately vulnerable target showed both:
//
//  1. If the application's vulnerable parameter is not called `test`/`xss`/`file`, the payload
//     lands somewhere the application never reads. The probe is sent, the response is clean, and
//     the row reports nothing — while looking exactly like a target that is not vulnerable.
//  2. If it *is* called that, appending a second copy still does not test it. `?file=report.txt`
//     plus `&file=../../etc/passwd` is read by net/http's Query().Get as the FIRST value, so the
//     application sees `report.txt`. The probe tested the baseline.
//
// Together those made the rows close to undetectable in practice, and worse than undetectable in
// one specific way: a demo endpoint whose parameter happened to be named `test` made SQL injection
// look like it worked. A check that passes because a fixture was named after its own constant is
// not evidence of anything.
//
// ZAP's framework makes this class of bug unrepresentable — AbstractAppParamPlugin owns the loop
// over parameters and hands each rule `scan(msg, paramName, value)`, so a rule has no way to name
// a parameter. ProbeHarness is burpsy's equivalent: bcheck.Enumerate finds the points, the check
// says only what to put in them.
//
// # These return errors now
//
// The old functions returned `[]*Finding` with no error, so "no sender configured" and "the target
// is clean" were the same value. Reaching the harness makes the refusal explicit, which is what
// CheckRunner's contract requires.

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// checkSQLInjectionCore reports SQL injection confirmed by a database error the baseline did not
// produce, a boolean differential, or a time-based response delay (saq3.2.1).
//
// The techniques were error-only before, and ProbeTiming had no production caller — meaning blind
// SQLi (no error, no echo) was invisible. They run inside ONE insertion-point walk
// (blindInjectionPointProbes in sqli_techniques.go) rather than as three checks of the same type,
// because the audit's check set is one descriptor per catalog TypeIndex and a point's coverage,
// effectiveness prior and light-audit record would otherwise be charged three times for probes
// that answer the same question. Each technique still carries its own method gate at the probe:
// a disabled family is withheld and counted, and the remaining techniques still run.
func checkSQLInjectionCore(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if offline, isOffline, err := offlineSignatureScan(cc, sqlInjectionIssue, SQLErrorSignatures); isOffline {
		return offline, err
	}
	res, err := runInjection(ctx, cc, "SQLInjectionCore", cc.ProbeInsertionKinds(),
		func(h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
			probes := h.ProbeErrorSignatures(ctx, p, sqlErrorProbePayloads(), SQLErrorSignatures)
			return append(probes, blindInjectionPointProbes(ctx, h, p)...)
		})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sqlInjectionIssue, err)
	}
	if !res.confirmed {
		return nil, res.unresolved(sqlInjectionIssue)
	}
	return []*Finding{buildInjectionFinding(cc, sqlInjectionIssue, "high", res)}, nil
}

// offlineSignatureScan is the no-sender path: read the captured response for the row's signatures
// and report what is there, without pretending a probe was sent.
//
// It exists because auditing a stored capture with no sender is a supported mode, and removing it
// would silently drop that capability. But the evidence is weaker than the online path's and the
// finding says so: nothing here establishes that a *parameter* caused the signature to appear, so
// the confidence is tentative and the detail states that no probe was sent. An online scan
// reaching the same signature through an insertion point earns `firm`.
//
// The second return value distinguishes "this was the offline path" from "the offline path found
// nothing", so a caller cannot mistake one for the other. The third is the refusal: absence of a
// signature offline is NOT a clean result, because no probe was sent to make it one.
func offlineSignatureScan(cc *CheckContext, row string, signatures []string) ([]*Finding, bool, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil || cc.Scanner.sender != nil {
		return nil, false, nil
	}
	body := cc.Scanner.getResponseBody(cc.Exchange)

	// The baseline is the same bytes, so ClassifyErrorEvidence would call every match
	// pre-existing. This is a direct signature read, and its weaker standing is carried by the
	// confidence rather than hidden by reusing a differential classifier that does not apply.
	forms := matchableForms(body)
	for _, sig := range signatures {
		if !containsAny(forms, strings.ToLower(sig)) {
			continue
		}
		severity, remediation := "high", ""
		if definition, ok := ByName(row); ok {
			severity = definition.TypicalSeverity
			remediation = definition.Remediation
		}
		return []*Finding{{
			Name:       row,
			Severity:   severity,
			Confidence: "tentative",
			Description: fmt.Sprintf("%s: signature %q is present in the captured response. "+
				"No probe was sent (this scan has no sender), so nothing establishes that a "+
				"parameter controls it — confirm by auditing this endpoint with a sender configured.",
				row, sig),
			URL:        cc.Exchange.Path,
			Method:     cc.Exchange.Method,
			Evidence:   sig,
			Solution:   remediation,
			ExchangeID: cc.Exchange.ID,
			Timestamp:  nowUTC(),
		}}, true, nil
	}

	// No signature in the captured bytes, and no way to send a probe that might have produced one.
	// Returning (nil, nil) here would have been the conflation this file's own header calls a
	// defect: it reads as "this endpoint was tested for %s and is clean", when the truth is that
	// nothing was tested. Every other active row in the package refuses through RequireEgress for
	// exactly this reason; these three used to be the outliers that pretended.
	return nil, true, fmt.Errorf(
		"%s: no sender is configured, so no probe could be sent, and the captured response carries "+
			"none of this row's signatures — that is an untested endpoint, not a clean one: %w",
		row, errCheckUnsupported)
}

// sqlErrorProbePayloads are the minimal forms that unbalance a quoted or numeric context. The
// escaped-pair form is the control: an application that errors on `'` but not on `”` is parsing
// the value as SQL, whereas one that errors on both is probably rejecting the character outright.
func sqlErrorProbePayloads() []string {
	return []string{"'", `"`, "')", "';", "1'", "''"}
}

// checkReflectedXSSCore reports reflected XSS confirmed by a breakout, not by reflection.
//
// The breakout classification is the one the predecessor used (see xss.go, derived from Java's
// server-side evidence): a canary-tagged tag or a broken-out JavaScript string literal has to
// survive unescaped. What changed is only WHERE the payload goes — each enumerated point rather
// than a parameter named `xss`.
func checkReflectedXSSCore(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	// Offline, there is no breakout to observe: a breakout is a statement about what the
	// application did with a payload we sent. Reporting reflected XSS from a stored response alone
	// would be a guess, so this row stays silent rather than guessing.
	if cc != nil && cc.Scanner != nil && cc.Scanner.sender == nil {
		return nil, nil
	}
	browserConfirm := cc != nil && cc.Scanner != nil && cc.Scanner.config != nil && cc.Scanner.config.CheckXSSBrowserConfirm
	if browserConfirm && len(cc.Scanner.config.XSSBrowserTargets) == 0 {
		// The switch is on and the caller named no routes: fall back to the built-in ones, so flipping
		// the flag against a target this build knows works without a second step. A host the built-ins
		// do not cover still declines by name.
		cc.Scanner.config.XSSBrowserTargets = BuiltinXSSBrowserTargets()
	}
	h, err := NewProbeHarness(ctx, cc, cc.ProbeInsertionKinds())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", xssReflectedIssue, err)
	}
	points := h.Points()
	// The cap is reported rather than silently applied. A finding that says "Probed 8 insertion
	// points" for a request carrying 20 is a coverage claim the check did not earn; the extra
	// points are recorded in the finding's evidence text instead.
	capped := 0
	if len(points) > MaxInjectionPointsPerCheck {
		capped = len(points) - MaxInjectionPointsPerCheck
		points = points[:MaxInjectionPointsPerCheck]
	}

	// One finding per fact: a breakout stops the walk (the first confirmed point is the
	// finding, as before), while a decoding-without-breakout is a lesser fact that does not,
	// and is collected here so a later point's breakout cannot lose it.
	var findings []*Finding

	for _, point := range points {
		var evidence XSSEvidence

		// A probe with a bare canary first, to learn WHERE this point's value lands before
		// choosing what to send at it.
		//
		// A payload is exploitable or inert entirely according to its context, and no single
		// payload covers them all: `';…//` sits inertly inside a double-quoted host and vice
		// versa, and a value reflected into a text node needs no quote at all. Sending a fixed
		// pair and hoping was the previous approach, and it is why three of cmd/xsschallenge's
		// contexts were missed — their exploits contain no quote character, so nothing the old
		// payloads carried could ever have appeared. This is ZAP's ordering: observe the context,
		// then attack it.
		//
		// The observation probe is not wasted. A reflection it sees is recorded even when no
		// breakout follows, which is the honest half of the result.
		observed := newXSSCanary()
		var contexts []xssContext
		// landedOn names the page a followed redirect reached when the breakout was found there
		// (follow_redirections, burpsy-react-ui-o2p3) — Burp's own example for the setting is XSS in an
		// error message returned only after a redirect. Everything below reads the page a browser
		// would render: the landing page when the run followed, the response itself otherwise.
		landedOn := ""
		if sent, err := h.SendFollowing(ctx, point, observed); err == nil {
			res := sent.landing()
			contentType := rawHeaderValue(string(res.Raw), "Content-Type")
			if strings.Contains(res.Body, observed) {
				evidence |= XSSEvidenceReflected
				if rendersAsMarkup(contentType) {
					contexts = classifyXSSContexts(res.Body, observed)
				}
			}
		}

		// Each distinct context gets the payload that actually works there. Distinct, because a
		// value echoed into both a text node and an attribute is ordinary, and the two need
		// different payloads.
		bank := xssPayloadsForContexts(contexts)
		// viaDecoding names the Burp decoding variants (burpsy-react-ui-79ld) whose encoded
		// form of the primary payload confirmed a breakout at this point; decodedOnly names
		// the variants whose payload came back DECODED but neutralized — the transformation
		// half, reported on its own row below.
		var viaDecoding, decodedOnly []string
		for _, payload := range bank {
			canary := newXSSCanary()
			sent, err := h.SendFollowing(ctx, point, payload.build(canary))
			if err != nil {
				continue
			}
			res := sent.landing()
			contentType := rawHeaderValue(string(res.Raw), "Content-Type")
			if !strings.Contains(res.Body, canary) {
				continue
			}
			evidence |= XSSEvidenceReflected
			if !rendersAsMarkup(contentType) {
				// Reflected into something no browser parses. Recorded, never a breakout.
				evidence |= XSSEvidenceReflectedEncoded
				continue
			}
			// Each payload brings its own evidence. Checking a context-specific payload against
			// the generic markers is what made three contexts unreportable and cost four more:
			// `javascript:` opens no tag, an injected attribute opens no tag, and srcdoc's payload
			// must stay ENCODED, so none of them can produce `<svg id=CANARY onload=alert(1)>`.
			if payload.confirm != nil {
				bit := payload.bit
				if bit == 0 {
					bit = XSSEvidenceHTMLBreakout
				}
				if payload.confirm(res.Body, canary) {
					evidence |= bit
				} else {
					evidence |= XSSEvidenceReflectedEncoded
				}
			} else {
				evidence |= analyzeXSSReflection(res.Body, canary, contentType,
					xssHTMLBreakoutMarker(canary), xssScriptBreakoutMarker(canary))
			}
			if xssBreakoutConfirmed(evidence) {
				landedOn = sent.FollowedTo
				break
			}
		}

		// The decoding variants (burpsy-react-ui-79ld), in Burp's own order (Zguu.java:63-77:
		// plain APPEND, plain REPLACE, and only then the variant list, breaking on the first
		// confirmation). They run only where the plain bank failed while the canary still
		// reflected — the XSS that fires only after the application decodes its input — which
		// is also what bounds the cost: at most five probes per reflected-but-unbroken point,
		// under the same per-check point cap as everything above.
		//
		// The primary payload is the bank's first, the most specific attempt the point's
		// context chose; encoding the whole bank would re-ask a question one probe answers.
		if evidence&XSSEvidenceReflected != 0 && !xssBreakoutConfirmed(evidence) && len(bank) > 0 {
			primary := bank[0]
			for _, variant := range xssDecodingVariants() {
				canary := newXSSCanary()
				plain := primary.build(canary)
				sent, err := h.SendFollowingOpts(ctx, point, variant.encode(plain), bcheck.ApplyOptions{Raw: true})
				if err != nil {
					continue
				}
				res := sent.landing()
				contentType := rawHeaderValue(string(res.Raw), "Content-Type")
				if !strings.Contains(res.Body, canary) {
					continue
				}
				evidence |= XSSEvidenceReflected
				bit := primary.bit
				if bit == 0 {
					bit = XSSEvidenceHTMLBreakout
				}
				if rendersAsMarkup(contentType) && primary.confirm != nil && primary.confirm(res.Body, canary) {
					evidence |= bit
					viaDecoding = append(viaDecoding, variant.name)
					landedOn = sent.FollowedTo
					break
				}
				// No live markup. The variant's transformMarker is the byte-level signal that
				// the application performed the decoding anyway — Burp's
				// UNEXPECTED_TRANSFORMATION half, reported on the row that exists for it.
				if variant.transformMarker != nil {
					if marker := variant.transformMarker(plain, canary); marker != "" && strings.Contains(res.Body, marker) {
						decodedOnly = append(decodedOnly, variant.name)
					}
				}
			}
		}

		// Burp's file-upload HTML variant (FILE_UPLOAD_FILE_EXTENSION_HTML, burpsy-react-ui-kzt7): a
		// file part whose name is not already .html is re-sent as an HTML document — filename
		// <original><3 random chars>.html, Content-Type text/html, the payload as its content — so an
		// upload the application serves back by its extension is tested as the page a victim would
		// open. Only when the plain bank and the variants did not already break out at this point.
		if !xssBreakoutConfirmed(evidence) && len(bank) > 0 {
			if name, ok := point.UploadFilename(h.reqBytes); ok && !strings.HasSuffix(strings.ToLower(name), ".html") {
				// The uploaded file IS the document, so its content is parsed as page content: the
				// text-node breakout is the payload, whatever context the plain probes guessed.
				primary := xssPayloadsForContexts([]xssContext{{Kind: xssCtxText}})[0]
				canary := newXSSCanary()
				newName := name + randomLetters(3) + ".html"
				if sent, err := h.SendHTMLUpload(ctx, point, primary.build(canary), newName); err == nil {
					res := sent
					contentType := rawHeaderValue(string(res.Raw), "Content-Type")
					if strings.Contains(res.Body, canary) {
						evidence |= XSSEvidenceReflected
						if rendersAsMarkup(contentType) && primary.confirm != nil && primary.confirm(res.Body, canary) {
							bit := primary.bit
							if bit == 0 {
								bit = XSSEvidenceHTMLBreakout
							}
							evidence |= bit
							viaDecoding = append(viaDecoding, "file upload as "+newName)
						}
					}
				}
			}
		}

		if len(decodedOnly) > 0 {
			// "Suspicious input transformation (reflected)" is a catalogue row with its own
			// descriptor (checks_final.go); the finding is filed under THAT row rather than a
			// new name, because the transformation is a different (and lesser) fact than the
			// breakout this check exists for, and the row is where an operator already reads it.
			if definition, ok := ByName("Suspicious input transformation (reflected)"); ok {
				findings = append(findings, buildHeaderFinding(cc, "Suspicious input transformation (reflected)",
					definition.TypicalSeverity, "firm",
					fmt.Sprintf("the application decoded the payload before output-encoding it (%s)", strings.Join(decodedOnly, ", ")),
					fmt.Sprintf("a value submitted in %s %q is reflected here after the application decoded it — "+
						"the breakout did not confirm, but the decoding is itself worth reviewing",
						point.Kind, point.Name)))
			}
		}

		// The browser confirmation (j1mk.38): the point reflected the payload but into a content type
		// no browser parses as markup, so the server-side check refuses to call it a breakout. That
		// refusal is right on the wire and wrong about the application when the PAGE's own script takes
		// the answer and writes it into the document — measured on OWASP VulnerableApp, whose XSS
		// levels answer text/plain and render it with innerHTML. Only a browser can settle it.
		if evidence&XSSEvidenceReflected != 0 && !xssBreakoutConfirmed(evidence) && browserConfirm {
			if f := confirmReflectedXSSInBrowser(ctx, cc, point, bank); f != nil {
				findings = append(findings, f)
				break
			}
		}

		if !xssBreakoutConfirmed(evidence) {
			continue
		}
		severity, remediation := "high", ""
		if definition, ok := ByName(xssReflectedIssue); ok {
			severity = definition.TypicalSeverity
			remediation = definition.Remediation
		}
		detail := fmt.Sprintf("%s %q: %s", point.Kind, point.Name, xssEvidenceText(evidence))
		if landedOn != "" {
			detail += "; the breakout was on " + landedOn + ", reached by following the probe's redirect (follow_redirections)"
		}
		if capped > 0 {
			detail += fmt.Sprintf("; %d further insertion point(s) were NOT probed (cap %d reached)",
				capped, MaxInjectionPointsPerCheck)
		}
		// The evidence names the decoding when a variant carried the breakout: "markup
		// breakout via URL decoding" says what the plain payload could not — that the
		// application decodes this input before reflecting it.
		evidenceText := xssEvidenceText(evidence)
		if len(viaDecoding) > 0 {
			evidenceText += " via " + strings.Join(viaDecoding, ", ")
			detail += "; the plain payload did not break out, the encoded one did"
		}
		findings = append(findings, &Finding{
			Name:             xssReflectedIssue,
			Severity:         severity,
			Confidence:       "firm",
			Description:      "Reflected XSS evidence: " + detail,
			URL:              cc.Exchange.Path,
			Method:           cc.Exchange.Method,
			Evidence:         evidenceText,
			Solution:         remediation,
			ExchangeID:       cc.Exchange.ID,
			Timestamp:        nowUTC(),
			DecodingVariants: DecodingVariants(viaDecoding),
		})
		break
	}
	return findings, nil
}

// checkFilePathTraversalCore reports a traversal sequence that escaped the intended directory,
// proven by the contents of the file it reached.
//
// The proof is file content, never the payload coming back. An endpoint that echoes
// `../../etc/passwd` has reflected a string; one that returns a line starting `root:x:0:0:` has
// read a file. internal/vulnapp keeps a /safe/download endpoint that does the former precisely so
// this distinction stays under test.
//
// This row is the dot-dot-slash escape. Its sibling "File path manipulation" takes the absolute
// path forms — see filePathManipulationPayloads for why the two banks are kept apart.
func checkFilePathTraversalCore(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if offline, isOffline, err := offlineSignatureScan(cc, "File path traversal", TraversalFileSignatures); isOffline {
		return offline, err
	}
	res, err := runInjection(ctx, cc, "FilePathTraversalCore", cc.ProbeInsertionKinds(),
		func(h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
			// Raw, because a traversal payload IS its own escaping (j1mk.35): `..%2f` is spelled
			// for a filter that contains-checks a literal `..`, and `%00` for one that truncates
			// on the string but not on the path. The default percent-escape would turn `..%2f`
			// into `..%252f`, which the target decodes once to a literal `%2f` the application
			// never decodes again — the probe would test the wrong string.
			return h.ProbeErrorSignaturesRaw(ctx, p, TraversalPayloadsFor(p.BaseValue), TraversalFileSignatures)
		})
	if err != nil {
		return nil, fmt.Errorf("File path traversal: %w", err)
	}
	if !res.confirmed {
		return nil, res.unresolved("File path traversal")
	}
	return []*Finding{buildInjectionFinding(cc, "File path traversal", "high", res)}, nil
}

// filePathManipulationPayloads are absolute and drive-qualified paths, with no traversal sequence
// in them.
//
// The two rows were both confirmed by the same dot-dot-slash bank, which made them one detection
// reported under two names — the kind of double count this project treats as dishonest. Burp
// separates them and so does this: traversal is escaping a directory you were meant to stay in,
// manipulation is naming a file outright. An application that concatenates a filename onto a
// directory is vulnerable to the first; one that passes the parameter to open() is vulnerable to
// the second, and the payload that proves each is different.
var filePathManipulationPayloads = []string{
	"/etc/passwd",
	"/etc/passwd%00",
	`C:\windows\win.ini`,
	`\windows\win.ini`,
	"file:///etc/passwd",
}

// nowUTC is the timestamp helper these findings use, kept in one place so the two constructors in
// this file cannot drift apart.
func nowUTC() time.Time { return time.Now().UTC() }

// coreInjectionDescriptors returns the three rows this file owns.
//
// They keep their original ScanConfig switches (CheckSqli / CheckXss / CheckPathTraversal) because
// callers already set them; only the implementation behind each changed.
func coreInjectionDescriptors() []CheckDescriptor {
	return []CheckDescriptor{
		// ONE SQL-injection descriptor, as the registry's one-per-catalog-type invariant demands.
		// Its three techniques (error, boolean, timing; saq3.2.1) run inside the check and are
		// gated per technique at the probe; the descriptor's declared method set comes from
		// burpsyDetectionMethods, which lists all five implemented methods, and the dispatch rule
		// (Zwy6) withholds the check only when every one of them is disabled.
		nativeDescriptor(sqlInjectionIssue, DispatchScopePerUrl,
			func(c *ScanConfig) bool { return c != nil && c.CheckSqli }, checkSQLInjectionCore),
		nativeDescriptor(xssReflectedIssue, DispatchScopePerUrl,
			func(c *ScanConfig) bool { return c != nil && c.CheckXss }, checkReflectedXSSCore),
		nativeDescriptor("File path traversal", DispatchScopePerUrl,
			func(c *ScanConfig) bool { return c != nil && c.CheckPathTraversal }, checkFilePathTraversalCore),
	}
}

// randomLetters returns n random lowercase letters, for the upload variant's filename.
func randomLetters(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("x", n)
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}
