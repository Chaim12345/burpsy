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
	"fmt"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// coreInjectionKinds are the places these three rows look. Body and cookie are included because a
// login form's SQL injection lives in the body, which is exactly the case the query-only
// predecessor could not reach.
var coreInjectionKinds = []string{"query", "body", "cookie"}

// checkSQLInjectionCore reports SQL injection confirmed by a database error the baseline did not
// produce.
//
// Error evidence only, deliberately. Boolean and timing differentials for this row would duplicate
// what the dedicated injection family already does with better classification; this row's job is
// the case Burp reports as plain "SQL injection" — a quote that reaches a query and comes back as
// a parser error.
func checkSQLInjectionCore(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if offline, ok := offlineSignatureScan(cc, sqlInjectionIssue, SQLErrorSignatures); ok {
		return offline, nil
	}
	res, err := runInjection(ctx, cc, coreInjectionKinds,
		func(h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
			return h.ProbeErrorSignatures(ctx, p, sqlErrorProbePayloads(), SQLErrorSignatures)
		})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sqlInjectionIssue, err)
	}
	if !res.confirmed {
		return nil, nil
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
// nothing", so a caller cannot mistake one for the other.
func offlineSignatureScan(cc *CheckContext, row string, signatures []string) ([]*Finding, bool) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil || cc.Scanner.sender != nil {
		return nil, false
	}
	body := cc.Scanner.getResponseBody(cc.Exchange)
	if body == "" {
		return nil, true
	}
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
		}}, true
	}
	return nil, true
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
	h, err := NewProbeHarness(ctx, cc, coreInjectionKinds)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", xssReflectedIssue, err)
	}
	points := h.Points()
	if len(points) > MaxInjectionPointsPerCheck {
		points = points[:MaxInjectionPointsPerCheck]
	}

	for _, point := range points {
		var evidence XSSEvidence

		// Two probes per point, each with its own canary so a reflection can be attributed to
		// the payload that caused it rather than to the other probe.
		htmlCanary := newXSSCanary()
		if res, err := h.Send(ctx, point, htmlBreakoutPayload(htmlCanary)); err == nil {
			evidence |= analyzeXSSReflection(res.Body, htmlCanary,
				xssHTMLBreakoutMarker(htmlCanary), xssScriptBreakoutMarker(htmlCanary))
		}
		scriptCanary := newXSSCanary()
		if res, err := h.Send(ctx, point, scriptBreakoutPayload(scriptCanary)); err == nil {
			evidence |= analyzeXSSReflection(res.Body, scriptCanary,
				xssHTMLBreakoutMarker(scriptCanary), xssScriptBreakoutMarker(scriptCanary))
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
		return []*Finding{{
			Name:        xssReflectedIssue,
			Severity:    severity,
			Confidence:  "firm",
			Description: "Reflected XSS evidence: " + detail,
			URL:         cc.Exchange.Path,
			Method:      cc.Exchange.Method,
			Evidence:    xssEvidenceText(evidence),
			Solution:    remediation,
			ExchangeID:  cc.Exchange.ID,
			Timestamp:   nowUTC(),
		}}, nil
	}
	return nil, nil
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
	if offline, ok := offlineSignatureScan(cc, "File path traversal", TraversalFileSignatures); ok {
		return offline, nil
	}
	res, err := runInjection(ctx, cc, coreInjectionKinds,
		func(h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
			return h.ProbeErrorSignatures(ctx, p, PathTraversalPayloads, TraversalFileSignatures)
		})
	if err != nil {
		return nil, fmt.Errorf("File path traversal: %w", err)
	}
	if !res.confirmed {
		return nil, nil
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
		nativeDescriptor(sqlInjectionIssue, DispatchScopePerUrl,
			func(c *ScanConfig) bool { return c != nil && c.CheckSqli }, checkSQLInjectionCore),
		nativeDescriptor(xssReflectedIssue, DispatchScopePerUrl,
			func(c *ScanConfig) bool { return c != nil && c.CheckXss }, checkReflectedXSSCore),
		nativeDescriptor("File path traversal", DispatchScopePerUrl,
			func(c *ScanConfig) bool { return c != nil && c.CheckPathTraversal }, checkFilePathTraversalCore),
	}
}
