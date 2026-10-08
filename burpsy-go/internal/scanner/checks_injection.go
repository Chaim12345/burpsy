package scanner

// Wired active injection evaluators: the recovered payload banks driven through ProbeHarness
// and judged by the differential classifiers.
//
// # Why a capability absence is an error, not an empty result
//
// Every check here returns the harness's error when there is no sender or no baseline. That
// makes the audit engine count a refusal, which is the honest signal: "we could not look" is
// not "we looked and found nothing". Returning nil findings instead would quietly turn an
// unusable scan into a clean report, and these checks exist to avoid exactly that.
//
// # Why the point set is bounded
//
// points x payloads is unbounded, and an endpoint with fifty parameters would otherwise turn
// one check into a thousand requests. The cap is applied per check and the untested remainder
// is reported through ProbeCoverage, so the bound shows up as reduced coverage rather than as
// a silently short scan.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

func injectionChecksEnabled(c *ScanConfig) bool { return c != nil && c.CheckActiveInjection }

// MaxInjectionPointsPerCheck bounds how many insertion points one check probes. Points beyond
// it are counted as untested in the coverage line rather than dropped silently.
const MaxInjectionPointsPerCheck = 8

// InjectionTimingDelay is the delay requested by time-based payloads. Long enough to clear
// network jitter against TimingMargin, short enough that a false positive costs seconds.
const InjectionTimingDelay = 5 * time.Second

// injectionResult carries what one evaluator learned, including what it could not reach.
type injectionResult struct {
	best      InjectionProbe
	confirmed bool
	coverage  ProbeCoverage
}

// runInjection is the shared driver: build the harness, walk a bounded set of points, collect
// every probe, and pick the strongest evidence.
// checkName names the check this run belongs to, and is part of the effectiveness prior's
// identity: one check finding nothing at a place is not evidence about another check, so a
// prior shared across checks would gate away a check that had never looked (y4om).
func runInjection(ctx context.Context, cc *CheckContext, checkName string, kinds []string,
	perPoint func(*ProbeHarness, bcheck.InsertionPoint) []InjectionProbe) (injectionResult, error) {

	// The check's own row name is part of the effectiveness prior's identity (y4om): one check
	// finding nothing at a place must not gate another check away from it. Written onto the
	// check context, because that is what the harness enumerates through.
	cc.PointEffectiveCheck = checkName

	h, err := NewProbeHarness(ctx, cc, kinds)
	if err != nil {
		return injectionResult{}, err
	}
	points := h.Points()
	tested := len(points)
	// capped is reported, not hidden: a check that probed 8 of 20 points has not tested the
	// endpoint, and a coverage line that says otherwise is the silent false negative this
	// package's Declined type exists to prevent.
	capped := 0
	if tested > MaxInjectionPointsPerCheck {
		capped = tested - MaxInjectionPointsPerCheck
		points = points[:MaxInjectionPointsPerCheck]
		tested = MaxInjectionPointsPerCheck
	}

	// The light-audit tier (burpsy-react-ui-7bkj): a (kind, host) type that has produced
	// enough CLEAN points this run is skipped for the rest of that type on that host —
	// Burp's "Skipped due to repetitive behavior". The skip is counted, never hidden: a
	// check that probed 8 of 30 query points because 20 clean query points on this host
	// came before has NOT tested 22 points, and the coverage line must say so in its own
	// field rather than reading as a smaller request.
	//
	// The counter consult happens BEFORE the point's probes: a point that is skipped never
	// sends, which is the whole saving. A point that runs and finds nothing records CLEAN,
	// which is what raises the type toward the threshold.
	light := cc.LightAudit
	var skippedRepetitive int
	var probes []InjectionProbe
	for _, point := range points {
		if light != nil && light.ShouldSkipRepetitive(string(point.Kind), cc.Exchange.Host) {
			skippedRepetitive++
			light.RecordSkippedPoint()
			continue
		}
		pointStart := len(probes)
		probes = append(probes, perPoint(h, point)...)
		// A point whose probes were all WITHHELD (their detection method is disabled, 2hze) asked
		// the target nothing, so it is neither clean nor answered: recording it either way would
		// raise the light tier's repetition prior, or the effectiveness ledger's, on evidence nobody
		// gathered.
		if !anySent(probes[pointStart:]) {
			continue
		}
		// A point whose probes all came back without evidence is CLEAN for the tier's
		// purposes — a signal (an error signature, a differential, an OOB hit) means this
		// type on this host deserves full price again, so the prior must not rise.
		if light != nil {
			clean := true
			for _, pr := range probes[pointStart:] {
				if pr.Evidence != InjectionEvidenceNone {
					clean = false
					break
				}
			}
			if clean {
				light.RecordCleanPoint(string(point.Kind), cc.Exchange.Host)
			}
		}
		// The per-point effectiveness gate's own record (burpsy-react-ui-y4om). Same clean/not-clean
		// question the light tier asks, asked of the POINT rather than its type, and asked here for
		// the same reason: the gate can only judge a place on evidence this run actually gathered,
		// and the evidence is the probe set this point just produced. A point that has now been
		// probed MinPointEffectivenessProbes times with nothing found is dropped by the next
		// dispatch; a point that answered something is never dropped by this gate again.
		if pe := effectivenessFrom(cc); pe != nil {
			// The check's own name is part of the prior's identity: one check's silence on a
			// parameter is not evidence that another check would find nothing there, and
			// Burp's own gate is a per-MESSAGE-CLASS probe (Zcgg.Zw → point.Zp(new Zc3c())
			// matches one message class), so a prior shared across checks would block a
			// check that had never looked.
			answered := false
			for _, pr := range probes[pointStart:] {
				if pr.Evidence != InjectionEvidenceNone {
					answered = true
					break
				}
			}
			pe.record(checkName, point, cc.Exchange.Host, answered)
		}
		// Stop at the first confirmation: further payloads cost requests and add nothing
		// to a finding that is already proven.
		if _, confirmed := BestEvidence(probes); confirmed {
			break
		}
	}
	// Every probe this check would have sent was withheld: the check did not run in any sense that
	// produces a verdict, and a nil result here would read as a clean one. Refused as unsupported,
	// which the engine counts as Skipped, and the ledger already holds the reason.
	if len(probes) > 0 && !anySent(probes) {
		return injectionResult{}, fmt.Errorf("%s: every probe was withheld because its detection method is disabled for this issue type: %w",
			checkName, errCheckUnsupported)
	}
	best, confirmed := BestEvidence(probes)
	cov := h.Coverage(probes, tested-skippedRepetitive)
	cov.PointsCapped = capped
	cov.PointsSkippedRepetitive = skippedRepetitive
	if pe := effectivenessFrom(cc); pe != nil {
		// How many probes the run has spent on points that answered nothing. Reported so a
		// smaller request count is legible: the same reason PointsSkippedRepetitive exists.
		cov.PointsJudgedIneffective = pe.Count()
	}
	return injectionResult{best: best, confirmed: confirmed, coverage: cov}, nil
}

// anySent reports whether at least one probe in the set was actually sent.
func anySent(probes []InjectionProbe) bool {
	for _, p := range probes {
		if !p.Withheld {
			return true
		}
	}
	return false
}

// effectivenessFrom returns the run's per-point effectiveness ledger, or nil when there is
// none. Nil is the honest answer for a context built outside a dispatched audit, and for a run
// that set skip_ineffective_checks to zero: in both cases there is no gate to record for, and a
// nil here must not look like "every point answered nothing".
func effectivenessFrom(cc *CheckContext) *pointEffectiveness {
	if cc == nil || cc.PointEffectiveness == nil {
		return nil
	}
	return cc.PointEffectiveness
}

// unresolved reports the inconclusive sentinel when nothing confirmed but some probe was undecided.
func (r injectionResult) unresolved(row string) error {
	if r.confirmed || r.coverage.Inconclusive == 0 {
		return nil
	}
	return fmt.Errorf("%s: %d of %d probe(s) undecided: %w",
		row, r.coverage.Inconclusive, r.coverage.PayloadsSent, errCheckInconclusive)
}

// buildInjectionFinding renders a confirmed injection result. Coverage is folded into the
// description so a reader sees how much of the endpoint the verdict rests on.
func buildInjectionFinding(cc *CheckContext, name, severity string, res injectionResult) *Finding {
	confidence := "firm"
	switch res.best.Evidence {
	case InjectionEvidenceEvaluated, InjectionEvidenceOutOfBand:
		confidence = "certain"
	case InjectionEvidenceErrorSignature, InjectionEvidenceTiming:
		confidence = "firm"
	case InjectionEvidenceBooleanDifferential:
		confidence = "tentative"
	}
	detail := fmt.Sprintf("%s (%s). Probed %d insertion point(s) with %d payload(s); %d inconclusive, %d point(s) could not be enumerated.",
		res.best.Detail, res.best.Evidence,
		res.coverage.PointsTested, res.coverage.PayloadsSent,
		res.coverage.Inconclusive, res.coverage.PointsDeclined)
	if res.coverage.PointsCapped > 0 {
		detail += fmt.Sprintf(" %d further point(s) were NOT probed: the per-check cap of %d was reached.",
			res.coverage.PointsCapped, MaxInjectionPointsPerCheck)
	}

	f := buildHeaderFinding(cc, name, severity, confidence, res.best.Payload, detail)
	if res.best.Detail != "" {
		f.Param = injectionParamFromDetail(res.best.Detail)
	}
	return f
}

// injectionParamFromDetail pulls the parameter name out of a probe detail, which the harness
// formats as `kind "name": ...`.
func injectionParamFromDetail(detail string) string {
	open := strings.Index(detail, `"`)
	if open < 0 {
		return ""
	}
	rest := detail[open+1:]
	close := strings.Index(rest, `"`)
	if close < 0 {
		return ""
	}
	return rest[:close]
}

// ---------------------------------------------------------------------------
// error-signature families: XPath, XML
// ---------------------------------------------------------------------------

// xpathProbePayloads are the fragments that provoke an XPath parse error. They reuse the SQL
// fragment bank from burp.Ze2s, which is correct rather than lazy: burp.Zg_c drives SQL and
// XPath from one check with one fragment set, and the two families are told apart by which
// error signatures come back, not by which payload went out.
func xpathProbePayloads() []string {
	return []string{"'", `"`, "']", `"]`, "' or '1'='1", "count(/*)"}
}

func checkXPathInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	res, err := runInjection(ctx, cc, "XPathInjection", cc.ProbeInsertionKinds(),
		func(h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
			return h.ProbeErrorSignatures(ctx, p, xpathProbePayloads(), XPathErrorSignatures)
		})
	if err != nil {
		return nil, err
	}
	if !res.confirmed {
		return nil, res.unresolved("XPath injection")
	}
	return []*Finding{buildInjectionFinding(cc, "XPath injection", "high", res)}, nil
}

func checkXMLInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	res, err := runInjection(ctx, cc, "XMLInjection", cc.ProbeInsertionKinds(),
		func(h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
			var payloads []string
			for _, x := range XMLInjectionPayloads("bsyxml") {
				payloads = append(payloads, x.Body)
			}
			return h.ProbeErrorSignatures(ctx, p, payloads, XMLErrorSignatures)
		})
	if err != nil {
		return nil, err
	}
	if !res.confirmed {
		return nil, res.unresolved("XML injection")
	}
	return []*Finding{buildInjectionFinding(cc, "XML injection", "medium", res)}, nil
}

// ---------------------------------------------------------------------------
// boolean family: LDAP
// ---------------------------------------------------------------------------

func checkLDAPInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	res, err := runInjection(ctx, cc, "LDAPInjection", cc.ProbeInsertionKinds(),
		func(h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
			payloads := LDAPPayloads(p.BaseValue)
			// payloads[1] closes the filter and opens an always-true one; payloads[2]
			// negates the original. True-vs-false is exactly the pair
			// ClassifyBooleanDifferential needs.
			probes := []InjectionProbe{h.ProbeBoolean(ctx, p, payloads[1], payloads[2])}
			// An error signature is also worth having: a malformed filter often surfaces
			// as an LDAP error rather than a behavioural change.
			probes = append(probes, h.ProbeErrorSignatures(ctx, p, []string{payloads[0], "("}, LDAPErrorSignatures)...)
			return probes
		})
	if err != nil {
		return nil, err
	}
	if !res.confirmed {
		return nil, res.unresolved("LDAP injection")
	}
	return []*Finding{buildInjectionFinding(cc, "LDAP injection", "high", res)}, nil
}

// ---------------------------------------------------------------------------
// file read: path manipulation
// ---------------------------------------------------------------------------

func checkFilePathManipulation(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	res, err := runInjection(ctx, cc, "FilePathManipulation", cc.ProbeInsertionKinds(),
		func(h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
			// A read is proven by file content, not by the absence of an error, which is
			// why TraversalFileSignatures rather than an error bank.
			return h.ProbeErrorSignatures(ctx, p, PathTraversalPayloads, TraversalFileSignatures)
		})
	if err != nil {
		return nil, err
	}
	if !res.confirmed {
		return nil, res.unresolved("File path manipulation")
	}
	return []*Finding{buildInjectionFinding(cc, "File path manipulation", "high", res)}, nil
}

// ---------------------------------------------------------------------------
// evaluation family: OS command, and the five interpreted languages
// ---------------------------------------------------------------------------

func checkOSCommandInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	// A fresh marker per run, not a compile-time constant.
	//
	// It was "bsycmd" + ArithmeticProofProduct(), i.e. the literal "bsycmd42" on every scan of
	// every target forever. xss.go:27-30 already documents why that is wrong, and the failure here
	// is worse than the false positive it warns about: NewProbeHarness fetches a live baseline, and
	// ClassifyEvaluation returns Inconclusive when the marker is already in it. So once any
	// endpoint renders a stored copy of a previous scan's marker — a comment field, a log viewer,
	// an error page quoting the last request — this check goes permanently silent on a genuinely
	// command-injectable target, and silently, because Inconclusive never reaches a report.
	marker := newProbeCanary("bsycmd")
	res, err := runInjection(ctx, cc, "OSCommandInjection", cc.ProbeInsertionKinds(),
		func(h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
			var probes []InjectionProbe
			for _, payload := range OSCommandPayloads(marker) {
				// The marker is echoed by the shell, so it appears in the response
				// without being part of a reflection of the payload — which is what
				// ClassifyMarkerEcho distinguishes.
				probes = append(probes, h.ProbeEvaluation(ctx, p, payload, marker))
			}
			return probes
		})
	if err != nil {
		return nil, err
	}
	if !res.confirmed {
		return nil, res.unresolved("OS command injection")
	}
	return []*Finding{buildInjectionFinding(cc, "OS command injection", "high", res)}, nil
}

// codeInjectionCheck builds an evaluator for one interpreted language, walking that
// language's emitters across all three quoting contexts.
func codeInjectionCheck(rowName, language, severity string) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		// The effectiveness prior keys on the CHECK's name as well as the place (y4om:
		// runInjection writes this name onto cc.PointEffectiveCheck, and the ledger records
		// per (check, kind, name, host)), so every language must probe under its own row name.
		// All five used to pass "OSCommandInjection" — the OS command check's own id — which
		// made five checks' silence one prior: the Python check's two silent probes at a place
		// retired the Ruby check there too, a gate dropping a check on the strength of probes
		// it never sent. The row name is unique per row, which is the granularity the key
		// exists for; the OS command check keeps its own id below.
		res, err := runInjection(ctx, cc, rowName, cc.ProbeInsertionKinds(),
			func(h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
				var probes []InjectionProbe
				for _, probe := range CodeInjectionProbeSet(language) {
					out := h.ProbeEvaluation(ctx, p, probe.Payload, ArithmeticProofProduct())
					out.Context = probe.Context
					probes = append(probes, out)
				}
				return probes
			})
		if err != nil {
			return nil, err
		}
		if !res.confirmed {
			return nil, res.unresolved(rowName)
		}
		f := buildInjectionFinding(cc, rowName, severity, res)
		f.Description = fmt.Sprintf("%s The payload landed in %s context.",
			f.Description, res.best.Context.Label())
		return []*Finding{f}, nil
	}
}

// ---------------------------------------------------------------------------
// template and expression language
// ---------------------------------------------------------------------------

// templateArithmeticPayloads are the standard non-out-of-band template probes: each engine
// family's own delimiters wrapped around the recovered arithmetic.
//
// PROVENANCE: the delimiters are NOT recovered. burp.Zwv2 carries only the engine names and
// the prose describing this technique ("This payload begins with syntax designed to break out
// of the template statement context. The resulting response contained the string ..."), and
// burp.Zp3p's recovered payloads are all out-of-band. These are the documented standard forms
// for each engine, labelled here rather than presented as recovered.
func templateArithmeticPayloads() []string {
	arith := fmt.Sprintf("%d*%d", ArithmeticProofLeft, ArithmeticProofRight)
	return []string{
		"${" + arith + "}",     // JSP EL, FreeMarker, Java EL
		"{{" + arith + "}}",    // Jinja2, Twig, Django, Handlebars
		"#{" + arith + "}",     // Spring, Thymeleaf, Ruby interpolation
		"<%= " + arith + " %>", // ERB, JSP scriptlet
		"{" + arith + "}",      // Smarty
		"${{" + arith + "}}",   // nested-delimiter breakout
		"}}{{" + arith + "}}",  // breakout from an existing statement
		`"}}` + "{{" + arith + "}}",
	}
}

func checkServerSideTemplateInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	res, err := runInjection(ctx, cc, "ServerSideTemplateInjection", cc.ProbeInsertionKinds(),
		func(h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
			var probes []InjectionProbe
			for _, payload := range templateArithmeticPayloads() {
				probes = append(probes, h.ProbeEvaluation(ctx, p, payload, ArithmeticProofProduct()))
			}
			return probes
		})
	if err != nil {
		return nil, err
	}
	if !res.confirmed {
		return nil, res.unresolved("Server-side template injection")
	}
	return []*Finding{buildInjectionFinding(cc, "Server-side template injection", "high", res)}, nil
}

func checkExpressionLanguageInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	arith := fmt.Sprintf("%d*%d", ArithmeticProofLeft, ArithmeticProofRight)
	res, err := runInjection(ctx, cc, "ExpressionLanguageInjection", cc.ProbeInsertionKinds(),
		func(h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
			var probes []InjectionProbe
			// The EL subset of the template delimiters, plus the recovered class-probe
			// shape from burp.Zp1w (`${''.class}`) rendered as arithmetic.
			for _, payload := range []string{"${" + arith + "}", "#{" + arith + "}", "${{" + arith + "}}"} {
				probes = append(probes, h.ProbeEvaluation(ctx, p, payload, ArithmeticProofProduct()))
			}
			return probes
		})
	if err != nil {
		return nil, err
	}
	if !res.confirmed {
		return nil, res.unresolved("Expression Language injection")
	}
	return []*Finding{buildInjectionFinding(cc, "Expression Language injection", "high", res)}, nil
}

// InjectionCheckDescriptors returns the twelve wired active injection checks.
func InjectionCheckDescriptors() []CheckDescriptor {
	return []CheckDescriptor{
		nativeDescriptor("OS command injection", DispatchScopePerUrl, injectionChecksEnabled, checkOSCommandInjection),
		nativeDescriptor("LDAP injection", DispatchScopePerUrl, injectionChecksEnabled, checkLDAPInjection),
		nativeDescriptor("XPath injection", DispatchScopePerUrl, injectionChecksEnabled, checkXPathInjection),
		nativeDescriptor("XML injection", DispatchScopePerUrl, injectionChecksEnabled, checkXMLInjection),
		nativeDescriptor("File path manipulation", DispatchScopePerUrl, injectionChecksEnabled, checkFilePathManipulation),
		nativeDescriptor("Server-side template injection", DispatchScopePerUrl, injectionChecksEnabled, checkServerSideTemplateInjection),
		nativeDescriptor("Expression Language injection", DispatchScopePerUrl, injectionChecksEnabled, checkExpressionLanguageInjection),

		nativeDescriptor("PHP code injection", DispatchScopePerUrl, injectionChecksEnabled,
			codeInjectionCheck("PHP code injection", "php", "high")),
		nativeDescriptor("Perl code injection", DispatchScopePerUrl, injectionChecksEnabled,
			codeInjectionCheck("Perl code injection", "perl", "high")),
		nativeDescriptor("Ruby code injection", DispatchScopePerUrl, injectionChecksEnabled,
			codeInjectionCheck("Ruby code injection", "ruby", "high")),
		nativeDescriptor("Python code injection", DispatchScopePerUrl, injectionChecksEnabled,
			codeInjectionCheck("Python code injection", "python", "high")),
		nativeDescriptor("Server-side JavaScript code injection", DispatchScopePerUrl, injectionChecksEnabled,
			codeInjectionCheck("Server-side JavaScript code injection", "javascript", "high")),
	}
}
