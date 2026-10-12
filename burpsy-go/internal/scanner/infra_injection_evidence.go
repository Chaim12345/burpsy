package scanner

// Differential evidence classification for the active injection evaluators.
//
// A payload bank is not an evaluator. What makes an injection finding honest is the
// comparison: an error signature that was already in the baseline response proves nothing,
// a "42" that the page always contained proves nothing, and a slow response on a slow
// endpoint proves nothing. Every classifier here takes the baseline as an argument for
// that reason, and every one has a state meaning "could not tell" that is distinct from
// both "vulnerable" and "not vulnerable".

import (
	"html"
	"net/url"
	"strings"
	"time"
)

// InjectionEvidence is how strongly one probe is supported.
type InjectionEvidence uint8

const (
	// InjectionEvidenceNone means the probe ran and the discriminator did not appear.
	InjectionEvidenceNone InjectionEvidence = iota
	// InjectionEvidenceInconclusive means the comparison could not be made — the
	// baseline already carried the discriminator, or the timing was too noisy. It is
	// NOT a clean result.
	//
	// This used to be silence, and the distinction was worth nothing: BestEvidence returns
	// confirmed=false for Inconclusive, every caller then did `if !res.confirmed { return nil, nil }`,
	// and res.coverage.Inconclusive was rendered only inside buildInjectionFinding — i.e. only once
	// something ELSE had already confirmed, which is exactly the case where it does not matter. A
	// probe that could not be judged was reported identically to a target that is clean.
	//
	// It is now carried all the way out. injectionResult.unresolved wraps errCheckInconclusive
	// (bcheck_runner.go), the audit engine counts that as Ran plus Unmeasurable rather than as a
	// failure — so the breaker does not trip on it — and AuditOutcome.Summary renders
	// "N check(s) undecided, not clean". The tests holding this in place are
	// TestAPoisonedBaselineReportsUndecidedRatherThanClean (infra_injection_test.go) and
	// TestADeferredStoredClaimIsCountedUndecidedNotFailed (stored_lifecycle_test.go). So a clean
	// injection result now means "probes ran and found nothing", and an undecided one says so.
	InjectionEvidenceInconclusive
	// InjectionEvidenceErrorSignature means an error the baseline did not produce.
	InjectionEvidenceErrorSignature
	// InjectionEvidenceBooleanDifferential means true and false conditions produced
	// materially different responses in the expected direction.
	InjectionEvidenceBooleanDifferential
	// InjectionEvidenceEvaluated means the payload was evaluated, not echoed — an
	// arithmetic product or an echoed marker appeared.
	InjectionEvidenceEvaluated
	// InjectionEvidenceTiming means a controllable delay was observed.
	InjectionEvidenceTiming
	// InjectionEvidenceOutOfBand means the target contacted a collaborator host.
	InjectionEvidenceOutOfBand
)

func (e InjectionEvidence) String() string {
	switch e {
	case InjectionEvidenceNone:
		return "no evidence"
	case InjectionEvidenceInconclusive:
		return "inconclusive"
	case InjectionEvidenceErrorSignature:
		return "error signature absent from baseline"
	case InjectionEvidenceBooleanDifferential:
		return "boolean differential"
	case InjectionEvidenceEvaluated:
		return "payload evaluated, not echoed"
	case InjectionEvidenceTiming:
		return "controllable time delay"
	case InjectionEvidenceOutOfBand:
		return "out-of-band interaction"
	}
	return "unknown"
}

// Confirms reports whether this evidence supports a finding. Inconclusive does not, and
// neither does None — but they are different reports and callers must not merge them.
func (e InjectionEvidence) Confirms() bool {
	switch e {
	case InjectionEvidenceErrorSignature, InjectionEvidenceBooleanDifferential,
		InjectionEvidenceEvaluated, InjectionEvidenceTiming, InjectionEvidenceOutOfBand:
		return true
	}
	return false
}

// ErrorEvidence is the classification plus the signatures that justified it.
type ErrorEvidence struct {
	Evidence InjectionEvidence
	// Matched are signatures present in the injected response and absent from the
	// baseline.
	Matched []string
	// Preexisting are signatures the baseline already carried. They are reported rather
	// than discarded: an endpoint that always emits a SQL error is worth knowing about,
	// and it is why the verdict is inconclusive instead of positive.
	Preexisting []string
}

// ClassifyErrorEvidence looks for signatures the injected response introduced.
//
// A signature already in the baseline is recorded in Preexisting and never counted. If
// every match was pre-existing the verdict is Inconclusive: the endpoint errors regardless,
// so this probe learned nothing about it.
//
// # Matching survives HTML entity encoding
//
// Signatures are looked for in the body as sent AND in its HTML-unescaped form. An application
// that echoes file contents or a database error into a page escapes them on the way out, so
// `root:x:0:0:` arrives as `root&#x3a;x&#x3a;0&#x3a;0&#x3a;` and a raw substring search finds
// nothing. The vulnerability is identical; only the presentation differs. Matching one form only
// meant the applications that encode their output correctly were the ones this scanner failed to
// find traversal and SQL errors in — a false negative that scales with the target's quality.
// ZAP does the same thing (StringEscapeUtils.unescapeHtml4 before matching) and has a regression
// test for it; this is that behaviour.
func ClassifyErrorEvidence(baselineBody, injectedBody string, signatures []string) ErrorEvidence {
	baseForms := matchableForms(baselineBody)
	injForms := matchableForms(injectedBody)

	var res ErrorEvidence
	for _, sig := range signatures {
		needle := strings.ToLower(sig)
		inInjected := containsAny(injForms, needle)
		inBaseline := containsAny(baseForms, needle)
		switch {
		case inInjected && inBaseline:
			res.Preexisting = append(res.Preexisting, sig)
		case inInjected:
			res.Matched = append(res.Matched, sig)
		}
	}
	switch {
	case len(res.Matched) > 0:
		res.Evidence = InjectionEvidenceErrorSignature
	case len(res.Preexisting) > 0:
		res.Evidence = InjectionEvidenceInconclusive
	default:
		res.Evidence = InjectionEvidenceNone
	}
	return res
}

// matchableForms returns the lowercased forms of a body a signature may appear in: the bytes as
// received, and the same bytes with HTML entities resolved. The unescaped form is only added when
// it differs, so the common case costs one comparison.
func matchableForms(body string) []string {
	lower := strings.ToLower(body)
	unescaped := strings.ToLower(html.UnescapeString(body))
	if unescaped == lower {
		return []string{lower}
	}
	return []string{lower, unescaped}
}

func containsAny(forms []string, needle string) bool {
	for _, f := range forms {
		if strings.Contains(f, needle) {
			return true
		}
	}
	return false
}

// ClassifySQLError and ClassifyXPathError bind the recovered banks to the comparison.
func ClassifySQLError(baselineBody, injectedBody string) ErrorEvidence {
	return ClassifyErrorEvidence(baselineBody, injectedBody, SQLErrorSignatures)
}

func ClassifyXPathError(baselineBody, injectedBody string) ErrorEvidence {
	return ClassifyErrorEvidence(baselineBody, injectedBody, XPathErrorSignatures)
}

// ClassifyEvaluation reports whether a marker the payload was supposed to *produce* appears
// in the response without having been in the baseline.
//
// The marker must also be absent from the payload's own echo to be meaningful, which is why
// callers pass the rendered payload: a response that merely reflects the payload text
// contains the marker without having evaluated anything.
//
// # Why the echo test is not a verbatim search
//
// It used to be `strings.Contains(injectedBody, renderedPayload)`, which only recognised an
// echo that came back byte-identical. Applications that reflect input *correctly* do not: they
// HTML-escape it. A runtime scan of a target that reflects `&echo bsy…&` as
// `&amp;echo bsy…&amp;` therefore found the marker, failed to attribute it to the echo, and
// reported OS command injection at `certain` confidence against an endpoint that ran nothing.
// The better an application's output encoding, the more confidently it was libelled.
//
// So the echo is subtracted in every form it plausibly arrives in — raw, HTML-escaped,
// percent-encoded — and only a marker that survives that subtraction counts as evaluated.
// Over-subtracting is the safe direction here: it can only turn a finding into
// Inconclusive, never invent one.
func ClassifyEvaluation(baselineBody, injectedBody, renderedPayload, expected string) InjectionEvidence {
	if expected == "" {
		return InjectionEvidenceInconclusive
	}
	if strings.Contains(baselineBody, expected) {
		return InjectionEvidenceInconclusive
	}
	if !strings.Contains(injectedBody, expected) {
		return InjectionEvidenceNone
	}
	// The response contains the expected value. If the payload carried it, the marker only counts
	// once the echo of that payload has been removed — in whatever encoding it came back in.
	if strings.Contains(renderedPayload, expected) {
		for _, form := range echoComparableForms(injectedBody) {
			if !strings.Contains(strings.ReplaceAll(form, renderedPayload, ""), expected) {
				return InjectionEvidenceInconclusive
			}
		}
	}
	return InjectionEvidenceEvaluated
}

// echoComparableForms returns the forms of a response body in which a reflected payload can be
// recognised and subtracted.
//
// Decoding beats enumerating. The first version of this listed the encodings a payload might come
// back in — HTML-escaped, percent-encoded — and compared against each. That fails on the first
// escaping style not on the list, and there are many: net/http's own redirect body writes `"` as
// `&#34;` where the list had `&quot;`, so an OS-command payload reflected by http.Redirect was not
// recognised as an echo and the endpoint was reported as executing commands.
//
// Unescaping the body instead handles every entity form at once, named or numeric, because it asks
// the decoder rather than guessing the encoder. The raw body is kept alongside the decoded one so a
// payload that genuinely arrived verbatim is still matched, and percent-decoding is applied because
// a value round-tripped through a URL comes back that way.
func echoComparableForms(body string) []string {
	forms := []string{body}
	if unescaped := html.UnescapeString(body); unescaped != body {
		forms = append(forms, unescaped)
	}
	if decoded, err := url.QueryUnescape(body); err == nil && decoded != body {
		forms = append(forms, decoded)
	}
	return forms
}

// ClassifyArithmeticProof is the code-injection confirmation from burp.Zxvv: the product
// must appear, and must not be attributable to the baseline or to an echo of the payload.
func ClassifyArithmeticProof(baselineBody, injectedBody, renderedPayload string) InjectionEvidence {
	return ClassifyEvaluation(baselineBody, injectedBody, renderedPayload, ArithmeticProofProduct())
}

// ClassifyMarkerEcho is the OS command confirmation from burp.Zx8l: the shell echoed the
// marker, so it appears in the response but not inside a reflection of the payload.
func ClassifyMarkerEcho(baselineBody, injectedBody, renderedPayload, marker string) InjectionEvidence {
	return ClassifyEvaluation(baselineBody, injectedBody, renderedPayload, marker)
}

// ResponseFingerprint is the coarse shape used for differential comparison. No Go library
// offers response-similarity clustering, so this is deliberately simple and its limits are
// stated: status plus body length plus a normalised body hash catches the substitutions
// that boolean injection produces, and will not catch a change confined to a timestamp.
type ResponseFingerprint struct {
	Status  int
	BodyLen int
	Body    string
}

// NewResponseFingerprint normalises whitespace so incidental formatting differences do not
// register as a behavioural change.
func NewResponseFingerprint(status int, body string) ResponseFingerprint {
	return ResponseFingerprint{
		Status:  status,
		BodyLen: len(body),
		Body:    strings.Join(strings.Fields(body), " "),
	}
}

// SameShape reports whether two responses are materially the same.
func (f ResponseFingerprint) SameShape(other ResponseFingerprint) bool {
	return f.Status == other.Status && f.Body == other.Body
}

// ClassifyBooleanDifferential is the LDAP / SQL boolean technique.
//
// The condition is directional and both halves matter: the always-true payload must leave
// the response as the baseline had it, and the always-false payload must change it. Either
// one alone is ambiguous — if both differ from baseline the parameter is merely being
// validated, and if neither differs the injection did not take.
func ClassifyBooleanDifferential(baseline, whenTrue, whenFalse ResponseFingerprint) InjectionEvidence {
	trueMatchesBase := baseline.SameShape(whenTrue)
	falseMatchesBase := baseline.SameShape(whenFalse)

	switch {
	case trueMatchesBase && !falseMatchesBase:
		return InjectionEvidenceBooleanDifferential
	case !trueMatchesBase && !falseMatchesBase:
		// Both changed: the payloads were rejected or sanitised, not interpreted.
		return InjectionEvidenceInconclusive
	default:
		return InjectionEvidenceNone
	}
}

// TimingMargin is the fraction of the requested delay that must actually be observed.
// Networks add jitter in both directions, so demanding the full delay produces false
// negatives and accepting a fraction of it produces false positives; 0.6 is a documented
// choice, not a recovered Burp constant.
const TimingMargin = 0.6

// TimingBaselineNoiseCeiling bounds how much of the requested delay ordinary variance may
// account for. If the baseline itself takes longer than this share of the delay, the probe
// cannot distinguish injection from a slow endpoint.
const TimingBaselineNoiseCeiling = 0.5

// ClassifyTimingEvidence reports a controllable delay.
//
// It is deliberately conservative in two directions. A baseline already slow relative to
// the requested delay yields Inconclusive rather than a finding, because the delay is not
// distinguishable from the endpoint's own latency. And the observed increase is measured
// against the baseline, not against zero, so a uniformly slow endpoint does not read as
// injectable.
func ClassifyTimingEvidence(baseline, injected, requestedDelay time.Duration) InjectionEvidence {
	if requestedDelay <= 0 {
		return InjectionEvidenceInconclusive
	}
	if baseline >= time.Duration(float64(requestedDelay)*TimingBaselineNoiseCeiling) {
		return InjectionEvidenceInconclusive
	}
	increase := injected - baseline
	if increase >= time.Duration(float64(requestedDelay)*TimingMargin) {
		return InjectionEvidenceTiming
	}
	return InjectionEvidenceNone
}

// ClassifyTraversalRead reports whether a traversal payload actually read a file, using the
// recovered content signatures rather than the absence of an error.
func ClassifyTraversalRead(baselineBody, injectedBody string) ErrorEvidence {
	return ClassifyErrorEvidence(baselineBody, injectedBody, TraversalFileSignatures)
}

// InjectionProbe is one payload and what its response showed, so a caller can report which
// of several attempts carried the finding.
type InjectionProbe struct {
	Payload  string
	Context  QuotingContext
	Evidence InjectionEvidence
	Detail   string
	// Withheld marks a probe the harness did NOT send because its detection method is disabled for
	// this issue type (burpsy-react-ui-2hze). Its Evidence is None, and it must never be read as a
	// clean answer: nothing was asked, so nothing was answered.
	Withheld bool
	// Tentative marks evidence that proves less than its Evidence kind usually does - the SQL
	// statement echo proves concatenation, not a changed query - so the finding is rated
	// tentative whatever the kind's default confidence (burpsy-react-ui-j1mk.36).
	Tentative bool
}

// BestEvidence returns the strongest probe in a set, and whether anything confirmed.
//
// Inconclusive outranks None so a set where nothing confirmed but something was
// unmeasurable does not report as clean.
func BestEvidence(probes []InjectionProbe) (InjectionProbe, bool) {
	rank := map[InjectionEvidence]int{
		InjectionEvidenceNone:                0,
		InjectionEvidenceInconclusive:        1,
		InjectionEvidenceErrorSignature:      2,
		InjectionEvidenceBooleanDifferential: 3,
		InjectionEvidenceTiming:              4,
		InjectionEvidenceEvaluated:           5,
		InjectionEvidenceOutOfBand:           6,
	}
	var best InjectionProbe
	found := false
	for _, p := range probes {
		if !found || rank[p.Evidence] > rank[best.Evidence] {
			best, found = p, true
		}
	}
	return best, found && best.Evidence.Confirms()
}
