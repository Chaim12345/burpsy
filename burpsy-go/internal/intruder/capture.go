package intruder

import (
	"fmt"
	"regexp"
)

// The capture filter (burpsy-react-ui-ip2b): Burp's "Capture filter - Choose which items Intruder captures
// during the attack to control resource usage" (results/filtering-results.html), as distinct from the view
// filter, which only hides rows. A discarded item is never captured: no results row, no stored request or
// response. What it does NOT do here is make the attack lie about what it sent — Sent, Failed, the error
// groups and every bucket's count still include discarded items, and the report counts them as Discarded.
//
// Ground truth, from the decompiled original. The filter is the AND of independent predicates
// (Zbjk.allMatch over Zcg9 instances), defaults all-capture (Ze3x):
//
//   - Zpoo, "Discard items without responses": with it on, an item is captured only when it has a response
//     of non-zero length.
//   - Zht8, "Capture by status code": four class toggles, 2xx/3xx/4xx/5xx. An item with no response passes
//     (the class filter has nothing to judge); a status outside 200-599 passes too — only the four named
//     classes can be switched off.
//   - Zs3t, "Capture by search term": the term searched in the response (and in the item's comment, which
//     burpsy items do not have at capture time), literal or regex, case-sensitive or not; an item with no
//     response does not contain the term. Negative search inverts the result. An empty term is no filter.
//   - Zefp, "Capture by annotation" (comments or highlights only): burpsy has no annotations at capture
//     time — a result row's comment is typed in the browser afterwards — so it is not offered (gaps.md).

// StatusClass is one of the four status-code classes the capture filter can switch off.
type StatusClass string

const (
	Status2xx StatusClass = "2xx"
	Status3xx StatusClass = "3xx"
	Status4xx StatusClass = "4xx"
	Status5xx StatusClass = "5xx"
)

// CaptureFilterSpec is the capture filter as configured — the run request's capture_filter, and what the
// report echoes back.
type CaptureFilterSpec struct {
	// DiscardNoResponse is "Discard items without responses".
	DiscardNoResponse bool `json:"discard_no_response"`
	// Term is "Capture by search term": only items whose response contains it are captured (or, with
	// Negate, only items whose response does not). Empty is no term filter.
	Term          string `json:"term"`
	Regex         bool   `json:"regex"`
	CaseSensitive bool   `json:"case_sensitive"`
	Negate        bool   `json:"negate"`
	// Statuses are the status classes captured. Nil captures every class — Burp's default, all four
	// boxes ticked. An empty list captures none of the four (a status outside them still passes).
	Statuses []StatusClass `json:"statuses"`
}

// CaptureFilter is a compiled CaptureFilterSpec.
type CaptureFilter struct {
	spec    CaptureFilterSpec
	term    *regexp.Regexp
	classes [4]bool // 2xx, 3xx, 4xx, 5xx captured
}

// NewCaptureFilter compiles spec, refusing an unknown status class or a term that does not compile — a
// filter that silently captures everything, or nothing, is not the filter the operator configured.
func NewCaptureFilter(spec CaptureFilterSpec) (*CaptureFilter, error) {
	f := &CaptureFilter{spec: spec, classes: [4]bool{true, true, true, true}}
	if spec.Statuses != nil {
		f.classes = [4]bool{}
		for _, s := range spec.Statuses {
			switch s {
			case Status2xx:
				f.classes[0] = true
			case Status3xx:
				f.classes[1] = true
			case Status4xx:
				f.classes[2] = true
			case Status5xx:
				f.classes[3] = true
			default:
				return nil, fmt.Errorf("capture_filter: unknown status class %q (want 2xx, 3xx, 4xx or 5xx)", s)
			}
		}
	}
	if spec.Term != "" {
		pattern := spec.Term
		if !spec.Regex {
			pattern = regexp.QuoteMeta(pattern)
		}
		if !spec.CaseSensitive {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("capture_filter: term %q does not compile: %w", spec.Term, err)
		}
		f.term = re
	}
	return f, nil
}

// Spec is the configuration the filter was compiled from.
func (f *CaptureFilter) Spec() CaptureFilterSpec { return f.spec }

// captures reports whether an item is captured. resp is the response bytes, nil when the item produced
// none (a send failure, a refusal); status is the response's status, nil when it has none.
func (f *CaptureFilter) captures(resp []byte, status *int) bool {
	if f == nil {
		return true
	}
	if f.spec.DiscardNoResponse && len(resp) == 0 {
		return false
	}
	if resp != nil && status != nil {
		class := *status/100 - 2
		if class >= 0 && class < 4 && !f.classes[class] {
			return false
		}
	}
	if f.term != nil {
		found := resp != nil && f.term.Match(resp)
		if found == f.spec.Negate {
			return false
		}
	}
	return true
}

// captureSpec is the report's echo of the filter, nil when there was none.
func captureSpec(f *CaptureFilter) *CaptureFilterSpec {
	if f == nil {
		return nil
	}
	s := f.spec
	return &s
}

// WithCapture attaches a capture filter. Nil captures everything.
func (a *Attack) WithCapture(f *CaptureFilter) *Attack {
	a.Capture = f
	return a
}
