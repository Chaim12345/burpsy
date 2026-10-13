package scanner

// File path manipulation by path equivalence (burpsy-react-ui-0vzb.33).
//
// # The gap this closes
//
// The row's only technique was file content: an absolute path (/etc/passwd, c:\windows\win.ini)
// whose signature came back in the response. That proves a read of a file the attacker chose, and it
// is silent on an application that refuses `..` and absolute paths but still hands the value to the
// filesystem as a path inside its own directory. Such a parameter serves ANY file in that directory,
// including ones never meant to be exposed (a credentials file next to the two documents the page
// links to), and the absence of an allowlist is the defect. Burp's definition of the row covers it:
// user-controllable data placed into a file path used to access local resources, "within or outside
// the web root".
//
// # The evidence
//
// The parameter's original value V must look like a file name and have served something, and three
// answers are compared with the baseline, with the value as sent masked out of each body so an echo
// cannot decide anything:
//
//   - "./V": the SAME answer. A filesystem path treats a leading dot segment as the current
//     directory, so this names the same file. Sent first, it is also the stability check: a page that
//     changes on every request (a timestamp, a token) fails it, so the two controls below can never
//     "differ" merely because the page did.
//   - "<random>/V": a DIFFERENT answer. Under a directory that does not exist the file cannot be
//     opened. This control rejects an application that keeps only the last path component (a
//     basename lookup, which is the safe pattern) and one that ignores the value.
//   - ".V": a DIFFERENT answer. A different file name to a filesystem, but the same words to a
//     tokenising search or a lookup that trims punctuation, so it rejects the application that
//     treats "./V" like V because it discards the punctuation, not because it resolved a path.
//
// Only the combination says "this value is resolved with filesystem path semantics": a lookup
// table, a search index, a basename flattener and an allowlist each fail at least one of the three.
// The finding is rated tentative: it proves a raw file path with no allowlist, NOT that it escapes
// the directory (that is the file-content technique's claim, and the traversal row's), and an
// application that confines the path to one directory on purpose answers the same way.
//
// # Safety
//
// Every probe names V itself or a file that does not exist. Nothing is written and no file outside
// what the application already served for V is requested.

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// fileLikeValue is a value that names a file: path segments of ordinary name characters ending
// in an extension. A value without an extension (an id, a word, a sort key) is not probed, which keeps
// the technique off parameters it could only produce noise on.
var fileLikeValue = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*\.[A-Za-z0-9]{1,8}$`)

// pathEquivalenceCandidate reports whether a point's value is worth the three probes.
func pathEquivalenceCandidate(v string) bool {
	return len(v) <= 128 && !strings.Contains(v, "..") && fileLikeValue.MatchString(v)
}

// pathEquivalenceAnswer is one probe's answer with the value it was sent masked out of the body.
type pathEquivalenceAnswer struct {
	status int
	body   string
}

// maskSent removes every rendering of the sent value from a body: as sent, with JSON's and HTML's
// escaped slashes undone first, and the bare original value (an application may echo the name it
// resolved rather than the one it was given).
func maskSent(body, sent, original string) string {
	body = unescapeLocationText(body)
	for _, s := range []string{sent, original} {
		if s != "" {
			body = strings.ReplaceAll(body, s, "\x01")
		}
	}
	return body
}

func pathEquivalenceSame(a, b pathEquivalenceAnswer) bool {
	return a.status == b.status && a.body == b.body
}

// ProbePathEquivalence runs the three-answer comparison at one point. It returns a confirming probe
// (InjectionEvidenceBooleanDifferential, rated tentative) only when all three answers line up, and a
// None probe otherwise; a send that failed is Inconclusive, never clean.
func (h *ProbeHarness) ProbePathEquivalence(ctx context.Context, point bcheck.InsertionPoint) InjectionProbe {
	v := point.BaseValue
	out := InjectionProbe{Payload: "./" + v, Evidence: InjectionEvidenceNone, Tentative: true}
	if !pathEquivalenceCandidate(v) {
		return out
	}
	base := pathEquivalenceAnswer{status: h.baseline.Status, body: maskSent(h.baseline.Body, v, v)}
	if base.status < 200 || base.status >= 300 || strings.TrimSpace(base.body) == "" {
		// Nothing was served for V, so there is no file whose other spellings could be compared, and
		// nothing is sent.
		return out
	}
	missingDir := "bfm" + strings.ToLower(randomLetters(8))
	sent := []string{"./" + v, missingDir + "/" + v, "." + v}
	answers := make([]pathEquivalenceAnswer, len(sent))
	for i, payload := range sent {
		resp, err := h.Send(ctx, point, payload)
		if err != nil {
			out.Evidence = InjectionEvidenceInconclusive
			out.Detail = fmt.Sprintf("%s %q: path-equivalence probe %q not sent: %v", point.Kind, point.Name, payload, err)
			return out
		}
		answers[i] = pathEquivalenceAnswer{status: resp.Status, body: maskSent(resp.Body, payload, v)}
	}
	dotSlash, underMissing, dotPrefixed := answers[0], answers[1], answers[2]
	switch {
	case !pathEquivalenceSame(base, dotSlash):
		// Not the same file, or not a stable page: either way nothing below can be attributed to V.
		return out
	case pathEquivalenceSame(base, underMissing):
		return out
	case pathEquivalenceSame(base, dotPrefixed):
		return out
	}
	out.Evidence = InjectionEvidenceBooleanDifferential
	out.Detail = fmt.Sprintf("%s %q: %q and %q return the same answer (HTTP %d, %d bytes), while %q (a directory "+
		"that does not exist) and %q (a different file name with the same words) do not; the value is resolved "+
		"as a filesystem path with no allowlist. It is NOT shown to leave the directory",
		point.Kind, point.Name, v, "./"+v, base.status, len(h.baseline.Body), sent[1], sent[2])
	return out
}
