package core

import (
	"bytes"
	"io"
	"strings"

	"golang.org/x/net/html"
)

// CookieNames returns the cookie names a response sets, in first-seen order without repeats.
//
// Computed once at capture from bytes already in hand, for the same reason MimeEssence is:
// /api/history must never read response bodies to answer a column. A name is the token before
// the first '=' or ';' in each Set-Cookie value; a value with neither (a bare flag) contributes
// nothing, because there is no name to show. Empty is "set no cookies", indistinguishable from
// "no response" only if the caller ignores Response — same contract as Mime.
func CookieNames(raw []byte) []string {
	headEnd, _ := findHeaderEnd(raw)
	head := raw[:headEnd]
	pos := 0
	if eol := findLineEnd(head, 0); eol >= 0 {
		pos = nextLineStart(head, eol)
	} else {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	want := []byte("set-cookie")
	for pos < len(head) {
		eol := findLineEnd(head, pos)
		if eol < 0 {
			eol = len(head)
		}
		line := head[pos:eol]
		if colon := bytes.IndexByte(line, ':'); colon >= 0 {
			name := bytes.TrimSpace(line[:colon])
			if len(name) == len(want) && bytes.EqualFold(name, want) {
				value := bytes.TrimSpace(line[colon+1:])
				if semi := bytes.IndexByte(value, ';'); semi >= 0 {
					value = value[:semi]
				}
				cookieName := string(bytes.TrimSpace(value))
				if eq := strings.IndexByte(cookieName, '='); eq >= 0 {
					cookieName = strings.TrimSpace(cookieName[:eq])
				} else {
					cookieName = ""
				}
				if cookieName != "" && !seen[cookieName] {
					seen[cookieName] = true
					out = append(out, cookieName)
				}
			}
		}
		pos = nextLineStart(head, eol)
	}
	return out
}

// titleScanBudget bounds how much of a body ResponseTitle will parse. A title lives in <head>,
// so anything past this never held one; parsing megabytes of body to render one column cell
// would make the capture path pay per byte for a display string.
const titleScanBudget = 32 << 10

// titleValueCap bounds the stored value. A 300-character title already overflows any column;
// storing kilobytes of <title> text per row would bloat the row for bytes nobody reads.
const titleValueCap = 300

// ResponseTitle returns the response's HTML <title> text, or "" when there is none.
//
// HTML only — anything else cannot have a title, and sniffing a body for "<title>" without
// checking the media type first would title a JSON string that happens to contain the word.
// Parsed with x/net/html over the first titleScanBudget bytes rather than regexed: a regex
// cannot tell <title> from "<!-- <title>" from a script string, and a wrong title in a
// column is worse than none.
func ResponseTitle(raw []byte) string {
	if MimeEssence(raw) != "text/html" {
		return ""
	}
	headEnd, _ := findHeaderEnd(raw)
	body := raw[headEnd:]
	if len(body) > titleScanBudget {
		body = body[:titleScanBudget]
	}
	doc, err := html.Parse(io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		return ""
	}
	// Iterative, not recursive: the input is attacker-controlled HTML and a nest thousands
	// deep would turn a recursive walk into a stack overflow on the capture path.
	title := ""
	stack := []*html.Node{doc}
	for len(stack) > 0 && title == "" {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "title") && n.FirstChild != nil {
			title = n.FirstChild.Data
			break
		}
		for c := n.LastChild; c != nil; c = c.PrevSibling {
			stack = append(stack, c)
		}
	}
	title = strings.TrimSpace(title)
	if len(title) > titleValueCap {
		title = title[:titleValueCap]
	}
	return title
}

// RequestFingerprint is a 64-bit FNV-1a over one request's raw bytes, computed once at
// capture (burpsy-react-ui-6n4d).
//
// # What it is for
//
// The audit ledger collapses identical work by (dispatch unit, check), and the URL-keyed
// scopes key by host/path alone — so a second capture of the same URL with a different body
// or different parameters was collapsed as "already covered" even though its semantics
// changed under the checks. The fingerprint rides the unit key: same content = same unit
// (still collapsed — cross-task dedup's whole point), changed content = a different unit
// (re-admitted and re-audited, counted as dispatched, never silently deduped).
//
// # Why FNV-1a over a cryptographic hash
//
// This is not an adversarial digest: the input is burpsy's own captured bytes, keyed only
// to tell two captures of one endpoint apart. FNV-1a is 64 bits, allocation-free over the
// request head+body in one pass, and stores as the exchange row's uint64. A collision would
// need two DIFFERENT requests of one URL colliding in the same session — ~2^32 requests by
// birthday, against a ledger that resets at 20k units; the failure mode is one missed
// re-audit, the same loss the feature replaces (every changed request was missed before).
//
// # Why the whole request, not just the body
//
// "Changed content" includes a changed Content-Type on an identical body, a changed header
// the checks read, a changed method on the same path. The request IS the content; splitting
// it would re-open the same silent dedup for everything outside the split.
func RequestFingerprint(raw []byte) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for _, b := range raw {
		h ^= uint64(b)
		h *= prime64
	}
	return h
}
