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
