package http2

import (
	"bytes"
	"fmt"
	"strings"
)

// Kettled requests (burpsy-react-ui-jae5): an HTTP/2 request whose header list cannot be written as
// HTTP/1 text without losing information.
//
// # What Burp calls kettled
//
// Burp's HTTP/2 documentation ("Kettled requests", desktop/http2/index.html) names the edits that kettle
// a request, all of them made in the Inspector, where an HTTP/2 request is an ordered list of name and
// value fields rather than lines of text:
//
//   - an uppercase letter or a colon in a header name;
//   - a newline character in a header name or value;
//   - a :scheme value other than the connection's own;
//   - a space in :path or :method;
//   - a duplicate pseudo-header;
//   - a semicolon and space ("; ") in a cookie value.
//
// Each is a field list HTTP/1 text cannot carry. A line break in a value ends the line, so what follows
// reads as the next header. HTTP/1 has no field for :scheme, so a changed scheme has nowhere to go. A
// space in the method or path splits the request line differently. A second :path has no second request
// line to sit in. An HTTP/1 rendering lowercases nothing and has no pseudo-header syntax, so an
// uppercase or colon-bearing name is either rewritten or misread.
//
// # The cookie rule, read at the field level
//
// Burp states its cookie trigger against the Inspector's cookie list, which burpsy's kettled Inspector
// does not have. At the field level the same loss happens in one place: RFC 9113 §8.2.3 lets a client
// split a cookie into several `cookie` fields ("crumbs"), and requires them to be joined with "; " when
// the request is passed on as HTTP/1. A crumb that itself contains "; " then cannot be told apart from
// a crumb boundary. So the rule here is: more than one `cookie` field, and at least one of them
// contains "; ". A single `cookie` field containing "; " is not kettled — one Cookie line carries it
// exactly. That reading is recorded in gaps.md.
//
// # One reason burpsy adds
//
// A pseudo-header placed after a regular header. HTTP/1 text puts the method and path in the request
// line and the authority in Host, so it cannot say where among the headers a pseudo-header sat — and
// a peer is required to reject a request with that layout (RFC 9113 §8.3), so whether it does is
// exactly what an operator who built one is testing. Burp's list does not name it; gaps.md records it
// as a burpsy addition.
//
// # Kettled is not refused
//
// This file says what HTTP/1 text cannot show. Whether the request can be *sent* is authorise.go's
// question, and the two are deliberately separate: a CR/LF inside a regular header's value is kettled
// and perfectly sendable, while a space in :path is kettled and refused, because the scope gate reads a
// request line and a path with a space in it would be authorised up to the space and sent whole. The
// send refusals for a kettled list come from Authorise, never from here.

// KettleKind names one construct that makes a header list unrepresentable as HTTP/1 text.
type KettleKind int

const (
	// KettleUppercaseName is an uppercase letter in a field name. HTTP/2 names are lowercase on the
	// wire (RFC 9113 §8.2.1), and HTTP/1 text would show the casing without saying it was sent.
	KettleUppercaseName KettleKind = iota
	// KettleColonInName is a colon in a regular field's name, or a pseudo-header name that is not one of
	// the four request pseudo-headers. HTTP/1 ends a field name at its first colon.
	KettleColonInName
	// KettleNewlineInName is a CR or LF in a field name.
	KettleNewlineInName
	// KettleNewlineInValue is a CR or LF in a field value.
	KettleNewlineInValue
	// KettleSchemeModified is a :scheme other than the one the connection uses.
	KettleSchemeModified
	// KettleSpaceInPseudoHeader is a space in :method or :path.
	KettleSpaceInPseudoHeader
	// KettleDuplicatePseudoHeader is a second :method, :scheme, :authority or :path.
	KettleDuplicatePseudoHeader
	// KettleCookieCrumbSeparator is "; " inside one of several cookie fields.
	KettleCookieCrumbSeparator
	// KettlePseudoHeaderAfterRegular is a pseudo-header after a regular field — burpsy's addition.
	KettlePseudoHeaderAfterRegular
)

// KettleKindAll is every kind, in the order KettleReasons checks a field for them.
var KettleKindAll = [9]KettleKind{
	KettleUppercaseName,
	KettleColonInName,
	KettleNewlineInName,
	KettleNewlineInValue,
	KettleSchemeModified,
	KettleSpaceInPseudoHeader,
	KettleDuplicatePseudoHeader,
	KettleCookieCrumbSeparator,
	KettlePseudoHeaderAfterRegular,
}

// Slug is the kind's stable wire name, for a UI that branches on it.
func (k KettleKind) Slug() string {
	switch k {
	case KettleUppercaseName:
		return "uppercase-name"
	case KettleColonInName:
		return "colon-in-name"
	case KettleNewlineInName:
		return "newline-in-name"
	case KettleNewlineInValue:
		return "newline-in-value"
	case KettleSchemeModified:
		return "scheme-modified"
	case KettleSpaceInPseudoHeader:
		return "space-in-pseudo-header"
	case KettleDuplicatePseudoHeader:
		return "duplicate-pseudo-header"
	case KettleCookieCrumbSeparator:
		return "cookie-crumb-separator"
	case KettlePseudoHeaderAfterRegular:
		return "pseudo-header-after-regular"
	}
	return "unrecognised"
}

// KettleReason is one field that kettles the request, and why.
type KettleReason struct {
	Kind KettleKind
	// Index is the field's position in the list, so a UI can point at the row.
	Index int
	// Name is the field's name as written.
	Name string
	// Text is the sentence an operator reads under "This request is kettled because:".
	Text string
}

// requestPseudoHeaders are the four pseudo-headers an HTTP/2 request may carry (RFC 9113 §8.3.1).
var requestPseudoHeaders = map[string]bool{":method": true, ":scheme": true, ":authority": true, ":path": true}

// KettleReasons lists every construct in fields that HTTP/1 text cannot carry, in field order. tls is
// the connection's scheme, which is what a :scheme value is compared against. The result is never nil,
// so a caller marshalling it sends [] rather than null for a request that is not kettled.
func KettleReasons(fields []HeaderField, tls bool) []KettleReason {
	out := []KettleReason{}
	wantScheme := "http"
	if tls {
		wantScheme = "https"
	}
	seenPseudo := map[string]bool{}
	firstRegular := -1
	cookies := 0
	for _, f := range fields {
		if bytes.EqualFold(f.Name, []byte("cookie")) {
			cookies++
		}
	}
	for i, f := range fields {
		name := string(f.Name)
		value := string(f.Value)
		shown := quoteField(name)
		add := func(kind KettleKind, text string) {
			out = append(out, KettleReason{Kind: kind, Index: i, Name: name, Text: text})
		}
		pseudo := strings.HasPrefix(name, ":")
		if name != strings.ToLower(name) {
			add(KettleUppercaseName, fmt.Sprintf("the name %s has an uppercase letter; HTTP/2 sends names lowercase, and HTTP/1 text cannot show the casing that goes out", shown))
		}
		switch {
		case pseudo && !requestPseudoHeaders[strings.ToLower(name)]:
			add(KettleColonInName, fmt.Sprintf("%s is not a request pseudo-header, and HTTP/1 text ends a field name at its colon", shown))
		case !pseudo && strings.Contains(name, ":"):
			add(KettleColonInName, fmt.Sprintf("the name %s contains a colon, and HTTP/1 text ends a field name at its first colon", shown))
		}
		if strings.ContainsAny(name, "\r\n") {
			add(KettleNewlineInName, fmt.Sprintf("the name %s contains %s, which HTTP/1 text reads as the end of the line", shown, newlineWords(name)))
		}
		if strings.ContainsAny(value, "\r\n") {
			add(KettleNewlineInValue, fmt.Sprintf("the value of %s contains %s, so HTTP/1 text would read the rest as the start of another header", shown, newlineWords(value)))
		}
		if !pseudo {
			if firstRegular < 0 {
				firstRegular = i
			}
			if cookies > 1 && strings.EqualFold(name, "cookie") && strings.Contains(value, "; ") {
				add(KettleCookieCrumbSeparator, fmt.Sprintf("this request sends %d cookie fields and this one contains \"; \"; HTTP/1 joins cookie fields with \"; \" (RFC 9113 §8.2.3), so where this field ends could not be told apart", cookies))
			}
			continue
		}
		lower := strings.ToLower(name)
		if !requestPseudoHeaders[lower] {
			continue
		}
		if seenPseudo[lower] {
			add(KettleDuplicatePseudoHeader, fmt.Sprintf("%s appears more than once, and HTTP/1 has one request line to put it in", lower))
		}
		seenPseudo[lower] = true
		if firstRegular >= 0 {
			add(KettlePseudoHeaderAfterRegular, fmt.Sprintf("%s comes after the regular header %s; HTTP/1 text puts pseudo-headers in the request line, so it cannot show this order", lower, quoteField(string(fields[firstRegular].Name))))
		}
		switch lower {
		case ":scheme":
			if value != wantScheme {
				add(KettleSchemeModified, fmt.Sprintf(":scheme is %q on a connection that is %s, and HTTP/1 has no field to carry a different scheme", value, wantScheme))
			}
		case ":method", ":path":
			if strings.Contains(value, " ") {
				add(KettleSpaceInPseudoHeader, fmt.Sprintf("%s contains a space, which would split the HTTP/1 request line at a different place", lower))
			}
		}
	}
	return out
}

// quoteField renders a field name for a sentence, with CR and LF made visible.
func quoteField(name string) string {
	return fmt.Sprintf("%q", name)
}

// newlineWords names which line-break octets s contains.
func newlineWords(s string) string {
	cr, lf := strings.Contains(s, "\r"), strings.Contains(s, "\n")
	switch {
	case cr && lf:
		return "a carriage return and a line feed"
	case cr:
		return "a carriage return"
	default:
		return "a line feed"
	}
}

// EncodeLiteral writes a header block in which every field is a §6.2.2 literal without indexing, with a
// literal name and no Huffman coding.
//
// This is the encoding for a field list an operator wrote by hand. It references neither table, so:
//
//   - every octet of every name and value is on the wire exactly as given — an uppercase letter is not
//     folded onto a static-table name, and CR or LF is written as itself;
//   - nothing is inserted into the peer's dynamic table, so the block decodes the same way whatever the
//     peer's SETTINGS_HEADER_TABLE_SIZE turns out to be — the one caveat authorise.go states about
//     decoding a block offline does not arise.
//
// The cost is size, which for a Repeater request does not matter.
func EncodeLiteral(fields []HeaderField) []byte {
	out := []byte{}
	for _, f := range fields {
		out = append(out, 0x00)
		out = encodeHpackString(out, f.Name)
		out = encodeHpackString(out, f.Value)
	}
	return out
}
