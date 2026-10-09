package scanner

// Burp's decoding-reflection variants (burpsy-react-ui-79ld): the five encoded forms a
// breakout payload is sent in when the plain one failed, so an XSS that only fires after the
// application decodes its input is detectable at all.
//
// # What is recovered and what is burpsy's own
//
// Burp's shape is CONFIRMED from the decompiled build 51467:
//
//   - Zwe8.java:11-34 — the 24 reflection-type constants: REPLACE/APPEND ×
//     {plain, OVERLONG_UTF8_DECODING, INVALID_UTF8_DECODING, URL_DECODING,
//     BACKSLASH_UNESCAPING, HTML_DECODING} × {normal, UNEXPECTED_TRANSFORMATION}. The
//     UNEXPECTED_TRANSFORMATION half of each pair is the "the application transformed my
//     input" report; the normal half is the breakout.
//   - Zp9v.java — the abstract driver: one probe per insertion point, reported first under
//     the normal types and then under the unexpected-transformation types.
//   - Zp9c/Zp9y.java — the recovered marker BYTES: {0xC1, 0x81} for overlong (the two-byte
//     overlong encoding of 'A') and {0xC1, 0x01} for invalid. The overlong encoder below
//     reproduces the first of those from its formula, which is the cross-check that the
//     formula is Burp's and not an invention.
//   - Zguu.java:63-77 (findXssIssues) — the ordering: plain APPEND, then plain REPLACE, and
//     only when neither confirmed, the variant list, breaking on the first confirmation.
//
// What is NOT recovered: the payload literals of the URL, HTML and backslash drivers
// (Zp9q/Zp9g/Zp9d's prefix bytes live in ZKM-stripped static fields). The encoders below are
// therefore burpsy's own, documented as such, and the vulnapp endpoints that exercise them
// recognise the SHAPE of a decoding rather than any literal payload — the same convention the
// rest of this package's fixtures hold.
//
// # The wire forms, and why the URL variant is double-escaped
//
// Each encoder produces the bytes the APPLICATION must receive, and the probes are sent
// through ApplyOptions.Raw so percentEscape does not rewrite them in transit. One container
// decode happens anyway: a `k=v` query parameter is decoded once by the target's own parsing
// before the application sees it, so the URL-decoding variant's wire form is escaped TWICE —
// the application this variant targets decodes again (the double-decode bug class), and a
// single escape would arrive already decoded and behave exactly like the plain payload. On a
// container that does not decode (a cookie, a header), the URL variant carries one escape too
// many and cannot fire — a scope limit, not a false positive, and the finding is never raised
// on evidence that was not gathered.
//
// The UTF-8 variants encode only the bytes a breakout needs intact — the tag brackets and the
// spaces — so the payload survives an application that strips or escapes the LITERAL forms.
// The two spell deliberately different decoder populations:
//
//   - overlong: two-byte sequences with valid continuation bits (0xC0 0xBC for '<'), decoded
//     by the lenient decoders that never rejected overlong forms — old MySQL utf8, lenient
//     iconv, the decoders Burp's own marker byte pair assumes;
//   - invalid: three-byte sequences whose "continuation" bytes are NOT continuation bytes
//     (0xE0 0x40 0x7C for '<'), decoded only by decoders that mask the low six bits without
//     validating — the loosest population there is. The literal '<' byte never appears, so
//     an angle-bracket filter in front of the decoder cannot see it.
//
// The backslash variant spells the same bytes as `\x3c` hex escapes — the form string
// unescapers (template engines, eval paths, Go's own strconv family) understand; a
// backslash-REMOVING unescaper cannot produce a '<' from nothing, so the hex form is the only
// backslash spelling that can carry markup through one.
//
// # The two findings a variant can produce
//
// A variant probe that comes back as live markup confirms reflected XSS, and the finding's
// evidence names the decoding that carried it ("markup breakout via URL decoding"). A probe
// that comes back showing the payload in its DECODED spelling — but neutralized, no live
// markup — is the UNEXPECTED_TRANSFORMATION half of Burp's pair: the application decoded the
// input, which is worth reporting on its own row, "Suspicious input transformation
// (reflected)", rather than folding into the XSS row it did not earn.

import (
	"fmt"
	"strings"
)

// xssDecodingVariant is one encoded form of a breakout payload.
type xssDecodingVariant struct {
	// name is the decoding in Burp's vocabulary: "URL decoding", "HTML decoding", "backslash
	// unescaping", "overlong UTF-8 decoding", "invalid UTF-8 decoding". Evidence text names it.
	name string
	// encode renders the plain breakout into the bytes the application must receive.
	encode func(payload string) string
	// transformMarker returns the substring of the PLAIN payload whose presence in a
	// response proves the application performed this decoding even when the breakout did
	// not confirm — the byte-level "what I sent came back different" signal Burp's own
	// driver reads off the byte between two canaries (Zh_1). Nil for the variants whose
	// decoded-then-escaped form is byte-identical to their encoded form, where no byte can
	// prove anything.
	transformMarker func(payload, canary string) string
}

// xssDecodingVariants are the five forms, in Burp's Zwe8 declaration order.
func xssDecodingVariants() []xssDecodingVariant {
	return []xssDecodingVariant{
		{name: "URL decoding", encode: urlDecodingEncode,
			transformMarker: markerBeforeCanary(func(c byte) bool { return !isQueryLiteral(c) })},
		{name: "HTML decoding", encode: htmlDecodingEncode, transformMarker: nil},
		{name: "backslash unescaping", encode: backslashUnescapingEncode,
			transformMarker: markerBeforeCanary(backslashEscapes)},
		{name: "overlong UTF-8 decoding", encode: overlongUTF8Encode, transformMarker: nil},
		{name: "invalid UTF-8 decoding", encode: invalidUTF8Encode, transformMarker: nil},
	}
}

// urlDecodingEncode percent-encodes every byte that is not a query-safe literal, then escapes
// the percent signs once more — the double-escaped wire form a query container decodes down
// to the single-escaped form the application is meant to decode. See the file header for why
// one escape fewer would make the variant behave exactly like the plain payload.
func urlDecodingEncode(payload string) string {
	var sb strings.Builder
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		if isQueryLiteral(c) {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "%%%02X", c)
		}
	}
	return strings.ReplaceAll(sb.String(), "%", "%25")
}

// isQueryLiteral reports whether a byte may appear in a query value without escaping. Only the
// unreserved set, so the encoded form is unambiguous about what it carries.
func isQueryLiteral(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// htmlDecodingEncode spells the HTML-significant bytes as the entities a decoder turns back
// into markup. The transport escape ApplyOpts performs under Raw (`&` → `%26`, for a `k=v`
// container) composes with the container's own decode, so the application receives the entity
// spelling exactly as written here.
func htmlDecodingEncode(payload string) string {
	var sb strings.Builder
	for i := 0; i < len(payload); i++ {
		switch payload[i] {
		case '<':
			sb.WriteString("&lt;")
		case '>':
			sb.WriteString("&gt;")
		case '&':
			sb.WriteString("&amp;")
		case '"':
			sb.WriteString("&quot;")
		case '\'':
			sb.WriteString("&#39;")
		default:
			sb.WriteByte(payload[i])
		}
	}
	return sb.String()
}

// backslashUnescapingEncode spells the markup-carrying bytes as `\xHH` hex escapes — the form
// a string unescaper understands. A payload whose specials were spelled `\<` would arrive
// with the special still literal and be stopped by whatever stopped the plain payload, and a
// backslash-REMOVING unescaper cannot produce a '<' at all, so the hex form is the spelling
// that can actually carry markup.
func backslashUnescapingEncode(payload string) string {
	var sb strings.Builder
	for i := 0; i < len(payload); i++ {
		switch payload[i] {
		case '<', '>', '"', '\'', '\\', '&', '=':
			fmt.Fprintf(&sb, "\\x%02x", payload[i])
		default:
			sb.WriteByte(payload[i])
		}
	}
	return sb.String()
}

// overlongUTF8Encode renders each markup-carrying byte as its two-byte overlong form:
// lead 0xC0|(c>>6), continuation 0x80|(c&0x3F). Burp's own recovered marker {0xC1, 0x81} is
// this formula over 'A' (65 = 0b1000001: 0xC0|1 = 0xC1, 0x80|1 = 0x81), which is the
// cross-check that the spelling is Burp's decoder population and not an invention.
func overlongUTF8Encode(payload string) string {
	var sb strings.Builder
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		if c >= 0x80 || c == '<' || c == '>' || c == ' ' {
			sb.WriteByte(0xC0 | (c >> 6))
			sb.WriteByte(0x80 | (c & 0x3F))
			continue
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

// invalidUTF8Encode renders each markup-carrying byte as a three-byte sequence whose
// "continuation" bytes are not continuation bytes: 0xE0 0x40|((c>>6)&0x3F) 0x40|(c&0x3F). A
// decoder that validates rejects the sequence outright; a decoder that masks the low six bits
// without validating reconstructs the byte. The literal target byte never appears on the wire,
// which is the point: this variant reaches past a filter that strips the literal form.
func invalidUTF8Encode(payload string) string {
	var sb strings.Builder
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		if c >= 0x80 || c == '<' || c == '>' || c == ' ' {
			sb.WriteByte(0xE0)
			sb.WriteByte(0x40 | ((c >> 6) & 0x3F))
			sb.WriteByte(0x40 | (c & 0x3F))
			continue
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

// markerBeforeCanary builds the transformMarker for a variant that alters the payload byte
// immediately before the canary: the plain spelling of that byte plus the canary can only be
// in a response if the application undid the variant's encoding, because the wire form
// carries that byte in its encoded spelling. A payload whose pre-canary byte the encoder
// passes through has no marker — an unaltered byte proves nothing — and "" is returned.
func markerBeforeCanary(altered func(byte) bool) func(payload, canary string) string {
	return func(payload, canary string) string {
		i := strings.Index(payload, canary)
		if i <= 0 || !altered(payload[i-1]) {
			return ""
		}
		return payload[i-1 : i+len(canary)]
	}
}

// backslashEscapes reports whether the backslash variant encodes this byte.
func backslashEscapes(c byte) bool {
	switch c {
	case '<', '>', '"', '\'', '\\', '&', '=':
		return true
	}
	return false
}
