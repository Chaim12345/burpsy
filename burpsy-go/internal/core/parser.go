package core

import ()

// ParseError represents errors from parsing a raw message.
type ParseError struct {
	Code ParseErrorCode
}

type ParseErrorCode int

const (
	ParseNoHeaderTerminator ParseErrorCode = iota
	ParseEmptyStartLine
	ParseMalformedStartLine
)

func (e ParseError) Error() string {
	switch e.Code {
	case ParseNoHeaderTerminator:
		return "no CRLFCRLF/LFLF header terminator"
	case ParseEmptyStartLine:
		return "empty start line"
	case ParseMalformedStartLine:
		return "start line does not have 3 tokens"
	default:
		return "unknown parse error"
	}
}

// Parse parses a raw HTTP message into spans. Never allocates for the body.
// Tolerant by design: accepts both CRLF and bare LF.
func Parse(raw []byte, direction Direction) (MessageShape, error) {
	headEnd, bodyStart := findHeaderEnd(raw)
	if headEnd == -1 {
		return MessageShape{}, ParseError{Code: ParseNoHeaderTerminator}
	}

	lineEnd := findLineEnd(raw, 0)
	if lineEnd == -1 {
		lineEnd = headEnd
	}
	if lineEnd == 0 {
		return MessageShape{}, ParseError{Code: ParseEmptyStartLine}
	}

	first, second, third, ok := split3(raw, 0, lineEnd)
	if !ok {
		return MessageShape{}, ParseError{Code: ParseMalformedStartLine}
	}

	var headers []HeaderSpan
	pos := nextLineStart(raw, lineEnd)
	for pos < headEnd {
		eol := findLineEnd(raw, pos)
		if eol == -1 {
			eol = headEnd
		}
		if eol <= pos {
			break
		}

		colon := -1
		for i := pos; i < eol; i++ {
			if raw[i] == ':' {
				colon = i
				break
			}
		}

		if colon != -1 {
			name := Span{Offset: pos, Len: colon - pos}
			vs := colon + 1
			for vs < eol && (raw[vs] == ' ' || raw[vs] == '\t') {
				vs++
			}
			headers = append(headers, HeaderSpan{
				Name:  name,
				Value: Span{Offset: vs, Len: eol - vs},
			})
		}
		pos = nextLineStart(raw, eol)
	}

	return MessageShape{
		Direction:   direction,
		FirstToken:  first,
		SecondToken: second,
		ThirdToken:  third,
		Headers:     headers,
		Body:        Span{Offset: bodyStart, Len: len(raw) - bodyStart},
	}, nil
}

// findHeaderEnd returns (index of end-of-headers, index where body starts).
func findHeaderEnd(raw []byte) (int, int) {
	// Look for CRLFCRLF
	for i := 0; i+3 < len(raw); i++ {
		if raw[i] == '\r' && raw[i+1] == '\n' && raw[i+2] == '\r' && raw[i+3] == '\n' {
			return i, i + 4
		}
	}
	// Look for LFLF
	for i := 0; i+1 < len(raw); i++ {
		if raw[i] == '\n' && raw[i+1] == '\n' {
			return i, i + 2
		}
	}
	// No terminator found: treat whole buffer as head, empty body
	return len(raw), len(raw)
}

// findLineEnd finds the end of a line (CR or LF).
func findLineEnd(raw []byte, from int) int {
	for i := from; i < len(raw); i++ {
		if raw[i] == '\r' || raw[i] == '\n' {
			return i
		}
	}
	return -1
}

// nextLineStart returns the start of the next line after an EOL.
func nextLineStart(raw []byte, eol int) int {
	if eol < len(raw) && raw[eol] == '\r' && eol+1 < len(raw) && raw[eol+1] == '\n' {
		return eol + 2
	} else if eol < len(raw) && raw[eol] == '\n' {
		return eol + 1
	}
	return eol
}

// split3 splits raw[start..end] on ASCII space into exactly three spans.
func split3(raw []byte, start, end int) (Span, Span, Span, bool) {
	seg := raw[start:end]
	s1 := -1
	for i, b := range seg {
		if b == ' ' {
			s1 = i
			break
		}
	}
	if s1 == -1 {
		return Span{}, Span{}, Span{}, false
	}

	rest := seg[s1+1:]
	s2 := -1
	for i, b := range rest {
		if b == ' ' {
			s2 = i
			break
		}
	}

	if s2 == -1 {
		// No third token (e.g., "HTTP/1.1 200")
		return (Span{Offset: start, Len: s1}),
			(Span{Offset: start + s1 + 1, Len: len(rest)}),
			(Span{Offset: end, Len: 0}),
			true
	}

	return (Span{Offset: start, Len: s1}),
		(Span{Offset: start + s1 + 1, Len: s2}),
		(Span{Offset: start + s1 + 1 + s2 + 1, Len: len(rest) - s2 - 1}),
		true
}
