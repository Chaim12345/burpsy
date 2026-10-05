package intruder

import (
	"fmt"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// Unicode-normalization payload variants (burpsy-react-ui-d617): PortSwigger's #4 technique of 2025,
// "Lost in Translation". A filter that validates input and then normalises it is bypassed by a
// payload spelled in a form that validates clean but normalises — server-side — into the dangerous
// characters. The processor emits that form, so a marked insertion point can be swept for it.
//
// The Unicode-standard forms (NFC/NFD/NFKC/NFKD) come from golang.org/x/text; fullwidth and homoglyph
// are substitution tables. Fullwidth is the high-signal one: every ASCII printable has a fullwidth
// twin in U+FF01..U+FF5E that NFKC/NFKD collapse straight back to the ASCII character, so a target
// that NFKC-normalises after validating sees the raw payload. Homoglyph is the visual-confusable
// cousin — Latin letters spelled in Cyrillic/Greek lookalikes — which is a different class (spoofing,
// not reversible normalisation) and is offered for the IDN/display-name filters it defeats.

// NormForm is a normalization variant the processor can emit.
type NormForm int

const (
	normNFC NormForm = iota
	normNFD
	normNFKC
	normNFKD
	normFullwidth
	normHomoglyph
)

// parseNormForm resolves the form name an operator spells. The four standard forms take their usual
// spellings; the two substitutions are named by what they do.
func parseNormForm(name string) (NormForm, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "nfc":
		return normNFC, true
	case "nfd":
		return normNFD, true
	case "nfkc":
		return normNFKC, true
	case "nfkd":
		return normNFKD, true
	case "fullwidth":
		return normFullwidth, true
	case "homoglyph":
		return normHomoglyph, true
	}
	return 0, false
}

func (f NormForm) String() string {
	switch f {
	case normNFC:
		return "nfc"
	case normNFD:
		return "nfd"
	case normNFKC:
		return "nfkc"
	case normNFKD:
		return "nfkd"
	case normFullwidth:
		return "fullwidth"
	case normHomoglyph:
		return "homoglyph"
	}
	return "unknown"
}

// homoglyphs maps an ASCII letter to a visually-identical non-Latin rune. Curated rather than
// exhaustive: the letters that actually appear in payloads and host names, each a Cyrillic or Greek
// character a human reads as its Latin twin. A letter with no good confusable is left ASCII.
var homoglyphs = map[rune]rune{
	'a': 'а', // CYRILLIC SMALL A
	'c': 'с', // CYRILLIC SMALL ES
	'e': 'е', // CYRILLIC SMALL IE
	'i': 'і', // CYRILLIC SMALL BYELORUSSIAN-UKRAINIAN I
	'j': 'ј', // CYRILLIC SMALL JE
	'o': 'о', // CYRILLIC SMALL O
	'p': 'р', // CYRILLIC SMALL ER
	's': 'ѕ', // CYRILLIC SMALL DZE
	'x': 'х', // CYRILLIC SMALL HA
	'y': 'у', // CYRILLIC SMALL U
	'A': 'А',
	'B': 'В',
	'C': 'С',
	'E': 'Е',
	'H': 'Н',
	'K': 'К',
	'M': 'М',
	'O': 'О',
	'P': 'Р',
	'T': 'Т',
	'X': 'Х',
}

// normalizeVariant renders one payload in the given form. Input and output are UTF-8 bytes; an input
// that is not valid UTF-8 is returned unchanged for the standard forms (x/text leaves invalid bytes
// alone) and passed rune by rune for the substitutions (invalid bytes become U+FFFD under range, so
// those two forms are documented as operating on text, not arbitrary bytes).
func normalizeVariant(form NormForm, payload []byte) []byte {
	switch form {
	case normNFC:
		return norm.NFC.Bytes(payload)
	case normNFD:
		return norm.NFD.Bytes(payload)
	case normNFKC:
		return norm.NFKC.Bytes(payload)
	case normNFKD:
		return norm.NFKD.Bytes(payload)
	case normFullwidth:
		return mapRunes(payload, func(r rune) rune {
			// U+0021..U+007E -> U+FF01..U+FF5E; space (U+0020) has an ideographic space but it is not a
			// printable twin and is left alone so the payload's structure survives.
			if r >= '!' && r <= '~' {
				return r + 0xFEE0
			}
			return r
		})
	case normHomoglyph:
		return mapRunes(payload, func(r rune) rune {
			if h, ok := homoglyphs[r]; ok {
				return h
			}
			return r
		})
	}
	return payload
}

// mapRunes applies f to each rune of valid UTF-8 text.
func mapRunes(b []byte, f func(rune) rune) []byte {
	return []byte(strings.Map(f, string(b)))
}

// normFormError is the RuleError for an unknown normalization form.
func normFormError(name string) error {
	return fmt.Errorf("unknown normalization form %q: want nfc, nfd, nfkc, nfkd, fullwidth or homoglyph", name)
}
