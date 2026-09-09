package intruder

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/burpsy-go/burpsy/internal/tools"
)

// The payload-processing rule chain: an ordered list of transformations applied to each
// payload, ported from burpsy-intruder::process.
//
// # Where in the attack this runs, and why not later
//
// Burp applies processing rules at send time, once per request, inside the attack loop. Here
// the chain runs at resolve time, over the PayloadSet a PayloadSource produced, before an
// AttackPlan is built over it.
//
// That is not a shortcut, it is the only placement that keeps the two properties the intruder
// crate is built on:
//
//   - A result row holds an ordinal and nothing else. If processing ran per-send, recovering a
//     payload would mean re-running the chain — and a chain with a random-seeded step would
//     recover a *different* payload than the one that was sent.
//   - A skipped payload is a shorter set, not a hole in the plan. `skip-if-matches` drops a
//     payload here, so the plan is built over what will actually be sent.
//
// # Refuse rather than mangle
//
// A rule that cannot be applied — base64-decoding a payload that is not base64, inflating bytes
// that are not compressed — drops the payload with a reason rather than passing it through
// unchanged. Passing it through would send a payload the operator did not ask for while the
// report said the rule was applied. Reasons are grouped and counted, one line per distinct
// reason, never one per payload.

// MaxDropReasons bounds distinct drop reasons for the same reason result buckets are bounded:
// a chain that drops 199 999 payloads for one reason is one row.
const MaxDropReasons = 32

// RuleSpec is one processing rule, in the form it arrives over the wire.
//
// Split from the compiled Chain so patterns are validated once, at the edge. A single struct
// rather than a tagged enum, because Go has no sealed variants; NewChain refuses a rule name it
// does not know, which is where the Rust serde tagged enum would fail instead.
type RuleSpec struct {
	// Rule is the snake_case rule name: add_prefix, add_suffix, replace, uppercase, lowercase,
	// encode, decode, hash, skip_if_matches.
	Rule string `json:"rule"`
	// Text is the literal for add_prefix / add_suffix.
	Text string `json:"text"`
	// Pattern is the regex for replace and skip_if_matches.
	Pattern string `json:"pattern"`
	// Replace is the substitution for replace; `$1` refers to a capture group.
	Replace string `json:"replace"`
	// All replaces every occurrence rather than only the first.
	All bool `json:"all"`
	// Layer is the codec name for encode / decode (url, html, base64, base64url, hex, gzip,
	// deflate). Names and behaviour come from burpsy_tools::decoder.
	Layer string `json:"layer"`
	// Algorithm is the digest for hash: md5 or sha256.
	Algorithm string `json:"algorithm"`
}

// RuleErrorKind distinguishes the ways a rule can refuse to build.
type RuleErrorKind int

const (
	// RuleErrBadRegex: a pattern that is not a valid regex.
	RuleErrBadRegex RuleErrorKind = iota
	// RuleErrUnknownLayer: an encode/decode layer that is not a codec.
	RuleErrUnknownLayer
	// RuleErrUnknownHash: a hash algorithm that is not md5 or sha256.
	RuleErrUnknownHash
)

// RuleError is a rule that could not be built. Every kind is an operator typo, reported once.
type RuleError struct {
	Kind      RuleErrorKind
	Pattern   string
	Message   string
	Layer     string
	Algorithm string
}

func (e *RuleError) Error() string {
	switch e.Kind {
	case RuleErrBadRegex:
		return fmt.Sprintf("bad regex %q: %s", e.Pattern, e.Message)
	case RuleErrUnknownLayer:
		return fmt.Sprintf("unknown encoding %q: expected url, html, base64, base64url, hex, gzip or deflate", e.Layer)
	case RuleErrUnknownHash:
		return fmt.Sprintf("unknown hash %q: expected md5 or sha256", e.Algorithm)
	default:
		return "unknown rule error"
	}
}

// hashAlg is the digest for the hash step. The Rust copy (hash.rs) is knowing duplication
// scheduled for deletion in favour of the tools decoder's hashing; Go goes straight to the
// standard library, which is checked against the same RFC 1321 / FIPS 180-4 vectors.
type hashAlg int

const (
	hashMD5 hashAlg = iota
	hashSHA256
)

func parseHash(s string) (hashAlg, bool) {
	switch s {
	case "md5", "md-5":
		return hashMD5, true
	case "sha256", "sha-256", "sha2":
		return hashSHA256, true
	default:
		return 0, false
	}
}

func (a hashAlg) hex(in []byte) string {
	switch a {
	case hashMD5:
		sum := md5.Sum(in)
		return hex.EncodeToString(sum[:])
	case hashSHA256:
		sum := sha256.Sum256(in)
		return hex.EncodeToString(sum[:])
	default:
		panic("unreachable: unhandled hash algorithm")
	}
}

// A compiled rule.
type step struct {
	kind stepKind
	// text is the literal for add_prefix / add_suffix and the replacement for replace.
	text []byte
	// re is the compiled pattern for replace and skip_if_matches.
	re  *regexp.Regexp
	all bool
	// layer is the codec for encode / decode; "" for rules that have none.
	layer     tools.Layer
	hasLayer  bool
	hash      hashAlg
	hasHash   bool
	layerName string
	pattern   string
}

type stepKind int

const (
	stepAddPrefix stepKind = iota
	stepAddSuffix
	stepReplace
	stepUppercase
	stepLowercase
	stepEncode
	stepDecode
	stepHash
	stepSkipIfMatches
)

// Chain is an ordered chain of processing rules, ready to run.
type Chain struct {
	steps []step
}

// NewChain compiles the chain. Order is the order given. Every regex is compiled and every
// layer and algorithm name resolved here; nothing reaches the per-payload loop uncompiled, and
// an unparseable pattern is one error at the edge rather than N identical drops.
func NewChain(specs []RuleSpec) (*Chain, error) {
	steps := make([]step, 0, len(specs))
	for _, s := range specs {
		switch s.Rule {
		case "add_prefix":
			steps = append(steps, step{kind: stepAddPrefix, text: []byte(s.Text)})
		case "add_suffix":
			steps = append(steps, step{kind: stepAddSuffix, text: []byte(s.Text)})
		case "replace":
			re, err := compile(s.Pattern)
			if err != nil {
				return nil, err
			}
			steps = append(steps, step{kind: stepReplace, re: re, text: []byte(s.Replace), all: s.All})
		case "uppercase":
			steps = append(steps, step{kind: stepUppercase})
		case "lowercase":
			steps = append(steps, step{kind: stepLowercase})
		case "encode", "decode":
			l, ok := tools.ParseLayer(s.Layer)
			if !ok {
				return nil, &RuleError{Kind: RuleErrUnknownLayer, Layer: s.Layer}
			}
			kind := stepEncode
			if s.Rule == "decode" {
				kind = stepDecode
			}
			steps = append(steps, step{kind: kind, layer: l, hasLayer: true, layerName: l.String()})
		case "hash":
			a, ok := parseHash(s.Algorithm)
			if !ok {
				return nil, &RuleError{Kind: RuleErrUnknownHash, Algorithm: s.Algorithm}
			}
			steps = append(steps, step{kind: stepHash, hash: a, hasHash: true})
		case "skip_if_matches":
			re, err := compile(s.Pattern)
			if err != nil {
				return nil, err
			}
			steps = append(steps, step{kind: stepSkipIfMatches, re: re, pattern: s.Pattern})
		default:
			// The Rust tagged enum refuses this at deserialisation; the Go struct cannot,
			// so the refusal lives here, at construction, where an operator typo is one
			// error and not N payloads that silently survive.
			return nil, fmt.Errorf("unknown rule %q", s.Rule)
		}
	}
	return &Chain{steps: steps}, nil
}

// IsEmpty reports whether the chain has no rules.
func (c *Chain) IsEmpty() bool {
	return len(c.steps) == 0
}

// Len is the number of rules in the chain.
func (c *Chain) Len() int {
	return len(c.steps)
}

// Processed is what the chain did with one payload.
type Processed struct {
	// Keep is the payload to send. Only meaningful when !Dropped.
	Keep []byte
	// Dropped is true when the chain refused the payload.
	Dropped bool
	// Reason names why it was dropped, matching the Rust Drop message.
	Reason string
}

func compile(pattern string) (*regexp.Regexp, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, &RuleError{Kind: RuleErrBadRegex, Pattern: pattern, Message: err.Error()}
	}
	return re, nil
}

// Apply runs the chain over one payload, in rule order.
func (c *Chain) Apply(payload []byte) Processed {
	cur := append([]byte(nil), payload...)
	for i, st := range c.steps {
		switch st.kind {
		case stepAddPrefix:
			v := make([]byte, 0, len(st.text)+len(cur))
			v = append(v, st.text...)
			v = append(v, cur...)
			cur = v
		case stepAddSuffix:
			cur = append(cur, st.text...)
		case stepReplace:
			if st.all {
				cur = st.re.ReplaceAll(cur, st.text)
			} else {
				cur = replaceFirst(st.re, cur, st.text)
			}
		case stepUppercase:
			asciiUpper(cur)
		case stepLowercase:
			asciiLower(cur)
		case stepEncode:
			v, err := tools.Encode(st.layer, cur)
			if err != nil {
				return Processed{Dropped: true, Reason: fmt.Sprintf("rule %d (%s): %s", i, st.layerName, err)}
			}
			cur = v
		case stepDecode:
			v, truncated, err := tools.Decode(st.layer, cur)
			if err != nil {
				return Processed{Dropped: true, Reason: fmt.Sprintf("rule %d (%s): %s", i, st.layerName, err)}
			}
			if truncated {
				// A partial decode is a different payload than the one the rule describes.
				return Processed{Dropped: true, Reason: fmt.Sprintf("rule %d (%s): decoded only part of the payload", i, st.layerName)}
			}
			cur = v
		case stepHash:
			cur = []byte(st.hash.hex(cur))
		case stepSkipIfMatches:
			if st.re.Match(cur) {
				return Processed{Dropped: true, Reason: fmt.Sprintf("rule %d: skipped, matches %s", i, st.pattern)}
			}
		}
		if len(cur) > MaxItemLen {
			return Processed{Dropped: true, Reason: fmt.Sprintf("rule %d: payload grew to %d bytes, over the %d-byte limit", i, len(cur), MaxItemLen)}
		}
	}
	return Processed{Keep: cur}
}

// replaceFirst substitutes the first match only, expanding `$1` capture references, as the
// Rust `re.replace` (first match) does.
func replaceFirst(re *regexp.Regexp, src, repl []byte) []byte {
	loc := re.FindSubmatchIndex(src)
	if loc == nil {
		return src
	}
	out := make([]byte, 0, len(src))
	out = append(out, src[:loc[0]]...)
	out = re.Expand(out, repl, src, loc)
	out = append(out, src[loc[1]:]...)
	return out
}

// asciiUpper folds a-z to A-Z in place. Rust uses make_ascii_uppercase: a payload is bytes and
// may not be UTF-8 at all, so a Unicode-aware fold would have to decide what to do with the
// bytes that are not text; ASCII case-folding is total, and it is what Burp's own rules do.
func asciiUpper(b []byte) {
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
}

func asciiLower(b []byte) {
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
}

// Run applies the chain to every payload in set, in place.
//
// Dropped payloads are removed rather than blanked, so the set that comes out is exactly what
// will be sent — and set.Skipped plus set.Dropped account for the difference. An empty chain is
// a no-op and does not even walk the set. Count is kept in lockstep with Items, because Items
// is not serialised and Count is what a caller sees.
func (c *Chain) Run(set *PayloadSet) {
	if len(c.steps) == 0 {
		return
	}
	kept := make([]string, 0, len(set.Items))
	for _, p := range set.Items {
		switch res := c.Apply([]byte(p)); {
		case res.Dropped:
			set.Skipped++
			noteDrop(&set.Dropped, res.Reason)
		default:
			kept = append(kept, string(res.Keep))
		}
	}
	set.Items = kept
	set.Count = len(kept)
}

func noteDrop(into *[]DropReason, reason string) {
	for i := range *into {
		if (*into)[i].Reason == reason {
			(*into)[i].Count++
			return
		}
	}
	if len(*into) < MaxDropReasons {
		*into = append(*into, DropReason{Reason: reason, Count: 1})
	}
}

// URLEncodeSet applies Burp's "URL-encode these characters" final pass to one payload
// set: every rune in the named character set is percent-encoded, everything else passes
// through untouched (burpsy-react-ui-8cbc). Burp runs this as the last step before
// sending, independent of the payload type — which is where the handler calls it, after
// the operator's rule chain, so an explicit encode rule still runs first and the safety
// net encodes what remains.
//
// The safe set is always encoded additionally: a space or a control character in a
// payload would break the request line or the framing headers no matter what the
// operator asked for, and sending a request the peer cannot parse reports a transport
// error that reads as a finding. Burp behaves the same way.
func URLEncodeSet(ps *PayloadSet, chars string) {
	if chars == "" {
		// An empty named set is the off state — but the always-encode rule still applies to
		// any payload that carries an unrepresentable character, because the request it would
		// produce cannot be delivered. Only a payload with nothing to encode skips the walk.
		needsWalk := false
		for _, item := range ps.Items {
			for _, r := range item {
				if r <= 0x20 || r == 0x7f {
					needsWalk = true
					break
				}
			}
			if needsWalk {
				break
			}
		}
		if !needsWalk {
			return
		}
	}
	encode := func(b []byte) []byte {
		var out bytes.Buffer
		for _, r := range string(b) {
			c := string(r)
			if chars != "" && strings.ContainsRune(chars, r) || r <= 0x20 || r == 0x7f {
				for _, bb := range []byte(c) {
					fmt.Fprintf(&out, "%%%02X", bb)
				}
				continue
			}
			out.WriteString(c)
		}
		return out.Bytes()
	}
	for i, item := range ps.Items {
		ps.Items[i] = string(encode([]byte(item)))
	}
}
