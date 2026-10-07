package intruder

// The bundled wordlist corpus and the named-list resolver (burpsy-react-ui-kal).
//
// # Why a corpus at all
//
// Burp ships 48 payload wordlists; burpsy shipped zero. Generators and corpora are not
// substitutes: a generator produces a space you describe, a wordlist carries knowledge
// someone else gathered. An operator who opens Intruder with an empty payload set has a
// functional but unarmed tool.
//
// # What ships, and the honest-counting rule
//
// Six starter lists — SQLi probes, XSS probes, fuzzing strings, usernames, content-discovery
// paths, SSTI probes — one per category an operator reaches for first. Every list carries a
// provenance header (# lines) naming its public source and licence basis and stating, in the
// file itself, that nothing is extracted from PortSwigger's shipped resources. The content
// is industry-standard public payloads (OWASP / PayloadAllTheThings / MIT-licensed SecLists),
// per the recorded licensing decision on the bead: use everything, no vetting gate.
//
// # The builtin: shorthand
//
// FileSource.Filename "builtin:<name>" resolves from the embedded corpus — the same reader
// the plain path uses, one contract, so an uploaded list, a server-side list and a bundled
// list are indistinguishable to the engine (which is the point: the engine should not know
// where knowledge came from, only that it arrived as lines).
//
// The reader skips leading-'#' comment lines: the provenance header is part of the file's
// honesty, not part of its payload space. A '#' payload an operator genuinely wants is still
// expressible — only lines whose first character is '#' at column zero are comments, and an
// operator's own file with no header behaves exactly as before.

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
	"sync"
)

//go:embed wordlists/*.txt
var wordlistFS embed.FS

// wordlistNames is the bundled list, materialised once. Sorted so /api/wordlists and the
// UI picker render in a stable order.
var wordlistNames = func() []string {
	entries, err := fs.Glob(wordlistFS, "wordlists/*.txt")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := strings.TrimSuffix(strings.TrimPrefix(e, "wordlists/"), ".txt")
		out = append(out, name)
	}
	// embed.Glob does not guarantee order; a reshuffling picker is one nobody trusts.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}()

// builtinWordlistPrefix is the shorthand that addresses the embedded corpus.
const builtinWordlistPrefix = "builtin:"

// IsBuiltinWordlist reports whether a FileSource filename addresses the bundled corpus.
func IsBuiltinWordlist(filename string) bool {
	return strings.HasPrefix(filename, builtinWordlistPrefix)
}

// BuiltinWordlistNames returns the bundled list names, sorted.
func BuiltinWordlistNames() []string {
	return append([]string(nil), wordlistNames...)
}

// builtinWordlistLines reads one bundled list, splitting payload lines: blank lines and
// column-zero '#' comment lines (the provenance header) are not payloads.
func builtinWordlistLines(name string) ([]string, error) {
	data, err := wordlistFS.ReadFile("wordlists/" + name + ".txt")
	if err != nil {
		return nil, fmt.Errorf("no bundled wordlist named %q", name)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") {
			continue // the provenance header, not payload space
		}
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

// wordlistCounts memoises the per-list line counts so the manager can report them without
// re-reading the embed per request. Bounded: the bundled corpus is fixed at build time.
var wordlistCounts sync.Map

// BuiltinWordlistCount returns the payload-line count of one bundled list. Counted from
// the file itself, never from the header's claim — drift between the two is a defect, and
// the count an operator plans an attack around must be the count that will fire.
func BuiltinWordlistCount(name string) int {
	if v, ok := wordlistCounts.Load(name); ok {
		return v.(int)
	}
	n := 0
	if lines, err := builtinWordlistLines(name); err == nil {
		n = len(lines)
	}
	wordlistCounts.Store(name, n)
	return n
}

// resolveBuiltinWordlist expands the shorthand into payload lines, applying the same
// per-payload length check the plain file reader holds.
func resolveBuiltinWordlist(filename string, checkLen func(int) error) ([]string, error) {
	name := strings.TrimPrefix(filename, builtinWordlistPrefix)
	lines, err := builtinWordlistLines(name)
	if err != nil {
		return nil, err
	}
	for _, l := range lines {
		if err := checkLen(len(l)); err != nil {
			return nil, err
		}
	}
	return lines, nil
}
