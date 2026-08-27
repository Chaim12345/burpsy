package web

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- no source file may be invisible to grep -----------------------------------------------
//
// This test exists because of one byte.
//
// `ui/src/ui/inspector.tsx` used a literal NUL as a field delimiter in rowFingerprint. grep
// (ugrep here) classifies a file containing NUL as binary and, when recursing, reports **zero
// matches in it while exiting 0** — no warning, no "binary file matches" line, nothing that
// distinguishes "this pattern does not appear" from "this file was never read".
//
// The consequence was not theoretical. The Burp-parity audit's flagship finding, W6 #12, was that
// `inspectorPanelState` had "zero readers, zero writers" — evidenced by a repo-wide grep. The
// readers were at inspector.tsx:475 and :550 the whole time. The audit's own positive control
// (the same grep for `density`, which found readers) did not catch it, because `density`'s readers
// live in files grep could read: the control proved the method worked in general while the specific
// target stayed invisible. A second analyst and I then each "confirmed" the finding with the same
// blind tool before anyone read the file.
//
// So the invariant is not about NUL bytes for their own sake. It is that every source file in the
// tree must be *searchable*, because searchability is what every audit in this repo is built on.
//
// Control characters are still perfectly usable as delimiters — they just have to be written as
// escapes (`\u0000`), which produce identical code units and leave the file readable as text.

// controlBytesAllowed are the control characters that legitimately appear in source: tab, newline,
// carriage return. Everything else below 0x20, plus DEL, makes a file binary to grep.
var controlBytesAllowed = map[byte]bool{'\t': true, '\n': true, '\r': true}

func TestNoUISourceFileIsInvisibleToGrep(t *testing.T) {
	// Walk the checked-in frontend source. dist/ is excluded: it is a build artifact, nobody greps
	// it for intent, and esbuild may legitimately emit whatever it likes.
	root := filepath.Join("ui", "src")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("frontend source not present at %s: %v", root, err)
	}

	var offenders []string
	scanned := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", "dist", "artifacts":
				return fs.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".ts", ".tsx", ".js", ".jsx", ".css", ".json", ".md", ".html":
		default:
			return nil
		}

		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		scanned++

		for i := 0; i < len(raw); i++ {
			b := raw[i]
			if (b < 0x20 && !controlBytesAllowed[b]) || b == 0x7f {
				line := 1 + bytes.Count(raw[:i], []byte{'\n'})
				offenders = append(offenders, fmt.Sprintf(
					"%s:%d holds a raw control byte 0x%02x — grep treats this whole file as binary "+
						"and silently reports zero matches in it. Write it as an escape (\\u%04x) instead.",
					path, line, b, b))
				// One report per file is enough to act on.
				return nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	if scanned == 0 {
		t.Fatal("scanned 0 files, so this test proves nothing — the walk or the extension filter is wrong")
	}
	t.Logf("scanned %d frontend source files", scanned)

	if len(offenders) > 0 {
		t.Errorf("%d source file(s) are invisible to grep:\n  %s\n\n"+
			"This is how W6 #12 became a false 'zero readers' finding: the one file holding the "+
			"answer could not be read by the tool used to look for it.",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}

// The delimiter that started it must stay an escape. Pinned by name because the fingerprint is
// load-bearing — it decides when buffered Inspector edits are dropped — so a future author
// reaching for a raw byte again should get a failure that explains itself rather than a silently
// unsearchable file.
func TestTheInspectorRowFingerprintUsesEscapedDelimiters(t *testing.T) {
	path := filepath.Join("ui", "src", "ui", "inspector.tsx")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("%s not present: %v", path, err)
	}

	var fingerprint string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "rowFingerprint =") {
			fingerprint = line
			break
		}
	}
	if fingerprint == "" {
		t.Skip("rowFingerprint has moved or been renamed; this test's premise no longer holds")
	}

	if strings.ContainsRune(fingerprint, 0) || strings.ContainsRune(fingerprint, 1) {
		t.Error("rowFingerprint carries a raw control byte again; use \\u0000 / \\u0001")
	}
	// Both escapes present, so the two-level delimiting (field, then record) survives.
	for _, want := range []string{`\u0000`, `\u0001`} {
		if !strings.Contains(fingerprint, want) {
			t.Errorf("rowFingerprint no longer contains %s: %s", want, strings.TrimSpace(fingerprint))
		}
	}
}
