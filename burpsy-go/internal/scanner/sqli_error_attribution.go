package scanner

// Attributing a SQL error signature to the interpreter that produced it (burpsy-react-ui-j1mk.40).
//
// # The false positive this closes
//
// A quote probe proves SQL injection by introducing a parse error the baseline did not have. The
// proof is only as good as the claim that a SQL parser produced the error, and a few of the banked
// signatures (burp.Ze2s) are generic quote-balancing wording that other interpreters share. A
// POSIX shell is the one that matters in practice: an endpoint that hands its parameter to
// `sh -c "ping -c 2 " + value` answers `127.0.0.1'` with dash's
//
//	sh: 1: Syntax error: Unterminated quoted string
//
// and busybox ash's `sh: syntax error: unterminated quoted string`. Both contain the
// PostgreSQL-banked signature "unterminated quoted string", the baseline does not, and the doubled
// quote `''` repairs it exactly as it would repair a SQL literal, so the shell passes every test
// the error technique applies. A full run against OWASP VulnerableApp reported SQL injection, Firm,
// on every one of its OS-command-injection levels this way. There is no database behind them.
//
// # The rule
//
// A diagnostic names its interpreter. A shell prefixes its own messages with the shell's name and,
// for `sh -c`, the script line: `sh: 1: `, `bash: -c: line 0: `, `/bin/sh: `, `zsh:1: `. A
// signature counts as SQL evidence unless EVERY occurrence of it in the response sits on a line
// that a shell diagnostic owns: the shell's name and position prefix, then at most one short
// diagnostic label ("Syntax error: "), then the signature. A database error relayed by the
// application never has that shape. An occurrence on any other line still counts, so a page that
// carries both a shell message and a real database error stays a finding.
//
// The rule recognises a diagnostic FORMAT, a shell program's name followed by its position
// prefix, and never an application's wording. It removes evidence and never adds any, so it can
// only turn a finding into "no evidence from this probe" and cannot invent one.

import (
	"regexp"
	"strings"
)

// shellDiagnosticHead matches the text between the start of a line and a signature when that line
// is a shell's own diagnostic. It is applied to the lowercased line head, anchored at its end. The
// parts, in order:
//   - a boundary, so `bash` inside `hibash:` or a path component does not count;
//   - an optional absolute path (`/bin/sh`, `/usr/bin/bash`);
//   - the shell's name, optionally with a pid (`sh[123]`);
//   - one or more position fields: `: 1`, `: -c`, `: line 0`, or zsh's `:1` with no space;
//   - at most one short diagnostic label ending in a colon (`syntax error: `), and nothing else.
var shellDiagnosticHead = regexp.MustCompile(
	`(?:^|[^a-z0-9_.\-/])(?:/[a-z0-9_.\-]+)*/?(?:sh|bash|dash|ash|zsh|ksh|mksh|busybox)(?:\[\d+\])?` +
		`(?::\s*(?:\d+|-c|line \d+))*:\s*(?:[a-z][a-z ]{0,30}:\s*)?$`)

// scriptSyntaxErrorHead matches a line head that ends in a script engine's own syntax-error
// exception name: JavaScript's (SpiderMonkey, as MongoDB's $where relays it inside a
// MongoServerError: `... caused by :: SyntaxError: unterminated string literal`, V8, Node) and
// Python's, which share the class name `SyntaxError`, optionally `Uncaught`. Its wording,
// "unterminated string literal", is also a banked SQL signature, and a quote breaks a JavaScript
// string exactly as it breaks a SQL literal (burpsy-react-ui-v0ei.2, reported from the NoSQL
// fixtures). A database driver's own class is namespaced (`PG::SyntaxError`, a Java package), so a
// `SyntaxError` preceded by `::`, `.` or a word character is not this; such a head stays SQL.
var scriptSyntaxErrorHead = regexp.MustCompile(`(?:^|[^a-z0-9_:.])(?:uncaught\s+)?syntaxerror:\s*$`)

// foreignDiagnosticHead reports whether the head of a line, up to a signature, makes that line
// another interpreter's own diagnostic: a command shell's or a script engine's syntax error.
func foreignDiagnosticHead(head string) bool {
	return shellDiagnosticHead.MatchString(head) || scriptSyntaxErrorHead.MatchString(head)
}

// lineHead returns the part of the line that holds the byte at `at`, up to `at`. A line ends at a
// real line break, at a JSON-escaped one (an application that wraps a command's output in a JSON
// string relays `\n` as two characters), or at an HTML `<br`.
func lineHead(text string, at int) string {
	head := text[:at]
	start := 0
	for _, sep := range []string{"\n", "\r", `\n`, `\r`, "<br"} {
		if i := strings.LastIndex(head, sep); i >= 0 && i+len(sep) > start {
			start = i + len(sep)
		}
	}
	return head[start:]
}

// signatureOwnedByShell reports whether every occurrence of sig in body is on another
// interpreter's diagnostic line: a shell's, or a script engine's SyntaxError (foreignDiagnosticHead). A signature that does not occur at all is not owned by anything, so it reports false.
func signatureOwnedByShell(body, sig string) bool {
	needle := strings.ToLower(sig)
	seen := false
	for _, form := range matchableForms(body) {
		from := 0
		for {
			i := strings.Index(form[from:], needle)
			if i < 0 {
				break
			}
			at := from + i
			seen = true
			if !foreignDiagnosticHead(lineHead(form, at)) {
				return false
			}
			from = at + len(needle)
		}
	}
	return seen
}

// attributeSQLErrors removes from ev every introduced signature that a shell diagnostic owns in the
// injected body, recording it in Foreign, and recomputes the verdict. A probe whose only introduced
// error was a shell's reads as no SQL evidence, not as undecided: the shell answered the question.
func attributeSQLErrors(ev ErrorEvidence, injectedBody string) ErrorEvidence {
	if len(ev.Matched) == 0 {
		return ev
	}
	kept := ev.Matched[:0:0]
	for _, sig := range ev.Matched {
		if signatureOwnedByShell(injectedBody, sig) {
			ev.Foreign = append(ev.Foreign, sig)
			continue
		}
		kept = append(kept, sig)
	}
	ev.Matched = kept
	switch {
	case len(ev.Matched) > 0:
		ev.Evidence = InjectionEvidenceErrorSignature
	case len(ev.Preexisting) > 0:
		ev.Evidence = InjectionEvidenceInconclusive
	default:
		ev.Evidence = InjectionEvidenceNone
	}
	return ev
}

// classifySQLErrorAttributed is ClassifyErrorEvidence over a SQL signature bank followed by the
// interpreter attribution above.
func classifySQLErrorAttributed(baselineBody, injectedBody string, signatures []string) ErrorEvidence {
	return attributeSQLErrors(ClassifyErrorEvidence(baselineBody, injectedBody, signatures), injectedBody)
}
