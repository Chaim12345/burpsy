// Refusing links whose text or target signals a destructive action (CRAWL-04).
//
// # Why this is here at all
//
// PortSwigger's own crawler documentation does not cover destructive-action avoidance. Their
// crawler will happily follow a "Delete account" link on a target the operator authorised, because
// the operator authorised the target. That is a defensible position for a tool with a human
// watching it, and it is the wrong default for an unattended crawl: the cost of following a logout
// link is that every request after it is unauthenticated and the crawl silently covers the public
// site instead of the application, and the cost of following a delete link is somebody's data.
//
// So this table exists, and it errs towards refusing. It is also the reason the refusal ledger in
// skip.go is as detailed as it is: a check that guesses must show its work, or an operator cannot
// tell an over-refusal from a genuine absence.
//
// # What is matched, and against what
//
// Both the link *target* and the link *text* are checked, because either alone misses the common
// cases. A REST-shaped application deletes with `POST /api/v2/records/8814` and the only word
// "delete" anywhere near it is the button label; a server-rendered application deletes with
// `<a href="/records/8814/delete">✕</a>` and there is no label at all. One table, applied to both
// strings, catches both.
//
// # Token-run matching, not substring matching
//
// A naive `strings.Contains` on the lowercased URL refuses `/user/presets` because "reset" is
// inside "presets", and `/cancellation-policy` because "cancel" is inside "cancellation". Those are
// not close calls; they are ordinary paths in ordinary applications, and a check that refuses them
// trains its operator to ignore it.
//
// So both sides are tokenised first: lowercased, split on every non-alphanumeric byte and on
// camelCase humps, and a signal matches when its own token sequence appears as a *contiguous run*
// of the haystack's tokens. That makes `deleteRecord`, `delete-record`, `delete_record`,
// `/records/delete` and the text "Delete record" all match the one-token signal `delete`, while
// `presets`, `cancellation` and `undeleted` — one token each, none equal to a signal token — do
// not.
//
// Two consequences worth stating plainly:
//
//   - A signal written with a separator, like `empty trash`, is a two-token sequence, so it matches
//     `empty-trash`, `emptyTrash`, `empty_trash` and the text "Empty Trash" without the table
//     needing a row for each spelling. That is why the table below has no separator variants in it.
//   - A single word glued to another with no separator or case change — `logoutnow` — is one token
//     and does not match. That is a real miss, and it is a deliberate trade against the false
//     positives substring matching produces. It is named here rather than left to be discovered.
//
// # Where the check sits, and what it does not cover
//
// Order of the frontier's gates is documented on Crawler.admit. The destructive check runs before
// the scope and query gates so that a refusal is labelled by the most specific thing wrong with it:
// a logout link that is also out of scope reports as a logout refusal, which is what an operator
// needs to see.
//
// Seeds are deliberately *not* checked. The threat model here is that the *target* controls link
// text and link targets — that is what makes an unattended crawl following them dangerous. A seed
// is the operator's own typed instruction about where to start, so refusing it would be the tool
// overriding an explicit decision with a guess. Seeds still pass every other gate: scheme, host,
// scope and the crawl-scope query.
//
// Query-string *values* are tokenised along with the rest of the URL, so `?action=delete` and
// `?next=/logout` are both caught. The cost is that a search query like `?q=how+to+delete+my+data`
// is refused too; it is counted and named, and refusing is the safe direction.
package crawler

import (
	"net/url"
	"strings"
	"unicode"
)

// destructiveSignal is one entry in the table: a token sequence and the refusal reason it implies.
type destructiveSignal struct {
	// tokens is the signal, already tokenised — see tokenise. Never empty.
	tokens []string
	// reason is the bucket a match lands in.
	reason Skip
	// phrase is the signal as written, for the SkipRecord's Signal field.
	phrase string
}

// destructiveSignals is the table. It covers the six classes CRAWL-04 names, and it is ordered so
// that the more specific classes are tested before the general state-changing-verb class — a
// `logout` link must report as a logout refusal, not as a generic verb.
//
// Every row is a word or phrase that, in a link an application offers, means "this request changes
// or destroys something". Read-only after init; nothing mutates it.
var destructiveSignals = buildSignals([]struct {
	phrases []string
	reason  Skip
}{
	// Logout first and on its own: it is the one destructive action whose damage is silent. A crawl
	// that follows it keeps returning 200s, from the public site, and reports coverage of an
	// application it is no longer inside.
	{[]string{
		"logout", "log out", "logoff", "log off", "signout", "sign out",
		"session destroy", "sessions destroy", "end session", "sign me out",
	}, SkipDestructiveLogout},

	{[]string{
		"delete", "del", "destroy", "remove", "erase", "unlink", "discard",
		"delete account", "delete all",
	}, SkipDestructiveDelete},

	{[]string{
		"purge", "empty trash", "empty bin", "trash empty", "truncate", "wipe",
		"clear all", "flush", "drop table", "drop database", "empty cache",
	}, SkipDestructivePurge},

	{[]string{
		"deactivate", "disable", "close account", "account close", "cancel account",
		"cancel subscription", "unsubscribe", "suspend", "ban", "block user",
	}, SkipDestructiveDeactivate},

	// The administrative class: one request here can take an application offline or replace its
	// code. `install`/`uninstall`/`upgrade` are listed bare because in a link they essentially only
	// ever mean this.
	{[]string{
		"plugin install", "install plugin", "uninstall", "install", "upgrade",
		"update core", "setup", "reinstall", "factory reset", "restore defaults",
		"maintenance mode", "shutdown", "shut down", "reboot", "restart", "format",
	}, SkipDestructiveAdminPlugin},

	// Everything else that changes state. Broader and vaguer than the classes above, which is why
	// it is last: a link matching both a specific class and this one reports as the specific class.
	{[]string{
		"reset", "revoke", "deauthorize", "deauthorise", "deregister", "unregister",
		"approve", "reject", "decline", "publish", "unpublish", "archive", "unarchive",
		"restore", "merge", "cancel", "confirm", "transfer", "rotate", "regenerate",
		"invalidate", "expire", "detach", "eject", "kick", "leave", "abandon",
		"withdraw", "refund", "chargeback", "submit order", "place order", "checkout",
	}, SkipDestructiveStateChange},
})

func buildSignals(groups []struct {
	phrases []string
	reason  Skip
}) []destructiveSignal {
	var out []destructiveSignal
	for _, g := range groups {
		for _, p := range g.phrases {
			toks := tokenise(p)
			if len(toks) == 0 {
				// Unreachable for the table above, and a guard rather than a panic because an empty
				// signal would match every link — the one failure mode worse than missing one.
				continue
			}
			out = append(out, destructiveSignal{tokens: toks, reason: g.reason, phrase: p})
		}
	}
	return out
}

// DestructiveVerdict is the outcome of the check on one candidate link.
type DestructiveVerdict struct {
	// Refused says whether the link is refused. When false, every other field is zero.
	Refused bool
	// Reason is the bucket, one of the six CategoryDestructive values.
	Reason Skip
	// Signal is the matched phrase as the table spells it, with where it matched appended —
	// "delete (target)" or "log out (text)". This goes straight into SkipRecord.Signal.
	Signal string
}

// classifyDestructive tests a link's target and text against the table.
//
// The target is checked first so that a URL match — the stronger evidence, since it describes the
// request that would actually be sent — is the one reported when both match.
//
// The target is checked in both its percent-decoded and its literal form. Decoded, because
// `/user%2Fdelete` and `?action=%64elete` are the same request as their plain spellings and a check
// that only reads the literal bytes is one `%` away from being bypassed. Literal as well, because
// decoding can only ever be attempted once here and a form that survives decoding unchanged still
// deserves the check. One decode pass, not a loop to a fixed point: a doubly-encoded signal is a
// documented miss rather than an invitation to write an unbounded decoder.
//
// target should be the absolute URL including its query; text should be the link text or form
// label, and may be empty.
func classifyDestructive(target, text string) DestructiveVerdict {
	decoded := target
	if unescaped, err := url.PathUnescape(target); err == nil {
		decoded = unescaped
	}
	if sig, ok := matchSignals(tokenise(decoded)); ok {
		return DestructiveVerdict{Refused: true, Reason: sig.reason, Signal: sig.phrase + " (target)"}
	}
	if decoded != target {
		if sig, ok := matchSignals(tokenise(target)); ok {
			return DestructiveVerdict{Refused: true, Reason: sig.reason, Signal: sig.phrase + " (target)"}
		}
	}
	if text != "" {
		if sig, ok := matchSignals(tokenise(text)); ok {
			return DestructiveVerdict{Refused: true, Reason: sig.reason, Signal: sig.phrase + " (text)"}
		}
	}
	return DestructiveVerdict{}
}

// matchSignals returns the first signal whose token sequence appears as a contiguous run in toks.
// Table order decides which of several matches is reported, which is why the table is ordered
// specific-class-first.
func matchSignals(toks []string) (destructiveSignal, bool) {
	if len(toks) == 0 {
		return destructiveSignal{}, false
	}
	for _, sig := range destructiveSignals {
		if containsRun(toks, sig.tokens) {
			return sig, true
		}
	}
	return destructiveSignal{}, false
}

// containsRun reports whether want appears as a contiguous subsequence of have.
func containsRun(have, want []string) bool {
	if len(want) == 0 || len(want) > len(have) {
		return false
	}
	for i := 0; i+len(want) <= len(have); i++ {
		match := true
		for j := range want {
			if have[i+j] != want[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// tokenise lowercases s and splits it into alphanumeric tokens, breaking on every non-alphanumeric
// byte and on every camelCase hump.
//
// A hump is a lower-to-upper transition (`deleteUser` -> delete, user) and the tail of an
// acronym run followed by a word (`HTTPDelete` -> http, delete). Digits stay attached to the token
// they appear in, so `/v2/records/8814/delete` tokenises to v2, records, 8814, delete — the numeric
// id is its own token and matches no signal, which is what lets an id-bearing REST path be checked
// at all.
//
// Non-ASCII letters are kept and treated as lowercase word characters: an internationalised path
// should not be silently split into fragments that accidentally equal a signal token.
func tokenise(s string) []string {
	runes := []rune(s)
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i, r := range runes {
		switch {
		case unicode.IsUpper(r):
			// Break before an uppercase rune that starts a new word: either the previous rune was
			// lowercase or a digit (`deleteUser`, `v2Delete`), or the next rune is lowercase while
			// the previous was uppercase (`HTTPDelete` -> http, delete).
			prevLowerish := i > 0 && (unicode.IsLower(runes[i-1]) || unicode.IsDigit(runes[i-1]))
			acronymTail := i > 0 && unicode.IsUpper(runes[i-1]) && i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if prevLowerish || acronymTail {
				flush()
			}
			cur.WriteRune(unicode.ToLower(r))
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			cur.WriteRune(unicode.ToLower(r))
		default:
			// Every other byte — /, ?, =, &, -, _, ., +, %, whitespace — is a boundary.
			flush()
		}
	}
	flush()
	return out
}
