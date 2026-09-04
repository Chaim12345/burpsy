package web

import (
	"bytes"
	"strings"

	"github.com/burpsy-go/burpsy/internal/intruder"
)

// Attaching the session cookie jar to an Intruder attack.
//
// # The gap
//
// Server.cookieHeaderFor had exactly one caller, the Repeater send handler. An Intruder attack went
// out with whatever Cookie header the captured base request happened to carry — which is a cookie
// captured at some earlier moment, stale by the time the attack runs, and absent entirely for a base
// request built by hand. So an attack against an authenticated endpoint described the login wall
// rather than the endpoint, which is not a partial result: every bucket in the report is a fact about
// the wrong resource.
//
// Burp's behaviour, from settings/sessions/index.html: the jar "is shared between all of Burp's
// tools", and "the sessid cookie is updated when Intruder is fuzzing other parameters" — with the
// explicit exception that "when the Scanner or Intruder makes a request that manipulates a cookie
// […] that is affected by a session handling action, the session handling action is not applied to
// that request."
//
// # Why the jar wins, and where it does not
//
// The jar overwrites a same-named cookie in the base request rather than deferring to it. That is the
// opposite of the Repeater's rule ("a header the operator wrote always wins"), and deliberately: a
// Repeater request is bytes the operator is editing right now, while an Intruder base request is a
// capture from history whose Cookie header is a snapshot of a session that has probably since
// rotated. Deferring to it is how the whole attack goes out unauthenticated while the jar holds a
// live session.
//
// The exception is a cookie the attack is fuzzing. A payload spliced into a cookie value is the
// question being asked, and overwriting it from the jar would make every request in the attack
// identical — the attack would run, report a single bucket, and mean nothing. Those names are exempt
// and their values pass through exactly as spliced. This is Burp's rule and it is applied by name,
// taken from the selected PointCookieValue insertion points' labels.
//
// # Why this runs after the splice, not before
//
// Insertion points are byte spans into the base request, discovered from the stored message. Adding a
// Cookie header to the base bytes would shift every span after it and the splice would land in the
// wrong place. So the merge runs on the already-spliced request, inside the send path.

// exemptCookieNames returns the cookie names this attack is fuzzing, lowercased.
//
// Cookie names are case-sensitive per RFC 6265, but a server that accepts `SESSID` and `sessid` as
// one cookie is common enough that an exemption keyed case-sensitively would silently fail to exempt
// the position being fuzzed. Over-exempting leaves the spliced value alone, which is the safe
// direction: the failure is "one cookie was not refreshed", not "the attack asked the same question
// N times".
func exemptCookieNames(points []intruder.InsertionPoint) map[string]bool {
	out := make(map[string]bool, len(points))
	for _, p := range points {
		if p.Kind == intruder.PointCookieValue {
			out[strings.ToLower(strings.TrimSpace(p.Label))] = true
		}
	}
	return out
}

// cookiePair is one name=value pair from a Cookie header, kept as the exact source text so a value
// containing '=' or surrounding whitespace round-trips unchanged.
type cookiePair struct {
	name  string
	value string
}

// parseCookieHeader splits a Cookie header value into pairs. A segment with no '=' is kept with an
// empty name so it survives the rebuild: it is not a cookie this can reason about, and dropping bytes
// the operator's capture carried is not this function's business.
func parseCookieHeader(v string) []cookiePair {
	segs := strings.Split(v, ";")
	out := make([]cookiePair, 0, len(segs))
	for _, seg := range segs {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		name, value, ok := strings.Cut(seg, "=")
		if !ok {
			out = append(out, cookiePair{name: "", value: seg})
			continue
		}
		out = append(out, cookiePair{name: strings.TrimSpace(name), value: value})
	}
	return out
}

// applyJarCookies merges the jar's cookies into one spliced request's Cookie header.
//
// `jarHeader` is a Cookie header value ("a=1; b=2") as session.Coordinator.CookieHeader produces.
// `exempt` holds lowercased cookie names the attack is fuzzing, whose values are left exactly as
// they arrived. Returns `raw` unchanged when there is nothing to add, so an attack against an
// unauthenticated target allocates nothing per request.
//
// Merge order is the request's own pairs first, in their original order, then the jar's remaining
// names. Preserving the request's order matters for a target that is sensitive to it, and it means an
// attack whose base request already carries the jar's cookies is byte-identical to the one that ran
// before this existed.
func applyJarCookies(raw []byte, jarHeader string, exempt map[string]bool) []byte {
	if jarHeader == "" {
		return raw
	}
	jar := parseCookieHeader(jarHeader)
	if len(jar) == 0 {
		return raw
	}
	// Index the jar by lowercased name. A jar with two cookies of the same name cannot happen —
	// cookieJar is a map keyed by name — so last-wins here is unreachable rather than a policy.
	jarByName := make(map[string]string, len(jar))
	for _, p := range jar {
		if p.name != "" {
			jarByName[strings.ToLower(p.name)] = p.value
		}
	}

	head, body, terminated := repeaterHeadBody(raw)
	if !terminated {
		// No header terminator: there is nowhere honest to put a header, and rewriting a truncated
		// head would be guessing. Same refusal repeaterInsertHeader makes.
		return raw
	}

	lines := bytes.Split(head, []byte("\r\n"))
	used := make(map[string]bool, len(jarByName))
	rewrote := false
	kept := make([][]byte, 0, len(lines)+1)
	for _, line := range lines {
		i := bytes.IndexByte(line, ':')
		if i <= 0 || !strings.EqualFold(string(line[:i]), "Cookie") {
			kept = append(kept, line)
			continue
		}
		merged := make([]string, 0, 8)
		for _, p := range parseCookieHeader(string(line[i+1:])) {
			lower := strings.ToLower(p.name)
			switch {
			case p.name == "":
				merged = append(merged, p.value)
			case exempt[lower]:
				// The position being fuzzed. Passed through exactly as spliced — see the file comment.
				merged = append(merged, p.name+"="+p.value)
				used[lower] = true
			default:
				if v, ok := jarByName[lower]; ok {
					merged = append(merged, p.name+"="+v)
					used[lower] = true
					continue
				}
				merged = append(merged, p.name+"="+p.value)
			}
		}
		// Every jar cookie the request did not already name, appended to the first Cookie header. A
		// request with two Cookie headers gets the additions once, on the first, and the second is
		// merged in place: two Cookie headers is legal and some stacks read only the first, so
		// spraying the jar across both would change which cookies that stack sees.
		if !rewrote {
			for _, p := range jar {
				if p.name == "" {
					continue
				}
				lower := strings.ToLower(p.name)
				if used[lower] || exempt[lower] {
					continue
				}
				merged = append(merged, p.name+"="+p.value)
				used[lower] = true
			}
			rewrote = true
		}
		// A fresh slice, not append(line[:i+1], …): bytes.Split hands back subslices of one backing
		// array, so appending into this line would overwrite the lines after it.
		rebuilt := make([]byte, 0, i+2+len(merged)*24)
		rebuilt = append(rebuilt, line[:i+1]...)
		rebuilt = append(rebuilt, ' ')
		rebuilt = append(rebuilt, strings.Join(merged, "; ")...)
		kept = append(kept, rebuilt)
	}

	if !rewrote {
		// The request carried no Cookie header at all, so one is added with every non-exempt jar
		// cookie. An exempt name with nothing to splice into does not appear: the attack is fuzzing a
		// position that is not in this request, which selectPoints already refused.
		add := make([]string, 0, len(jar))
		for _, p := range jar {
			if p.name == "" || exempt[strings.ToLower(p.name)] {
				continue
			}
			add = append(add, p.name+"="+p.value)
		}
		if len(add) == 0 {
			return raw
		}
		kept = append(kept, []byte("Cookie: "+strings.Join(add, "; ")))
	}

	out := bytes.Join(kept, []byte("\r\n"))
	return append(append(out, '\r', '\n', '\r', '\n'), body...)
}
