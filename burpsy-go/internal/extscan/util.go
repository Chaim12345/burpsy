package extscan

import (
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// isNotAllowed distinguishes "the operator never allowed this tool" from "the
// allowed tool's binary is missing", which are different things to tell someone
// and different outcomes to record.
func isNotAllowed(err error) bool { return errors.Is(err, ErrNotAllowed) }

// pathOf extracts the path from a URL a tool reported, defaulting to "/". A
// URL this package cannot parse yields "/" rather than an error: the tool
// already made the request, and a scope re-check against "/" is the
// conservative reading of an address burpsy cannot interpret.
func pathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return "/"
	}
	return u.Path
}

// statusText names a status code the way a row title should. Codes the stdlib
// does not know are rendered as the bare number by the caller's format string.
func statusText(code int) string {
	if t := http.StatusText(code); t != "" {
		return t
	}
	return "response"
}

func sortInts(v []int) { sort.Ints(v) }

func sortStringsBy(v []string, less func(a, b string) bool) {
	sort.SliceStable(v, func(i, j int) bool { return less(v[i], v[j]) })
}

// sortedKeys renders a set as a stable slice, so a report of the same run is
// byte-identical every time it is rendered.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// dedupe removes repeats while keeping first-seen order.
func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
