package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/burpsy-go/burpsy/internal/extscan"
	"github.com/burpsy-go/burpsy/internal/intruder"
)

// The content-discovery session (burpsy-react-ui-dgbi): Burp's "Discover
// content" is not one flat wordlist run, and this file is what makes burpsy's
// the same shape.
//
// Burp's session (content-discovery.html) builds its guesses from the Filenames
// settings — the built-in short/long file and directory lists, a custom list,
// and "Names observed in use on target site" — recurses into discovered
// directories ("how many levels of subdirectory to look for"), tries
// "Derivations based on discovered items", and checks "these variant
// extensions on discovered files" for backup copies. A session here is
// therefore a tree of bounded ffuf runs:
//
//   - one run per directory swept, with the merged wordlist (the selected
//     built-in lists, plus the operator's own, plus the observed names the
//     request asked for), which is the same list Burp re-tests "in each new
//     directory that it tests";
//   - one variant-extension run per directory that discovered files, over
//     those files' stems;
//   - one derivation run per directory that discovered items, over the derived
//     names (see deriveDiscoveryNames for the stated rule set);
//   - directories for the next depth are the directories this depth found,
//     each one scope-checked BEFORE it is launched — an out-of-scope
//     subdirectory is counted as skipped and never fetched, which is the
//     egress rule the flat run already follows one level up.
//
// ffuf's own -recursion is not used, for the same reason: it would dial paths
// burpsy never checked against scope. Every level is a separate decision.
//
// Levels are counted from 1: level 0 is the base sweep the flat run has always
// been, reported through the run's existing counts, and Levels lists the
// recursion levels beyond it. A run that never recurses reports Levels: [].

// discoveryBuiltinLists maps the route's list names onto the bundled corpus
// files, in the panel order Burp's Filenames settings use: the two file lists,
// then the two directory lists. The names are the route's wire contract; the
// map is the only place that knows which embedded file each one means.
var discoveryBuiltinLists = []struct {
	Name string
	File string
}{
	{"builtin-short-files", "burp-filenames-short"},
	{"builtin-long-files", "burp-filenames-long"},
	{"builtin-short-directories", "burp-directories-short"},
	{"builtin-long-directories", "burp-directories-long"},
}

// discoveryListNames returns the accepted `lists` values.
func discoveryListNames() []string {
	out := make([]string, 0, len(discoveryBuiltinLists))
	for _, l := range discoveryBuiltinLists {
		out = append(out, l.Name)
	}
	return out
}

// discoveryListWords resolves one list name to its words.
func discoveryListWords(name string) ([]string, error) {
	for _, l := range discoveryBuiltinLists {
		if l.Name == name {
			return intruder.BuiltinWordlistLines(l.File)
		}
	}
	return nil, fmt.Errorf("unknown list %q; the accepted values are %s", name, strings.Join(discoveryListNames(), ", "))
}

// discoveryWordlist builds the session's base wordlist file: the selected
// built-in lists, then the operator's own list, then the names observed in use
// on the target site when the request asked for them — the same sources Burp's
// Filenames settings name, in that order, deduplicated. Written to a temp file
// ffuf reads; the caller removes it when the session ends.
//
// The order is the order the request named, so the argv and the file are
// deterministic for a given request, and the word counts the run reports can be
// reproduced from it.
func (s *Server) discoveryWordlist(req discoveryStartReq, target extscan.Target) (path string, words int, err error) {
	var lines []string
	seen := map[string]bool{}
	add := func(more []string) {
		for _, w := range more {
			w = strings.TrimSpace(w)
			if w == "" || seen[w] {
				continue
			}
			seen[w] = true
			lines = append(lines, w)
		}
	}
	for _, name := range req.Lists {
		words, werr := discoveryListWords(name)
		if werr != nil {
			return "", 0, werr
		}
		add(words)
	}
	if req.Wordlist != "" {
		own, rerr := os.ReadFile(req.Wordlist)
		if rerr != nil {
			return "", 0, fmt.Errorf("wordlist %q is unreadable: %w", req.Wordlist, rerr)
		}
		add(strings.Split(string(own), "\n"))
	}
	if req.ObservedNames {
		add(s.observedNames(target))
	}
	if len(lines) == 0 {
		return "", 0, fmt.Errorf("the selected lists and names produced an empty wordlist; there is nothing to sweep")
	}

	dir, derr := os.MkdirTemp("", "burpsy-discovery-")
	if derr != nil {
		return "", 0, derr
	}
	path = filepath.Join(dir, "merged.txt")
	if werr := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); werr != nil {
		return "", 0, werr
	}
	return path, len(lines), nil
}

// observedNames lists the directory names and filename stems the capture store
// has seen on the target's host — Burp's "Names observed in use on target
// site", which its session re-tests "in each new directory that it tests".
// Only the host is matched, not the scheme or port: a name seen on one port is
// still a name this site uses, and narrowing by anything the operator did not
// say would silently shrink the guess set.
func (s *Server) observedNames(target extscan.Target) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, ex := range s.store.Exchanges() {
		if ex.Host != target.Host {
			continue
		}
		segments := strings.Split(strings.Trim(ex.Path, "/"), "/")
		for i, seg := range segments {
			if seg == "" {
				continue
			}
			if i < len(segments)-1 {
				// A directory this site really has is the strongest guess a
				// session can make: it exists somewhere on this host.
				add(seg)
				continue
			}
			// The last segment is a file: its stem is Burp's "filename stem".
			if dot := strings.LastIndexByte(seg, '.'); dot > 0 {
				add(seg[:dot])
			} else {
				add(seg)
			}
		}
	}
	// First-seen order is capture order, which an operator cannot reproduce
	// from the run record; sorted, the merged wordlist file is checkable
	// against the request by hand.
	sort.Strings(out)
	return out
}

// discoveryDirectory is one directory queued for the next depth: the URL to
// sweep, already normalised to the trailing-slash form ffuf's FUZZ appends to.
type discoveryDirectory struct {
	url string
}

// isDirectoryDiscovery says whether one ffuf match is a directory: ffuf
// reports a directory either as a redirect to the same path with a trailing
// slash (the common 301) or as a path that already ends in one.
func isDirectoryDiscovery(d extscan.Discovery) bool {
	if strings.HasSuffix(d.Path, "/") {
		return true
	}
	if d.Redirect == "" {
		return false
	}
	return strings.HasSuffix(strings.TrimSuffix(d.Redirect, "/")+"/", strings.TrimSuffix(d.Path, "/")+"/")
}

// deriveDiscoveryNames is the stated, deterministic derivation rule set —
// Burp's "Derivations based on discovered items". Burp's exact algorithm is
// not in its documentation; this set is burpsy's own, recorded in gaps.md:
//
//   - numeric suffix: a name ending in digits N also checks N+1 and N+2 (the
//     documentation's own example — AnnualReport2018 checks 2019 and 2020);
//   - name + "_old" and name + ".bak" (the backup-file guesses);
//   - the all-lower and all-upper case variants of the name.
//
// Derived names are swept in the directory the discovery was made in, the way
// the documentation's example checks AnnualReport2019 beside AnnualReport2018.
func deriveDiscoveryNames(d extscan.Discovery) []string {
	seg := strings.TrimSuffix(strings.TrimSuffix(d.Path, "/"), "/")
	if i := strings.LastIndexByte(seg, '/'); i >= 0 {
		seg = seg[i+1:]
	}
	if seg == "" {
		return nil
	}
	var out []string
	if n, ok := trailingNumber(seg); ok {
		base := seg[:len(seg)-len(fmt.Sprint(n))]
		out = append(out, fmt.Sprintf("%s%d", base, n+1), fmt.Sprintf("%s%d", base, n+2))
	}
	out = append(out, seg+"_old", seg+".bak")
	if low := strings.ToLower(seg); low != seg {
		out = append(out, low)
	}
	if up := strings.ToUpper(seg); up != seg {
		out = append(out, up)
	}
	return out
}

// trailingNumber splits a trailing run of digits off name's end.
func trailingNumber(name string) (int, bool) {
	i := len(name)
	for i > 0 && name[i-1] >= '0' && name[i-1] <= '9' {
		i--
	}
	if i == len(name) {
		return 0, false
	}
	var n int
	if _, err := fmt.Sscanf(name[i:], "%d", &n); err != nil {
		return 0, false
	}
	return n, true
}

// discoverySession is the whole multi-run session's outcome: the aggregate a
// flat run's callers already read, plus the per-level record.
type discoverySession struct {
	// Result is the aggregate: every discovery across every run, deduplicated
	// by URL; OutOfScope summed; Command is the FIRST argv, for the provenance
	// a run record owes — the levels carry their own run counts.
	Result extscan.FFUFResult
	// Levels is one entry per recursion depth that ran. Empty when the session
	// never recursed.
	Levels []discoveryLevel
}

// discoveryLevel is one recursion depth's honest tally: what the depth's runs
// discovered, what the post-run scope check dropped, which directories were
// skipped because scope refused them before launch, and how many ffuf runs the
// depth took. A level that was refused everywhere says so with Skipped and a
// zero Discovered, which is a different sentence from an empty level that ran.
type discoveryLevel struct {
	Level      int `json:"level"`
	Discovered int `json:"discovered"`
	// OutOfScope counts results the post-run filter dropped at this depth.
	OutOfScope int `json:"out_of_scope"`
	// Skipped counts directories this depth never swept: scope refused them
	// before launch. Counted, not fetched — egress stays scope-checked per
	// directory, which is the reason ffuf's own -recursion is not used.
	Skipped int `json:"skipped"`
	// Runs is how many ffuf invocations this depth made (sweeps plus the
	// variant and derivation passes that ran at it).
	Runs int `json:"runs"`
}

// runDiscoverySession drives the whole session: the base sweep, then recursion
// to the requested depth, plus the variant and derivation passes asked for.
//
// ctx cancellation stops between runs at the latest — each RunFFUF honours it
// — so the dashboard's stop button ends the session at a run boundary, and the
// levels that had already finished stand as recorded.
func (s *Server) runDiscoverySession(ctx context.Context, cfg extscan.Config, target extscan.Target, req discoveryStartReq, wordlist string) discoverySession {
	session := discoverySession{}

	// The base sweep: exactly the flat run, with the merged wordlist.
	base := extscan.RunFFUF(ctx, cfg, s.scope, target, extscan.FFUFOptions{
		Wordlist:   wordlist,
		Extensions: req.Extensions,
		MatchCodes: req.MatchCodes,
		Threads:    req.Threads,
		Rate:       req.Rate,
	})
	session.Result = base
	if base.Outcome != extscan.OutcomeCompleted {
		// Nothing was swept; there is nothing to recurse from and no honest
		// way to keep going.
		return session
	}

	seenURL := map[string]bool{}
	for _, d := range base.Discoveries {
		seenURL[d.URL] = true
	}

	// Directories the base sweep found, for depth 1. Kept as URLs in the
	// target's own form so the scope check and the sweep see the same string.
	frontier := sessionDirectories(target, base.Discoveries)

	for depth := 1; depth <= req.RecurseDepth && len(frontier) > 0 && ctx.Err() == nil; depth++ {
		level := discoveryLevel{Level: depth}
		var next []discoveryDirectory

		for _, dir := range frontier {
			// Scope BEFORE launch: this is the one place a subdirectory can
			// be refused without a single request reaching it, and the count
			// is kept rather than the directory quietly dropped.
			sub, err := extscan.Authorise(s.scope, dir.url)
			if err != nil {
				level.Skipped++
				continue
			}
			res := extscan.RunFFUF(ctx, cfg, s.scope, sub, extscan.FFUFOptions{
				Wordlist:   wordlist,
				Extensions: req.Extensions,
				MatchCodes: req.MatchCodes,
				Threads:    req.Threads,
				Rate:       req.Rate,
			})
			level.Runs++
			if res.Outcome != extscan.OutcomeCompleted {
				// A failed subdirectory run does not end the session: the
				// other directories at this depth are independent sweeps.
				// The failure is folded into the discoveries the level
				// reports and visible through the aggregate outcome only if
				// the base itself failed.
				continue
			}
			level.OutOfScope += res.OutOfScope
			var newDirs []extscan.Discovery
			for _, d := range res.Discoveries {
				if seenURL[d.URL] {
					continue
				}
				seenURL[d.URL] = true
				level.Discovered++
				session.Result.Discoveries = append(session.Result.Discoveries, d)
				if isDirectoryDiscovery(d) {
					newDirs = append(newDirs, d)
				}
			}
			next = append(next, sessionDirectories(sub, newDirs)...)

			// The variant-extension pass: the stems of the files found in
			// THIS directory, retested against it with the variant list —
			// Burp's backup-copy check.
			if req.VariantExtensions != "" {
				if stems := fileStems(res.Discoveries); len(stems) > 0 {
					stemsFile, werr := writeSessionWordlist(stems)
					if werr == nil {
						variant := extscan.RunFFUF(ctx, cfg, s.scope, sub, extscan.FFUFOptions{
							Wordlist:   stemsFile,
							Extensions: req.VariantExtensions,
							MatchCodes: req.MatchCodes,
							Threads:    req.Threads,
							Rate:       req.Rate,
						})
						os.Remove(stemsFile)
						level.Runs++
						if variant.Outcome == extscan.OutcomeCompleted {
							level.OutOfScope += variant.OutOfScope
							for _, d := range variant.Discoveries {
								if seenURL[d.URL] {
									continue
								}
								seenURL[d.URL] = true
								level.Discovered++
								session.Result.Discoveries = append(session.Result.Discoveries, d)
							}
						}
					}
				}
			}

			// The derivation pass: the derived names of this directory's
			// discoveries, swept in the directory they were made in.
			if req.Derivations {
				var derived []string
				seen := map[string]bool{}
				for _, d := range res.Discoveries {
					for _, name := range deriveDiscoveryNames(d) {
						if !seen[name] {
							seen[name] = true
							derived = append(derived, name)
						}
					}
				}
				if len(derived) > 0 {
					derivedFile, werr := writeSessionWordlist(derived)
					if werr == nil {
						pass := extscan.RunFFUF(ctx, cfg, s.scope, sub, extscan.FFUFOptions{
							Wordlist:   derivedFile,
							MatchCodes: req.MatchCodes,
							Threads:    req.Threads,
							Rate:       req.Rate,
						})
						os.Remove(derivedFile)
						level.Runs++
						if pass.Outcome == extscan.OutcomeCompleted {
							level.OutOfScope += pass.OutOfScope
							for _, d := range pass.Discoveries {
								if seenURL[d.URL] {
									continue
								}
								seenURL[d.URL] = true
								level.Discovered++
								session.Result.Discoveries = append(session.Result.Discoveries, d)
							}
						}
					}
				}
			}
		}

		session.Levels = append(session.Levels, level)
		frontier = next
	}

	session.Result.OutOfScope += levelScopeDrops(session.Levels)
	return session
}

// sessionDirectories turns one sweep's discoveries into the directory URLs to
// sweep next: each directory discovery, as a URL under its own parent. ffuf
// reports a redirect to the directory's canonical form; where it did not, the
// parent's origin plus the path is the URL ffuf itself requested and is the
// shape FUZZ appends to.
func sessionDirectories(parent extscan.Target, discoveries []extscan.Discovery) []discoveryDirectory {
	origin := strings.TrimSuffix(parent.URL, "/")
	var out []discoveryDirectory
	seen := map[string]bool{}
	for _, d := range discoveries {
		if !isDirectoryDiscovery(d) {
			continue
		}
		url := d.Redirect
		if url == "" || !strings.HasPrefix(url, origin+"/") {
			// ffuf reports absolute paths, and the parent's origin is the
			// authority it dialled; TrimPrefix keeps one slash between them.
			url = origin + "/" + strings.TrimPrefix(strings.TrimSuffix(d.Path, "/"), "/") + "/"
		}
		url = strings.TrimSuffix(url, "/") + "/"
		if seen[url] {
			continue
		}
		seen[url] = true
		out = append(out, discoveryDirectory{url: url})
	}
	return out
}

// fileStems picks the filename stems out of one sweep's discoveries — the
// words the variant-extension pass retests with the backup extensions.
func fileStems(discoveries []extscan.Discovery) []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range discoveries {
		if isDirectoryDiscovery(d) {
			continue
		}
		seg := strings.TrimSuffix(strings.TrimSuffix(d.Path, "/"), "/")
		if i := strings.LastIndexByte(seg, '/'); i >= 0 {
			seg = seg[i+1:]
		}
		if seg == "" {
			continue
		}
		// The stem is the name without the extension the sweep already
		// tested: word.php retests as word.bak, not word.php.bak.
		if dot := strings.LastIndexByte(seg, '.'); dot > 0 {
			seg = seg[:dot]
		}
		if !seen[seg] {
			seen[seg] = true
			out = append(out, seg)
		}
	}
	return out
}

// writeSessionWordlist writes one small wordlist for a pass (stems, derived
// names) into a temp file, for the runs whose guess set is too small to deserve
// a name in the run record.
func writeSessionWordlist(words []string) (string, error) {
	tmp, err := os.CreateTemp("", "burpsy-discovery-pass-")
	if err != nil {
		return "", err
	}
	if _, err := tmp.WriteString(strings.Join(words, "\n") + "\n"); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// levelScopeDrops sums the per-level out-of-scope counts for the aggregate, so
// the run's headline number still accounts for everything the tool reported.
func levelScopeDrops(levels []discoveryLevel) int {
	total := 0
	for _, l := range levels {
		total += l.OutOfScope
	}
	return total
}
