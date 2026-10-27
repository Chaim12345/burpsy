package web

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
		// Bounded before it is read: the merged list is built in this process, and a wordlist path
		// naming something huge (or a device that never ends) must not exhaust it.
		if info, serr := os.Stat(req.Wordlist); serr == nil && (!info.Mode().IsRegular() || info.Size() > maxMergedWordlistBytes) {
			return "", 0, fmt.Errorf("wordlist %q is not a regular file of at most %d MiB", req.Wordlist, maxMergedWordlistBytes>>20)
		}
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
		os.RemoveAll(dir)
		return "", 0, werr
	}
	return path, len(lines), nil
}

// removeMergedWordlist deletes the merged wordlist and the directory
// discoveryWordlist made for it. The directory is removed only when it carries
// that function's own prefix, so a path from anywhere else can never take a
// shared directory with it.
func removeMergedWordlist(path string) {
	dir := filepath.Dir(path)
	if strings.HasPrefix(filepath.Base(dir), "burpsy-discovery-") && filepath.Base(path) == "merged.txt" {
		os.RemoveAll(dir)
		return
	}
	os.Remove(path)
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
		// The path without its query or fragment: a query is not a name the site uses for a
		// resource, and its '?', '=' and escapes would go out as request paths.
		path, _, _ := strings.Cut(ex.Path, "?")
		path, _, _ = strings.Cut(path, "#")
		segments := strings.Split(strings.Trim(path, "/"), "/")
		for i, seg := range segments {
			if seg == "" {
				continue
			}
			if decoded, err := url.PathUnescape(seg); err == nil {
				seg = decoded
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
	if n, digits, ok := trailingNumber(seg); ok {
		// The digits' own width is kept, so report009 derives report010, not report0010.
		base := seg[:len(seg)-digits]
		out = append(out, fmt.Sprintf("%s%0*d", base, digits, n+1), fmt.Sprintf("%s%0*d", base, digits, n+2))
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

// trailingNumber splits a trailing run of digits off name's end, returning the
// value and how many digits spelled it.
func trailingNumber(name string) (int, int, bool) {
	i := len(name)
	for i > 0 && name[i-1] >= '0' && name[i-1] <= '9' {
		i--
	}
	if i == len(name) || len(name)-i > 9 {
		return 0, 0, false
	}
	n, err := strconv.Atoi(name[i:])
	if err != nil {
		return 0, 0, false
	}
	return n, len(name) - i, true
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
// skipped because scope refused them before launch, how many ffuf runs the
// depth took and how many of those failed. Level 0 is the base sweep's own
// variant and derivation passes; it is recorded only when one ran. A level that
// was refused everywhere says so with Skipped and a zero Discovered, which is a
// different sentence from an empty level that ran.
type discoveryLevel struct {
	Level      int `json:"level"`
	Discovered int `json:"discovered"`
	// OutOfScope counts results the post-run filter dropped at this depth.
	OutOfScope int `json:"out_of_scope"`
	// Skipped counts directories this depth never swept: scope refused them
	// before launch, or a session bound (Capped) was reached. Counted, not
	// fetched — egress stays scope-checked per directory, which is the reason
	// ffuf's own -recursion is not used.
	Skipped int `json:"skipped"`
	// Runs is how many ffuf invocations this depth made (sweeps plus the
	// variant and derivation passes that ran at it).
	Runs int `json:"runs"`
	// Failed is how many of those runs did not complete; their directories
	// were not swept, and the level's counts are a floor.
	Failed int `json:"failed"`
	// Capped names the session bound that stopped this level early, empty when
	// none did.
	Capped string `json:"capped,omitempty"`
}

// maxMergedWordlistBytes bounds the operator's own wordlist, read into this process to merge it.
const maxMergedWordlistBytes = 64 << 20

// The session's bounds. A target that answers every word with a directory
// redirect (a catch-all) would otherwise multiply each level by the wordlist
// and send traffic until stopped; the bounds turn that into a recorded stop.
const (
	// MaxDiscoveryRecurseDepth is the deepest recursion a request may ask for.
	MaxDiscoveryRecurseDepth = 5
	// maxDiscoveryDirsPerLevel bounds the directories swept at one depth.
	maxDiscoveryDirsPerLevel = 50
	// maxDiscoveryRuns bounds the ffuf invocations of one session.
	maxDiscoveryRuns = 300
)

// runDiscoverySession drives the whole session: the base sweep, its variant and
// derivation passes, then recursion to the requested depth with the same passes
// in each directory swept.
//
// ctx cancellation stops between runs at the latest — each RunFFUF honours it
// — so the dashboard's stop button ends the session at a run boundary, and the
// levels that had already finished stand as recorded.
func (s *Server) runDiscoverySession(ctx context.Context, cfg extscan.Config, target extscan.Target, req discoveryStartReq, wordlist string) discoverySession {
	session := discoverySession{}
	runs := 0
	// Every sweep's egress-gate refusals, summed onto the session result at the end so the summary
	// counts the whole session's, not the base sweep's alone.
	gateRefused := 0
	sweep := func(t extscan.Target, opts extscan.FFUFOptions) extscan.FFUFResult {
		runs++
		opts.MatchCodes, opts.Threads, opts.Rate = req.MatchCodes, req.Threads, req.Rate
		r := extscan.RunFFUF(ctx, cfg, s.scope, t, opts)
		gateRefused += r.GateRefused
		return r
	}

	// The base sweep: exactly the flat run, with the merged wordlist.
	base := sweep(target, extscan.FFUFOptions{Wordlist: wordlist, Extensions: req.Extensions})
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
	record := func(level *discoveryLevel, found []extscan.Discovery) []extscan.Discovery {
		var fresh []extscan.Discovery
		for _, d := range found {
			if seenURL[d.URL] {
				continue
			}
			seenURL[d.URL] = true
			level.Discovered++
			session.Result.Discoveries = append(session.Result.Discoveries, d)
			fresh = append(fresh, d)
		}
		return fresh
	}

	// The variant-extension and derivation passes over one directory's
	// discoveries, swept in that directory. Run for the base sweep and for every
	// directory recursion reaches, so a file the base sweep found (config.php)
	// is variant-tested (config.bak) whether or not recursion was asked for.
	passes := func(level *discoveryLevel, dir extscan.Target, found []extscan.Discovery) {
		if req.VariantExtensions != "" && ctx.Err() == nil && runs < maxDiscoveryRuns {
			if stems := fileStems(found); len(stems) > 0 {
				if stemsFile, werr := writeSessionWordlist(stems); werr == nil {
					variant := sweep(dir, extscan.FFUFOptions{Wordlist: stemsFile, Extensions: req.VariantExtensions})
					os.Remove(stemsFile)
					level.Runs++
					if variant.Outcome == extscan.OutcomeCompleted {
						level.OutOfScope += variant.OutOfScope
						record(level, variant.Discoveries)
					} else {
						level.Failed++
					}
				}
			}
		}
		if req.Derivations && ctx.Err() == nil && runs < maxDiscoveryRuns {
			var derived []string
			seen := map[string]bool{}
			for _, d := range found {
				for _, name := range deriveDiscoveryNames(d) {
					if !seen[name] {
						seen[name] = true
						derived = append(derived, name)
					}
				}
			}
			if len(derived) > 0 {
				if derivedFile, werr := writeSessionWordlist(derived); werr == nil {
					pass := sweep(dir, extscan.FFUFOptions{Wordlist: derivedFile})
					os.Remove(derivedFile)
					level.Runs++
					if pass.Outcome == extscan.OutcomeCompleted {
						level.OutOfScope += pass.OutOfScope
						record(level, pass.Discoveries)
					} else {
						level.Failed++
					}
				}
			}
		}
	}

	baseLevel := discoveryLevel{Level: 0}
	passes(&baseLevel, target, base.Discoveries)
	if baseLevel.Runs > 0 {
		session.Levels = append(session.Levels, baseLevel)
	}

	// Directories the base sweep found, for depth 1. Kept as URLs in the
	// target's own form so the scope check and the sweep see the same string.
	frontier := sessionDirectories(target, base.Discoveries)
	depthLimit := min(req.RecurseDepth, MaxDiscoveryRecurseDepth)

	for depth := 1; depth <= depthLimit && len(frontier) > 0 && ctx.Err() == nil; depth++ {
		level := discoveryLevel{Level: depth}
		var next []discoveryDirectory

		for i, dir := range frontier {
			if ctx.Err() != nil {
				level.Skipped += len(frontier) - i
				break
			}
			if i >= maxDiscoveryDirsPerLevel || runs >= maxDiscoveryRuns {
				level.Skipped += len(frontier) - i
				if i >= maxDiscoveryDirsPerLevel {
					level.Capped = fmt.Sprintf("%d directories per level", maxDiscoveryDirsPerLevel)
				} else {
					level.Capped = fmt.Sprintf("%d ffuf runs per session", maxDiscoveryRuns)
				}
				break
			}
			// Scope BEFORE launch: this is the one place a subdirectory can
			// be refused without a single request reaching it, and the count
			// is kept rather than the directory quietly dropped.
			sub, err := extscan.Authorise(s.scope, dir.url)
			if err != nil {
				level.Skipped++
				continue
			}
			res := sweep(sub, extscan.FFUFOptions{Wordlist: wordlist, Extensions: req.Extensions})
			level.Runs++
			if res.Outcome != extscan.OutcomeCompleted {
				// A failed subdirectory run does not end the session — the
				// other directories at this depth are independent sweeps — but
				// it is counted, so the level does not read as complete.
				level.Failed++
				continue
			}
			level.OutOfScope += res.OutOfScope
			fresh := record(&level, res.Discoveries)
			var newDirs []extscan.Discovery
			for _, d := range fresh {
				if isDirectoryDiscovery(d) {
					newDirs = append(newDirs, d)
				}
			}
			next = append(next, sessionDirectories(sub, newDirs)...)
			passes(&level, sub, res.Discoveries)
		}

		session.Levels = append(session.Levels, level)
		frontier = next
	}

	session.Result.OutOfScope += levelScopeDrops(session.Levels)
	session.Result.GateRefused = gateRefused
	return session
}

// sessionDirectories turns one sweep's discoveries into the directory URLs to
// sweep next. ffuf reports each discovery's path from the host root, so the URL
// is the parent's scheme and authority plus that path — never the parent's own
// URL plus it, which doubles any path prefix the parent had (/app/ + /app/admin).
// A redirect ffuf reported to the directory's canonical form on the same origin
// is taken as given.
func sessionDirectories(parent extscan.Target, discoveries []extscan.Discovery) []discoveryDirectory {
	origin := parent.URL
	if u, err := url.Parse(parent.URL); err == nil && u.Scheme != "" && u.Host != "" {
		origin = u.Scheme + "://" + u.Host
	}
	var out []discoveryDirectory
	seen := map[string]bool{}
	for _, d := range discoveries {
		if !isDirectoryDiscovery(d) {
			continue
		}
		dirURL := d.Redirect
		if dirURL == "" || !strings.HasPrefix(dirURL, origin+"/") {
			dirURL = origin + "/" + strings.TrimPrefix(strings.TrimSuffix(d.Path, "/"), "/") + "/"
		}
		dirURL = strings.TrimSuffix(dirURL, "/") + "/"
		if seen[dirURL] {
			continue
		}
		seen[dirURL] = true
		out = append(out, discoveryDirectory{url: dirURL})
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
