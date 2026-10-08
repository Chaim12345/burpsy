package scanner

// Console authoring of custom scan checks (burpsy-react-ui-kbu1): Burp's Extensions > Custom scan
// checks — Import, New, Validate, Test, Export, Delete, Reload — over the same corpus the --bchecks
// directory loads. A check added here joins the one ordered entry list, and every change rebuilds the
// passive/active/insertion/tool sets from that list (classifyChecks) and swaps them in together, so the
// passive scanner, the audit engine (via the web layer's WithCorpusChecks) and the corpus leaf keep
// reading one corpus.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// OriginConsole marks a check imported or written in the console rather than loaded from a file.
const OriginConsole = "console"

// checkEntry is one loaded check, its source text, and where it came from: a file path under the
// --bchecks directory, or OriginConsole.
type checkEntry struct {
	check  *bcheck.Check
	source string
	origin string
}

// CheckEntry is the read-only view of one loaded check.
type CheckEntry struct {
	Name   string
	Origin string
	Source string
	Check  *bcheck.Check
}

// ErrCheckConflict is returned when an import names a check that is already loaded and may not be
// replaced: one from the directory (edit the file and reload), or a console one without replace.
var ErrCheckConflict = errors.New("a check with this name is already loaded")

// ErrCheckNotConsole is returned when the console tries to delete a check loaded from a file.
var ErrCheckNotConsole = errors.New("the check was loaded from the --bchecks directory")

// ErrNoCheckDir is returned by ReloadDir when the process started without --bchecks.
var ErrNoCheckDir = errors.New("no --bchecks directory was given at startup")

// Entries lists every loaded check in load order.
func (s *PassiveScanner) Entries() []CheckEntry {
	s.setsMu.RLock()
	defer s.setsMu.RUnlock()
	out := make([]CheckEntry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, CheckEntry{Name: e.check.Name, Origin: e.origin, Source: e.source, Check: e.check})
	}
	return out
}

// Entry finds a loaded check by name: the first one, in load order.
func (s *PassiveScanner) Entry(name string) (CheckEntry, bool) {
	for _, e := range s.Entries() {
		if e.Name == name {
			return e, true
		}
	}
	return CheckEntry{}, false
}

// ConsoleSources are the console-imported checks' sources, in order — what the project persists.
func (s *PassiveScanner) ConsoleSources() []string {
	var out []string
	for _, e := range s.Entries() {
		if e.Origin == OriginConsole {
			out = append(out, e.Source)
		}
	}
	return out
}

// ImportCheck parses src and adds it as a console check. A loaded check of the same name is a
// conflict, unless it is itself a console check and replace is set, in which case the new source
// takes its place in the order.
func (s *PassiveScanner) ImportCheck(src string, replace bool) (*bcheck.Check, error) {
	c, err := bcheck.Parse(src)
	if err != nil {
		return nil, err
	}
	s.setsMu.Lock()
	defer s.setsMu.Unlock()
	for i, e := range s.entries {
		if e.check.Name != c.Name {
			continue
		}
		if e.origin != OriginConsole {
			return nil, fmt.Errorf("%w: %q comes from %s — edit the file and reload", ErrCheckConflict, c.Name, filepath.Base(e.origin))
		}
		if !replace {
			return nil, fmt.Errorf("%w: %q was imported earlier", ErrCheckConflict, c.Name)
		}
		s.entries[i] = checkEntry{check: c, source: src, origin: OriginConsole}
		s.rebuildLocked()
		return c, nil
	}
	s.entries = append(s.entries, checkEntry{check: c, source: src, origin: OriginConsole})
	s.rebuildLocked()
	return c, nil
}

// RemoveCheck deletes a console check by name. A directory check is refused: the file would load it
// again on the next reload, so deleting it here would be a promise the corpus does not keep.
func (s *PassiveScanner) RemoveCheck(name string) error {
	s.setsMu.Lock()
	defer s.setsMu.Unlock()
	for i, e := range s.entries {
		if e.check.Name != name {
			continue
		}
		if e.origin != OriginConsole {
			return fmt.Errorf("%w (%s): remove the file and reload", ErrCheckNotConsole, filepath.Base(e.origin))
		}
		s.entries = append(s.entries[:i:i], s.entries[i+1:]...)
		s.rebuildLocked()
		return nil
	}
	return fmt.Errorf("no check named %q is loaded", name)
}

// ReloadDir re-reads the --bchecks directory: its files replace the directory's previous entries,
// console checks are kept after them, and a console check whose name a file now uses is dropped in
// the file's favour (and reported in the returned names).
func (s *PassiveScanner) ReloadDir() (LoadReport, []string, error) {
	s.setsMu.RLock()
	dir := s.dir
	s.setsMu.RUnlock()
	if dir == "" {
		return LoadReport{}, nil, ErrNoCheckDir
	}
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".bcheck") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return LoadReport{}, nil, err
	}
	sort.Strings(files)
	var fresh []checkEntry
	var errs []LoadError
	names := map[string]bool{}
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, LoadError{File: path, Err: err.Error()})
			continue
		}
		c, err := bcheck.Parse(string(src))
		if err != nil {
			errs = append(errs, LoadError{File: path, Err: err.Error()})
			continue
		}
		fresh = append(fresh, checkEntry{check: c, source: string(src), origin: path})
		names[c.Name] = true
	}
	s.setsMu.Lock()
	defer s.setsMu.Unlock()
	var shadowed []string
	for _, e := range s.entries {
		if e.origin != OriginConsole {
			continue
		}
		if names[e.check.Name] {
			shadowed = append(shadowed, e.check.Name)
			continue
		}
		fresh = append(fresh, e)
	}
	s.entries = fresh
	s.dirErrs, s.dirFiles = errs, len(files)
	s.rebuildLocked()
	return s.report, shadowed, nil
}

// rebuildLocked reclassifies every entry and swaps the sets in. Coverage counters carry over by name,
// so a reload does not zero the run counts of the checks it kept. Callers hold setsMu.
func (s *PassiveScanner) rebuildLocked() {
	checks := make([]*bcheck.Check, len(s.entries))
	for i, e := range s.entries {
		checks[i] = e.check
	}
	// Files counts the directory's files only: a console check is a check, not a file, and the summary
	// says "N files" (the passive/active counts below do include console checks).
	report := LoadReport{Files: s.dirFiles, Errors: append([]LoadError(nil), s.dirErrs...)}
	passive, active, insertion, tools, report := classifyChecks(checks, report)
	cov := newCoverageTracker(passive)
	if s.coverage != nil {
		old := map[string]CheckCoverage{}
		for _, c := range s.coverage.Snapshot().Checks {
			old[c.Name] = c
		}
		for i := range cov.perCheck {
			if o, ok := old[cov.perCheck[i].Name]; ok {
				cov.perCheck[i] = o
			}
		}
	}
	s.passive, s.active, s.insertion, s.tools, s.report, s.coverage = passive, active, insertion, tools, report, cov
}
