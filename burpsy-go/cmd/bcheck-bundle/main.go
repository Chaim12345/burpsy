// Command bcheck-bundle regenerates internal/bcheck/bundled/portswigger from a checkout of
// PortSwigger's BChecks repository: it copies the importable checks verbatim, copies the upstream
// LICENSE, and writes a manifest that accounts for every upstream `.bcheck` file.
//
//	go run ./cmd/bcheck-bundle -src /path/to/BChecks -commit <sha> -commit-date <date>
//
// Review decisions are carried forward from the existing manifest, keyed by upstream path AND
// digest: an exclusion (unsafe, weak-evidence, false-positive, interpreter-gap) survives a
// re-import of the same bytes, and a file whose bytes changed upstream comes back "unreviewed" —
// disabled until someone reads it again. A new upstream file is unreviewed for the same reason.
// Nothing is enabled by this command that a person has not looked at.
//
// The command never decides precision itself. The vulnapp sweep in internal/scanner
// (bundled_corpus_test.go) is what finds false positives; its findings are recorded here as
// false-positive exclusions by editing the manifest.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/bcheck/bundled"
)

func main() {
	src := flag.String("src", "", "checkout of github.com/PortSwigger/BChecks")
	commit := flag.String("commit", "", "upstream commit the checkout is at")
	commitDate := flag.String("commit-date", "", "that commit's date")
	out := flag.String("out", "internal/bcheck/bundled/"+bundled.Root, "output directory")
	flag.Parse()
	if *src == "" || *commit == "" {
		fmt.Fprintln(os.Stderr, "bcheck-bundle: -src and -commit are required")
		os.Exit(2)
	}
	if err := run(*src, *commit, *commitDate, *out); err != nil {
		fmt.Fprintln(os.Stderr, "bcheck-bundle:", err)
		os.Exit(1)
	}
}

func run(src, commit, commitDate, out string) error {
	prev := map[string]bundled.Entry{}
	if raw, err := os.ReadFile(filepath.Join(out, "manifest.json")); err == nil {
		var m bundled.Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("existing manifest: %w", err)
		}
		for _, e := range m.Entries {
			prev[e.SourcePath] = e
		}
	}

	var paths []string
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(p), ".bcheck") {
			rel, err := filepath.Rel(src, p)
			if err != nil {
				return err
			}
			paths = append(paths, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(paths)

	checksDir := filepath.Join(out, "checks")
	if err := os.RemoveAll(checksDir); err != nil {
		return err
	}
	m := bundled.Manifest{Source: bundled.Source{
		Repository:  "https://github.com/PortSwigger/BChecks",
		Commit:      commit,
		CommitDate:  commitDate,
		License:     "LGPL-3.0",
		LicenseFile: bundled.Root + "/LICENSE",
		NoticeFile:  bundled.Root + "/NOTICE",
		ImportedAt:  time.Now().UTC().Format("2006-01-02"),
		Importer:    "go run ./cmd/bcheck-bundle",
	}}
	for _, rel := range paths {
		raw, err := os.ReadFile(filepath.Join(src, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		e := bundled.Entry{SourcePath: rel, SHA256: hex.EncodeToString(sum[:])}
		c, perr := bcheck.Parse(string(raw))
		if perr != nil {
			e.ParseError = perr.Error()
			e.Exclusion = &bundled.Exclusion{Category: bundled.CategoryParseError, Reason: "the parser refuses it: " + perr.Error()}
			m.Entries = append(m.Entries, e)
			continue
		}
		e.Parses, e.Name, e.Given, e.Family = true, c.Name, c.Given, family(c)

		old, reviewed := prev[rel]
		reviewed = reviewed && old.SHA256 == e.SHA256 && !(old.Exclusion != nil && old.Exclusion.Category == bundled.CategoryUnreviewed)
		switch {
		case e.Family == bundled.FamilyPassive:
			e.Exclusion = &bundled.Exclusion{Category: bundled.CategoryPassive, Reason: "a `given response` check: check_corpus gates the active audit only, so the passive set is recorded and not embedded"}
		case reviewed:
			e.Exclusion, e.RunGap, e.Runs = old.Exclusion, old.RunGap, old.Runs
		default:
			e.Exclusion = &bundled.Exclusion{Category: bundled.CategoryUnreviewed, Reason: "new or changed upstream: not yet reviewed for safety and precision"}
		}
		unsafe := e.Exclusion != nil && e.Exclusion.Category == bundled.CategoryUnsafe
		if e.Family != bundled.FamilyPassive && !unsafe {
			e.Imported = true
			e.File = "checks/" + rel
			dst := filepath.Join(checksDir, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(dst, raw, 0o644); err != nil {
				return err
			}
		}
		if !e.Imported {
			e.Runs = false
		}
		e.Enabled = e.Exclusion == nil
		m.Entries = append(m.Entries, e)
	}

	lic, err := os.ReadFile(filepath.Join(src, "LICENSE"))
	if err != nil {
		return fmt.Errorf("upstream LICENSE: %w", err)
	}
	if err := os.WriteFile(filepath.Join(out, "LICENSE"), lic, 0o644); err != nil {
		return err
	}
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), append(buf, '\n'), 0o644); err != nil {
		return err
	}
	cnt := m.Counts()
	fmt.Printf("upstream %d, imported %d, parses %d, runs %d, enabled %d, excluded %v\n",
		cnt.Upstream, cnt.Imported, cnt.Parses, cnt.Runs, cnt.Enabled, cnt.ByCategory)
	return nil
}

// family classifies a check the way the scanner's load report does (classifyChecks).
func family(c *bcheck.Check) string {
	switch {
	case c.NeedsCollaborator():
		return bundled.FamilyCollaborator
	case c.NeedsTool():
		return bundled.FamilyTool
	case c.IsPassive():
		return bundled.FamilyPassive
	case c.M2Runnable():
		return bundled.FamilyActive
	default:
		return bundled.FamilyInsertionPoint
	}
}
