package bundled

import (
	"io/fs"
	"path"
	"strings"
	"testing"
)

func loadManifest(t *testing.T) *Manifest {
	t.Helper()
	m, err := LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The manifest and the embedded tree describe each other exactly: every embedded check is listed
// with its digest, every imported entry's file is there and hashes to the recorded value, and
// every entry that is not enabled says why.
func TestTheManifestMatchesTheEmbeddedFiles(t *testing.T) {
	m := loadManifest(t)
	for _, err := range m.Verify() {
		t.Error(err)
	}
	if len(m.Entries) == 0 {
		t.Fatal("the manifest lists no entries; every assertion above was vacuous")
	}
}

// Every upstream file is accounted for, and the counts the report quotes are the manifest's own.
func TestEveryUpstreamCheckIsAccountedFor(t *testing.T) {
	m := loadManifest(t)
	c := m.Counts()
	// The pinned upstream commit has 266 .bcheck files. A re-import that changes this must
	// change it here too, which is the point: a file that vanished from the accounting is a
	// silently dropped check.
	if c.Upstream != 266 {
		t.Errorf("manifest lists %d upstream files, want 266", c.Upstream)
	}
	excluded := 0
	for _, n := range c.ByCategory {
		excluded += n
	}
	if c.Enabled+excluded != c.Upstream {
		t.Errorf("enabled %d + excluded %d != upstream %d", c.Enabled, excluded, c.Upstream)
	}
	if c.Enabled == 0 {
		t.Fatal("no check is enabled")
	}
	if n := c.ByCategory[CategoryUnreviewed]; n != 0 {
		t.Errorf("%d entries are unreviewed; review them before bundling", n)
	}
	t.Logf("upstream %d, imported %d, parses %d, runs %d, enabled %d, excluded %v",
		c.Upstream, c.Imported, c.Parses, c.Runs, c.Enabled, c.ByCategory)
}

// Every enabled check parses, and Checks returns exactly the enabled set, each name once (the
// scanner disables corpus checks by name, so two enabled checks sharing one would be one switch).
func TestEveryEnabledCheckParses(t *testing.T) {
	m := loadManifest(t)
	checks, err := Checks()
	if err != nil {
		t.Fatal(err)
	}
	want := m.Counts().Enabled
	if len(checks) != want {
		t.Fatalf("Checks returned %d, the manifest enables %d", len(checks), want)
	}
	seen := map[string]bool{}
	for _, c := range checks {
		if c == nil || c.Name == "" {
			t.Fatalf("an enabled check parsed to %v", c)
		}
		if seen[c.Name] {
			t.Errorf("two enabled checks are named %q", c.Name)
		}
		seen[c.Name] = true
		if c.IsPassive() {
			t.Errorf("%q is passive; check_corpus dispatches active checks only", c.Name)
		}
	}
}

// A check excluded as unsafe is not in the binary at all — a disabled flag can be flipped, an
// absent file cannot.
func TestUnsafeChecksAreNotEmbedded(t *testing.T) {
	m := loadManifest(t)
	unsafe := 0
	for _, e := range m.Entries {
		if e.Exclusion == nil || e.Exclusion.Category != CategoryUnsafe {
			continue
		}
		unsafe++
		if e.Imported || e.File != "" {
			t.Errorf("%s is excluded as unsafe but imported as %q", e.SourcePath, e.File)
		}
		if _, err := fs.Stat(FS(), path.Join(Root, "checks", e.SourcePath)); err == nil {
			t.Errorf("%s is excluded as unsafe but its file is embedded", e.SourcePath)
		}
	}
	if unsafe == 0 {
		t.Fatal("no entry is excluded as unsafe; the assertion above was vacuous")
	}
}

// The licence and notice travel with the files.
func TestTheLicenceAndNoticeAreEmbedded(t *testing.T) {
	m := loadManifest(t)
	lic, err := fs.ReadFile(FS(), m.Source.LicenseFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lic), "GNU LESSER GENERAL PUBLIC LICENSE") || !strings.Contains(string(lic), "Version 3") {
		t.Errorf("%s is not the LGPL-3.0 text", m.Source.LicenseFile)
	}
	notice, err := fs.ReadFile(FS(), m.Source.NoticeFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(notice), m.Source.Commit) {
		t.Errorf("%s does not name the pinned commit %s", m.Source.NoticeFile, m.Source.Commit)
	}
}

// Negative controls for Verify: each kind of drift it exists to catch is caught.
func TestVerifyCatchesDrift(t *testing.T) {
	fresh := func() *Manifest {
		m := loadManifest(t)
		return m
	}
	firstImported := func(m *Manifest) int {
		for i, e := range m.Entries {
			if e.Imported && e.Enabled {
				return i
			}
		}
		t.Fatal("no imported, enabled entry")
		return -1
	}
	cases := map[string]func(m *Manifest){
		"digest changed": func(m *Manifest) {
			m.Entries[firstImported(m)].SHA256 = strings.Repeat("0", 64)
		},
		"embedded file dropped from the manifest": func(m *Manifest) {
			i := firstImported(m)
			m.Entries = append(m.Entries[:i], m.Entries[i+1:]...)
		},
		"excluded check enabled without clearing its exclusion": func(m *Manifest) {
			for i, e := range m.Entries {
				if e.Exclusion != nil && e.Exclusion.Category == CategoryFalsePositive {
					m.Entries[i].Enabled = true
					return
				}
			}
			t.Fatal("no false-positive entry")
		},
		"exclusion with no reason": func(m *Manifest) {
			for i, e := range m.Entries {
				if e.Exclusion != nil {
					m.Entries[i].Exclusion = &Exclusion{Category: e.Exclusion.Category}
					return
				}
			}
		},
		"a check that does not run, enabled": func(m *Manifest) {
			i := firstImported(m)
			m.Entries[i].Runs = false
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := fresh()
			mutate(m)
			if errs := m.Verify(); len(errs) == 0 {
				t.Errorf("Verify accepted a manifest with %s", name)
			}
		})
	}
}
