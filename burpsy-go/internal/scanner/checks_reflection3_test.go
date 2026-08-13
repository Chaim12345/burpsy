package scanner

import "testing"

// ---------------------------------------------------------------------------
// splitPathForBackup
// ---------------------------------------------------------------------------

func TestSplitPathForBackupWithExtension(t *testing.T) {
	dir, base, ext := splitPathForBackup("/app/config.php?x=1")
	if dir != "/app/" || base != "config" || ext != ".php" {
		t.Fatalf("got (%q, %q, %q), want (/app/, config, .php)", dir, base, ext)
	}
}

func TestSplitPathForBackupNoExtension(t *testing.T) {
	dir, base, ext := splitPathForBackup("/download")
	if dir != "/" || base != "download" || ext != "" {
		t.Fatalf("got (%q, %q, %q), want (/, download, \"\")", dir, base, ext)
	}
}

func TestSplitPathForBackupRootPath(t *testing.T) {
	dir, base, ext := splitPathForBackup("/")
	if dir != "/" || base != "" || ext != "" {
		t.Fatalf("got (%q, %q, %q), want (/, \"\", \"\")", dir, base, ext)
	}
}

func TestSplitPathForBackupHiddenFile(t *testing.T) {
	// A leading dot with nothing after it (e.g. ".htaccess") must not be split at that dot: the
	// LastIndexByte(">0") guard exists exactly for this case.
	dir, base, ext := splitPathForBackup("/.htaccess")
	if dir != "/" || base != ".htaccess" || ext != "" {
		t.Fatalf("got (%q, %q, %q), want (/, .htaccess, \"\")", dir, base, ext)
	}
}

// ---------------------------------------------------------------------------
// Backup-file mutation lists carry the real recovered evidence, not placeholders
// ---------------------------------------------------------------------------

func TestBackupFilenameSuffixesContainRecoveredEvidence(t *testing.T) {
	want := map[string]bool{"_bak": false, "_backup": false, "_old": false, " (copy)": false}
	for _, s := range backupFilenameSuffixes {
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for s, found := range want {
		if !found {
			t.Errorf("expected recovered suffix %q in backupFilenameSuffixes", s)
		}
	}
}

func TestBackupFilenamePrefixesContainRecoveredEvidence(t *testing.T) {
	want := map[string]bool{"bak_": false, "backup_": false, "old_": false}
	for _, p := range backupFilenamePrefixes {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for p, found := range want {
		if !found {
			t.Errorf("expected recovered prefix %q in backupFilenamePrefixes", p)
		}
	}
}

// ---------------------------------------------------------------------------
// ResponseDependenceCheckDescriptors registration shape
// ---------------------------------------------------------------------------

func TestResponseDependenceCheckDescriptorsAreValidAndNative(t *testing.T) {
	descs := ResponseDependenceCheckDescriptors()
	if len(descs) != 5 {
		t.Fatalf("got %d descriptors, want 5", len(descs))
	}
	seen := make(map[uint32]struct{})
	for _, d := range descs {
		if d.Implementation != ImplementationNative {
			t.Errorf("%q is Implementation %q, want ImplementationNative", d.Name, d.Implementation)
		}
		if !d.Valid() || !d.Runnable() {
			t.Errorf("%q is not a valid, runnable descriptor", d.Name)
		}
		if _, dup := seen[d.TypeIndex]; dup {
			t.Errorf("duplicate TypeIndex %d in ResponseDependenceCheckDescriptors", d.TypeIndex)
		}
		seen[d.TypeIndex] = struct{}{}
	}
}

func TestASPDebuggingResponseMarkersAreTheRecoveredLiterals(t *testing.T) {
	if len(aspDebuggingResponseMarkers) != 2 {
		t.Fatalf("got %d markers, want 2", len(aspDebuggingResponseMarkers))
	}
	if aspDebuggingResponseMarkers[0] != "Debug access denied to '/Default.aspx'." {
		t.Errorf("unexpected first marker %q", aspDebuggingResponseMarkers[0])
	}
}
