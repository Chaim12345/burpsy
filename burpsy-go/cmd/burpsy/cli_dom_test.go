package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ---- The -dom flag: the shipping binary's only door to DOM-based checks ------------------------
//
// The gap these tests close: internal/domexec grew two engine modes and the test suite
// demonstrated 160/160 catalog rows through both, while `cmd/burpsy` never called
// WithBrowserProvider at all. So every DOM-based check in the *shipped* binary reported
// "no DOM execution capability is configured for this scan" — honest, but zero DOM coverage
// for an operator who had Chrome installed and no way to say so.
//
// One flag, three forms, because domexec refuses RemoteURL together with ChromePath as a
// configuration contradiction: with a single flag that contradiction cannot be expressed at
// all, rather than being expressible and then rejected.

func TestDomEngineFlagNamesAnEngineOrRefusesATypo(t *testing.T) {
	// An executable that really exists, so the path form is tested against exec.LookPath's
	// actual behaviour rather than against a machine-specific browser install.
	dir := t.TempDir()
	fakeBrowser := filepath.Join(dir, "my-chromium")
	if err := os.WriteFile(fakeBrowser, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	empty, err := domEngineOptions("")
	if err != nil {
		t.Fatalf("an empty -dom must not be an error, it is the default: %v", err)
	}
	if empty != nil {
		t.Error("an empty -dom produced options; DOM checks must stay counted-but-excluded until an operator names an engine")
	}

	auto, err := domEngineOptions("chrome")
	if err != nil {
		t.Fatalf(`-dom chrome: %v`, err)
	}
	if auto == nil || auto.ChromePath != "" || auto.RemoteURL != "" {
		t.Errorf("-dom chrome must mean launch-and-discover (both fields empty), got %+v", auto)
	}

	remote, err := domEngineOptions("ws://127.0.0.1:9225")
	if err != nil {
		t.Fatalf("-dom ws://…: %v", err)
	}
	if remote == nil || remote.RemoteURL != "ws://127.0.0.1:9225" {
		t.Errorf("a ws:// engine must attach as RemoteURL, got %+v", remote)
	}
	if remote != nil && remote.ChromePath != "" {
		t.Error("a ws:// engine set ChromePath too; domexec refuses that pair, so this flag would build a config that cannot start")
	}

	path, err := domEngineOptions(fakeBrowser)
	if err != nil {
		t.Fatalf("-dom <path to a real executable>: %v", err)
	}
	if path == nil || path.ChromePath != fakeBrowser || path.RemoteURL != "" {
		t.Errorf("a filesystem path must become ChromePath alone, got %+v", path)
	}

	if _, err := domEngineOptions(filepath.Join(dir, "no-such-browser")); err == nil {
		t.Error("a -dom path that resolves to nothing was accepted; the typo must be refused at the command line, " +
			"not surface mid-engagement as DOM checks that silently never ran")
	}
}

// What proves the wiring is the scanner's own report of whether it has the capability: the
// provider is lazy, so an engine can be configured — and observed — without launching anything.
func TestCLIContextWiresTheDomEngineIntoTheActiveScanner(t *testing.T) {
	plain, err := newCLIContext("", 1<<20, "*", "", "", "", "", "")
	if err != nil {
		t.Fatalf("newCLIContext (no -dom): %v", err)
	}
	if plain.scanner.DOMCapabilityConfigured() {
		t.Error("a context built without -dom claims a DOM capability; a scan would then report DOM results it cannot produce")
	}

	wired, err := newCLIContext("", 1<<20, "*", "", "", "", "", "chrome")
	if err != nil {
		t.Fatalf("newCLIContext (-dom chrome): %v", err)
	}
	if !wired.scanner.DOMCapabilityConfigured() {
		t.Error("-dom chrome did not reach the scanner: every DOM-based check would still refuse for want of a browser")
	}

	// The second gate, and the one that made the first insufficient: ScanConfig.CheckDOM. An engine
	// attached while the DOM families stay out of the dispatch set is a browser launched for checks
	// that can never run, which reads as a clean scan of a page nobody looked at.
	if wired.scanner.ActiveCheckCount() <= plain.scanner.ActiveCheckCount() {
		t.Fatalf("naming an engine did not admit the DOM check families: plain=%d wired=%d",
			plain.scanner.ActiveCheckCount(), wired.scanner.ActiveCheckCount())
	}
}
