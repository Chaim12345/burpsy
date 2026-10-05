package extension

// Tests for auto-reload and reload-on-start (burpsy-react-ui-1ye7).
//
// # Why these copy the test binary
//
// The helper plugin IS this test binary re-invoked (plugin_helper_test.go), and a test cannot
// rebuild the binary it is running from. So each test that needs a "rebuild" copies the binary to
// a temp path, points the spec at the copy, and then changes the copy — which is exactly the shape
// the feature watches for: the executable named in the spec is replaced while the plugin runs.
//
// # Why they call reloadChangedPlugins directly
//
// The watch loop is a ticker around one pass. Driving the pass is deterministic; driving the
// ticker means sleeping past an interval and hoping, which is how a test earns a place on a
// flaky-test list. The loop itself is three lines (select on ctx.Done and the tick) and is covered
// by the start/stop test at the bottom.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

// copiedHelper copies the test binary to a temp path and returns a spec that launches the COPY as
// plugin `behaviour`, plus the copy's path so a test can modify it.
func copiedHelper(t *testing.T, behaviour string) (PluginSpec, string) {
	t.Helper()
	src, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Skipf("cannot read the test binary to copy it: %v", err)
	}
	path := filepath.Join(t.TempDir(), "plugin-under-watch")
	if err := os.WriteFile(path, src, 0o755); err != nil {
		t.Fatalf("writing the plugin copy: %v", err)
	}
	spec := helper(behaviour)
	spec.Path = path
	return spec, path
}

// touchExecutable makes the file look rebuilt: a later modification time AND a different size,
// which is what a real compiler produces and what the stamp compares.
//
// It writes a NEW file and renames it over the old one rather than appending in place, because
// Linux refuses to write to a running executable (ETXTBSY) — which is precisely why compilers and
// linkers replace by rename. Doing it the same way here means the test exercises the case that
// actually occurs rather than one the operating system would never produce.
func touchExecutable(t *testing.T, path string) {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the plugin copy: %v", err)
	}
	// Trailing bytes after an ELF's last section are ignored by the loader, so the replacement
	// still executes — the point is only that stat sees a different size.
	replacement := append(append([]byte(nil), src...), []byte("\n# rebuilt\n")...)
	staged := path + ".new"
	if err := os.WriteFile(staged, replacement, 0o755); err != nil {
		t.Fatalf("staging the rebuilt plugin: %v", err)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatalf("renaming the rebuilt plugin over the old one: %v", err)
	}
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatalf("setting the plugin copy's mtime: %v", err)
	}
}

// THE CLAIM: a loaded plugin whose executable is rebuilt comes back on the new binary without the
// operator pressing anything.
func TestARebuiltPluginIsReloadedWithoutTheOperatorAsking(t *testing.T) {
	spec, path := copiedHelper(t, "ok")
	h := NewHost(Config{Plugins: map[string]PluginSpec{"p": spec}, Logger: zap.NewNop()})
	defer h.Close()

	if _, err := h.Load("p"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	before := h.pluginLoadedAt(t, "p")

	touchExecutable(t, path)
	h.reloadChangedPlugins()

	if state := h.pluginState(t, "p"); state != StateLoaded {
		t.Fatalf("state = %q after a rebuild, want %q: the watch must leave the plugin running on "+
			"the new binary, not stopped", state, StateLoaded)
	}
	if after := h.pluginLoadedAt(t, "p"); after == before {
		t.Errorf("loadedAt is unchanged (%d) after the executable was rebuilt; the plugin was never "+
			"actually reloaded, so an author's rebuild is still invisible until they press Load",
			after)
	}
}

// The inverse, and the one that keeps the watch from being a restart loop: an unchanged executable
// must NOT be reloaded. Without this a plugin would be torn down and respawned every poll — once a
// second — which would read as "the plugin keeps crashing" to anyone watching the console.
func TestAnUnchangedExecutableIsNotReloaded(t *testing.T) {
	spec, _ := copiedHelper(t, "ok")
	h := NewHost(Config{Plugins: map[string]PluginSpec{"p": spec}, Logger: zap.NewNop()})
	defer h.Close()

	if _, err := h.Load("p"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	before := h.pluginLoadedAt(t, "p")

	h.reloadChangedPlugins()
	h.reloadChangedPlugins()

	if after := h.pluginLoadedAt(t, "p"); after != before {
		t.Errorf("loadedAt moved from %d to %d across two polls with no rebuild; the watch is "+
			"reloading unconditionally, which respawns every running plugin once per interval",
			before, after)
	}
}

// A changed executable for a plugin the operator never loaded must not start it. A build is not a
// request to run something.
func TestAChangedExecutableDoesNotStartAnUnloadedPlugin(t *testing.T) {
	spec, path := copiedHelper(t, "ok")
	h := NewHost(Config{Plugins: map[string]PluginSpec{"p": spec}, Logger: zap.NewNop()})
	defer h.Close()

	touchExecutable(t, path)
	h.reloadChangedPlugins()

	if state := h.pluginState(t, "p"); state != StateUnloaded {
		t.Errorf("state = %q after the executable of a NEVER-LOADED plugin changed, want %q; a file "+
			"changing must not turn into burpsy executing a binary nobody asked for",
			state, StateUnloaded)
	}
}

// A vanished executable must not unload a working plugin: that is what a compiler does to its own
// output halfway through a build, and killing the author's running session for it would be the
// watch making their loop worse.
func TestAVanishedExecutableLeavesTheRunningPluginAlone(t *testing.T) {
	spec, path := copiedHelper(t, "ok")
	h := NewHost(Config{Plugins: map[string]PluginSpec{"p": spec}, Logger: zap.NewNop()})
	defer h.Close()

	if _, err := h.Load("p"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("removing the plugin copy: %v", err)
	}
	h.reloadChangedPlugins()

	if state := h.pluginState(t, "p"); state != StateLoaded {
		t.Errorf("state = %q after the executable disappeared mid-build, want %q; the running "+
			"session must survive until a successful build replaces it", state, StateLoaded)
	}
}

// ReloadOnStart loads the allowlist as NewHost returns.
func TestReloadOnStartLoadsTheAllowlist(t *testing.T) {
	spec, _ := copiedHelper(t, "ok")
	h := NewHost(Config{
		Plugins:       map[string]PluginSpec{"p": spec},
		ReloadOnStart: true,
		Logger:        zap.NewNop(),
	})
	defer h.Close()

	if state := h.pluginState(t, "p"); state != StateLoaded {
		t.Errorf("state = %q with ReloadOnStart set, want %q", state, StateLoaded)
	}
}

// And its default is off — the careful default NewHost's own doc promises. A host built without
// asking must still start nothing, or "started with -plugins" silently becomes "executed three
// binaries on boot".
func TestWithoutReloadOnStartNothingIsLoaded(t *testing.T) {
	spec, _ := copiedHelper(t, "ok")
	h := NewHost(Config{Plugins: map[string]PluginSpec{"p": spec}, Logger: zap.NewNop()})
	defer h.Close()

	if state := h.pluginState(t, "p"); state != StateUnloaded {
		t.Errorf("state = %q on a host that was not asked to load anything, want %q",
			state, StateUnloaded)
	}
}

// The watch loop starts only when asked, and Close stops it. Asserted through the loop rather than
// the pass, because the goroutine's lifetime is the one thing reloadChangedPlugins cannot show.
func TestTheWatchLoopRunsOnlyWhenAskedAndStopsOnClose(t *testing.T) {
	spec, path := copiedHelper(t, "ok")
	h := NewHost(Config{
		Plugins:        map[string]PluginSpec{"p": spec},
		AutoReload:     true,
		ReloadInterval: 10 * time.Millisecond,
		Logger:         zap.NewNop(),
	})
	if _, err := h.Load("p"); err != nil {
		h.Close()
		t.Fatalf("Load: %v", err)
	}
	before := h.pluginLoadedAt(t, "p")
	touchExecutable(t, path)

	// The loop is running, so the reload happens with nothing else driving it.
	deadline := time.Now().Add(3 * time.Second)
	reloaded := false
	for time.Now().Before(deadline) {
		if h.pluginLoadedAt(t, "p") != before {
			reloaded = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.Close()
	if !reloaded {
		t.Fatal("the plugin was never reloaded with AutoReload on and a 10ms interval; the watch " +
			"loop is not running")
	}

	// After Close the loop must be gone: a further rebuild changes nothing.
	afterClose := h.pluginLoadedAt(t, "p")
	touchExecutable(t, path)
	time.Sleep(60 * time.Millisecond)
	if h.pluginLoadedAt(t, "p") != afterClose {
		t.Error("a plugin was reloaded after Close; the watch goroutine outlived the host it " +
			"belongs to, which is a leak that survives every shutdown")
	}
}

// pluginLoadedAt reads one plugin's loadedAtMs, which is how these tests tell "reloaded" from
// "still the session I started with".
func (h *Host) pluginLoadedAt(t *testing.T, name string) int64 {
	t.Helper()
	p, err := h.lookup(name)
	if err != nil {
		t.Fatalf("lookup(%q): %v", name, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.loadedAtMs
}

// AutoReload off means no watch at all. Without this, the watcher could start unconditionally and
// every test above would still pass — a host that polls when nobody asked is doing work the
// operator did not request, on a path they did not opt into.
func TestWithoutAutoReloadARebuiltPluginIsLeftAlone(t *testing.T) {
	spec, path := copiedHelper(t, "ok")
	h := NewHost(Config{
		Plugins: map[string]PluginSpec{"p": spec},
		// AutoReload deliberately unset.
		ReloadInterval: 10 * time.Millisecond,
		Logger:         zap.NewNop(),
	})
	defer h.Close()

	if _, err := h.Load("p"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	before := h.pluginLoadedAt(t, "p")
	touchExecutable(t, path)
	// Several intervals' worth: if a watch were running at all, it would have fired by now.
	time.Sleep(80 * time.Millisecond)

	if after := h.pluginLoadedAt(t, "p"); after != before {
		t.Errorf("the plugin was reloaded (loadedAt %d -> %d) with AutoReload unset; the watch must "+
			"not run unless the operator asked for it", before, after)
	}
}

// A rebuild that lands inside the same filesystem timestamp tick must still be noticed. This is
// the case the size half of the stamp exists for, and it is not hypothetical: a fast incremental
// build routinely finishes within one tick, and an mtime-only stamp would report nothing — the
// exact silence this feature was built to end.
func TestARebuildWithinTheSameTimestampTickIsStillNoticed(t *testing.T) {
	spec, path := copiedHelper(t, "ok")
	h := NewHost(Config{Plugins: map[string]PluginSpec{"p": spec}, Logger: zap.NewNop()})
	defer h.Close()

	if _, err := h.Load("p"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	before := h.pluginLoadedAt(t, "p")

	// Read the mtime the load recorded, replace the binary with a DIFFERENT SIZE, then put the
	// original mtime back — a rebuild that is invisible to a clock-only check.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	original := fi.ModTime()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the plugin copy: %v", err)
	}
	staged := path + ".new"
	if err := os.WriteFile(staged, append(append([]byte(nil), src...), []byte("\n# same tick\n")...), 0o755); err != nil {
		t.Fatalf("staging: %v", err)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := os.Chtimes(path, original, original); err != nil {
		t.Fatalf("restoring the original mtime: %v", err)
	}

	h.reloadChangedPlugins()

	if after := h.pluginLoadedAt(t, "p"); after == before {
		t.Errorf("a rebuild with an unchanged mtime but a different size was not noticed "+
			"(loadedAt stayed %d); the stamp must compare size as well as time, or a fast "+
			"incremental build reloads nothing and the author debugs the old binary", before)
	}
}

// pluginState reads one plugin's state without inventing a public accessor for a test's benefit.
func (h *Host) pluginState(t *testing.T, name string) State {
	t.Helper()
	p, err := h.lookup(name)
	if err != nil {
		t.Fatalf("lookup(%q): %v", name, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}
