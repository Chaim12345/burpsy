package extension

// Auto-reload: load the allowlist at start, and re-load a plugin whose executable changes on disk
// (burpsy-react-ui-1ye7).
//
// # The problem it solves
//
// A plugin author's loop is edit → rebuild → test. Without this the third step is "press Unload,
// press Load, then test", twice per iteration, and the cost is not the two clicks — it is that a
// rebuild which did NOT get reloaded looks exactly like a code change that did not work. The
// author debugs the wrong thing.
//
// # Why polling, and what it costs
//
// The watch set is the allowlist: a handful of paths, fixed at construction, never growing. One
// stat per loaded plugin per interval is a cost that does not scale with traffic, findings, or
// anything else this process does — unlike a filesystem-notification dependency, which behaves
// differently on Linux, macOS and WSL and would be a third-party package in the hot path of a
// feature only plugin authors use.
//
// # What it deliberately does NOT do
//
// It does not reload a plugin that is not loaded. A changed executable for an unloaded plugin is
// not an event: the operator never asked for it to run, and starting it because a file changed
// would turn a build into an execution. It also does not watch directories, only the executable
// named in the spec — a plugin whose real logic lives in a script the executable reads is beyond
// what a stat of one path can see, and pretending otherwise would be a watch that silently misses
// most changes.

import (
	"os"
	"time"

	"go.uber.org/zap"
)

// startAutoReload begins the watch loop when the config asked for it, and returns immediately.
//
// Started from NewHost rather than from the first Load so that ReloadOnStart's loads are already
// in flight when the watcher takes its first baseline — otherwise the first poll would see every
// just-loaded plugin as "changed since I last looked" and reload each one once for nothing.
func (h *Host) startAutoReload() {
	if !h.cfg.AutoReload {
		return
	}
	go h.watchForRebuilds(h.cfg.ReloadInterval)
}

// watchForRebuilds re-loads each loaded plugin whose executable's modification time or size has
// moved since it was loaded. It returns when the host's context is cancelled, which Close does.
//
// Size as well as mtime, because a rebuild that lands within the same filesystem timestamp tick is
// exactly the case an author hits with a fast incremental build — mtime alone would miss it and
// report nothing, which is the failure this feature exists to prevent.
func (h *Host) watchForRebuilds(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.reloadChangedPlugins()
		}
	}
}

// reloadChangedPlugins is one pass of the watch: stat every loaded plugin's executable and reload
// the ones that moved. Separate from the loop so a test can drive one pass deterministically
// rather than sleeping and hoping.
func (h *Host) reloadChangedPlugins() {
	h.mu.Lock()
	plugins := make([]*plugin, 0, len(h.byName))
	for _, p := range h.byName {
		plugins = append(plugins, p)
	}
	h.mu.Unlock()

	for _, p := range plugins {
		p.mu.Lock()
		loaded := p.state == StateLoaded
		path := p.spec.Path
		was := p.binStamp
		p.mu.Unlock()

		// Not loaded is not an event — see the file's note on why a changed file must not start
		// a plugin the operator never ran.
		if !loaded || path == "" {
			continue
		}
		now, ok := stampOf(path)
		if !ok {
			// The executable is gone or unreadable. That is not a reload: unloading a working
			// plugin because its file vanished mid-build (which is what a compiler does to its
			// own output) would kill the session the author is using, and the next successful
			// build is what should bring it back.
			continue
		}
		if now == was {
			continue
		}

		h.cfg.Logger.Info("plugin executable changed, reloading",
			zap.String("plugin", p.name), zap.String("path", path))
		if _, err := h.Unload(p.name); err != nil {
			h.cfg.Logger.Warn("auto-reload could not unload the plugin",
				zap.String("plugin", p.name), zap.Error(err))
			continue
		}
		if _, err := h.Load(p.name); err != nil {
			// Left unloaded, deliberately and visibly: a rebuild that does not start is the
			// author's own broken binary, and the state plus detail say so. Re-loading the old
			// one is not possible — it is no longer on disk — and pretending the plugin is fine
			// would hide the build they need to fix.
			h.cfg.Logger.Warn("auto-reload could not load the rebuilt plugin",
				zap.String("plugin", p.name), zap.Error(err))
		}
	}
}

// binStamp is the identity of an executable's contents as cheaply as a stat can tell it: its
// modification time and size. Recorded at load, compared on each poll.
type binStamp struct {
	modUnixNano int64
	size        int64
}

// stampOf stats one path. The second return distinguishes "unreadable" from a zero stamp, which a
// real file can legitimately have (an empty file at the Unix epoch) — refusing to conflate the two
// is what keeps a missing executable from reading as a changed one.
func stampOf(path string) (binStamp, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return binStamp{}, false
	}
	return binStamp{modUnixNano: fi.ModTime().UnixNano(), size: fi.Size()}, true
}

// loadAllowlist loads every allowlisted plugin, for Config.ReloadOnStart.
//
// Failures are logged, never fatal: one plugin that cannot start must not stop the others, and the
// per-plugin state already records why — the operator reads it in the same table they would have
// pressed Load in.
func (h *Host) loadAllowlist() {
	h.mu.Lock()
	names := append([]string(nil), h.ordered...)
	h.mu.Unlock()

	for _, name := range names {
		if _, err := h.Load(name); err != nil {
			h.cfg.Logger.Warn("reload-on-start could not load the plugin",
				zap.String("plugin", name), zap.Error(err))
		}
	}
}
