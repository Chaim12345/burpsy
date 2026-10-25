package extension

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"go.uber.org/zap"
)

// State is where one allowlisted plugin currently stands.
//
// Five states rather than a `loaded bool`, because the four ways of not being
// loaded are the ones an operator needs told apart: never started, asked to stop,
// tried and could not start, and started and then died. A boolean would render the
// last three identically — which is the "partial result looking complete" defect
// this tree treats as a bug.
type State string

const (
	// StateUnloaded is allowlisted and not running: either never started, or
	// stopped on request.
	StateUnloaded State = "unloaded"
	// StateLoading is spawned, handshake in flight.
	StateLoading State = "loading"
	// StateLoaded is running with a completed handshake.
	StateLoaded State = "loaded"
	// StateFailed is a load attempt that did not complete. Detail says why.
	StateFailed State = "failed"
	// StateCrashed is a plugin that was loaded and whose process then exited
	// without being asked to. Exit says how.
	StateCrashed State = "crashed"
)

// ExitInfo is how a child process ended.
type ExitInfo struct {
	AtMs int64 `json:"at_ms"`
	Code int   `json:"code"`
	// Signal is set when a signal ended the process, in which case Code is -1 and
	// is not on its own an answer.
	Signal string `json:"signal,omitempty"`
	// Detail is set when the wait itself failed rather than the process exiting.
	Detail string `json:"detail,omitempty"`
}

// Errors the API layer maps to status codes. Sentinels rather than strings so the
// mapping is a type decision and not a substring match.
var (
	// ErrUnknownPlugin means the name is not on the operator's allowlist. This is
	// the whole safety model, exactly as in scanner.execToolRunner.Run: a name that
	// was not explicitly mapped on the command line cannot be executed.
	ErrUnknownPlugin = errors.New("plugin is not in the configured allowlist")
	// ErrAlreadyLoaded means a load was asked for while one is running or starting.
	ErrAlreadyLoaded = errors.New("plugin is already loaded")
	// ErrNotLoaded means an operation needs a running plugin and there is not one.
	ErrNotLoaded = errors.New("plugin is not loaded")
	// ErrUnknownRegistration means the plugin never registered that id.
	ErrUnknownRegistration = errors.New("plugin registered no such id")
	// ErrSelectionTooLarge is a hotkey invocation carrying more than MaxHotkeySelection rows.
	ErrSelectionTooLarge = errors.New("hotkey selection too large")
)

// Config is the operator's allowlist and every bound this host imposes.
type Config struct {
	// Plugins maps an allowlist name to how to launch it. A name not present here
	// cannot be loaded. An empty map is a supported and common state: it means the
	// operator started burpsy without -plugins, and every load is refused.
	Plugins map[string]PluginSpec

	LoadTimeout   time.Duration
	CallTimeout   time.Duration
	ShutdownGrace time.Duration

	MaxConsoleLines     int
	MaxConsoleLineBytes int
	MaxMessageBytes     int
	MaxRegistrations    int

	// ReloadOnStart loads every allowlisted plugin as NewHost returns, instead of waiting for the
	// operator to press Load (burpsy-react-ui-1ye7).
	//
	// OFF by default, and the default is the careful one: "burpsy was started with -plugins" must
	// not silently mean "burpsy executed three binaries on boot" — see NewHost's own note. A plugin
	// author who is iterating turns it on; an operator running someone else's plugins leaves it off.
	ReloadOnStart bool
	// Grants maps a plugin's allowlist name to the plugin->host methods the operator has
	// allowed it (see GrantableMethods). A method not listed answers CodeNoGrant. Check the
	// operator's input with ValidateGrants.
	Grants map[string][]string
	// Services is what the grants reach. A nil field answers CodeNotWired.
	Services Services
	// AutoReload re-loads a loaded plugin when its executable changes on disk, so an author who has
	// just rebuilt does not have to press Unload and Load to see the new binary.
	//
	// Polling rather than inotify, deliberately: the watch set is the allowlist — a handful of paths
	// at most — and a poll costs one stat each per interval, against a filesystem-notification
	// dependency that behaves differently on every platform this runs on. The cost is bounded and
	// the behaviour is the same everywhere.
	AutoReload bool
	// ReloadInterval is how often AutoReload stats the watch set. Zero takes DefaultReloadInterval.
	ReloadInterval time.Duration
	Logger         *zap.Logger
}

func (c Config) withDefaults() Config {
	if c.LoadTimeout <= 0 {
		c.LoadTimeout = DefaultLoadTimeout
	}
	if c.CallTimeout <= 0 {
		c.CallTimeout = DefaultCallTimeout
	}
	if c.ShutdownGrace <= 0 {
		c.ShutdownGrace = DefaultShutdownGrace
	}
	if c.MaxConsoleLines <= 0 {
		c.MaxConsoleLines = DefaultMaxConsoleLines
	}
	if c.MaxConsoleLineBytes <= 0 {
		c.MaxConsoleLineBytes = DefaultMaxConsoleLineBytes
	}
	if c.MaxMessageBytes <= 0 {
		c.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if c.MaxRegistrations <= 0 {
		c.MaxRegistrations = DefaultMaxRegistrations
	}
	if c.ReloadInterval <= 0 {
		c.ReloadInterval = DefaultReloadInterval
	}
	if c.Logger == nil {
		c.Logger = zap.NewNop()
	}
	return c
}

// plugin is one allowlist entry's record: its state, its consoles, and its live
// session when it has one.
type plugin struct {
	name string
	spec PluginSpec
	// grants is the sorted, de-duplicated set the operator allowed this plugin.
	grants []string

	console *console

	// Counted with atomics rather than under mu because the list view reads them
	// while an invocation is in flight, and an invocation deliberately does not
	// hold mu for its duration.
	invocations atomic.Int64
	failures    atomic.Int64

	mu       sync.Mutex
	state    State
	detail   string
	manifest Manifest
	// registrations are the ones that passed validation. refused counts the rest,
	// so "4 registered" and "4 registered, 2 refused" are different answers.
	registrations []Registration
	refused       int
	loadedAtMs    int64
	exit          *ExitInfo
	session       *session
	// stopping distinguishes an exit we asked for from one we did not, which is the
	// difference between StateUnloaded and StateCrashed.
	stopping bool
	// binStamp is the executable's mtime+size as of the load that produced the current session —
	// the baseline Config.AutoReload compares against on each poll (burpsy-react-ui-1ye7). Zero
	// for a plugin that has never loaded, which is why the watcher checks state before comparing.
	binStamp binStamp
}

// Host owns every allowlisted plugin and the processes they run as.
type Host struct {
	cfg    Config
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	byName  map[string]*plugin
	ordered []string
}

// NewHost builds the host from the operator's allowlist.
//
// It starts nothing. A plugin runs only when something asks for it by name, which
// keeps "burpsy was started with -plugins" from meaning "burpsy executed three
// binaries on boot" — the load is an act the operator performs and the route
// classifies accordingly.
func NewHost(cfg Config) *Host {
	cfg = cfg.withDefaults()
	ctx, cancel := context.WithCancel(context.Background())
	h := &Host{cfg: cfg, ctx: ctx, cancel: cancel, byName: make(map[string]*plugin, len(cfg.Plugins))}
	for name, spec := range cfg.Plugins {
		h.byName[name] = &plugin{
			name:    name,
			spec:    spec,
			grants:  cleanGrants(cfg.Grants[name]),
			state:   StateUnloaded,
			console: newConsole(cfg.MaxConsoleLines, cfg.MaxConsoleLineBytes),
		}
		h.ordered = append(h.ordered, name)
	}
	// Sorted once here rather than on every list: the allowlist never changes after
	// construction, and a list whose order came from Go's map iteration would
	// reshuffle the operator's table on every refresh.
	sort.Strings(h.ordered)
	// ReloadOnStart first, then the watcher: the loads must already have happened when the watch
	// takes its first baseline, or the first poll would see every just-loaded plugin as "changed
	// since I looked" and reload each one once for nothing (burpsy-react-ui-1ye7).
	//
	// Both are off by default, which keeps NewHost's own contract above intact: it still starts
	// nothing unless the operator asked, and "burpsy was started with -plugins" still does not mean
	// "burpsy executed three binaries on boot".
	if cfg.ReloadOnStart {
		h.loadAllowlist()
	}
	h.startAutoReload()
	return h
}

// Close stops every running plugin and refuses further work.
//
// Called on process shutdown. The context cancel is the backstop: exec.CommandContext
// kills a child whose context is done, so a plugin that ignores both `shutdown` and
// a closed stdin still cannot outlive the host.
func (h *Host) Close() {
	h.mu.Lock()
	plugins := make([]*plugin, 0, len(h.byName))
	for _, p := range h.byName {
		plugins = append(plugins, p)
	}
	h.mu.Unlock()
	for _, p := range plugins {
		if _, err := h.unload(p, "burpsy is shutting down"); err != nil && !errors.Is(err, ErrNotLoaded) {
			h.cfg.Logger.Warn("plugin did not stop cleanly", zap.String("plugin", p.name), zap.Error(err))
		}
	}
	h.cancel()
}

func (h *Host) lookup(name string) (*plugin, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.byName[name]
	if !ok {
		return nil, fmt.Errorf("%q: %w", name, ErrUnknownPlugin)
	}
	return p, nil
}

// ResolveRegistration finds the loaded plugin that declares `id` with kind `kind`.
//
// It exists because a session rule's Invoke-an-extension action names a *registration*, not a
// plugin: Burp's action points at an extension's session-handling action by name, and making the
// operator also name the plugin that owns it would be a second field that must agree with the
// first. Resolution is by registration id across the loaded plugins, and the two ways it can fail
// are separated on purpose — "no plugin offers this" and "two plugins offer this" need different
// fixes, and a rule that silently picked one of the two would send a real request through the wrong
// plugin.
func (h *Host) ResolveRegistration(id string, kind Kind) (string, error) {
	if id == "" {
		return "", errors.New("the registration id is empty, so no plugin can be resolved")
	}
	h.mu.Lock()
	names := append([]string(nil), h.ordered...)
	byName := make(map[string]*plugin, len(h.byName))
	for name, p := range h.byName {
		byName[name] = p
	}
	h.mu.Unlock()
	var owners []string
	for _, name := range names {
		p := byName[name]
		p.mu.Lock()
		loaded := p.state == StateLoaded && p.session != nil
		var declares bool
		for _, reg := range p.registrations {
			if reg.ID == id && reg.Kind == kind {
				declares = true
				break
			}
		}
		p.mu.Unlock()
		if declares && loaded {
			owners = append(owners, name)
		}
	}
	switch len(owners) {
	case 0:
		return "", fmt.Errorf("no loaded plugin registers %q as a %s; a plugin must be loaded and must declare "+
			"the registration in its manifest", id, kind)
	case 1:
		return owners[0], nil
	default:
		// Named, not chosen. Burp's own model has one extension per action, and here the id is the
		// plugin's own handle — two plugins using the same one is an ambiguity only the operator
		// can resolve, and guessing would fire the wrong code against a live engagement.
		return "", fmt.Errorf("two loaded plugins register %q as a %s (%s); rename one, because a rule "+
			"that picked one would send a real request through whichever it happened to choose",
			id, kind, strings.Join(owners, ", "))
	}
}

// List reports every allowlisted plugin and the state breakdown across them.
func (h *Host) List() ListView {
	h.mu.Lock()
	names := append([]string(nil), h.ordered...)
	byName := make(map[string]*plugin, len(h.byName))
	for name, p := range h.byName {
		byName[name] = p
	}
	h.mu.Unlock()

	view := ListView{
		Extensions:  make([]PluginView, 0, len(names)),
		Allowlisted: len(names),
		Policy:      h.Policy(),
	}
	for _, name := range names {
		row := byName[name].view()
		switch row.State {
		case StateLoaded:
			view.Loaded++
		case StateLoading:
			view.Loading++
		case StateCrashed:
			view.Crashed++
		case StateFailed:
			view.Failed++
		default:
			view.Unloaded++
		}
		view.Extensions = append(view.Extensions, row)
	}
	view.Detail = listDetail(view)
	return view
}

// listDetail says in words what the counts say in numbers, and its first case is
// the one that matters: an empty list must not read as "no plugins exist".
func listDetail(view ListView) string {
	if view.Allowlisted == 0 {
		return "No plugin is allowlisted, so nothing can be loaded. A plugin is a local executable " +
			"named on the command line: start burpsy with -plugins name=/path/to/plugin. There is no " +
			"registry or store to browse."
	}
	detail := fmt.Sprintf("%d plugin(s) allowlisted: %d loaded, %d unloaded",
		view.Allowlisted, view.Loaded, view.Unloaded)
	if view.Loading > 0 {
		detail += fmt.Sprintf(", %d loading", view.Loading)
	}
	if view.Failed > 0 {
		detail += fmt.Sprintf(", %d failed to load", view.Failed)
	}
	if view.Crashed > 0 {
		detail += fmt.Sprintf(", %d exited without being asked to", view.Crashed)
	}
	return detail + "."
}

// Policy reports the admission rules and bounds in force, so the Options tab shows
// what this process is actually doing rather than the defaults in the source.
func (h *Host) Policy() PolicyView {
	h.mu.Lock()
	count := len(h.byName)
	h.mu.Unlock()
	return PolicyView{
		Flag:                "-plugins name=/path/to/plugin",
		Allowlisted:         count,
		LoadTimeoutMs:       h.cfg.LoadTimeout.Milliseconds(),
		CallTimeoutMs:       h.cfg.CallTimeout.Milliseconds(),
		ShutdownGraceMs:     h.cfg.ShutdownGrace.Milliseconds(),
		MaxConsoleLines:     h.cfg.MaxConsoleLines,
		MaxConsoleLineBytes: h.cfg.MaxConsoleLineBytes,
		MaxMessageBytes:     h.cfg.MaxMessageBytes,
		MaxRegistrations:    h.cfg.MaxRegistrations,
		ProtocolVersion:     ProtocolVersion,
		EnvironmentPassed:   append([]string(nil), passedEnv...),
		Shell:               false,
		Registry:            nil,
		RegistryDetail: "There is no plugin registry, store or install path. Burp's BApp Store is a " +
			"hosted catalogue; nothing here fetches, resolves or installs anything. A tab offering a " +
			"store would imply a catalogue that does not exist.",
	}
}

// Console returns one plugin's two consoles. limit <= 0 means every retained line.
func (h *Host) Console(name string, limit int) (ConsoleView, error) {
	p, err := h.lookup(name)
	if err != nil {
		return ConsoleView{}, err
	}
	return p.console.view(limit), nil
}

// Load starts a plugin and completes the handshake.
//
// The child's lifetime is the host's, not the request's: it is spawned against the
// host context and the handshake is bounded by LoadTimeout alone. Threading a
// caller's context through would mean a browser tab closing mid-handshake left a
// running process with no manifest and no state — which is the worst of the
// available outcomes, since nothing would then know to stop it.
func (h *Host) Load(name string) (PluginView, error) {
	p, err := h.lookup(name)
	if err != nil {
		return PluginView{}, err
	}

	p.mu.Lock()
	if p.state == StateLoaded || p.state == StateLoading {
		view := p.viewLocked()
		p.mu.Unlock()
		return view, fmt.Errorf("%q: %w", name, ErrAlreadyLoaded)
	}
	p.state = StateLoading
	p.detail = ""
	p.exit = nil
	p.stopping = false
	p.registrations = nil
	p.refused = 0
	p.manifest = Manifest{}
	spec := p.spec
	p.mu.Unlock()

	p.console.append(StreamOutput, SourceHost, "loading "+spec.Path)

	sess, err := spawn(h.ctx, name, spec, p.console, h.cfg.MaxMessageBytes,
		newHostAPI(name, p.grants, h.cfg.Services), h.cfg.CallTimeout)
	if err != nil {
		return p.markFailed(err.Error()), err
	}

	ctx, cancel := context.WithTimeout(context.Background(), h.cfg.LoadTimeout)
	defer cancel()
	var manifest Manifest
	if err := sess.call(ctx, "initialize", InitializeParams{
		Protocol: ProtocolVersion,
		Host:     "burpsy",
		Plugin:   name,
	}, &manifest); err != nil {
		sess.stop(h.cfg.ShutdownGrace)
		return p.markFailed("handshake failed: " + err.Error()), err
	}
	if manifest.Protocol != ProtocolVersion {
		// Refused rather than tolerated. A plugin built against a different protocol
		// may answer initialize and then disagree about every method after it, and a
		// plugin that half-works reports nothing about which half.
		detail := fmt.Sprintf("plugin speaks protocol %d; this host speaks %d", manifest.Protocol, ProtocolVersion)
		sess.stop(h.cfg.ShutdownGrace)
		err := fmt.Errorf("%q: %s", name, detail)
		return p.markFailed(detail), err
	}

	registrations, refused := h.validate(p, manifest.Registrations)

	p.mu.Lock()
	p.state = StateLoaded
	p.detail = ""
	p.manifest = manifest
	p.registrations = registrations
	p.refused = refused
	p.loadedAtMs = time.Now().UnixMilli()
	p.session = sess
	// The baseline Config.AutoReload's watch compares against, taken here — at the load that
	// produced this session — rather than at the poll. A stamp read later would be the stamp of
	// whatever is on disk by then, so a rebuild that landed DURING the load would be recorded as
	// the thing already running and never reloaded (burpsy-react-ui-1ye7).
	p.binStamp, _ = stampOf(p.spec.Path)
	view := p.viewLocked()
	p.mu.Unlock()

	p.console.append(StreamOutput, SourceHost, fmt.Sprintf(
		"loaded %s %s (%s): %d registration(s) accepted, %d refused",
		orUnnamed(manifest.Name), orUnnamed(manifest.Version), orUnnamed(manifest.Type),
		len(registrations), refused))

	go h.watch(p, sess)
	return view, nil
}

// fmtChordRefused is the refusal for a hotkey whose chord this console cannot spell. A
// format string constant rather than an inline literal, because the message names the
// rule and the rule is one sentence, not two spellings of it.
const fmtChordRefused = "%q asks for %q, which this console cannot spell as a binding (mod or alt, plus shift, plus exactly one key)"

// fmtChordCollision is the refusal for a hotkey whose chord is already taken — by a
// shell binding or by another plugin. First wins; the second is refused.
const fmtChordCollision = "%q asks for %q, which is already bound to %s"

// shellChords is the set of chords the shell already uses. A plugin cannot take
// these — they belong to the console's own actions.
var shellChords = map[string]bool{
	"mod+r": true, "mod+i": true, "mod+o": true, "mod+f": true,
	"alt+t": true, "mod+enter": true, "mod+k": true,
	"mod+alt+right": true, "mod+alt+left": true,
	"mod+shift+l": true, "shift+slash": true,
	// Editor codec keys (fixed, not rebindable)
	"mod+u": true, "mod+shift+u": true, "mod+h": true, "mod+shift+h": true,
	"mod+b": true, "mod+shift+b": true, "mod+s": true,
}

// validate keeps the registrations that mean something and counts the rest.
//
// Refusing the whole load over one bad row would be harsher than useful — a plugin
// whose only job is to log still works — but accepting a bad row would put an
// action in the operator's list that cannot be invoked, which is indistinguishable
// from one that can. So each is refused individually, said out loud on the error
// console, and counted on the wire.
func (h *Host) validate(p *plugin, declared []Registration) ([]Registration, int) {
	kept := make([]Registration, 0, len(declared))
	seen := make(map[string]bool, len(declared))
	refused := 0
	refuse := func(reason string) {
		refused++
		p.console.append(StreamError, SourceHost, "registration refused: "+reason)
	}
	takenChords := map[string]string{} // chord -> plugin name (first wins)
	for _, reg := range declared {
		switch {
		case len(kept) >= h.cfg.MaxRegistrations:
			refuse(fmt.Sprintf("%q — the plugin declared more than the %d permitted", reg.ID, h.cfg.MaxRegistrations))
		case reg.ID == "":
			refuse("an entry with no id, which nothing could invoke")
		case seen[reg.ID]:
			refuse(fmt.Sprintf("%q is declared twice; an invoke could not say which was meant", reg.ID))
		case !validKinds[reg.Kind]:
			refuse(fmt.Sprintf("%q has kind %q; this host implements context-menu, menu, editor-tab, session-action, hotkey, payload-generator and payload-processor",
				reg.ID, reg.Kind))
		case reg.Label == "":
			refuse(fmt.Sprintf("%q has no label, and an unnamed action is a button with no name", reg.ID))
		case reg.Kind == KindHotKey && reg.Chord == "":
			refuse(fmt.Sprintf("%q is a hotkey with no chord; there is nothing to install", reg.ID))
		case reg.Kind == KindHotKey && NormaliseChord(reg.Chord) == "":
			refuse(fmt.Sprintf(fmtChordRefused, reg.ID, reg.Chord))
		default:
			if reg.Kind == KindHotKey {
				chord := NormaliseChord(reg.Chord)
				if shellChords[chord] {
					refuse(fmt.Sprintf(fmtChordCollision, reg.ID, reg.Chord, "a shell binding"))
					continue
				}
				if otherPlugin, taken := takenChords[chord]; taken {
					refuse(fmt.Sprintf(fmtChordCollision, reg.ID, reg.Chord, fmt.Sprintf("plugin %q", otherPlugin)))
					continue
				}
				takenChords[chord] = p.name
				reg.Binding = chord
			}
			seen[reg.ID] = true
			kept = append(kept, reg)
		}
	}
	return kept, refused
}

// watch turns an unrequested exit into a reported crash.
func (h *Host) watch(p *plugin, sess *session) {
	<-sess.exited
	p.mu.Lock()
	// A session that is no longer the plugin's has already been accounted for by
	// whoever replaced it, and an exit we asked for is Unload's to report.
	if p.session != sess || p.stopping {
		p.mu.Unlock()
		return
	}
	exit := sess.exit
	p.state = StateCrashed
	p.exit = &exit
	p.session = nil
	p.detail = crashDetail(exit)
	p.mu.Unlock()

	p.console.append(StreamError, SourceHost, "the plugin exited without being asked to: "+crashDetail(exit))
	h.cfg.Logger.Warn("plugin exited unexpectedly",
		zap.String("plugin", p.name), zap.Int("code", exit.Code), zap.String("signal", exit.Signal))
}

func crashDetail(exit ExitInfo) string {
	switch {
	case exit.Detail != "":
		return exit.Detail
	case exit.Signal != "":
		return exit.Signal
	default:
		return fmt.Sprintf("exit status %d", exit.Code)
	}
}

// Unload stops a running plugin.
func (h *Host) Unload(name string) (PluginView, error) {
	p, err := h.lookup(name)
	if err != nil {
		return PluginView{}, err
	}
	return h.unload(p, "operator unloaded the plugin")
}

func (h *Host) unload(p *plugin, reason string) (PluginView, error) {
	p.mu.Lock()
	if p.state != StateLoaded || p.session == nil {
		view := p.viewLocked()
		p.mu.Unlock()
		return view, fmt.Errorf("%q: %w", p.name, ErrNotLoaded)
	}
	sess := p.session
	p.stopping = true
	p.mu.Unlock()

	// Not under p.mu: stopping waits on a process, and holding the record's lock
	// for that long would block the list view behind an unresponsive plugin.
	exit := sess.stop(h.cfg.ShutdownGrace)

	p.mu.Lock()
	p.state = StateUnloaded
	p.detail = reason
	p.exit = &exit
	p.session = nil
	p.stopping = false
	p.registrations = nil
	p.refused = 0
	view := p.viewLocked()
	p.mu.Unlock()

	p.console.append(StreamOutput, SourceHost, fmt.Sprintf("unloaded: %s (%s)", reason, crashDetail(exit)))
	return view, nil
}

// Invoke runs one registration.
//
// The five literal method names below are the dispatch decision *and* the thing
// the protocol tests check: Test_the_documented_method_set_is_the_dispatched_method_set
// reads them out of the source, and Test_each_registration_kind_invokes_its_documented_method
// drives a real plugin and asserts which method arrived. A map from kind to method
// would read better and check nothing.
func (h *Host) Invoke(ctx context.Context, name string, params InvokeParams) (InvokeResult, error) {
	p, err := h.lookup(name)
	if err != nil {
		return InvokeResult{}, err
	}

	p.mu.Lock()
	if p.state != StateLoaded || p.session == nil {
		p.mu.Unlock()
		return InvokeResult{}, fmt.Errorf("%q: %w", name, ErrNotLoaded)
	}
	sess := p.session
	var kind Kind
	found := false
	for _, reg := range p.registrations {
		if reg.ID == params.Registration {
			kind, found = reg.Kind, true
			break
		}
	}
	p.mu.Unlock()
	if !found {
		return InvokeResult{}, fmt.Errorf("%q registration %q: %w", name, params.Registration, ErrUnknownRegistration)
	}

	if kind == KindHotKey {
		if len(params.Selected) > MaxHotkeySelection {
			return InvokeResult{}, fmt.Errorf("%q registration %q: %d rows, limit %d: %w",
				name, params.Registration, len(params.Selected), MaxHotkeySelection, ErrSelectionTooLarge)
		}
	} else {
		// Only hotkey.invoke documents these; do not widen another method's params.
		params.Selected, params.Editor = nil, nil
	}

	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, h.cfg.CallTimeout)
	defer cancel()

	p.invocations.Add(1)
	var result InvokeResult
	switch kind {
	case KindContextMenu:
		err = sess.call(callCtx, "contextMenu.invoke", params, &result)
	case KindMenu:
		err = sess.call(callCtx, "menu.invoke", params, &result)
	case KindEditorTab:
		err = sess.call(callCtx, "editor.render", params, &result)
	case KindSessionAction:
		err = sess.call(callCtx, "sessionAction.invoke", params, &result)
	case KindHotKey:
		err = sess.call(callCtx, "hotkey.invoke", params, &result)
	case KindPayloadGenerator:
		err = sess.call(callCtx, "payload.generate", params, &result)
	case KindPayloadProcessor:
		err = sess.call(callCtx, "payload.process", params, &result)
	default:
		// Unreachable: validate() refuses any other kind at load. Kept as a real
		// error rather than a panic so a future kind added to validKinds and not
		// here fails loudly instead of dispatching to nothing.
		err = fmt.Errorf("registration %q has kind %q, which Invoke does not dispatch", params.Registration, kind)
	}
	if err != nil {
		p.failures.Add(1)
		p.console.append(StreamError, SourceHost,
			fmt.Sprintf("invoking %q failed: %s", params.Registration, err.Error()))
		return InvokeResult{}, err
	}
	return result, nil
}

// ErrWrongKind is a payload call against a registration of the other payload kind.
var ErrWrongKind = errors.New("registration has a different kind")

func (h *Host) kindOf(name, registration string) (Kind, error) {
	p, err := h.lookup(name)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, reg := range p.registrations {
		if reg.ID == registration {
			return reg.Kind, nil
		}
	}
	return "", fmt.Errorf("%q registration %q: %w", name, registration, ErrUnknownRegistration)
}

func encodePayload(b []byte) (string, string) {
	if utf8.Valid(b) {
		return string(b), ""
	}
	return base64.StdEncoding.EncodeToString(b), "base64"
}

func decodePayload(s *string, encoding string) ([]byte, error) {
	if s == nil {
		return nil, nil
	}
	switch encoding {
	case "":
		return []byte(*s), nil
	case "base64":
		return base64.StdEncoding.DecodeString(*s)
	}
	return nil, fmt.Errorf("unknown payload encoding %q", encoding)
}

// GeneratePayload asks a payload-generator registration for the payload at position. done is
// true when the plugin has no more. The Intruder engine is the caller.
func (h *Host) GeneratePayload(ctx context.Context, name, registration string, position int) (payload []byte, done bool, err error) {
	kind, err := h.kindOf(name, registration)
	if err != nil {
		return nil, false, err
	}
	if kind != KindPayloadGenerator {
		return nil, false, fmt.Errorf("%q registration %q is %q: %w", name, registration, kind, ErrWrongKind)
	}
	res, err := h.Invoke(ctx, name, InvokeParams{Registration: registration, Position: &position})
	if err != nil {
		return nil, false, err
	}
	if res.Done {
		return nil, true, nil
	}
	if res.Payload == nil {
		return nil, false, fmt.Errorf("%q registration %q answered neither a payload nor done", name, registration)
	}
	out, err := decodePayload(res.Payload, res.Encoding)
	if err != nil {
		return nil, false, fmt.Errorf("%q registration %q: undecodable payload: %w", name, registration, err)
	}
	return out, false, nil
}

// ProcessPayload runs a payload-processor registration over one payload. skip is true when the
// plugin drops it. On any error the returned payload is nil, so the caller keeps the original.
func (h *Host) ProcessPayload(ctx context.Context, name, registration string, payload, base []byte) (out []byte, skip bool, err error) {
	kind, err := h.kindOf(name, registration)
	if err != nil {
		return nil, false, err
	}
	if kind != KindPayloadProcessor {
		return nil, false, fmt.Errorf("%q registration %q is %q: %w", name, registration, kind, ErrWrongKind)
	}
	ptext, penc := encodePayload(payload)
	params := InvokeParams{Registration: registration, Payload: &ptext, Encoding: penc}
	if base != nil {
		btext, benc := encodePayload(base)
		if benc != "" && penc == "" {
			// One encoding field covers both; send both as base64 when either needs it.
			ptext, penc = base64.StdEncoding.EncodeToString(payload), "base64"
			params.Payload, params.Encoding = &ptext, penc
		}
		if penc == "base64" && benc == "" {
			btext = base64.StdEncoding.EncodeToString(base)
		}
		params.BaseValue = &btext
	}
	res, err := h.Invoke(ctx, name, params)
	if err != nil {
		return nil, false, err
	}
	if res.Action == "skip" {
		return nil, true, nil
	}
	if res.Payload == nil {
		return nil, false, fmt.Errorf("%q registration %q answered neither a payload nor skip", name, registration)
	}
	out, err = decodePayload(res.Payload, res.Encoding)
	if err != nil {
		return nil, false, fmt.Errorf("%q registration %q: undecodable payload: %w", name, registration, err)
	}
	return out, false, nil
}

// markFailed records a load that did not complete and returns the row to serve.
func (p *plugin) markFailed(detail string) PluginView {
	p.mu.Lock()
	p.state = StateFailed
	p.detail = detail
	p.session = nil
	view := p.viewLocked()
	p.mu.Unlock()
	p.console.append(StreamError, SourceHost, "load failed: "+detail)
	return view
}

func (p *plugin) view() PluginView {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.viewLocked()
}

func (p *plugin) viewLocked() PluginView {
	output, errs := p.console.counts()
	console := p.console.view(0)
	view := PluginView{
		Name:                 p.name,
		Path:                 p.spec.Path,
		Args:                 append([]string(nil), p.spec.Args...),
		State:                p.state,
		Detail:               p.detail,
		DeclaredName:         p.manifest.Name,
		Version:              p.manifest.Version,
		Type:                 p.manifest.Type,
		Protocol:             p.manifest.Protocol,
		Registrations:        append([]Registration{}, p.registrations...),
		RegistrationsRefused: p.refused,
		LoadedAtMs:           p.loadedAtMs,
		Exit:                 p.exit,
		OutputLines:          output,
		ErrorLines:           errs,
		OutputDropped:        console.OutputDropped,
		ErrorDropped:         console.ErrorDropped,
		Invocations:          int(p.invocations.Load()),
		InvocationFailures:   int(p.failures.Load()),
	}
	view.Grants = append([]string{}, p.grants...)
	view.HostCalls = map[string]int{}
	if p.session != nil {
		view.ProtocolErrors = int(p.session.protocolErrors.Load())
		if api := p.session.api; api != nil {
			view.HostCalls = api.countsCopy()
			view.RefusedHostCalls = int(api.refused.Load())
		}
	}
	return view
}

func orUnnamed(value string) string {
	if value == "" {
		return "(unnamed)"
	}
	return value
}

func cleanGrants(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, g := range in {
		if isGrantable(g) && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out
}
