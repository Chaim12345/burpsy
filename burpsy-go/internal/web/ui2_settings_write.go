package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/upstream"
)

// ---- Settings write controls (passthrough, upstream proxy, backup config, pools) --------------
//
// Every write here is a two-step reviewed call: the confirm step builds the EXACT API call from
// the form, holds it server-side in the review map, and renders a review sheet whose projection
// is derived from the held bytes. The run step spends the entry atomically (LoadAndDelete),
// compares the submitted token in constant time, and dispatches the held call verbatim - the run
// form carries only the review id and token, so nothing typed after the review can change what
// is written.
//
// Two token mechanics sit under that one flow, because the confirm gate (needsConfirmation in
// agent_tools.go) covers riskScope and above while the passthrough, upstream-proxy and backup
// routes are riskLocal and ungated:
//   - pools (riskScope): the token is minted by the confirmation gate, bound to the exact call's
//     method, path, query and body digest (confirm_binding.go), and the run dispatches through
//     the guarded chain with the token in the confirm header - the same flow the triage editor
//     uses for its riskCredential PUT.
//   - passthrough / proxy / backup (riskLocal, ungated): the token is a ui2-local one-use review
//     handle (randomHex(16)) and the run dispatches through the internal mux. The exact-bytes
//     property is preserved by construction: the held call is dispatched verbatim and the entry
//     dies on any spend attempt. No gate claim is made for these routes.
//
// Scope decisions for this first write surface (independent review, 2026-10-31):
//   - No proxy URL or default carrying userinfo is minted on this page: an authenticated upstream
//     routes credentials with future traffic, and this surface has no redaction story yet. The
//     refusal names the PART (embedded credentials), never the value.
//   - Passthrough switches are written ONE pointer field per call: a whole-document prefill would
//     write back a stale other switch. The API leaves an omitted pointer untouched (verified in
//     handleTlsPassthrough's PUT arm).
//   - Upstream proxy rule writes and the default write are separate single-purpose forms. A rule
//     body never carries "default", so the default is preserved; clearing the default is an
//     explicit reviewed "direct" write, never an omitted field. No ?all=true clear and no carrier
//     update is offered here.
//   - The backup config PUT is whole-document, so the confirm step snapshots the current config
//     and the run step re-reads and REFUSES on drift. That is a review gate, not a lock: the
//     limitation is stated on the review sheet and nothing here claims CAS.
//   - Pools are create, same-name bounds edit, and delete ONLY. No rename: Registry.Update does
//     not rewrite schedule references and UsingPool is not checked on that path, so a rename
//     would leave schedules pointing at a name nothing holds. A bounds edit preserves the pool's
//     current throttle in the minted body so a whole-entry Update cannot silently reset it, and
//     the run re-reads /api/pools and refuses on drift for the same reason.
//
// ui2SettingsWriteReviewCap bounds the review map the same way as the triage cap: enough for a
// few open tabs, small enough that a full map is a pileup to refuse and say, not to paper over.
const ui2SettingsWriteReviewCap = 8

// ui2SettingsReview is one minted settings write held for review. The entry dies with the gate's
// ConfirmTTL so a stale review refuses alongside its token, and the run step spends it atomically
// so a double-confirm cannot dispatch twice.
type ui2SettingsReview struct {
	token        string
	gated        bool // the call dispatches through the confirmation gate with this token
	method       string
	callURL      string // the call's path with query, exactly as minted
	body         []byte // the exact minted body; nil for a bodyless call
	snapshotPath string // GET path re-read at run for drift, "" when the call is absolute-set
	snapshot     string // canonical JSON of that read at confirm time
	driftMsg     string
	expires      time.Time
}

// ui2SettingsCall is what a per-area parse produces: the exact gated call plus the review copy.
type ui2SettingsCall struct {
	gated        bool // the API route is in the confirmation gate's set (pools); riskLocal routes mint no gate token
	method       string
	apiBase      string // the gated route path (no query); the mint endpoint is apiBase+"/confirm"
	callURL      string
	body         []byte
	title        string
	container    string // the settings-page container id the answer swaps into
	consequences []string
	nonatomic    string // non-atomic limitation line, "" when not applicable
	snapshotPath string
	snapshot     string // canonical JSON read at confirm, compared at run
	driftMsg     string
}

// ui2CanonicalGet reads one of the console's own GET endpoints through the internal mux and
// returns the canonical JSON (map keys sorted by the re-marshal), so two reads of the same state
// compare equal byte-for-byte.
func (s *Server) ui2CanonicalGet(path string) (string, error) {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, path))
	if rec.Code != http.StatusOK {
		return "", fmt.Errorf("reading %s answered %d", path, rec.Code)
	}
	var v any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		return "", fmt.Errorf("reading %s: %v", path, err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("canonicalising %s: %v", path, err)
	}
	return string(b), nil
}

// ui2RefuseProxyUserinfo refuses a proxy URL carrying embedded credentials. The refusal names the
// PART, never the value - the same stance the triage page takes for secret-bearing base URLs.
func ui2RefuseProxyUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err == nil && u.User != nil {
		return "proxy URLs with embedded credentials (user:pass@host) are not accepted on this page - " +
			"an authenticated upstream would send those credentials with future traffic. Save an " +
			"unauthenticated upstream here, or use the API for an authenticated one"
	}
	return ""
}

// ---- per-area parsers -------------------------------------------------------------------------

func ui2ParsePassthroughCall(_ *Server, r *http.Request) (ui2SettingsCall, string) {
	c := ui2SettingsCall{
		apiBase:   "/api/proxy/passthrough",
		title:     "TLS passthrough",
		container: "settings-passthrough",
	}
	switch r.PostFormValue("op") {
	case "add":
		p := strings.TrimSpace(r.PostFormValue("pattern"))
		if p == "" {
			return c, "a passthrough rule needs a non-empty host pattern"
		}
		c.method = http.MethodPost
		c.callURL = c.apiBase
		c.body, _ = json.Marshal(map[string]any{"pattern": p})
		c.consequences = []string{
			"Future TLS connections to hosts matching \"" + p + "\" pass through UNTOUCHED: burpsy will not intercept, decrypt, or record them.",
		}
	case "remove":
		p := strings.TrimSpace(r.PostFormValue("pattern"))
		if p == "" {
			return c, "removing a passthrough rule needs its exact host pattern"
		}
		c.method = http.MethodDelete
		c.callURL = c.apiBase + "?pattern=" + url.QueryEscape(p)
		c.consequences = []string{
			"Future TLS connections to hosts matching \"" + p + "\" are intercepted and decrypted again.",
		}
	case "switch":
		field := r.PostFormValue("field")
		if field != "apply_out_of_scope" && field != "auto_add_on_failure" {
			return c, "unknown passthrough switch"
		}
		val, err := strconv.ParseBool(r.PostFormValue("value"))
		if err != nil {
			return c, "a passthrough switch value must be true or false"
		}
		c.method = http.MethodPut
		c.callURL = c.apiBase
		// Exactly ONE pointer field: the API leaves an omitted switch untouched, and sending both
		// would write back whatever state the other had when the form was drawn.
		c.body, _ = json.Marshal(map[string]bool{field: val})
		c.consequences = []string{ui2PassthroughSwitchCopy(field, val)}
	default:
		return c, "unknown passthrough operation"
	}
	return c, ""
}

// ui2PassthroughSwitchCopy states what a coupling switch means for FUTURE traffic, on or off.
func ui2PassthroughSwitchCopy(field string, val bool) string {
	switch field {
	case "apply_out_of_scope":
		if val {
			return "Hosts OUTSIDE the current scope will also pass through untouched: their TLS traffic is not intercepted or recorded."
		}
		return "Passthrough applies inside scope only again: out-of-scope hosts are intercepted normally."
	default: // auto_add_on_failure
		if val {
			return "When a client refuses burpsy's certificate, that host is added to this list AUTOMATICALLY: future connections to it bypass interception without you adding it."
		}
		return "A certificate refusal no longer adds hosts to the passthrough list automatically."
	}
}

// ui2ProxyView reads the live upstream-proxy view for review copy (the current default a removal
// falls back to). ok is false when the read failed: the copy must then say the current default is
// unavailable, never guess "direct" - an empty Default on a successful read is the only "direct".
func (s *Server) ui2ProxyView() (networkProxyView, bool) {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/network/proxy"))
	var view networkProxyView
	if rec.Code/100 != 2 || json.Unmarshal(rec.Body.Bytes(), &view) != nil {
		return networkProxyView{}, false
	}
	return view, true
}

func ui2ParseProxyRuleCall(s *Server, r *http.Request) (ui2SettingsCall, string) {
	c := ui2SettingsCall{
		apiBase:   "/api/network/proxy",
		title:     "Upstream proxy rule",
		container: "settings-proxy",
	}
	switch r.PostFormValue("op") {
	case "set":
		pattern := strings.TrimSpace(r.PostFormValue("pattern"))
		raw := strings.TrimSpace(r.PostFormValue("proxy"))
		if pattern == "" {
			return c, "a proxy rule needs a non-empty host pattern"
		}
		if raw == "" {
			return c, "a proxy rule needs a proxy URL (or \"direct\")"
		}
		if msg := ui2RefuseProxyUserinfo(raw); msg != "" {
			return c, msg
		}
		parsed, err := upstream.Parse(raw)
		if err != nil {
			return c, err.Error()
		}
		c.method = http.MethodPost
		c.callURL = c.apiBase
		c.body, _ = json.Marshal(map[string]any{"pattern": pattern, "proxy": raw})
		c.consequences = []string{
			"Future requests to hosts matching \"" + pattern + "\" are routed through " + parsed.Display() +
				" instead of the default route. This changes where burpsy sends traffic from the moment you confirm; recorded traffic is untouched.",
		}
	case "remove":
		pattern := strings.TrimSpace(r.PostFormValue("pattern"))
		if pattern == "" {
			return c, "removing a proxy rule needs its exact host pattern"
		}
		c.method = http.MethodDelete
		c.callURL = c.apiBase + "?pattern=" + url.QueryEscape(pattern)
		view, ok := s.ui2ProxyView()
		if !ok {
			c.consequences = []string{
				"Future requests to hosts matching \"" + pattern + "\" follow the default route instead. " +
					"The current default could not be read, so it is not stated here - re-check the upstream proxy settings before confirming.",
			}
		} else {
			fallback := view.Default
			if fallback == "" {
				fallback = "direct"
			}
			c.consequences = []string{
				"Future requests to hosts matching \"" + pattern + "\" follow the default route (" + fallback + ") instead.",
			}
		}
	default:
		return c, "unknown proxy rule operation"
	}
	return c, ""
}

func ui2ParseProxyDefaultCall(s *Server, r *http.Request) (ui2SettingsCall, string) {
	c := ui2SettingsCall{
		apiBase:   "/api/network/proxy",
		title:     "Upstream proxy default",
		container: "settings-proxy",
	}
	if r.PostFormValue("op") != "set" {
		return c, "unknown proxy default operation"
	}
	raw := strings.TrimSpace(r.PostFormValue("default"))
	if raw == "" {
		return c, "setting the default needs a value - enter \"direct\" to clear it"
	}
	if msg := ui2RefuseProxyUserinfo(raw); msg != "" {
		return c, msg
	}
	parsed, err := upstream.Parse(raw)
	if err != nil {
		return c, err.Error()
	}
	c.method = http.MethodPost
	c.callURL = c.apiBase
	c.body, _ = json.Marshal(map[string]any{"default": raw})
	view, ok := s.ui2ProxyView()
	old := "which could not be read - re-check the upstream proxy settings before confirming"
	if ok {
		old = view.Default
		if old == "" {
			old = "direct"
		}
	}
	if parsed.IsDirect() {
		c.consequences = []string{
			"Requests matching no rule go DIRECTLY to the target from now on - no upstream proxy. This clears the current default (" + old + ").",
		}
	} else {
		c.consequences = []string{
			"Requests matching no rule are routed through " + parsed.Display() + " from now on (replacing " + old + ").",
		}
	}
	return c, ""
}

func ui2ParseBackupCall(s *Server, r *http.Request) (ui2SettingsCall, string) {
	c := ui2SettingsCall{
		apiBase:   "/api/backup/config",
		title:     "Automatic backup",
		container: "settings-backup",
		// The whole-document PUT overwrites every field, so the run re-reads and refuses drift.
		// This is a review gate, not a lock - said on the sheet, never claimed as CAS.
		snapshotPath: "/api/backup/config",
		driftMsg:     "the backup settings changed between your review and this confirmation - review the current settings and save again",
		nonatomic: "Not atomic: the settings are re-read when you confirm and this save is refused if they changed " +
			"since your review, but a change landing inside the check-and-save instant is not locked out. " +
			"This is a review gate, not a transaction.",
	}
	if r.PostFormValue("op") != "set" {
		return c, "unknown backup operation"
	}
	interval, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("interval_minutes")))
	if err != nil {
		return c, "the backup interval must be whole minutes (0 turns automatic backup off)"
	}
	if interval < 0 {
		return c, "the backup interval cannot be negative (0 turns automatic backup off)"
	}
	retention, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("retention")))
	if err != nil {
		return c, "the retention must be a whole number of snapshots (0 takes the default, negative keeps everything)"
	}
	dir := strings.TrimSpace(r.PostFormValue("dir"))
	deleteOnShutdown := r.PostFormValue("delete_on_shutdown") != ""
	if s.persist == nil {
		return c, "this instance has no project database, so backup settings cannot be saved"
	}
	// The effective directory is stated, never blank: an empty dir means "beside the live
	// database", the same fallback the backup run and the shutdown sweep use (api_backup.go,
	// deleteBackupsOnShutdown). If that fallback cannot be grounded, the review is refused
	// rather than rendered with a guess.
	effectiveDir := dir
	if effectiveDir == "" {
		live := s.persist.Path()
		if live == "" {
			return c, "no directory is set and the live database has no path, so which directory backups " +
				"would use cannot be shown - set a directory explicitly"
		}
		effectiveDir = filepath.Dir(live)
	}
	c.method = http.MethodPut
	c.callURL = c.apiBase
	c.body, _ = json.Marshal(map[string]any{
		"interval_minutes":   interval,
		"dir":                dir,
		"retention":          retention,
		"delete_on_shutdown": deleteOnShutdown,
	})
	if interval == 0 {
		c.consequences = append(c.consequences,
			"Automatic backup turns OFF: the managed schedule is removed. No existing backup files are deleted by this change.")
	} else {
		c.consequences = append(c.consequences,
			fmt.Sprintf("Every %d minutes burpsy writes a full database snapshot into %s. The managed schedule is created or updated to match; the first snapshot is one interval from now, not immediate.", interval, effectiveDir))
	}
	switch {
	case retention == 0:
		c.consequences = append(c.consequences, "Retention: the default keep-count applies when a backup runs.")
	case retention < 0:
		c.consequences = append(c.consequences, "Retention: EVERY snapshot is kept - nothing is pruned, so the directory grows until you prune it.")
	default:
		c.consequences = append(c.consequences,
			fmt.Sprintf("Retention: only the newest %d snapshots are kept; older ones are pruned when a backup runs.", retention))
	}
	if dir == "" {
		c.consequences = append(c.consequences,
			"No directory is set: snapshots are written beside the live database ("+effectiveDir+"). That cannot fail for a missing path, but it is the worst place for a backup if the disk is what fails.")
	}
	if deleteOnShutdown {
		c.consequences = append(c.consequences,
			"On a CLEAN SHUTDOWN burpsy deletes every automatic-backup file in "+effectiveDir+". A crash leaves them in place; your own files in that directory are never matched.")
	}
	return c, ""
}

func ui2ParsePoolsCall(s *Server, r *http.Request) (ui2SettingsCall, string) {
	c := ui2SettingsCall{
		gated:     true, // /api/pools and /api/pools/ are riskScope
		apiBase:   "/api/pools",
		title:     "Resource pools",
		container: "settings-pools",
	}
	view := s.ui2PoolsView()
	switch r.PostFormValue("op") {
	case "create":
		name := strings.TrimSpace(r.PostFormValue("name"))
		mc, dm, msg := ui2ParsePoolBounds(r)
		if msg != "" {
			return c, msg
		}
		c.method = http.MethodPost
		c.callURL = c.apiBase
		// No throttle key: a pool created here has automatic throttling OFF, and the review says
		// so rather than implying the field does not exist.
		c.body, _ = json.Marshal(map[string]any{"name": name, "max_concurrent": mc, "delay_ms": dm})
		c.consequences = []string{
			fmt.Sprintf("Tools can now be pointed at pool %q: at most %d requests in flight, %d ms between requests, for runs started after you confirm.", name, mc, dm),
			"Automatic throttling: OFF - this form does not set it. Edit the pool over the API if you need it.",
		}
	case "edit":
		name := strings.TrimSpace(r.PostFormValue("name"))
		mc, dm, msg := ui2ParsePoolBounds(r)
		if msg != "" {
			return c, msg
		}
		var curThrottle any
		found := false
		for i := range view.Pools {
			if view.Pools[i].Name == name {
				curThrottle = view.Pools[i].Throttle
				found = true
				break
			}
		}
		if !found {
			return c, "no pool named \"" + name + "\" is saved - the page may be stale; reload it"
		}
		// Same-name bounds edit ONLY: the body's name restates the path's, so no rename can be
		// expressed (a rename dangles schedule references - Registry.Update does not rewrite them).
		// The current throttle is carried into the body because Update replaces the whole entry:
		// omitting it would silently turn a throttle the operator never touched off.
		body := map[string]any{"name": name, "max_concurrent": mc, "delay_ms": dm}
		throttleCopy := "Automatic throttling: unchanged (off)."
		if curThrottle != nil {
			body["throttle"] = curThrottle
			throttleCopy = "Automatic throttling: preserved unchanged (on) - the exact current setting is carried in the call above."
		}
		c.method = http.MethodPut
		c.callURL = c.apiBase + "/" + url.PathEscape(name)
		c.body, _ = json.Marshal(body)
		c.snapshotPath = "/api/pools"
		c.driftMsg = "the pools changed between your review and this confirmation - review the current pools and save again"
		c.nonatomic = "Not atomic: the pools are re-read when you confirm and this save is refused if they changed " +
			"since your review, but a change landing inside the check-and-save instant is not locked out. " +
			"This is a review gate, not a transaction."
		c.consequences = []string{
			fmt.Sprintf("Pool %q now allows at most %d requests in flight, %d ms between requests, for runs started after you confirm. The pool's name and identity do not change.", name, mc, dm),
			throttleCopy,
		}
	case "delete":
		name := strings.TrimSpace(r.PostFormValue("name"))
		if name == "" {
			return c, "deleting a pool needs its name"
		}
		c.method = http.MethodDelete
		c.callURL = c.apiBase + "/" + url.PathEscape(name)
		c.consequences = []string{
			"Pool \"" + name + "\" is deleted. Tools can no longer be pointed at it; runs already in flight keep the bounds they started with.",
		}
		if used := view.InUse[name]; len(used) > 0 {
			c.consequences = append(c.consequences,
				"It currently bounds schedule(s): "+strings.Join(used, ", ")+" - the API refuses this delete while that is true, and you will see that refusal.")
		}
	default:
		return c, "unknown pools operation"
	}
	return c, ""
}

// ui2PoolsView reads the live pools view for edit/delete review copy and throttle preservation.
func (s *Server) ui2PoolsView() poolsView {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/pools"))
	var view poolsView
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	return view
}

// ui2ParsePoolBounds reads and validates the two bounds fields shared by create and edit. The
// semantic ceilings live in pool.Validate; here only garbage is refused, so the API stays the
// authority on what a bound may be.
func ui2ParsePoolBounds(r *http.Request) (int, int, string) {
	mc, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("max_concurrent")))
	if err != nil {
		return 0, 0, "max concurrent requests must be a whole number"
	}
	dm, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("delay_ms")))
	if err != nil {
		return 0, 0, "the delay must be whole milliseconds"
	}
	return mc, dm, ""
}

var ui2SettingsWriteParsers = map[string]func(*Server, *http.Request) (ui2SettingsCall, string){
	"passthrough":   ui2ParsePassthroughCall,
	"proxy-rule":    ui2ParseProxyRuleCall,
	"proxy-default": ui2ParseProxyDefaultCall,
	"backup":        ui2ParseBackupCall,
	"pools":         ui2ParsePoolsCall,
}

// ui2SettingsWriteContainer maps a write area to the settings-page container its answers swap
// into: the two proxy write areas share the one proxy section.
func ui2SettingsWriteContainer(area string) string {
	return "settings-" + ui2SettingsWriteFragArea(area)
}

// ui2SettingsWriteFragArea maps a write area to the fragment that re-renders after its run:
// both proxy write areas load the one proxy section.
func ui2SettingsWriteFragArea(area string) string {
	if area == "proxy-rule" || area == "proxy-default" {
		return "proxy"
	}
	return area
}

// ---- confirm / run ----------------------------------------------------------------------------

// handleUI2SettingsWrite serves POST /ui2/settings/write/{area}/{action}: confirm mints and
// renders the review; run spends the held entry and dispatches the reviewed call.
func (s *Server) handleUI2SettingsWrite(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("action") {
	case "confirm":
		s.ui2SettingsWriteConfirm(w, r)
	case "run":
		s.ui2SettingsWriteRun(w, r)
	default:
		http.Error(w, "unknown settings write action", http.StatusBadRequest)
	}
}

func (s *Server) ui2SettingsWriteConfirm(w http.ResponseWriter, r *http.Request) {
	area := r.PathValue("area")
	parse, ok := ui2SettingsWriteParsers[area]
	if !ok {
		http.Error(w, "unknown settings area", http.StatusNotFound)
		return
	}
	fail := func(msg string) {
		model := map[string]any{"error": msg, "area": area, "container": ui2SettingsWriteContainer(area), "frag": ui2SettingsWriteFragArea(area)}
		ui2Fragment(w, r, "burpsy /ui2/ — Settings", "settings", ui2Exec("settings_write_confirm.html", model))
	}
	_ = r.ParseForm()
	call, errMsg := parse(s, r)
	if errMsg != "" {
		fail(errMsg)
		return
	}
	if call.snapshotPath != "" {
		snap, err := s.ui2CanonicalGet(call.snapshotPath)
		if err != nil {
			fail("could not read the current state to review against: " + err.Error())
			return
		}
		call.snapshot = snap
	}
	// A gated call's token comes from the confirmation gate and binds the exact method, path,
	// query and canonical body. An ungated (riskLocal) call gets a ui2-local one-use handle -
	// the exact-bytes property is the held entry itself, dispatched verbatim and spent once.
	token := ""
	if call.gated {
		mintCall := map[string]any{"method": call.method, "url": call.callURL}
		if call.body != nil {
			mintCall["body"] = string(call.body)
		}
		rawMint, _ := json.Marshal(mintCall)
		mintReq := newReq(http.MethodPost, call.apiBase+"/confirm")
		mintReq.Header.Set("Content-Type", "application/json")
		mintReq.Body = ioNopCloser(strings.NewReader(string(rawMint)))
		mintRec := newRecorder()
		s.confirmMux.ServeHTTP(mintRec, mintReq)
		var minted struct {
			Token string `json:"token"`
		}
		if mintRec.Code != http.StatusOK {
			fail("the confirmation gate refused to mint a review (" + http.StatusText(mintRec.Code) + ") - try again")
			return
		}
		if err := json.Unmarshal(mintRec.Body.Bytes(), &minted); err != nil || minted.Token == "" {
			fail("the confirmation gate refused to mint a review - try again")
			return
		}
		token = minted.Token
	} else {
		local, err := randomHex(16)
		if err != nil {
			fail("review token: " + err.Error())
			return
		}
		token = local
	}
	id, err := randomHex(16)
	if err != nil {
		fail("review id: " + err.Error())
		return
	}
	// Sweep expired entries on issue, then refuse when the map is still full - a full map means a
	// pileup of open reviews, which is a thing to say, not to silently drop.
	now := time.Now()
	s.ui2SettingsWriteReviews.Range(func(k, v any) bool {
		if e, ok := v.(ui2SettingsReview); ok && now.After(e.expires) {
			s.ui2SettingsWriteReviews.Delete(k)
		}
		return true
	})
	count := 0
	s.ui2SettingsWriteReviews.Range(func(_, _ any) bool { count++; return true })
	if count >= ui2SettingsWriteReviewCap {
		fail("too many reviews are open at once - confirm or let some expire, then try again")
		return
	}
	s.ui2SettingsWriteReviews.Store(id, ui2SettingsReview{
		token:        token,
		gated:        call.gated,
		method:       call.method,
		callURL:      call.callURL,
		body:         call.body,
		snapshotPath: call.snapshotPath,
		snapshot:     call.snapshot,
		driftMsg:     call.driftMsg,
		expires:      now.Add(ConfirmTTL),
	})
	// The projection is derived from the exact held bytes - parse and re-marshal so the sheet
	// shows what the token binds, never a second serialization of the form.
	projection := call.method + " " + call.callURL
	if call.body != nil {
		var m map[string]any
		if err := json.Unmarshal(call.body, &m); err == nil {
			if pretty, err := json.MarshalIndent(m, "", "  "); err == nil {
				projection += "\n" + string(pretty)
			} else {
				projection += "\n" + string(call.body)
			}
		} else {
			projection += "\n" + string(call.body)
		}
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Settings", "settings", ui2Exec("settings_write_confirm.html", map[string]any{
		"area":         area,
		"container":    call.container,
		"area_title":   call.title,
		"review_id":    id,
		"token":        token,
		"projection":   projection,
		"consequences": call.consequences,
		"nonatomic":    call.nonatomic,
		"frag":         ui2SettingsWriteFragArea(area),
	}))
}

func (s *Server) ui2SettingsWriteRun(w http.ResponseWriter, r *http.Request) {
	area := r.PathValue("area")
	if _, ok := ui2SettingsWriteParsers[area]; !ok {
		http.Error(w, "unknown settings area", http.StatusNotFound)
		return
	}
	fail := func(msg string) {
		model := map[string]any{"error": msg, "area": area, "container": ui2SettingsWriteContainer(area), "frag": ui2SettingsWriteFragArea(area)}
		ui2Fragment(w, r, "burpsy /ui2/ — Settings", "settings", ui2Exec("settings_write_confirm.html", model))
	}
	_ = r.ParseForm()
	// The entry is deleted on ANY spend attempt (unknown id, stale, token mismatch, drift,
	// dispatch result) so nothing here is replayable.
	v, ok := s.ui2SettingsWriteReviews.LoadAndDelete(r.PostFormValue("review_id"))
	entry, isReview := v.(ui2SettingsReview)
	if !ok || !isReview {
		fail("that review is unknown or was already used - review the change again")
		return
	}
	if time.Now().After(entry.expires) {
		fail("that review expired with the confirmation window - review the change again")
		return
	}
	// Both sides are 128-bit random values; compare in constant time anyway so the check never
	// becomes an oracle if the id scheme ever changes.
	if subtle.ConstantTimeCompare([]byte(entry.token), []byte(r.PostFormValue("token"))) != 1 {
		fail("that review does not match this confirmation - review the change again")
		return
	}
	if entry.snapshotPath != "" {
		now, err := s.ui2CanonicalGet(entry.snapshotPath)
		if err != nil {
			fail("could not re-read the current state to confirm against: " + err.Error())
			return
		}
		if now != entry.snapshot {
			fail(entry.driftMsg)
			return
		}
	}
	// Dispatch the held call verbatim. Re-marshaling here could produce bytes the review did not
	// show. A gated call goes through the guarded chain with its gate token in the confirm
	// header; an ungated (riskLocal) call is answered by the internal mux directly.
	req := newReq(entry.method, entry.callURL)
	if entry.body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Body = ioNopCloser(strings.NewReader(string(entry.body)))
	}
	rec := newRecorder()
	if entry.gated {
		req.Header.Set(ConfirmHeader, entry.token)
		req.Host = "127.0.0.1"
		req.Header.Set("Origin", "http://127.0.0.1")
		s.guarded.ServeHTTP(rec, req)
	} else {
		s.mux.ServeHTTP(rec, req)
	}
	if rec.Code == http.StatusPreconditionRequired {
		fail("confirmation required (428) - the review and the dispatch disagree; review again")
		return
	}
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		fail("the settings API refused the change: " + truncateForDisplay(strings.TrimSpace(rec.Body.String()), 200))
		return
	}
	s.handleUI2SettingsWriteArea(w, r, area)
}

// ---- area fragments ---------------------------------------------------------------------------

// handleUI2SettingsWriteFragment serves GET /ui2/settings/write/{area}: one live section of the
// settings page, loaded into its own container so this file set stays self-contained.
func (s *Server) handleUI2SettingsWriteFragment(w http.ResponseWriter, r *http.Request) {
	s.handleUI2SettingsWriteArea(w, r, r.PathValue("area"))
}

func (s *Server) handleUI2SettingsWriteArea(w http.ResponseWriter, r *http.Request, area string) {
	switch area {
	case "passthrough":
		model := map[string]any{}
		if s.tlsPolicy == nil {
			model["unwired"] = true
		} else {
			rec := newRecorder()
			s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/proxy/passthrough"))
			var view passthroughView
			if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
				model["unwired"] = true
			} else {
				model["patterns"] = view.Patterns
				model["apply_out_of_scope"] = view.ApplyOutOfScope
				model["auto_add_on_failure"] = view.AutoAddOnFailure
				model["auto_added"] = view.AutoAdded
			}
		}
		ui2Fragment(w, r, "burpsy /ui2/ — Settings", "settings", ui2Exec("settings_write_passthrough.html", model))
	case "proxy", "proxy-rule", "proxy-default":
		model := map[string]any{}
		if s.upstreamProxy == nil {
			model["unwired"] = true
		} else {
			view, ok := s.ui2ProxyView()
			if !ok {
				model["unwired"] = true
			} else {
				model["rules"] = view.Rules
				model["default"] = view.Default
				model["persisted"] = view.Persisted
				model["schemes"] = view.Schemes
			}
		}
		ui2Fragment(w, r, "burpsy /ui2/ — Settings", "settings", ui2Exec("settings_write_proxy.html", model))
	case "backup":
		model := map[string]any{}
		if s.persist == nil {
			model["unwired"] = true
		} else {
			rec := newRecorder()
			s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/backup/config"))
			var cfg backupConfig
			if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
				model["unwired"] = true
			} else {
				model["interval_minutes"] = cfg.IntervalMinutes
				model["dir"] = cfg.Dir
				model["retention"] = cfg.Retention
				model["delete_on_shutdown"] = cfg.DeleteOnShutdown
				effective := cfg.Dir
				if effective == "" {
					if live := s.persist.Path(); live != "" {
						effective = filepath.Dir(live)
					}
				}
				model["effective_dir"] = effective
			}
		}
		ui2Fragment(w, r, "burpsy /ui2/ — Settings", "settings", ui2Exec("settings_write_backup.html", model))
	case "pools":
		view := s.ui2PoolsView()
		model := map[string]any{
			"pools":      view.Pools,
			"in_use":     view.InUse,
			"count":      view.Count,
			"default_mc": view.Default.MaxConcurrent,
			"default_dm": view.Default.DelayMs,
		}
		ui2Fragment(w, r, "burpsy /ui2/ — Settings", "settings", ui2Exec("settings_write_pools.html", model))
	default:
		http.Error(w, "unknown settings area", http.StatusNotFound)
	}
}
