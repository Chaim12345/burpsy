package web

// ui2 Extender pages (unit 25): Installed, one plugin's detail with its consoles, Options and
// APIs - the server-rendered counterparts of pages/extensions.tsx.
//
// Every model is read from the JSON API in-process (/api/extensions, /api/extensions/console,
// /api/extensions/apis), so this file holds no plugin logic of its own. The four writes - load,
// unload, order and invoke - are two-step reviewed calls:
//
//   - POST /ui2/extensions/confirm resolves the plugin (and registration, and exchange) from
//     server state, builds the EXACT API call, holds it server-side and renders a review sheet
//     that names the plugin key, the executable it starts and the bytes it hands over.
//   - POST /ui2/extensions/run carries only the review id and token, spends the held entry once
//     and dispatches the held bytes verbatim.
//
// The token source follows the route's risk class: a route in the confirmation gate's set
// (needsConfirmation(routeRiskFor(path))) gets a gate-minted token sent in the confirm header;
// any other route gets a ui2-local one-use handle. Today load and invoke are riskExecute and
// unload and order are riskLocal - none is gated, so all four are server-held reviews - but the
// branch is derived, not hard-coded, so a reclassification is honoured without touching this file.

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/extension"
)

// ui2ExtReviewCap bounds open reviews per server: a full map is a pileup to refuse and say.
const ui2ExtReviewCap = 8

// ui2ExtDefaultConsoleLimit is how many lines per stream the detail page asks for by default.
const ui2ExtDefaultConsoleLimit = 200

// ui2ExtReviews holds reviewed-but-unspent extension calls, keyed by review id. Package-level
// rather than a Server field so this unit adds no field to the shared struct; each entry names
// its owning server and a run on any other server refuses it.
var ui2ExtReviews sync.Map

type ui2ExtReview struct {
	owner    *Server
	token    string
	gated    bool
	action   string
	name     string
	path     string
	body     []byte
	from     string // "installed" or "detail": which fragment the outcome re-renders
	exchange string // the detail page's exchange context, carried back to its re-render
	expires  time.Time
}

// ---- view models -------------------------------------------------------------------------------

var ui2ExtStateLabel = map[extension.State]string{
	extension.StateLoaded:   "loaded",
	extension.StateLoading:  "loading",
	extension.StateUnloaded: "not loaded",
	extension.StateFailed:   "failed to load",
	extension.StateCrashed:  "exited on its own",
}

var ui2ExtKindLabel = map[extension.Kind]string{
	extension.KindContextMenu:      "Context-menu item",
	extension.KindMenu:             "Menu action",
	extension.KindEditorTab:        "Message-editor tab",
	extension.KindSessionAction:    "Session-handling action",
	extension.KindHotKey:           "Hotkey",
	extension.KindHTTPHandler:      "HTTP handler (hook)",
	extension.KindProxyHandler:     "Proxy handler (hook)",
	extension.KindWebSocketHandler: "WebSocket handler (hook)",
	extension.KindPayloadGenerator: "Intruder payload generator",
	extension.KindPayloadProcessor: "Intruder payload processor",
}

type ui2ExtRow struct {
	Index         int
	Name          string
	State         string
	StateLabel    string
	Loaded        bool
	Type          string
	Version       string
	Registrations int
	Refused       int
	OutputLines   int
	ErrorLines    int
	First, Last   bool
	Prev, Next    string
	DetailURL     string
}

type ui2ExtAction struct {
	Plugin    string
	Kind      string
	Label     string
	DetailURL string
}

type ui2ExtInstalled struct {
	Error    string
	List     extension.ListView
	Rows     []ui2ExtRow
	Exchange string
	Actions  []ui2ExtAction
	Note     string
	Done     string
}

type ui2ExtReg struct {
	ID            string
	Kind          string
	KindLabel     string
	Chord         string
	Label         string
	Hint          string
	Runnable      bool
	NeedsExchange bool
	Why           string
}

type ui2ExtLine struct {
	Time   string
	Source string
	Text   string
}

type ui2ExtConsole struct {
	Name          string
	Error         string
	Live          bool
	Limit         int
	SelfURL       string
	ToggleURL     string
	Output        []ui2ExtLine
	Errors        []ui2ExtLine
	OutputDropped int
	ErrorDropped  int
	Truncated     int
	Bound         int
	Loaded        bool
}

type ui2ExtDetail struct {
	Error         string
	Name          string
	Plugin        extension.PluginView
	Row           ui2ExtRow
	Args          string
	ExitText      string
	Regs          []ui2ExtReg
	Exchange      string
	ExchangeLabel string
	ExchangeError string
	SelfURL       string
	Note          string
	Done          string
	ResultReg     string
	Result        string
	Console       ui2ExtConsole
}

type ui2ExtFact struct{ K, V string }

type ui2ExtReviewModel struct {
	Error        string
	Title        string
	Name         string
	Facts        []ui2ExtFact
	Projection   string
	Consequences []string
	Risk         string
	Gated        bool
	ReviewID     string
	Token        string
	Target       string
	Back         string
	Button       string
}

// ---- reads ---------------------------------------------------------------------------------------

// ui2ExtGet reads one of the extension JSON routes through the internal mux and decodes it.
func (s *Server) ui2ExtGet(path string, v any) string {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, path))
	if rec.Code != http.StatusOK {
		return fmt.Sprintf("%s answered %d: %s", strings.SplitN(path, "?", 2)[0], rec.Code, truncateForDisplay(strings.TrimSpace(rec.Body.String()), 200))
	}
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		return "unreadable " + path + ": " + err.Error()
	}
	return ""
}

func (s *Server) ui2ExtList() (extension.ListView, string) {
	var list extension.ListView
	return list, s.ui2ExtGet("/api/extensions", &list)
}

func ui2ExtFind(list extension.ListView, name string) (int, *extension.PluginView) {
	for i := range list.Extensions {
		if list.Extensions[i].Name == name {
			return i, &list.Extensions[i]
		}
	}
	return -1, nil
}

func ui2ExtDetailURL(name, exchange string) string {
	u := "/ui2/extensions/plugin?name=" + url.QueryEscape(name)
	if exchange != "" {
		u += "&exchange=" + url.QueryEscape(exchange)
	}
	return u
}

func ui2ExtRowOf(list extension.ListView, i int) ui2ExtRow {
	p := list.Extensions[i]
	row := ui2ExtRow{
		Index: i + 1, Name: p.Name, State: string(p.State), StateLabel: ui2ExtStateLabel[p.State],
		Loaded: p.State == extension.StateLoaded, Type: p.Type, Version: p.Version,
		Registrations: len(p.Registrations), Refused: p.RegistrationsRefused,
		OutputLines: p.OutputLines, ErrorLines: p.ErrorLines,
		First: i == 0, Last: i == len(list.Extensions)-1,
		DetailURL: ui2ExtDetailURL(p.Name, ""),
	}
	if row.StateLabel == "" {
		row.StateLabel = string(p.State)
	}
	if !row.First {
		row.Prev = list.Extensions[i-1].Name
	}
	if !row.Last {
		row.Next = list.Extensions[i+1].Name
	}
	return row
}

func ui2ExtTime(atMs int64) string {
	if atMs <= 0 {
		return "—"
	}
	return time.UnixMilli(atMs).Format("15:04:05")
}

func ui2ExtDuration(ms int64) string { return (time.Duration(ms) * time.Millisecond).String() }

// ui2ExtExchange resolves an exchange id to a label and its request bytes. Every failure is named.
func (s *Server) ui2ExtExchange(raw string) (id uint64, msg uint64, label, request, errText string) {
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, 0, "", "", "exchange must be a numeric exchange id"
	}
	ex, err := s.store.GetExchange(core.ExchangeID(n))
	if err != nil {
		return 0, 0, "", "", fmt.Sprintf("exchange #%d is not in the store", n)
	}
	label = fmt.Sprintf("#%d %s %s%s", n, ex.Method, ex.Host, ex.Path)
	if ex.Request == nil {
		return n, 0, label, "", fmt.Sprintf("exchange #%d has no stored request - a blind tunnel has nothing to hand a plugin", n)
	}
	m, err := s.store.Get(*ex.Request)
	if err != nil {
		return n, 0, label, "", fmt.Sprintf("the stored request for exchange #%d is unavailable: %v", n, err)
	}
	rawReq := m.Raw()
	if !utf8.Valid(rawReq) {
		return n, 0, label, "", fmt.Sprintf("the stored request for exchange #%d is not valid UTF-8 and cannot cross the invoke route's text field unchanged", n)
	}
	return n, uint64(*ex.Request), label, string(rawReq), ""
}

// ---- Installed -----------------------------------------------------------------------------------

func (s *Server) ui2ExtInstalledModel(exchange string) ui2ExtInstalled {
	list, errText := s.ui2ExtList()
	if errText != "" {
		return ui2ExtInstalled{Error: errText}
	}
	m := ui2ExtInstalled{List: list, Exchange: exchange}
	for i := range list.Extensions {
		m.Rows = append(m.Rows, ui2ExtRowOf(list, i))
	}
	if exchange != "" {
		// The plugin items a History/Logger row offers: every loaded plugin's exchange-taking
		// registration, each a link to that plugin's detail page with this exchange as context.
		for _, p := range list.Extensions {
			if p.State != extension.StateLoaded {
				continue
			}
			for _, reg := range p.Registrations {
				if reg.Kind == extension.KindContextMenu || reg.Kind == extension.KindEditorTab {
					m.Actions = append(m.Actions, ui2ExtAction{
						Plugin: p.Name, Kind: ui2ExtKindLabel[reg.Kind], Label: reg.Label,
						DetailURL: ui2ExtDetailURL(p.Name, exchange),
					})
				}
			}
		}
	}
	return m
}

// handleUI2Extensions serves GET /ui2/extensions: the allowlist metrics and the ordered plugin
// table. ?exchange=N adds the loaded plugins' exchange-taking items for that exchange.
func (s *Server) handleUI2Extensions(w http.ResponseWriter, r *http.Request) {
	exchange := strings.TrimSpace(r.URL.Query().Get("exchange"))
	ui2Fragment(w, r, "burpsy /ui2/ — Extensions", "extensions", ui2Exec("extensions.html", s.ui2ExtInstalledModel(exchange)))
}

// ---- Options and APIs -----------------------------------------------------------------------------

// handleUI2ExtensionsOptions serves GET /ui2/extensions/options: the admission rule and every
// bound in force, read from /api/extensions' policy.
func (s *Server) handleUI2ExtensionsOptions(w http.ResponseWriter, r *http.Request) {
	list, errText := s.ui2ExtList()
	p := list.Policy
	model := map[string]any{
		"error":  errText,
		"policy": p,
		"env":    strings.Join(p.EnvironmentPassed, " "),
		"bounds": []ui2ExtFact{
			{"Load timeout", ui2ExtDuration(p.LoadTimeoutMs) + " — spawn plus handshake"},
			{"Call timeout", ui2ExtDuration(p.CallTimeoutMs) + " — one invocation"},
			{"Shutdown grace", ui2ExtDuration(p.ShutdownGraceMs) + " — then stdin closes, then the process is killed"},
			{"Console lines", strconv.Itoa(p.MaxConsoleLines) + " — per stream, per plugin; oldest evicted and counted"},
			{"Console line bytes", strconv.Itoa(p.MaxConsoleLineBytes) + " — a longer line is cut and marked"},
			{"Message bytes", strconv.Itoa(p.MaxMessageBytes) + " — one JSON-RPC line, either direction"},
			{"Registrations", strconv.Itoa(p.MaxRegistrations) + " — per plugin; the excess is refused"},
		},
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Extender options", "extensions-options", ui2Exec("extensions_options.html", model))
}

// handleUI2ExtensionsAPIs serves GET /ui2/extensions/apis: the plugin contract from
// /api/extensions/apis.
func (s *Server) handleUI2ExtensionsAPIs(w http.ResponseWriter, r *http.Request) {
	var apis extension.APIView
	errText := s.ui2ExtGet("/api/extensions/apis", &apis)
	ui2Fragment(w, r, "burpsy /ui2/ — Extender APIs", "extensions-apis", ui2Exec("extensions_apis.html", map[string]any{"error": errText, "apis": apis}))
}

// ---- Detail and consoles --------------------------------------------------------------------------

func (s *Server) ui2ExtConsoleModel(name string, limit int, live bool) ui2ExtConsole {
	c := ui2ExtConsole{Name: name, Limit: limit, Live: live}
	self := "/ui2/extensions/console?name=" + url.QueryEscape(name) + "&limit=" + strconv.Itoa(limit)
	c.SelfURL = self
	if live {
		c.ToggleURL = self + "&live=0"
	} else {
		c.SelfURL = self + "&live=0"
		c.ToggleURL = self
	}
	var view extension.ConsoleView
	if errText := s.ui2ExtGet("/api/extensions/console?name="+url.QueryEscape(name)+"&limit="+strconv.Itoa(limit), &view); errText != "" {
		c.Error = errText
		c.Live = false
		return c
	}
	conv := func(lines []extension.Line) []ui2ExtLine {
		out := make([]ui2ExtLine, 0, len(lines))
		for _, l := range lines {
			out = append(out, ui2ExtLine{Time: ui2ExtTime(l.AtMs), Source: string(l.Source), Text: l.Text})
		}
		return out
	}
	c.Output, c.Errors = conv(view.Output), conv(view.Error)
	c.OutputDropped, c.ErrorDropped, c.Truncated, c.Bound = view.OutputDropped, view.ErrorDropped, view.Truncated, view.Limit
	return c
}

func ui2ExtConsoleParams(r *http.Request) (int, bool, string) {
	q := r.URL.Query()
	limit := ui2ExtDefaultConsoleLimit
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return 0, false, "limit must be a non-negative number of lines (0 means every retained line)"
		}
		limit = n
	}
	return limit, q.Get("live") != "0", ""
}

// handleUI2ExtensionsConsole serves GET /ui2/extensions/console?name=&limit=&live=: one plugin's
// output and error consoles; the fragment re-polls itself while live.
func (s *Server) handleUI2ExtensionsConsole(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	limit, live, errText := ui2ExtConsoleParams(r)
	var c ui2ExtConsole
	switch {
	case name == "":
		c = ui2ExtConsole{Error: "a console needs the name of an allowlisted plugin: ?name=<name>"}
	case errText != "":
		c = ui2ExtConsole{Name: name, Error: errText}
	default:
		c = s.ui2ExtConsoleModel(name, limit, live)
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Extension console", "extensions", ui2Exec("extensions_console.html", c))
}

func (s *Server) ui2ExtDetailModel(name, exchange string) ui2ExtDetail {
	d := ui2ExtDetail{Name: name, Exchange: exchange, SelfURL: ui2ExtDetailURL(name, exchange)}
	if name == "" {
		d.Error = "name an allowlisted plugin: /ui2/extensions/plugin?name=<name>"
		return d
	}
	list, errText := s.ui2ExtList()
	if errText != "" {
		d.Error = errText
		return d
	}
	i, p := ui2ExtFind(list, name)
	if p == nil {
		d.Error = fmt.Sprintf("%q is not on the plugin allowlist", name)
		return d
	}
	d.Plugin = *p
	d.Row = ui2ExtRowOf(list, i)
	d.Args = strings.Join(p.Args, " ")
	if p.Exit != nil {
		why := p.Exit.Detail
		if why == "" {
			why = p.Exit.Signal
		}
		if why == "" {
			why = fmt.Sprintf("exit status %d", p.Exit.Code)
		}
		d.ExitText = fmt.Sprintf("The process ended at %s: %s.", ui2ExtTime(p.Exit.AtMs), why)
	}
	if exchange != "" {
		_, _, d.ExchangeLabel, _, d.ExchangeError = s.ui2ExtExchange(exchange)
	}
	for _, reg := range p.Registrations {
		v := ui2ExtReg{ID: reg.ID, Kind: string(reg.Kind), KindLabel: ui2ExtKindLabel[reg.Kind], Chord: reg.Chord, Label: reg.Label, Hint: reg.Hint}
		if v.KindLabel == "" {
			v.KindLabel = string(reg.Kind)
		}
		switch reg.Kind {
		case extension.KindMenu, extension.KindHotKey:
			v.Runnable = d.Row.Loaded
			if !v.Runnable {
				v.Why = "load the plugin to run it"
			}
		case extension.KindContextMenu, extension.KindEditorTab:
			v.NeedsExchange = true
			switch {
			case !d.Row.Loaded:
				v.Why = "load the plugin to run it"
			case exchange == "":
				v.Why = "needs an exchange - set one above"
			case d.ExchangeError != "":
				v.Why = d.ExchangeError
			default:
				v.Runnable = true
			}
		case extension.KindPayloadGenerator, extension.KindPayloadProcessor:
			v.Why = "used in Intruder"
		case extension.KindSessionAction:
			v.Why = "used by a session-handling rule"
		default:
			v.Why = "a traffic hook - called by the engine, not by hand"
		}
		d.Regs = append(d.Regs, v)
	}
	d.Console = s.ui2ExtConsoleModel(name, ui2ExtDefaultConsoleLimit, true)
	return d
}

// handleUI2ExtensionsPlugin serves GET /ui2/extensions/plugin?name=&exchange=: one plugin's
// metrics, registrations (with Run) and live consoles.
func (s *Server) handleUI2ExtensionsPlugin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := s.ui2ExtDetailModel(q.Get("name"), strings.TrimSpace(q.Get("exchange")))
	ui2Fragment(w, r, "burpsy /ui2/ — Extension", "extensions", ui2Exec("extensions_detail.html", d))
}

// ---- reviewed writes -----------------------------------------------------------------------------

// ui2ExtForm admits exactly the named fields, each at most once, and no query fields.
func ui2ExtForm(r *http.Request, required, optional []string) string {
	if err := r.ParseForm(); err != nil {
		return "invalid form"
	}
	if len(r.URL.Query()) != 0 {
		return "query fields are not permitted here"
	}
	allowed := map[string]bool{}
	for _, k := range optional {
		allowed[k] = true
	}
	for _, k := range required {
		allowed[k] = true
		if len(r.PostForm[k]) != 1 || r.PostForm[k][0] == "" {
			return k + " is required, exactly once"
		}
	}
	for k, v := range r.PostForm {
		if !allowed[k] || len(v) != 1 {
			return k + " is not a single permitted field"
		}
	}
	return ""
}

func (s *Server) ui2ExtSheet(w http.ResponseWriter, r *http.Request, m ui2ExtReviewModel) {
	ui2Fragment(w, r, "burpsy /ui2/ — Extensions", "extensions", ui2Exec("extensions_review.html", m))
}

// handleUI2ExtensionsConfirm serves POST /ui2/extensions/confirm: build and hold the exact call,
// render the review sheet. Nothing runs here.
func (s *Server) handleUI2ExtensionsConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fail := func(msg string) { s.ui2ExtSheet(w, r, ui2ExtReviewModel{Error: msg}) }
	_ = r.ParseForm()
	action := r.PostFormValue("action")
	required := []string{"action", "name"}
	optional := []string{"from", "exchange"}
	if action == "invoke" {
		required = append(required, "registration")
	}
	if msg := ui2ExtForm(r, required, optional); msg != "" {
		fail(msg)
		return
	}
	name := r.PostFormValue("name")
	exchange := r.PostFormValue("exchange")
	from := r.PostFormValue("from")
	if from != "detail" {
		from = "installed"
	}
	if exchange != "" {
		// Outside invoke the exchange is only the detail page's context, carried back to its
		// re-render and never sent; it must still be an id.
		if _, err := strconv.ParseUint(exchange, 10, 64); err != nil {
			fail("exchange must be a numeric exchange id")
			return
		}
	}
	list, errText := s.ui2ExtList()
	if errText != "" {
		fail(errText)
		return
	}
	i, p := ui2ExtFind(list, name)
	if p == nil {
		fail(fmt.Sprintf("%q is not on the plugin allowlist - only a name passed to -plugins can be loaded", name))
		return
	}
	m := ui2ExtReviewModel{Name: name, Target: "#ext-main", Back: "/ui2/extensions"}
	if from == "detail" {
		m.Target, m.Back = "#ext-detail", ui2ExtDetailURL(name, exchange)
	}
	cmdline := strings.TrimSpace(p.Path + " " + strings.Join(p.Args, " "))
	state := ui2ExtStateLabel[p.State]
	var path string
	var payload map[string]any
	switch action {
	case "load":
		path, payload = "/api/extensions/load", map[string]any{"name": name}
		m.Title, m.Button = "load plugin "+name, "Confirm and load"
		m.Facts = []ui2ExtFact{{"Executable", cmdline}, {"Current state", state}}
		m.Consequences = []string{
			"Loading starts the executable above as a child process with burpsy's own privileges and speaks JSON-RPC to it: this runs operator-supplied code in this process's privileges.",
			fmt.Sprintf("The handshake must finish within %s; a failed load is reported with its reason on the error console.", ui2ExtDuration(list.Policy.LoadTimeoutMs)),
		}
	case "unload":
		path, payload = "/api/extensions/unload", map[string]any{"name": name}
		m.Title, m.Button = "unload plugin "+name, "Confirm and unload"
		m.Facts = []ui2ExtFact{{"Executable", cmdline}, {"Current state", state}}
		m.Consequences = []string{fmt.Sprintf("The plugin is asked to exit; after %s its stdin is closed and then the process is killed. Its registrations stop being offered.", ui2ExtDuration(list.Policy.ShutdownGraceMs))}
	case "up", "down":
		if action == "up" && i == 0 {
			fail(name + " is already first")
			return
		}
		if action == "down" && i == len(list.Extensions)-1 {
			fail(name + " is already last")
			return
		}
		path, payload = "/api/extensions/order", map[string]any{"name": name, "direction": action}
		other := ""
		where := "before"
		if action == "up" {
			other = list.Extensions[i-1].Name
		} else {
			other, where = list.Extensions[i+1].Name, "after"
		}
		m.Title, m.Button = fmt.Sprintf("move %s %s", name, action), "Confirm and move"
		m.Facts = []ui2ExtFact{{"Position", fmt.Sprintf("%d of %d", i+1, len(list.Extensions))}, {"Moves", where + " " + other}}
		m.Consequences = []string{"The order is the sequence the console offers and invokes plugin registrations in. No plugin is started or called."}
	case "invoke":
		reg := r.PostFormValue("registration")
		if p.State != extension.StateLoaded {
			fail(fmt.Sprintf("%s is %s - load it before running a registration", name, state))
			return
		}
		var found *extension.Registration
		for k := range p.Registrations {
			if p.Registrations[k].ID == reg {
				found = &p.Registrations[k]
				break
			}
		}
		if found == nil {
			fail(fmt.Sprintf("%s declared no registration %q", name, reg))
			return
		}
		payload = map[string]any{"name": name, "registration": reg}
		m.Facts = []ui2ExtFact{{"Executable", cmdline}, {"Registration", fmt.Sprintf("%s (%s) - %s", reg, found.Kind, found.Label)}}
		switch found.Kind {
		case extension.KindMenu, extension.KindHotKey:
			m.Consequences = []string{"The plugin is called with the registration id only: no exchange and no message bytes are handed over."}
		case extension.KindContextMenu, extension.KindEditorTab:
			if exchange == "" {
				fail("a " + string(found.Kind) + " registration needs an exchange - set one on the plugin page")
				return
			}
			exID, msgID, label, raw, exErr := s.ui2ExtExchange(exchange)
			if exErr != "" {
				fail(exErr)
				return
			}
			if found.Kind == extension.KindContextMenu {
				payload["exchange"] = exID
			}
			payload["message"] = msgID
			payload["raw"] = raw
			m.Facts = append(m.Facts, ui2ExtFact{"Exchange", label}, ui2ExtFact{"Handed over", fmt.Sprintf("the stored request (message #%d, %d bytes)", msgID, len(raw))})
			m.Consequences = []string{"The plugin is handed this exchange's stored request bytes: engagement data leaves burpsy for the plugin process, which may log, store or send it."}
		default:
			fail(fmt.Sprintf("a %s registration is not run by hand from this page", found.Kind))
			return
		}
		path = "/api/extensions/invoke"
		m.Title, m.Button = fmt.Sprintf("run %s on plugin %s", reg, name), "Confirm and run"
		m.Consequences = append(m.Consequences, fmt.Sprintf("The call is bounded by the %s call timeout. A plugin that answers with nothing is reported as having answered with nothing.", ui2ExtDuration(list.Policy.CallTimeoutMs)))
	default:
		fail("unknown extension action - use load, unload, up, down or invoke")
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		fail("building the call: " + err.Error())
		return
	}
	_, risk, _ := routeRiskFor(path)
	m.Risk = string(risk)
	m.Gated = needsConfirmation(risk)
	token := ""
	if m.Gated {
		tok, _, mintErr := s.ui2MintConfirm(path, http.MethodPost, path, body)
		if mintErr != "" || tok == "" {
			fail("the confirmation gate refused to mint a review - try again " + mintErr)
			return
		}
		token = tok
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
	now := time.Now()
	count := 0
	ui2ExtReviews.Range(func(k, v any) bool {
		e, ok := v.(ui2ExtReview)
		switch {
		case !ok || now.After(e.expires):
			ui2ExtReviews.Delete(k)
		case e.owner == s:
			count++
		}
		return true
	})
	if count >= ui2ExtReviewCap {
		fail("too many reviews are open at once - confirm or let some expire, then try again")
		return
	}
	ui2ExtReviews.Store(id, ui2ExtReview{
		owner: s, token: token, gated: m.Gated, action: action, name: name, path: path, body: body,
		from: from, exchange: exchange, expires: now.Add(ConfirmTTL),
	})
	m.ReviewID, m.Token = id, token
	m.Projection = "POST " + path + "\n" + ui2ExtProjection(payload)
	s.ui2ExtSheet(w, r, m)
}

// ui2ExtProjection pretty-prints the held body for the sheet; a long raw request is shortened
// for display only (the facts table states its full size).
func ui2ExtProjection(payload map[string]any) string {
	shown := make(map[string]any, len(payload))
	keys := make([]string, 0, len(payload))
	for k, v := range payload {
		shown[k] = v
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if raw, ok := shown["raw"].(string); ok && len(raw) > 2000 {
		shown["raw"] = truncateForDisplay(raw, 2000)
	}
	b, err := json.MarshalIndent(shown, "", "  ")
	if err != nil {
		return strings.Join(keys, ", ")
	}
	return string(b)
}

// handleUI2ExtensionsRun serves POST /ui2/extensions/run: spend the held review once and
// dispatch the held call verbatim, then re-render the fragment the review came from.
func (s *Server) handleUI2ExtensionsRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fail := func(msg string) {
		// The run form targets the fragment it came from, which an unknown review cannot name:
		// the refusal replaces the review sheet itself.
		w.Header().Set("HX-Retarget", "#ext-review")
		w.Header().Set("HX-Reswap", "outerHTML")
		s.ui2ExtSheet(w, r, ui2ExtReviewModel{Error: msg})
	}
	if msg := ui2ExtForm(r, []string{"review_id", "token"}, nil); msg != "" {
		fail(msg)
		return
	}
	v, ok := ui2ExtReviews.LoadAndDelete(r.PostFormValue("review_id"))
	entry, isReview := v.(ui2ExtReview)
	if !ok || !isReview || entry.owner != s {
		fail("that review is unknown or was already used - review the action again")
		return
	}
	if time.Now().After(entry.expires) {
		fail("that review expired with the confirmation window - review the action again")
		return
	}
	if subtle.ConstantTimeCompare([]byte(entry.token), []byte(r.PostFormValue("token"))) != 1 {
		fail("that review does not match this confirmation - review the action again")
		return
	}
	req := newReq(http.MethodPost, entry.path)
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(strings.NewReader(string(entry.body)))
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "http://127.0.0.1")
	if entry.gated {
		req.Header.Set(ConfirmHeader, entry.token)
	}
	rec := newRecorder()
	s.guarded.ServeHTTP(rec, req)

	note, done, result := "", "", ""
	if rec.Code != http.StatusOK {
		note = ui2ExtRefusal(rec.Code, rec.Body.Bytes())
	} else {
		switch entry.action {
		case "load":
			var out struct {
				Extension extension.PluginView `json:"extension"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &out)
			done = fmt.Sprintf("Loaded %s: %s, %d registration(s).", entry.name, ui2ExtStateLabel[out.Extension.State], len(out.Extension.Registrations))
		case "unload":
			done = "Unloaded " + entry.name + "."
		case "up", "down":
			done = fmt.Sprintf("Moved %s %s.", entry.name, entry.action)
		case "invoke":
			var out struct {
				Result extension.InvokeResult `json:"result"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &out)
			result = out.Result.Output
			if result == "" {
				result = out.Result.Text
			}
			if result == "" {
				result = "The plugin answered with no text. Anything it did is on its consoles."
			}
			done = "Ran the registration."
		}
	}
	if entry.from == "detail" {
		d := s.ui2ExtDetailModel(entry.name, entry.exchange)
		d.Note, d.Done, d.Result = note, done, result
		if entry.action == "invoke" {
			var b struct {
				Registration string `json:"registration"`
			}
			_ = json.Unmarshal(entry.body, &b)
			d.ResultReg = b.Registration
		}
		ui2Fragment(w, r, "burpsy /ui2/ — Extension", "extensions", ui2Exec("extensions_detail.html", d))
		return
	}
	m := s.ui2ExtInstalledModel("")
	m.Note, m.Done = note, done
	ui2Fragment(w, r, "burpsy /ui2/ — Extensions", "extensions", ui2Exec("extensions.html", m))
}

// ui2ExtRefusal states the API's own refusal: the JSON error field when there is one, else the
// plain-text body. The server's words verbatim - "no such file", "handshake failed" and
// "already loaded" are different problems.
func ui2ExtRefusal(code int, body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	text := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		text = e.Error
	}
	return fmt.Sprintf("refused (%d): %s", code, truncateForDisplay(text, 400))
}
