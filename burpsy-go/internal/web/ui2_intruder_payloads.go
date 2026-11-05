package web

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- ui2 Intruder launch form: attack type, positions, payload sets, processing, pool ----------
//
// The UI only builds the /api/intruder/run body; every generator and rule runs in the intruder
// package. ui2IntruderRunPayload (ui2_attack_pages.go) calls ui2IntruderAddLaunchFields so the
// confirm step and the run step build the body from the same function.

var ui2IntruderModes = []ui2Opt{
	{"sniper", "Sniper"}, {"battering_ram", "Battering ram"},
	{"pitchfork", "Pitchfork"}, {"cluster_bomb", "Cluster bomb"},
}

var ui2PayloadTypes = []ui2Opt{
	{"list", "Simple list"}, {"numbers", "Numbers"}, {"file", "File on the server"},
	{"brute_force", "Brute forcer"}, {"dates", "Dates"}, {"custom_iterator", "Custom iterator"},
	{"null", "Null payloads"}, {"char_substitution", "Character substitution"},
	{"case_modification", "Case modification"}, {"illegal_unicode", "Illegal Unicode"},
	{"character_blocks", "Character blocks"}, {"character_frobber", "Character frobber"},
	{"bit_flipper", "Bit flipper"}, {"username", "Username generator"},
	{"ecb_shuffler", "ECB block shuffler"}, {"copy_other", "Copy other payload"},
	{"recursive_grep", "Recursive grep"}, {"collaborator", "Collaborator payloads"},
	{"plugin", "Extension-generated (plugin)"},
}

var ui2PayloadRuleKinds = []ui2Opt{
	{"add_prefix", "Add prefix"}, {"add_suffix", "Add suffix"}, {"replace", "Match and replace"},
	{"uppercase", "Uppercase"}, {"lowercase", "Lowercase"}, {"encode", "Encode"}, {"decode", "Decode"},
	{"hash", "Hash"}, {"skip_if_matches", "Skip if it matches"}, {"normalize", "Unicode normalization"},
	{"plugin", "Plugin payload processor"},
}

var (
	ui2PayloadLayers = []string{"url", "html", "base64", "base64url", "hex", "gzip", "deflate"}
	ui2PayloadForms  = []string{"nfc", "nfd", "nfkc", "nfkd", "fullwidth", "homoglyph"}
	ui2PayloadHashes = []string{"md5", "sha256"}
)

// ui2DefaultURLEncode is Burp's default "URL-encode these characters" list (the SPA's default).
const ui2DefaultURLEncode = "=&+%;?/ #:"

// ui2MaxPayloadSets bounds the sets one form can carry; a cluster bomb past this is not a form.
const ui2MaxPayloadSets = 16

// ui2PayloadFields lists each type's form fields; ui2PayloadChecks are the checkbox ones.
var ui2PayloadFields = map[string][]string{
	"list":              {"items"},
	"numbers":           {"from", "to", "step"},
	"file":              {"filename"},
	"brute_force":       {"charset", "min_len", "max_len"},
	"dates":             {"from", "to", "step", "format"},
	"custom_iterator":   {"positions", "separator"},
	"null":              {"count"},
	"char_substitution": {"words", "subs", "max_per_word"},
	"case_modification": {"words", "lower", "upper", "capitalize"},
	"illegal_unicode":   {"chars", "overlong2", "overlong3", "overlong4", "percent_encode"},
	"character_blocks":  {"chars", "min_len", "max_len", "step"},
	"character_frobber": {"base", "chars"},
	"bit_flipper":       {"base"},
	"username":          {"names"},
	"ecb_shuffler":      {"sample", "encoding", "block_size"},
	"copy_other":        {"position"},
	"recursive_grep":    {"initial", "extract_re", "stop_duplicate"},
	"collaborator":      {"count", "include_location"},
	"plugin":            {"plugin"},
}

var ui2PayloadChecks = map[string]bool{
	"lower": true, "upper": true, "capitalize": true, "overlong2": true, "overlong3": true,
	"overlong4": true, "percent_encode": true, "stop_duplicate": true, "include_location": true,
}

// ui2PayloadDefaults are the values a set starts with when its type is first chosen.
var ui2PayloadDefaults = map[string]map[string]string{
	"numbers":           {"from": "1", "to": "100", "step": "1"},
	"brute_force":       {"charset": "abc", "min_len": "1", "max_len": "3"},
	"dates":             {"from": "2024-01-01", "to": "2024-12-31", "step": "1", "format": "yyyy-MM-dd"},
	"custom_iterator":   {"positions": "a,b\nc,d"},
	"null":              {"count": "1"},
	"case_modification": {"lower": "on", "upper": "on", "capitalize": "on"},
	"illegal_unicode":   {"chars": "/", "overlong2": "on", "percent_encode": "on"},
	"character_blocks":  {"chars": "A", "min_len": "1", "max_len": "100", "step": "1"},
	"ecb_shuffler":      {"encoding": "base64", "block_size": "16"},
	"copy_other":        {"position": "0"},
	"recursive_grep":    {"stop_duplicate": "on"},
	"collaborator":      {"count": "10", "include_location": "on"},
}

// ui2PayloadSet is one payload set as the form carries it.
type ui2PayloadSet struct {
	Index int
	Num   int    // Index+1, for labels
	P     string // field-name prefix, "set<Index>_"
	Type  string
	F     map[string]string
	Note  string // e.g. the upload result for this set
}

// ui2PayloadRule is one processing rule as the form carries it.
type ui2PayloadRule struct {
	Index int
	Num   int
	P     string
	Kind  string
	F     map[string]string
}

func ui2IsPayloadType(t string) bool {
	_, ok := ui2PayloadFields[t]
	return ok
}

// ui2ReadPayloadSet reads set i. A set whose fields were rendered for its current type
// (setN_seen == type) is read literally; otherwise it starts from the type's defaults, so a
// freshly chosen type renders — and a hand-built post builds — the same values.
func ui2ReadPayloadSet(form url.Values, i int) ui2PayloadSet {
	p := fmt.Sprintf("set%d_", i)
	t := form.Get(p + "type")
	if !ui2IsPayloadType(t) {
		t = "list"
	}
	set := ui2PayloadSet{Index: i, Type: t, F: map[string]string{}}
	seen := form.Get(p+"seen") == t
	if !seen {
		for k, v := range ui2PayloadDefaults[t] {
			set.F[k] = v
		}
	}
	for _, f := range ui2PayloadFields[t] {
		v, posted := form[p+f]
		switch {
		case ui2PayloadChecks[f] && seen:
			set.F[f] = ""
			if posted && len(v) > 0 && v[0] != "" {
				set.F[f] = "on"
			}
		case posted && len(v) > 0 && (seen || v[0] != ""):
			set.F[f] = v[0]
		}
	}
	return set
}

func ui2ReadPayloadRule(form url.Values, i int) ui2PayloadRule {
	p := fmt.Sprintf("rule%d_", i)
	rule := ui2PayloadRule{Index: i, Kind: form.Get(p + "kind"), F: map[string]string{
		"layer": "url", "algorithm": "sha256", "form": "nfkc",
	}}
	for _, f := range []string{"text", "pattern", "replace", "all", "layer", "algorithm", "form", "plugin"} {
		if v := form.Get(p + f); v != "" {
			rule.F[f] = v
		}
	}
	return rule
}

// ui2FormCount reads a small bounded count field (set_count, rule_count).
func ui2FormCount(form url.Values, name string, def, max int) int {
	n, err := strconv.Atoi(form.Get(name))
	if err != nil || n < 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func ui2ReadPayloadSets(form url.Values) []ui2PayloadSet {
	n := ui2FormCount(form, "set_count", 1, ui2MaxPayloadSets)
	if n == 0 {
		n = 1
	}
	sets := make([]ui2PayloadSet, 0, n)
	for i := 0; i < n; i++ {
		sets = append(sets, ui2ReadPayloadSet(form, i))
	}
	return sets
}

func ui2ReadPayloadRules(form url.Values) []ui2PayloadRule {
	n := ui2FormCount(form, "rule_count", 0, ui2MaxPayloadSets)
	rules := make([]ui2PayloadRule, 0, n)
	for i := 0; i < n; i++ {
		rules = append(rules, ui2ReadPayloadRule(form, i))
	}
	return rules
}

// ui2Lines splits a textarea into non-blank lines (the SPA's payloadList), CR stripped.
func ui2Lines(s string) []string {
	out := []string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

// ui2PluginValue/ui2PluginRef encode a plugin registration as one select value.
func ui2PluginValue(plugin, registration string) string {
	return url.QueryEscape(plugin) + "/" + url.QueryEscape(registration)
}

func ui2PluginRef(v string) (map[string]any, bool) {
	p, r, ok := strings.Cut(v, "/")
	if !ok {
		return nil, false
	}
	plugin, err1 := url.QueryUnescape(p)
	reg, err2 := url.QueryUnescape(r)
	if err1 != nil || err2 != nil || plugin == "" || reg == "" {
		return nil, false
	}
	return map[string]any{"plugin": plugin, "registration": reg}, true
}

// ui2NumParser collects the first parse error across a form's numeric fields.
type ui2NumParser struct{ err string }

func (p *ui2NumParser) int(field, s string) int64 {
	s = strings.TrimSpace(s)
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil && p.err == "" {
		p.err = field + " must be a whole number"
	}
	return n
}

func (p *ui2NumParser) float(field, s string) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil && p.err == "" {
		p.err = field + " must be a number"
	}
	return f
}

// ui2PayloadSource turns one form set into its /api/intruder/run payload_sources entry.
func ui2PayloadSource(set ui2PayloadSet, np *ui2NumParser) map[string]any {
	f := set.F
	name := fmt.Sprintf("payload set %d ", set.Index+1)
	on := func(k string) bool { return f[k] == "on" }
	src := map[string]any{"type": set.Type}
	switch set.Type {
	case "list":
		src["items"] = ui2Lines(f["items"])
	case "numbers":
		src["from"] = np.int(name+"from", f["from"])
		src["to"] = np.int(name+"to", f["to"])
		src["step"] = np.int(name+"step", f["step"])
	case "file":
		src["filename"] = strings.TrimSpace(f["filename"])
	case "brute_force":
		src["charset"] = f["charset"]
		src["min_len"] = np.int(name+"min length", f["min_len"])
		src["max_len"] = np.int(name+"max length", f["max_len"])
	case "dates":
		src["from"] = strings.TrimSpace(f["from"])
		src["to"] = strings.TrimSpace(f["to"])
		src["step"] = np.int(name+"step", f["step"])
		src["format"] = f["format"]
	case "custom_iterator":
		slots := [][]string{}
		for _, line := range ui2Lines(f["positions"]) {
			var slot []string
			for _, item := range strings.Split(line, ",") {
				if item = strings.TrimSpace(item); item != "" {
					slot = append(slot, item)
				}
			}
			if len(slot) > 0 {
				slots = append(slots, slot)
			}
		}
		src["positions"] = slots
		src["separator"] = f["separator"]
	case "null":
		src["count"] = np.int(name+"count", f["count"])
	case "char_substitution":
		subs := map[string]string{}
		for _, line := range strings.Split(f["subs"], "\n") {
			ch, rep, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
			if ch = strings.TrimSpace(ch); ok && ch != "" {
				subs[ch] = strings.TrimSpace(rep)
			}
		}
		src["words"] = ui2Lines(f["words"])
		src["subs"] = subs
		src["max_per_word"] = int64(0)
		if strings.TrimSpace(f["max_per_word"]) != "" {
			src["max_per_word"] = np.int(name+"max per word", f["max_per_word"])
		}
	case "case_modification":
		src["words"] = ui2Lines(f["words"])
		src["lower"], src["upper"], src["capitalize"] = on("lower"), on("upper"), on("capitalize")
	case "illegal_unicode":
		forms := []string{}
		for _, k := range []string{"overlong2", "overlong3", "overlong4"} {
			if on(k) {
				forms = append(forms, k)
			}
		}
		src["chars"] = f["chars"]
		src["forms"] = forms
		src["percent_encode"] = on("percent_encode")
	case "character_blocks":
		src["chars"] = f["chars"]
		src["min_len"] = np.int(name+"min length", f["min_len"])
		src["max_len"] = np.int(name+"max length", f["max_len"])
		src["step"] = np.int(name+"step", f["step"])
	case "character_frobber":
		src["base"] = f["base"]
		src["chars"] = f["chars"]
	case "bit_flipper":
		src["base"] = f["base"]
	case "username":
		src["names"] = ui2Lines(f["names"])
	case "ecb_shuffler":
		src["sample"] = strings.TrimSpace(f["sample"])
		src["encoding"] = f["encoding"]
		src["block_size"] = np.int(name+"block size", f["block_size"])
	case "copy_other":
		src["position"] = np.int(name+"position", f["position"])
	case "recursive_grep":
		src["initial"] = f["initial"]
		src["extract_re"] = f["extract_re"]
		src["stop_duplicate"] = on("stop_duplicate")
	case "collaborator":
		src["count"] = np.int(name+"count", f["count"])
		src["include_location"] = on("include_location")
	case "plugin":
		ref, ok := ui2PluginRef(f["plugin"])
		if !ok && np.err == "" {
			np.err = name + "has no plugin generator chosen"
		}
		src["plugin"] = ref
	}
	return src
}

// ui2PayloadRuleSpec turns one form rule into a payload_rules entry (intruder.RuleSpec's shape).
func ui2PayloadRuleSpec(rule ui2PayloadRule, np *ui2NumParser) (map[string]any, bool) {
	f := rule.F
	spec := map[string]any{"rule": rule.Kind}
	switch rule.Kind {
	case "add_prefix", "add_suffix":
		spec["text"] = f["text"]
	case "replace":
		spec["pattern"], spec["replace"], spec["all"] = f["pattern"], f["replace"], f["all"] == "on"
	case "uppercase", "lowercase":
	case "encode", "decode":
		spec["layer"] = f["layer"]
	case "hash":
		spec["algorithm"] = f["algorithm"]
	case "skip_if_matches":
		spec["pattern"] = f["pattern"]
	case "normalize":
		spec["form"] = f["form"]
	case "plugin":
		ref, ok := ui2PluginRef(f["plugin"])
		if !ok && np.err == "" {
			np.err = fmt.Sprintf("processing rule %d has no plugin processor chosen", rule.Index+1)
		}
		spec["plugin"] = ref
	default:
		return nil, false
	}
	return spec, true
}

// ui2IntruderAddLaunchFields adds the attack type, payload sets, processing rules, URL-encoding,
// Host-header switch and resource-pool fields to the run body. It reads only the posted form, so
// the confirm step and the run step produce the same bytes from the same fields.
func ui2IntruderAddLaunchFields(form url.Values, run map[string]any) string {
	np := &ui2NumParser{}
	mode := form.Get("mode")
	switch mode {
	case "sniper", "battering_ram", "pitchfork", "cluster_bomb":
	case "":
		mode = "sniper"
	default:
		return "unknown attack type " + strconv.Quote(mode)
	}
	run["mode"] = mode

	// A form that carries typed sets uses them; a hand-built post may still send `payloads`.
	if form.Get("set0_type") != "" {
		sets := ui2ReadPayloadSets(form)
		if mode == "sniper" || mode == "battering_ram" {
			sets = sets[:1] // these modes read set 1 only
		}
		allLists := true
		for _, set := range sets {
			allLists = allLists && set.Type == "list"
		}
		if allLists {
			lists := make([][]string, 0, len(sets))
			for _, set := range sets {
				lists = append(lists, ui2Lines(set.F["items"]))
			}
			run["payload_sets"] = lists
		} else {
			srcs := make([]map[string]any, 0, len(sets))
			for _, set := range sets {
				srcs = append(srcs, ui2PayloadSource(set, np))
			}
			run["payload_sources"] = srcs
		}
	} else if payloads := ui2Lines(form.Get("payloads")); len(payloads) > 0 {
		run["payloads"] = payloads
	}

	var rules []map[string]any
	for _, rule := range ui2ReadPayloadRules(form) {
		if spec, ok := ui2PayloadRuleSpec(rule, np); ok {
			rules = append(rules, spec)
		}
	}
	if len(rules) > 0 {
		run["payload_rules"] = rules
	}
	if v := form.Get("url_encode"); v != "" {
		run["url_encode_characters"] = v
	}
	if form.Get("update_host_header") == "on" {
		run["update_host_header"] = true
	}

	// Resource pool: a saved pool by name, or the inline limits — the API refuses both at once.
	if v := strings.TrimSpace(form.Get("max_requests")); v != "" {
		run["max_requests"] = np.int("max requests", v)
	}
	if name := strings.TrimSpace(form.Get("pool")); name != "" {
		run["pool"] = name
	} else {
		if v := strings.TrimSpace(form.Get("max_in_flight")); v != "" {
			run["max_in_flight"] = np.int("concurrent requests", v)
		}
		if v := strings.TrimSpace(form.Get("rps")); v != "" {
			run["rps"] = np.float("requests per second", v)
		}
		// Blank and 0 both mean "no variation" (the SPA's delayVariationFields).
		if v := strings.TrimSpace(form.Get("delay_jitter_percent")); v != "" {
			if f := np.float("delay variation", v); f != 0 {
				run["delay_jitter_percent"] = f
			}
		}
		if v := strings.TrimSpace(form.Get("delay_increment_ms")); v != "" {
			if n := np.int("delay increase", v); n != 0 {
				run["delay_increment_ms"] = n
			}
		}
	}
	return np.err
}

// ---- positions ---------------------------------------------------------------------------------

// ui2IntruderBase returns the stored request named by msgID and the exchange that carries it
// (nil when no exchange does — a message id the operator typed may be a bare stored message).
func (s *Server) ui2IntruderBase(msgID uint64) ([]byte, *core.Exchange, bool) {
	msg, err := s.store.Get(core.MsgId(msgID))
	if err != nil {
		return nil, nil, false
	}
	exs := s.store.Exchanges()
	for i := len(exs) - 1; i >= 0; i-- {
		if ex := exs[i]; ex.Request != nil && uint64(*ex.Request) == msgID {
			return msg.Raw(), ex, true
		}
	}
	return msg.Raw(), nil, true
}

// ui2IntruderBaseTarget is the default attack target: the base request's own Host (and its
// exchange's scheme), never whatever was captured last — a newer capture to another host must
// not retarget an attack built on this request.
func (s *Server) ui2IntruderBaseTarget(msgID uint64) string {
	raw, ex, ok := s.ui2IntruderBase(msgID)
	if !ok {
		return ""
	}
	host := ui2HostFromRequest(string(raw))
	if host == "" && ex != nil && ex.Host != "" {
		host = ex.Host
		if ex.Port != 0 && (!ex.TLS || ex.Port != 443) && (ex.TLS || ex.Port != 80) {
			host += ":" + strconv.Itoa(int(ex.Port))
		}
	}
	if host != "" && !strings.Contains(host, "://") && ex != nil && ex.TLS {
		host = "https://" + host
	}
	return host
}

// ui2MarkedSpans maps the § markers in the operator's copy of the base request to byte ranges
// of the stored request. The textarea may have rewritten CRLF as LF (or the reverse), so the
// walk matches line endings loosely and everything else exactly.
func ui2MarkedSpans(raw []byte, marked string) ([]map[string]int, string) {
	const marker = "§"
	if !strings.Contains(marked, marker) {
		return nil, ""
	}
	var spans []map[string]int
	open := -1
	ri := 0
	m := marked
	for len(m) > 0 {
		switch {
		case strings.HasPrefix(m, marker):
			if open < 0 {
				open = ri
			} else {
				spans = append(spans, map[string]int{"start": open, "end": ri})
				open = -1
			}
			m = m[len(marker):]
		case m[0] == '\r' && ri < len(raw) && raw[ri] == '\n':
			m = m[1:]
		case m[0] == '\n' && ri+1 < len(raw) && raw[ri] == '\r' && raw[ri+1] == '\n':
			m, ri = m[1:], ri+2
		case ri < len(raw) && m[0] == raw[ri]:
			m, ri = m[1:], ri+1
		default:
			return nil, fmt.Sprintf("the marked request differs from the base request at byte %d — mark positions only by adding § pairs", ri)
		}
	}
	if open >= 0 {
		return nil, "a § marker has no closing pair"
	}
	if ri != len(raw) && strings.TrimRight(string(raw[ri:]), "\r\n") != "" {
		return nil, "the marked request is shorter than the base request — mark positions only by adding § pairs"
	}
	return spans, ""
}

// ui2IntruderPositions is the positions-section model.
type ui2IntruderPositions struct {
	MsgID        string
	BaseExchange uint64
	AllPoints    bool
	Placement    string
	Points       []map[string]any
	Selected     map[int]bool
	PointsListed bool
	Error        string
	Marked       string
	MarkedOK     bool
	Note         string
}

// ui2IntruderPositionsModel builds the positions section from the form. op is "" (render as
// posted), "find" (discover, select all), "auto" (Burp's Auto §: the standard set, all selected,
// manual marks cleared) or "clear" (Clear §: manual marks cleared, selection kept).
func (s *Server) ui2IntruderPositionsModel(form url.Values, op string) ui2IntruderPositions {
	formSeen := form.Get("form_seen") != ""
	pm := ui2IntruderPositions{
		MsgID:     form.Get("msg_id"),
		AllPoints: form.Get("all_points") == "on" || form.Get("all") == "on" || form.Get("all") == "true" || !formSeen,
		Placement: form.Get("payload_placement"),
		Selected:  map[int]bool{},
	}
	msgID, perr := strconv.ParseUint(pm.MsgID, 10, 64)
	var raw []byte
	var ex *core.Exchange
	ok := false
	if perr == nil {
		raw, ex, ok = s.ui2IntruderBase(msgID)
	}
	if ex != nil {
		pm.BaseExchange = uint64(ex.ID)
	}
	if !ok && pm.MsgID != "" {
		pm.Error = "no stored message " + pm.MsgID
	}
	// The marked copy belongs to the message it was made from; a changed msg_id resets it.
	pm.Marked = form.Get("marked")
	if form.Get("marked_for") != pm.MsgID || pm.Marked == "" || op == "auto" || op == "clear" {
		pm.Marked = ""
		if ok && ui2TextareaSafe(raw) {
			pm.Marked = string(raw)
		}
	}
	pm.MarkedOK = ok && ui2TextareaSafe(raw)
	if op == "auto" {
		pm.AllPoints = false
	}
	if op == "" {
		pm.PointsListed = form.Get("points_listed") != ""
		for _, v := range form["point"] {
			if n, err := strconv.Atoi(v); err == nil {
				pm.Selected[n] = true
			}
		}
		if !pm.PointsListed {
			return pm
		}
	}
	if op == "clear" && form.Get("points_listed") == "" {
		return pm
	}
	if !ok {
		return pm
	}
	disc, errText := s.ui2APIResult(http.MethodPost, "/api/intruder/points", map[string]any{
		"msg_id": msgID, "all": pm.AllPoints, "payload_placement": pm.Placement,
	})
	if errText != "" {
		pm.Error = ui2APIErrorText(errText)
		return pm
	}
	list, _ := disc.([]any)
	pm.PointsListed = true
	for _, p := range list {
		if m, ok := p.(map[string]any); ok {
			pm.Points = append(pm.Points, m)
		}
	}
	switch op {
	case "find", "auto":
		for i := range pm.Points {
			pm.Selected[i] = true
		}
	case "clear", "":
		for _, v := range form["point"] {
			if n, err := strconv.Atoi(v); err == nil {
				pm.Selected[n] = true
			}
		}
	}
	if len(pm.Points) == 0 {
		pm.Note = "No insertion points were found in that message — mark positions by hand with § pairs below."
	}
	return pm
}

// ---- form model --------------------------------------------------------------------------------

// ui2IntruderFormModel is everything the launch form renders, re-filled from a posted form.
func (s *Server) ui2IntruderFormModel(form url.Values, defaultMsgID string) map[string]any {
	formSeen := form.Get("form_seen") != ""
	if form.Get("msg_id") == "" && defaultMsgID != "" {
		form = ui2CloneValues(form)
		form.Set("msg_id", defaultMsgID)
	}
	mode := form.Get("mode")
	if mode == "" {
		mode = "sniper"
	}
	model := map[string]any{
		"target":       form.Get("target"),
		"mode":         mode,
		"modes":        ui2IntruderModes,
		"positions":    s.ui2IntruderPositionsModel(form, ""),
		"update_host":  form.Get("update_host_header") == "on" || !formSeen,
		"pool":         form.Get("pool"),
		"pools":        s.ui2PoolNames(),
		"max_requests": form.Get("max_requests"), "max_in_flight": form.Get("max_in_flight"),
		"rps": form.Get("rps"), "delay_jitter_percent": form.Get("delay_jitter_percent"),
		"delay_increment_ms": form.Get("delay_increment_ms"),
	}
	for k, v := range s.ui2IntruderPayloadsModel(form, ui2ReadPayloadSets(form), ui2ReadPayloadRules(form)) {
		model[k] = v
	}
	model["mode"] = mode
	return model
}

// ui2IntruderPayloadsModel is the payload-sets/processing section's model.
func (s *Server) ui2IntruderPayloadsModel(form url.Values, sets []ui2PayloadSet, rules []ui2PayloadRule) map[string]any {
	urlEncode := form.Get("url_encode")
	if form.Get("form_seen") == "" {
		urlEncode = ui2DefaultURLEncode
	}
	for i := range sets {
		sets[i].Index, sets[i].Num, sets[i].P = i, i+1, fmt.Sprintf("set%d_", i)
	}
	for i := range rules {
		rules[i].Index, rules[i].Num, rules[i].P = i, i+1, fmt.Sprintf("rule%d_", i)
	}
	return map[string]any{
		"sets": sets, "set_count": len(sets),
		"rules": rules, "rule_count": len(rules),
		"mode":         form.Get("mode"),
		"types":        ui2PayloadTypes,
		"rule_kinds":   ui2PayloadRuleKinds,
		"layers":       ui2PayloadLayers,
		"forms":        ui2PayloadForms,
		"hashes":       ui2PayloadHashes,
		"wordlists":    s.ui2Wordlists(),
		"generators":   s.ui2PluginProviders("payload-generator"),
		"processors":   s.ui2PluginProviders("payload-processor"),
		"url_encode":   urlEncode,
		"next_set":     len(sets),
		"can_add_set":  len(sets) < ui2MaxPayloadSets,
		"can_add_rule": len(rules) < ui2MaxPayloadSets,
	}
}

func ui2CloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func (s *Server) ui2PoolNames() []string {
	res, _ := s.ui2APIResult(http.MethodGet, "/api/pools", nil)
	var names []string
	if m, ok := res.(map[string]any); ok {
		if list, ok := m["pools"].([]any); ok {
			for _, p := range list {
				if pm, ok := p.(map[string]any); ok {
					if n, _ := pm["name"].(string); n != "" {
						names = append(names, n)
					}
				}
			}
		}
	}
	return names
}

func (s *Server) ui2Wordlists() []map[string]any {
	res, _ := s.ui2APIResult(http.MethodGet, "/api/wordlists", nil)
	var out []map[string]any
	if m, ok := res.(map[string]any); ok {
		if list, ok := m["wordlists"].([]any); ok {
			for _, w := range list {
				if wm, ok := w.(map[string]any); ok {
					out = append(out, wm)
				}
			}
		}
	}
	return out
}

// ui2PluginProviders lists loaded plugins' registrations of one payload kind.
func (s *Server) ui2PluginProviders(kind string) []ui2Opt {
	res, _ := s.ui2APIResult(http.MethodGet, "/api/extensions", nil)
	var out []ui2Opt
	m, _ := res.(map[string]any)
	list, _ := m["extensions"].([]any)
	for _, e := range list {
		em, _ := e.(map[string]any)
		if em == nil || em["state"] != "loaded" {
			continue
		}
		name, _ := em["name"].(string)
		regs, _ := em["registrations"].([]any)
		for _, r := range regs {
			rm, _ := r.(map[string]any)
			if rm == nil || rm["kind"] != kind {
				continue
			}
			id, _ := rm["id"].(string)
			label, _ := rm["label"].(string)
			if label == "" {
				label = id
			}
			out = append(out, ui2Opt{Value: ui2PluginValue(name, id), Label: name + " — " + label})
		}
	}
	return out
}

// ---- handlers ----------------------------------------------------------------------------------

// handleUI2IntruderPayloads serves POST /ui2/intruder/payloads: re-renders the payload-sets and
// processing section from the posted form (a type changed, a set or rule added or removed).
// Read-only: nothing is stored or sent.
func (s *Server) handleUI2IntruderPayloads(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	sets := ui2ReadPayloadSets(r.PostForm)
	rules := ui2ReadPayloadRules(r.PostForm)
	op, arg, _ := strings.Cut(r.PostFormValue("op"), ":")
	at, err := strconv.Atoi(arg)
	switch {
	case op == "add_set" && len(sets) < ui2MaxPayloadSets:
		sets = append(sets, ui2ReadPayloadSet(url.Values{}, len(sets)))
	case op == "remove_set" && err == nil && at >= 0 && at < len(sets) && len(sets) > 1:
		sets = append(sets[:at], sets[at+1:]...)
	case op == "add_rule" && len(rules) < ui2MaxPayloadSets:
		rules = append(rules, ui2PayloadRule{Kind: "add_prefix", F: map[string]string{"layer": "url", "algorithm": "sha256", "form": "nfkc"}})
	case op == "remove_rule" && err == nil && at >= 0 && at < len(rules):
		rules = append(rules[:at], rules[at+1:]...)
	}
	model := s.ui2IntruderPayloadsModel(r.PostForm, sets, rules)
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", ui2Exec("intruder_payloads_sets.html", model))
}

// handleUI2IntruderPayloadUpload serves POST /ui2/intruder/payloads/upload (multipart): stores
// the chosen wordlist through /api/intruder/payload-files and re-renders the payload section
// with that set switched to "file on the server" naming the stored path.
func (s *Server) handleUI2IntruderPayloadUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		http.Error(w, "upload must be a multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}
	form := ui2CloneValues(r.PostForm)
	at, err := strconv.Atoi(form.Get("upload_set"))
	errText := ""
	if err != nil || at < 0 || at >= ui2MaxPayloadSets {
		errText = "the upload names no payload set"
	}
	var content []byte
	var filename string
	if errText == "" {
		file, hdr, ferr := r.FormFile(fmt.Sprintf("upload_file_%d", at))
		if ferr != nil {
			errText = "choose a wordlist file to upload first"
		} else {
			content, _ = io.ReadAll(io.LimitReader(file, 64<<20))
			_ = file.Close()
			filename = hdr.Filename
		}
	}
	note := ""
	if errText == "" {
		stored, lines, e := s.ui2UploadPayloadFile(filename, content)
		if e != "" {
			errText = e
		} else {
			p := fmt.Sprintf("set%d_", at)
			form.Set(p+"type", "file")
			form.Set(p+"seen", "file")
			form.Set(p+"filename", stored)
			note = fmt.Sprintf("Uploaded %s — %d payloads, stored as %s", filename, lines, stored)
		}
	}
	if n := ui2FormCount(form, "set_count", 1, ui2MaxPayloadSets); at >= n && errText == "" {
		form.Set("set_count", strconv.Itoa(at+1))
	}
	sets := ui2ReadPayloadSets(form)
	for i := range sets {
		if i == at {
			sets[i].Note = note
			if errText != "" {
				sets[i].Note = "Upload refused: " + errText
			}
		}
	}
	model := s.ui2IntruderPayloadsModel(form, sets, ui2ReadPayloadRules(form))
	if errText != "" && (at < 0 || at >= len(sets)) {
		model["error"] = errText
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", ui2Exec("intruder_payloads_sets.html", model))
}

// ui2UploadPayloadFile hands the bytes to /api/intruder/payload-files (the API stores them under
// a random name; the client's filename is display-only there).
func (s *Server) ui2UploadPayloadFile(name string, content []byte) (stored string, lines int, errText string) {
	req := newReq(http.MethodPost, "/api/intruder/payload-files")
	req.Header.Set("X-Payload-Filename", name)
	req.Body = io.NopCloser(bytes.NewReader(content))
	req.ContentLength = int64(len(content))
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		return "", 0, strings.TrimSpace(rec.Body.String())
	}
	var out struct {
		Filename string `json:"filename"`
		Lines    int    `json:"lines"`
	}
	if err := ui2DecodeJSON(rec.Body.Bytes(), &out); err != nil || out.Filename == "" {
		return "", 0, "the upload answered in a shape the page does not understand"
	}
	return out.Filename, out.Lines, ""
}

// ui2ConfirmEcho is the reviewed form carried back to the run step as hidden inputs: every posted
// field (so the run step rebuilds the same body from the same function), with the resolved target
// and selection in place of what was typed. A field edited in between changes the body, and the
// gate then refuses the token.
func ui2ConfirmEcho(form url.Values, run map[string]any) [][2]string {
	skip := map[string]bool{"token": true, "target": true, "point": true, "points_listed": true, "op": true}
	keys := make([]string, 0, len(form))
	for k := range form {
		if !skip[k] && !strings.HasPrefix(k, "upload_") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var out [][2]string
	for _, k := range keys {
		for _, v := range form[k] {
			out = append(out, [2]string{k, v})
		}
	}
	target, _ := run["target"].(string)
	out = append(out, [2]string{"target", target}, [2]string{"points_listed", "1"})
	if pts, ok := run["points"].([]int); ok {
		for _, p := range pts {
			out = append(out, [2]string{"point", strconv.Itoa(p)})
		}
	}
	return out
}
