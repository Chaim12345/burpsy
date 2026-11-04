package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ---- Comparer (/ui2/comparer) ----------------------------------------------------------------
//
// Slots A and B each hold a list of items (loaded by message id, from a file, or pasted) plus a
// working editor. The page holds no server state: every item rides the form as base64 in a hidden
// field, so an item's bytes come back exactly - a textarea would have normalised its line endings.
// The diff itself is POST /api/tools/compare; this file lays the ops out as two aligned panes (or a
// hex dump) with an anchor per difference for previous/next navigation.

const ui2CmpTitle = "burpsy /ui2/ — Comparer"

const (
	ui2CmpMaxUpload = 16 << 20
	ui2CmpMaxSegs   = 2000 // ops drawn before the panes stop
	ui2CmpMaxHex    = 8192 // bytes per side in the hex dump
	ui2CmpMaxListed = 500  // differences listed for stepping
	ui2CmpGap       = "·"  // filler opposite an insertion or deletion
)

type ui2CmpItem struct {
	Label  string
	Data   []byte
	Binary bool
}

// ui2CmpSlotState is one side as the form carried it.
type ui2CmpSlotState struct {
	Items []ui2CmpItem
	Sel   int
	Text  string
	Msg   string
}

// ui2CmpBinary reports whether bytes cannot cross a textarea as text.
func ui2CmpBinary(b []byte) bool { return !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 }

// ui2CmpDisplay renders bytes for a textarea or pane. Text shows as itself; a binary side shows
// one character per byte (controls as their Unicode pictures), so it survives the round-trip.
func ui2CmpDisplay(b []byte, binary bool) string {
	if !binary {
		return string(b)
	}
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\n' || c == '\t':
			sb.WriteByte(c)
		case c < 0x20:
			sb.WriteRune(rune(0x2400 + int(c)))
		case c == 0x7f:
			sb.WriteRune('␡')
		default:
			sb.WriteRune(rune(c))
		}
	}
	return sb.String()
}

func ui2CmpNormNL(s string) string { return strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(s) }

// ui2CmpFirstLine labels an item by its first line: what an operator reads to tell two apart.
func ui2CmpFirstLine(s string) string {
	line, _, _ := strings.Cut(ui2CmpNormNL(s), "\n")
	if utf8.RuneCountInString(line) > 72 {
		line = string([]rune(line)[:69]) + "..."
	}
	if line == "" {
		return "(no content)"
	}
	return line
}

// ui2CmpReadSlot reads one side from the form. A malformed item or selection is refused, never
// dropped: comparing a list with a silently missing item would compare something else.
func ui2CmpReadSlot(r *http.Request, name string) (ui2CmpSlotState, string) {
	st := ui2CmpSlotState{Sel: -1, Text: r.PostFormValue(name), Msg: strings.TrimSpace(r.PostFormValue(name + "_msg"))}
	items, labels, bins := r.PostForm[name+"_item"], r.PostForm[name+"_label"], r.PostForm[name+"_bin"]
	if len(labels) != len(items) || len(bins) != len(items) {
		return st, "slot " + strings.ToUpper(name) + "'s item list arrived incomplete - reload the page"
	}
	for i, enc := range items {
		data, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return st, fmt.Sprintf("item %d of slot %s is not valid base64", i+1, strings.ToUpper(name))
		}
		st.Items = append(st.Items, ui2CmpItem{Label: labels[i], Data: data, Binary: bins[i] == "1"})
	}
	if raw := r.PostFormValue(name + "_sel"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < -1 || n >= len(st.Items) {
			return st, "slot " + strings.ToUpper(name) + "'s selected item is not in its list"
		}
		st.Sel = n
	}
	return st, ""
}

func (st *ui2CmpSlotState) add(it ui2CmpItem) {
	st.Items = append(st.Items, it)
	st.Sel = len(st.Items) - 1
	st.Text = ui2CmpDisplay(it.Data, it.Binary)
}

// effective is what this side compares: the selected item's exact bytes while the editor still
// shows it, otherwise the editor text.
func (st *ui2CmpSlotState) effective() (data []byte, binary, fromItem bool) {
	if st.Sel >= 0 && st.Sel < len(st.Items) {
		it := st.Items[st.Sel]
		if ui2CmpNormNL(st.Text) == ui2CmpNormNL(ui2CmpDisplay(it.Data, it.Binary)) {
			return it.Data, it.Binary, true
		}
	}
	return []byte(st.Text), false, false
}

// ---- view models ------------------------------------------------------------------------------

type ui2CmpItemView struct {
	Index                int
	Label, B64, Size, Bn string
	Selected, Binary     bool
}

type ui2CmpSlotView struct {
	Name, Upper, Text, Msg, Size string
	Sel                          int
	Items                        []ui2CmpItemView
	Binary                       bool
}

type ui2CmpSeg struct {
	Kind, Mark, A, B string
	Hunk             int
	Unint            bool
}

type ui2CmpHunk struct {
	N, Shown, Prev, Next, AOff, BOff int
	Kind, A, B                       string
	Unint                            bool
}

type ui2CmpHexGroup struct {
	Kind, ID, Hex, ASCII string
	Unint                bool
}

type ui2CmpHexRow struct {
	Offset, Pad string
	Groups      []ui2CmpHexGroup
}

type ui2CmpHex struct {
	Label        string
	Rows         []ui2CmpHexRow
	Shown, Total int
	More         int
}

type ui2CmpResultView struct {
	Verdict, VerdictClass string
	Granularity           string
	OpsN, Hunks           int
	Changed               string
	Deleted, Inserted     string
	UnintOps              int
	Headers               string
	Truncated             bool
	Omitted, NotDrawn     int
	Identical             bool
	Segs                  []ui2CmpSeg
	List                  []ui2CmpHunk
	ListMore              int
	LastHunk              int
	HexA, HexB            *ui2CmpHex
	Unified               string
	Repaired              bool
	Notes                 []string
}

type ui2CmpRun struct {
	TaskID uint64
	Label  string
}

type ui2CmpSitemapRow struct {
	Authority, Path, Side, StatusA, StatusB string
	TLS, Both                               bool
}

type ui2CmpSitemaps struct {
	Runs                []ui2CmpRun
	RunA, RunB          uint64
	Error               string
	Ran                 bool
	TaskA, TaskB        uint64
	OnlyA, OnlyB, BothN int
	Rows                []ui2CmpSitemapRow
}

type ui2CmpPage struct {
	Error, Note string
	A, B        ui2CmpSlotView
	Granularity string
	View        string
	Wrap        bool
	Side        string
	Discounted  string
	Result      *ui2CmpResultView
	Sitemaps    ui2CmpSitemaps
}

func ui2CmpSize(n int) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	}
}

func ui2CmpSlotViewOf(name string, st ui2CmpSlotState) ui2CmpSlotView {
	v := ui2CmpSlotView{Name: name, Upper: strings.ToUpper(name), Text: st.Text, Msg: st.Msg, Sel: st.Sel}
	for i, it := range st.Items {
		bn := "0"
		if it.Binary {
			bn = "1"
		}
		v.Items = append(v.Items, ui2CmpItemView{Index: i, Label: it.Label, B64: base64.StdEncoding.EncodeToString(it.Data),
			Size: ui2CmpSize(len(it.Data)), Bn: bn, Selected: i == st.Sel, Binary: it.Binary})
	}
	data, bin, _ := st.effective()
	v.Size, v.Binary = ui2CmpSize(len(data)), bin
	return v
}

// ---- diff layout ------------------------------------------------------------------------------

// ui2CmpSlice returns one op's bytes from a side, bounds-checked.
func ui2CmpSlice(b []byte, off, n int) []byte {
	if off < 0 || n < 0 || off > len(b) || off+n > len(b) {
		return nil
	}
	return b[off : off+n]
}

// ui2CmpText renders a byte range for a pane. A byte-level op can split a multibyte character;
// the split bytes show as U+FFFD (repaired is set so the page says so).
func ui2CmpText(b []byte, binary bool, repaired *bool) string {
	if binary {
		return ui2CmpDisplay(b, true)
	}
	if !utf8.Valid(b) {
		*repaired = true
		return strings.ToValidUTF8(string(b), "�")
	}
	return string(b)
}

func ui2CmpTrunc(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

func ui2CmpLayout(ops []compareOp, a, b []byte, binA, binB bool, v *ui2CmpResultView) {
	drawn := ops
	if len(drawn) > ui2CmpMaxSegs {
		drawn, v.NotDrawn = drawn[:ui2CmpMaxSegs], len(ops)-ui2CmpMaxSegs
	}
	repaired := false
	hunk := 0
	for _, op := range drawn {
		at := ui2CmpText(ui2CmpSlice(a, op.AOffset, op.ALen), binA, &repaired)
		bt := ui2CmpText(ui2CmpSlice(b, op.BOffset, op.BLen), binB, &repaired)
		if op.Kind == "equal" {
			v.Segs = append(v.Segs, ui2CmpSeg{Kind: "equal", A: at, B: at, Hunk: -1})
			continue
		}
		seg := ui2CmpSeg{Kind: op.Kind, Hunk: hunk, Unint: op.Uninteresting}
		pad := func(s string, w int) string {
			return s + strings.Repeat(ui2CmpGap, max(w-utf8.RuneCountInString(s), 0))
		}
		switch op.Kind {
		case "insert":
			seg.Mark, seg.A, seg.B = "+", pad("", utf8.RuneCountInString(bt)), bt
		case "delete":
			seg.Mark, seg.A, seg.B = "−", at, pad("", utf8.RuneCountInString(at))
		default:
			w := max(utf8.RuneCountInString(at), utf8.RuneCountInString(bt))
			seg.Mark, seg.A, seg.B = "~", pad(at, w), pad(bt, w)
		}
		v.Segs = append(v.Segs, seg)
		if hunk < ui2CmpMaxListed {
			v.List = append(v.List, ui2CmpHunk{N: hunk, Shown: hunk + 1, Prev: hunk - 1, Next: hunk + 1, Kind: op.Kind,
				AOff: op.AOffset, BOff: op.BOffset, A: ui2CmpTrunc(at, 300), B: ui2CmpTrunc(bt, 300), Unint: op.Uninteresting})
		}
		hunk++
	}
	v.Hunks, v.LastHunk = hunk, hunk-1
	if hunk > ui2CmpMaxListed {
		v.ListMore = hunk - ui2CmpMaxListed
	}
	if len(v.List) > 0 {
		v.List[len(v.List)-1].Next = -1
	}
	if repaired {
		v.Notes = append(v.Notes, "Some differences split a multibyte character at a byte boundary; the split bytes show as � in the panes (the comparison used the real bytes).")
	}
}

// ui2CmpHexDump is one side's byte-tagged hex grid, built straight from the ops and that side's
// own bytes: padding glyphs never appear in the one view whose job is telling bytes apart.
func ui2CmpHexDump(ops []compareOp, data []byte, side string) *ui2CmpHex {
	if len(ops) > ui2CmpMaxSegs {
		ops = ops[:ui2CmpMaxSegs]
	}
	h := &ui2CmpHex{Label: strings.ToUpper(side)}
	type acc struct {
		kind, id   string
		unint      bool
		hunk       int
		hex, ascii []string
	}
	var row []acc
	rowLen, offset := 0, 0
	flush := func() {
		r := ui2CmpHexRow{Offset: fmt.Sprintf("%08x", offset), Pad: strings.Repeat("   ", 16-rowLen)}
		for _, g := range row {
			r.Groups = append(r.Groups, ui2CmpHexGroup{Kind: g.kind, ID: g.id, Unint: g.unint,
				Hex: strings.Join(g.hex, " "), ASCII: strings.Join(g.ascii, "")})
		}
		h.Rows = append(h.Rows, r)
		offset += 16
		row, rowLen = nil, 0
	}
	hunk := 0
	for _, op := range ops {
		cur := -1
		if op.Kind != "equal" {
			cur = hunk
			hunk++
		}
		off, n := op.AOffset, op.ALen
		if side == "b" {
			off, n = op.BOffset, op.BLen
		}
		bs := ui2CmpSlice(data, off, n)
		h.Total += len(bs)
		first := true
		for _, c := range bs {
			if h.Shown >= ui2CmpMaxHex {
				break
			}
			ascii := "."
			if c >= 0x20 && c <= 0x7e {
				ascii = string(rune(c))
			}
			hx := fmt.Sprintf("%02x", c)
			if last := len(row) - 1; last >= 0 && !first && row[last].hunk == cur && row[last].kind == op.Kind {
				row[last].hex = append(row[last].hex, hx)
				row[last].ascii = append(row[last].ascii, ascii)
			} else {
				g := acc{kind: op.Kind, unint: op.Uninteresting, hunk: cur, hex: []string{hx}, ascii: []string{ascii}}
				if first && cur >= 0 {
					g.id = fmt.Sprintf("p%s-%d", side, cur)
				}
				row = append(row, g)
			}
			first = false
			h.Shown++
			rowLen++
			if rowLen == 16 {
				flush()
			}
		}
	}
	if rowLen > 0 {
		flush()
	}
	h.More = h.Total - h.Shown
	return h
}

// ---- handlers ---------------------------------------------------------------------------------

// handleUI2Comparer serves GET /ui2/comparer (?a=&b= message-id seeds, ?run_a=&run_b= site-map
// compare) and treats POST as the workbench form.
func (s *Server) handleUI2Comparer(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleUI2ComparerRun(w, r)
		return
	}
	q := r.URL.Query()
	p := &ui2CmpPage{Granularity: "bytes", View: "text", Wrap: true, Side: "response"}
	a, b := ui2CmpSlotState{Sel: -1}, ui2CmpSlotState{Sel: -1}
	for _, seed := range []struct {
		raw string
		st  *ui2CmpSlotState
	}{{q.Get("a"), &a}, {q.Get("b"), &b}} {
		if seed.raw == "" {
			continue
		}
		seed.st.Msg = seed.raw
		if errText := s.ui2CmpLoadMsg(seed.st); errText != "" && p.Error == "" {
			p.Error = errText
		}
	}
	if len(a.Items) > 0 && len(b.Items) > 0 && p.Error == "" {
		s.ui2CmpCompare(p, &a, &b)
	}
	s.ui2CmpFinish(w, r, p, a, b, q.Get("run_a"), q.Get("run_b"))
}

// handleUI2ComparerRun serves POST /ui2/comparer/run: one workbench action (op) over the slots the
// form carries, then the re-rendered page. A read throughout: messages, files and the diff are
// read or computed, nothing is written.
func (s *Server) handleUI2ComparerRun(w http.ResponseWriter, r *http.Request) {
	if err := ui2SeqParseUploadForm(w, r, 2*ui2CmpMaxUpload); err != nil {
		http.Error(w, "the form could not be read: "+err.Error(), http.StatusBadRequest)
		return
	}
	p := &ui2CmpPage{Granularity: r.PostFormValue("granularity"), View: r.PostFormValue("view"),
		Wrap: r.PostFormValue("wrap") != "off", Side: r.PostFormValue("side")}
	if p.Granularity == "" {
		p.Granularity = "bytes"
	}
	if p.View != "hex" {
		p.View = "text"
	}
	if p.Side != "request" {
		p.Side = "response"
	}
	a, errA := ui2CmpReadSlot(r, "a")
	b, errB := ui2CmpReadSlot(r, "b")
	if errA != "" || errB != "" {
		p.Error = errA + errB
		s.ui2CmpFinish(w, r, p, a, b, "", "")
		return
	}
	op := r.PostFormValue("op")
	slot := func(name string) *ui2CmpSlotState {
		if name == "b" {
			return &b
		}
		return &a
	}
	verb, rest, _ := strings.Cut(op, "-")
	name, idxRaw, _ := strings.Cut(rest, "-")
	switch verb {
	case "", "compare":
		s.ui2CmpCompare(p, &a, &b)
	case "swap":
		a, b = b, a
		p.Note = "Slots swapped."
	case "load":
		if name != "a" && name != "b" {
			break
		}
		p.Error = s.ui2CmpLoadMsg(slot(name))
	case "file":
		if name != "a" && name != "b" {
			break
		}
		data, fname, attached, errText := ui2SeqReadUpload(r, name+"_file", ui2CmpMaxUpload)
		switch {
		case errText != "":
			p.Error = errText
		case !attached:
			p.Error = "choose a file for slot " + strings.ToUpper(name) + " first"
		default:
			bin := ui2CmpBinary(data)
			slot(name).add(ui2CmpItem{Label: "file: " + fname, Data: data, Binary: bin})
			p.Note = fname + " loaded into slot " + strings.ToUpper(name) + "."
			if bin {
				p.View = "hex"
				p.Note += " It is binary: compared byte-for-byte and shown in hex (editing the side drops the file bytes)."
			}
		}
	case "add":
		if name != "a" && name != "b" {
			break
		}
		st := slot(name)
		if st.Text == "" {
			p.Error = "slot " + strings.ToUpper(name) + "'s editor is empty: paste something first"
			break
		}
		data := []byte(st.Text)
		st.add(ui2CmpItem{Label: "paste: " + ui2CmpFirstLine(st.Text), Data: data, Binary: ui2CmpBinary(data)})
	case "clear":
		if name != "a" && name != "b" {
			break
		}
		*slot(name) = ui2CmpSlotState{Sel: -1}
	case "select", "remove":
		st := slot(name)
		i, err := strconv.Atoi(idxRaw)
		if (name != "a" && name != "b") || err != nil || i < 0 || i >= len(st.Items) {
			p.Error = "that item is not in the list"
			break
		}
		if verb == "select" {
			st.Sel = i
			st.Text = ui2CmpDisplay(st.Items[i].Data, st.Items[i].Binary)
			break
		}
		st.Items = append(st.Items[:i], st.Items[i+1:]...)
		switch {
		case i == st.Sel:
			st.Sel, st.Text = -1, ""
		case i < st.Sel:
			st.Sel--
		}
	default:
		p.Error = "unknown comparer action"
	}
	s.ui2CmpFinish(w, r, p, a, b, "", "")
}

// ui2CmpLoadMsg loads one stored message (GET /api/message/{id}) into a slot's list.
func (s *Server) ui2CmpLoadMsg(st *ui2CmpSlotState) string {
	id, err := strconv.ParseUint(st.Msg, 10, 64)
	if err != nil {
		return "a stored message id is a whole number, counting from 0"
	}
	raw, errText := s.ui2SeqAPIRaw(http.MethodGet, "/api/message/"+strconv.FormatUint(id, 10), nil)
	if errText != "" {
		return fmt.Sprintf("could not load message %d: %s", id, errText)
	}
	var mv MessageView
	if err := json.Unmarshal(raw, &mv); err != nil {
		return "unreadable message: " + err.Error()
	}
	data := []byte(mv.Text)
	st.add(ui2CmpItem{Label: fmt.Sprintf("msg %d: %s", id, ui2CmpFirstLine(mv.Text)), Data: data, Binary: ui2CmpBinary(data)})
	return ""
}

// ui2CmpCompare runs the diff over both sides' effective bytes and lays the result out.
func (s *Server) ui2CmpCompare(p *ui2CmpPage, a, b *ui2CmpSlotState) {
	ad, abin, aItem := a.effective()
	bd, bbin, bItem := b.effective()
	body := map[string]any{"response": p.Side == "response", "granularity": p.Granularity}
	// Editor text is repaired to valid UTF-8 before it is sent - JSON would do it silently -
	// and the repair is disclosed. Item bytes go exactly: as text when valid, else as base64.
	repaired := false
	sideBody := func(key string, data []byte, bin, fromItem bool) []byte {
		if bin {
			body[key+"_base64"] = base64.StdEncoding.EncodeToString(data)
			return data
		}
		txt := string(data)
		if !fromItem && !utf8.ValidString(txt) {
			txt = strings.ToValidUTF8(txt, "�")
			repaired = true
		}
		body[key] = txt
		return []byte(txt)
	}
	ad = sideBody("a", ad, abin, aItem)
	bd = sideBody("b", bd, bbin, bItem)
	raw, errText := s.ui2SeqAPIRaw(http.MethodPost, "/api/tools/compare", body)
	if errText != "" {
		p.Error = "comparison failed: " + errText
		return
	}
	var res struct {
		Identical         bool        `json:"identical"`
		IdenticalIgnoring bool        `json:"identical_ignoring_uninteresting"`
		UnintOps          int         `json:"uninteresting_ops"`
		Headers           []string    `json:"uninteresting_headers_applied"`
		Granularity       string      `json:"granularity"`
		Deleted           int         `json:"deleted_tokens"`
		Inserted          int         `json:"inserted_tokens"`
		Truncated         bool        `json:"truncated"`
		Omitted           int         `json:"ops_omitted"`
		Ops               []compareOp `json:"ops"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		p.Error = "unreadable comparison: " + err.Error()
		return
	}
	v := &ui2CmpResultView{Granularity: res.Granularity, OpsN: len(res.Ops), UnintOps: res.UnintOps,
		Headers: strings.Join(res.Headers, ", "), Truncated: res.Truncated, Omitted: res.Omitted,
		Identical: res.Identical, Repaired: repaired}
	switch {
	case res.Identical:
		v.Verdict, v.VerdictClass = "identical", "cmp-good"
	case res.IdenticalIgnoring:
		v.Verdict, v.VerdictClass = "same but for discounted headers", "cmp-good"
	default:
		v.Verdict, v.VerdictClass = "different", "cmp-warn"
	}
	unit := func(n int) string {
		if res.Granularity == "words" {
			if n == 1 {
				return "1 word"
			}
			return fmt.Sprintf("%d words", n)
		}
		return ui2CmpSize(n)
	}
	changed := 0
	for _, op := range res.Ops {
		if op.Kind == "replace" {
			changed += op.ALen
		}
	}
	v.Changed, v.Deleted, v.Inserted = ui2CmpSize(changed), unit(res.Deleted), unit(res.Inserted)
	ui2CmpLayout(res.Ops, ad, bd, abin, bbin, v)
	if abin || bbin {
		p.View = "hex"
		v.Notes = append(v.Notes, "A side holds binary bytes, so it was compared byte-for-byte and is shown in hex.")
	}
	if p.View == "hex" {
		v.HexA, v.HexB = ui2CmpHexDump(res.Ops, ad, "a"), ui2CmpHexDump(res.Ops, bd, "b")
	}
	if !abin && !bbin {
		var generic any
		_ = json.Unmarshal(raw, &generic)
		v.Unified = ui2RenderCompare(string(ad), string(bd), generic, repaired)
	}
	p.Result = v
}

// ui2CmpFinish fills the parts every render shares (discount list, site maps) and renders.
func (s *Server) ui2CmpFinish(w http.ResponseWriter, r *http.Request, p *ui2CmpPage, a, b ui2CmpSlotState, runA, runB string) {
	p.A, p.B = ui2CmpSlotViewOf("a", a), ui2CmpSlotViewOf("b", b)
	if p.A.Binary || p.B.Binary {
		p.View = "hex"
	}
	if raw, errText := s.ui2SeqAPIRaw(http.MethodGet, "/api/headers/uninteresting", nil); errText == "" {
		var lists uninterestingHeadersResponse
		if json.Unmarshal(raw, &lists) == nil {
			list := lists.Response
			if p.Side == "request" {
				list = lists.Request
			}
			p.Discounted = strings.Join(list, ", ")
		}
	}
	p.Sitemaps = s.ui2CmpSitemaps(runA, runB)
	ui2Fragment(w, r, ui2CmpTitle, "comparer", ui2Exec("comparer_page.html", p))
}

// ui2CmpSitemaps lists finished crawls and, when both runs are named, diffs their site maps.
func (s *Server) ui2CmpSitemaps(runA, runB string) ui2CmpSitemaps {
	var sm ui2CmpSitemaps
	if raw, errText := s.ui2SeqAPIRaw(http.MethodGet, "/api/crawl", nil); errText == "" {
		var list struct {
			Crawls []struct {
				TaskID uint64   `json:"task_id"`
				Seeds  []string `json:"seeds"`
				State  string   `json:"state"`
				Kind   string   `json:"kind"`
			} `json:"crawls"`
		}
		_ = json.Unmarshal(raw, &list)
		for _, c := range list.Crawls {
			if c.State == "running" {
				continue
			}
			what := strings.Join(c.Seeds, ", ")
			if what == "" {
				what = c.Kind
			}
			sm.Runs = append(sm.Runs, ui2CmpRun{TaskID: c.TaskID, Label: fmt.Sprintf("#%d · %s · %s", c.TaskID, what, c.State)})
		}
	}
	if len(sm.Runs) >= 2 {
		sm.RunA, sm.RunB = sm.Runs[0].TaskID, sm.Runs[1].TaskID
	}
	if runA == "" && runB == "" {
		return sm
	}
	ta, errA := strconv.ParseUint(runA, 10, 64)
	tb, errB := strconv.ParseUint(runB, 10, 64)
	if errA != nil || errB != nil {
		sm.Error = "run A and run B are task ids: whole numbers"
		return sm
	}
	sm.RunA, sm.RunB = ta, tb
	raw, errText := s.ui2SeqAPIRaw(http.MethodPost, "/api/tools/compare-sitemaps", map[string]uint64{"task_a": ta, "task_b": tb})
	if errText != "" {
		sm.Error = errText
		return sm
	}
	var res struct {
		TaskA uint64               `json:"task_a"`
		TaskB uint64               `json:"task_b"`
		Rows  []sitemapPathDiffRow `json:"rows"`
		OnlyA int                  `json:"only_a"`
		OnlyB int                  `json:"only_b"`
		Both  int                  `json:"both"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		sm.Error = "unreadable site-map comparison: " + err.Error()
		return sm
	}
	sm.Ran, sm.TaskA, sm.TaskB, sm.OnlyA, sm.OnlyB, sm.BothN = true, res.TaskA, res.TaskB, res.OnlyA, res.OnlyB, res.Both
	status := func(n int) string {
		if n == 0 {
			return "—"
		}
		return strconv.Itoa(n)
	}
	for _, row := range res.Rows {
		side := "both runs"
		switch row.Side {
		case "a":
			side = fmt.Sprintf("only in run %d", res.TaskA)
		case "b":
			side = fmt.Sprintf("only in run %d", res.TaskB)
		}
		sm.Rows = append(sm.Rows, ui2CmpSitemapRow{Authority: fmt.Sprintf("%s:%d", row.Host, row.Port), Path: row.Path,
			Side: side, Both: row.Side == "both", TLS: row.TLS, StatusA: status(row.StatusA), StatusB: status(row.StatusB)})
	}
	return sm
}

// ui2DiffSeg is one rendered diff piece: prefix is "  " (context), "- " (removed
// from a) or "+ " (added in b); text may contain newlines.
type ui2DiffSeg struct {
	prefix string
	text   string
}

// ui2CompareSegs turns byte-granular compare ops into display segments without
// ever splitting or duplicating a multibyte character. Ops are consumed in
// order; consecutive ops whose shared boundary falls inside a UTF-8 rune (on
// either side) are grouped, so every group's a-range and b-range is a whole
// number of runes and groups partition both buffers exactly. A group that is
// all-equal renders as context; any other group renders as common leading
// runes (context), the differing a-middle ("- "), the differing b-middle
// ("+ "), then common trailing runes (context). Concatenating the "  "/"- "
// segments therefore reconstructs a byte-for-byte, and "  "/"+ " reconstructs
// b — no widening past op boundaries, no dropped partial bytes.
func ui2CompareSegs(a, b string, ops []any) (segs []ui2DiffSeg, corruptRepaired bool) {
	num := func(v any) int {
		f, _ := v.(float64)
		return int(f)
	}
	type rawOp struct {
		kind                   string
		aOff, aLen, bOff, bLen int
	}
	runeAligned := func(s string, p int) bool {
		return p <= 0 || p >= len(s) || utf8.RuneStart(s[p])
	}
	// repair keeps corrupt op offsets from ever emitting invalid UTF-8: any
	// sliced segment that splits a rune is repaired for display and disclosed.
	repair := func(s string) string {
		if utf8.ValidString(s) {
			return s
		}
		corruptRepaired = true
		return strings.ToValidUTF8(s, "�")
	}
	// group accumulates ops sharing rune-split boundaries.
	var gOps []rawOp
	gAStart, gAEnd, gBStart, gBEnd := 0, 0, 0, 0
	flush := func() {
		if len(gOps) == 0 {
			return
		}
		aText, bText := "", ""
		if 0 <= gAStart && gAStart <= gAEnd && gAEnd <= len(a) {
			aText = repair(a[gAStart:gAEnd])
		}
		if 0 <= gBStart && gBStart <= gBEnd && gBEnd <= len(b) {
			bText = repair(b[gBStart:gBEnd])
		}
		allEqual := true
		for _, o := range gOps {
			if o.kind != "equal" {
				allEqual = false
				break
			}
		}
		switch {
		case aText == "" && bText == "":
			// nothing to show
		case allEqual && aText == bText:
			segs = append(segs, ui2DiffSeg{"  ", aText})
		default:
			ar, br := []rune(aText), []rune(bText)
			p := 0
			for p < len(ar) && p < len(br) && ar[p] == br[p] {
				p++
			}
			sfx := 0
			for sfx < len(ar)-p && sfx < len(br)-p && ar[len(ar)-1-sfx] == br[len(br)-1-sfx] {
				sfx++
			}
			if p > 0 {
				segs = append(segs, ui2DiffSeg{"  ", string(ar[:p])})
			}
			if mid := ar[p : len(ar)-sfx]; len(mid) > 0 {
				segs = append(segs, ui2DiffSeg{"- ", string(mid)})
			}
			if mid := br[p : len(br)-sfx]; len(mid) > 0 {
				segs = append(segs, ui2DiffSeg{"+ ", string(mid)})
			}
			if sfx > 0 {
				segs = append(segs, ui2DiffSeg{"  ", string(ar[len(ar)-sfx:])})
			}
		}
		gOps = nil
	}
	prevAEnd, prevBEnd := 0, 0
	for i, o := range ops {
		om, _ := o.(map[string]any)
		op := rawOp{
			kind: strOf(om["kind"]),
			aOff: num(om["a_offset"]), aLen: num(om["a_len"]),
			bOff: num(om["b_offset"]), bLen: num(om["b_len"]),
		}
		if len(gOps) == 0 {
			// Defensive: a gap between the previous group and this op is
			// uncovered bytes; emit it so reconstruction still holds.
			if op.aOff > prevAEnd && op.aOff <= len(a) {
				gap := repair(a[prevAEnd:op.aOff])
				bGap := ""
				if prevBEnd <= op.bOff && op.bOff <= len(b) {
					bGap = repair(b[prevBEnd:op.bOff])
				}
				if gap != "" && gap == bGap {
					segs = append(segs, ui2DiffSeg{"  ", gap})
				} else {
					if gap != "" {
						segs = append(segs, ui2DiffSeg{"- ", gap})
					}
					if bGap != "" {
						segs = append(segs, ui2DiffSeg{"+ ", bGap})
					}
				}
			}
			gAStart, gBStart = op.aOff, op.bOff
		}
		gOps = append(gOps, op)
		gAEnd, gBEnd = op.aOff+op.aLen, op.bOff+op.bLen
		// Close the group when the boundary to the next op is rune-aligned on
		// both sides (or the stream ends or jumps discontiguously).
		last := i == len(ops)-1
		if last || ((runeAligned(a, gAEnd) && runeAligned(b, gBEnd)) || boundaryJumps(ops, i, gAEnd, gBEnd, num)) {
			prevAEnd, prevBEnd = gAEnd, gBEnd
			flush()
		}
	}
	flush()
	// Defensive: bytes past the last op are uncovered; emit rather than drop.
	if prevAEnd < len(a) || prevBEnd < len(b) {
		aTail, bTail := "", ""
		if prevAEnd <= len(a) {
			aTail = repair(a[prevAEnd:])
		}
		if prevBEnd <= len(b) {
			bTail = repair(b[prevBEnd:])
		}
		if aTail != "" && aTail == bTail {
			segs = append(segs, ui2DiffSeg{"  ", aTail})
		} else {
			if aTail != "" {
				segs = append(segs, ui2DiffSeg{"- ", aTail})
			}
			if bTail != "" {
				segs = append(segs, ui2DiffSeg{"+ ", bTail})
			}
		}
	}
	return segs, corruptRepaired
}

func boundaryJumps(ops []any, i, aEnd, bEnd int, num func(any) int) bool {
	om, _ := ops[i+1].(map[string]any)
	return num(om["a_offset"]) != aEnd || num(om["b_offset"]) != bEnd
}

// ui2RenderCompare renders the compare ops against the two buffers as a readable
// line diff ("  " equal, "- " removed, "+ " added) — never a Go map dump.
// repaired reports that the handler already replaced invalid UTF-8 in the
// inputs; the disclosure is rendered, never silent.
func ui2RenderCompare(a, b string, result any, repaired bool) string {
	m, ok := result.(map[string]any)
	if !ok {
		return ""
	}
	var sb strings.Builder
	if id, _ := m["identical"].(bool); id {
		// identical after repair is not the same statement as identical: disclose.
		sb.WriteString("buffers are identical\n")
		if repaired {
			sb.WriteString("\u2026 identical only after invalid UTF-8 bytes in the input were replaced with \uFFFD\n")
		}
		return sb.String()
	}
	ops, _ := m["ops"].([]any)
	num := func(v any) int {
		f, _ := v.(float64)
		return int(f)
	}
	segs, corruptRepaired := ui2CompareSegs(a, b, ops)
	for _, seg := range segs {
		for i, line := range strings.Split(seg.text, "\n") {
			if i > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(seg.prefix + line)
		}
		sb.WriteByte('\n')
	}
	if n := num(m["ops_omitted"]); n > 0 {
		fmt.Fprintf(&sb, "\u2026 %d further ops omitted by the API\n", n)
	}
	if t, _ := m["truncated"].(bool); t {
		sb.WriteString("\u2026 alignment truncated by the diff engine limit - coarse replace shown, not a full alignment\n")
	}
	if corruptRepaired {
		sb.WriteString("\u2026 corrupt diff ops produced segments splitting a UTF-8 sequence - repaired with \uFFFD for display\n")
	}
	if repaired {
		sb.WriteString("\u2026 invalid UTF-8 bytes in the input were replaced with \uFFFD before comparing\n")
	}
	return sb.String()
}
