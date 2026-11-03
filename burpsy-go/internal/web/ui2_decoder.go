package web

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/burpsy-go/burpsy/internal/tools"
)

// ---- Decoder ---------------------------------------------------------------------------------
//
// A multi-step pipeline over /api/tools/decode|encode|hash, called in process: each step is fed
// the previous step's output and every intermediate result stays on screen. The page holds no
// codec logic — the operation lists come from the Go tables (tools.AllLayers, encodableNames,
// tools.DigestAlgorithmNames) and every transform is an API call. The form round-trips the
// steps as s<i>_op / s<i>_guess / s<i>_key / s<i>_key_enc / s<i>_out fields.

const ui2DecoderTitle = "burpsy /ui2/ — Decoder"

// ui2DecMaxSteps bounds the pipeline a form can ask for.
const ui2DecMaxSteps = 20

// ui2DecMaxHexDump caps the hex view: a hex row costs several times its bytes in markup.
const ui2DecMaxHexDump = 8192

var (
	ui2DecKeyEncodings = []string{"utf8", "hex", "base64"}
	ui2DecHashOutputs  = []string{"hex", "base64", "base64url"}
)

// ui2DecOption is one entry of a step's operation select ("kind:value").
type ui2DecOption struct {
	Value string
	Label string
}

// ui2DecOps is the operation vocabulary, derived from the same tables the API handlers use.
type ui2DecOps struct {
	Decode, Encode, Hash []ui2DecOption
	KeyEncodings         []string
	HashOutputs          []string
}

func ui2DecoderOps() ui2DecOps {
	ops := ui2DecOps{KeyEncodings: ui2DecKeyEncodings, HashOutputs: ui2DecHashOutputs}
	ops.Decode = append(ops.Decode, ui2DecOption{"decode:auto", "decode: smart detect"})
	for _, l := range tools.AllLayers() {
		ops.Decode = append(ops.Decode, ui2DecOption{"decode:" + l.String(), "decode: " + l.String()})
	}
	ops.Decode = append(ops.Decode, ui2DecOption{"decode:ascii", "decode: ascii"})
	for _, n := range encodableNames() {
		ops.Encode = append(ops.Encode, ui2DecOption{"encode:" + n, "encode: " + n})
	}
	for _, n := range tools.DigestAlgorithmNames() {
		ops.Hash = append(ops.Hash, ui2DecOption{"hash:" + n, "hash: " + n})
	}
	return ops
}

// ui2DecStep is one pipeline step as the form carries it.
type ui2DecStep struct {
	Index  int
	Num    int    // 1-based, for display
	Kind   string // decode | encode | hash
	Value  string // layer, encoding or algorithm ("auto" = smart decode)
	Guess  bool   // smart decode: accept unpadded base64 / separated hex
	Key    string // hmac-* only
	KeyEnc string
	Output string // hash digest format
	Keyed  bool
	Last   bool
}

func (st ui2DecStep) Op() string { return st.Kind + ":" + st.Value }

// ui2DecResult is one step's result card.
type ui2DecResult struct {
	Index     int
	Num       int
	Label     string
	Smart     bool
	Layers    []string
	Output    string
	Len       int
	UTF8      bool
	Truncated bool
	Partial   bool
	Hex       string
}

// ui2DecoderModel is the whole Decoder page.
type ui2DecoderModel struct {
	Input       string
	InputFormat string // text | hex
	SelStart    string
	SelEnd      string
	View        string // text | hex
	Steps       []ui2DecStep
	Ops         ui2DecOps

	Ran         bool
	Results     []ui2DecResult
	FailedAt    int // 1-based step number that failed, 0 when none
	FailMsg     string
	Selection   bool
	Before      string
	After       string
	Final       string // before + last output + after: what "Copy output" copies
	SpanNote    string
	InputNote   string
	HashNotLast int // 1-based index of a hash step that is not last, 0 when none
	Seed        string
	Error       string
}

func ui2DecNewStep(kind, value string) ui2DecStep {
	st := ui2DecStep{Kind: kind, Value: value, KeyEnc: "utf8", Output: "hex"}
	if kind == "decode" {
		st.Guess = true
	}
	return st
}

// ui2DecDefault is a step's default value for its kind.
func ui2DecDefault(kind string) string {
	switch kind {
	case "encode":
		return "base64"
	case "hash":
		return "sha256"
	default:
		return "auto"
	}
}

// ui2DecParseSteps reads the steps from the form. A legacy single-step form (op, arg) still works.
func ui2DecParseSteps(r *http.Request) []ui2DecStep {
	if op := r.PostFormValue("op"); r.PostFormValue("steps") == "" && (op == "decode" || op == "encode" || op == "hash") {
		arg := r.PostFormValue("arg")
		if arg == "" {
			arg = ui2DecDefault(op)
		}
		return []ui2DecStep{ui2DecNewStep(op, arg)}
	}
	n, _ := strconv.Atoi(r.PostFormValue("steps"))
	n = max(0, min(n, ui2DecMaxSteps))
	steps := make([]ui2DecStep, 0, n)
	for i := 0; i < n; i++ {
		p := "s" + strconv.Itoa(i) + "_"
		kind, value, ok := strings.Cut(r.PostFormValue(p+"op"), ":")
		if !ok || (kind != "decode" && kind != "encode" && kind != "hash") {
			kind, value = "decode", "auto"
		}
		st := ui2DecNewStep(kind, value)
		st.Guess = r.PostFormValue(p+"guess") != ""
		st.Key = r.PostFormValue(p + "key")
		if v := r.PostFormValue(p + "key_enc"); v != "" {
			st.KeyEnc = v
		}
		if v := r.PostFormValue(p + "out"); v != "" {
			st.Output = v
		}
		steps = append(steps, st)
	}
	return steps
}

// ui2DecApplyAction edits the step list for add-<kind>, remove-<i>, up-<i>, down-<i>.
func ui2DecApplyAction(steps []ui2DecStep, action string) []ui2DecStep {
	verb, arg, _ := strings.Cut(action, "-")
	if verb == "add" {
		if (arg == "decode" || arg == "encode" || arg == "hash") && len(steps) < ui2DecMaxSteps {
			steps = append(steps, ui2DecNewStep(arg, ui2DecDefault(arg)))
		}
		return steps
	}
	i, err := strconv.Atoi(arg)
	if err != nil || i < 0 || i >= len(steps) {
		return steps
	}
	switch verb {
	case "remove":
		steps = append(steps[:i:i], steps[i+1:]...)
	case "up":
		if i > 0 {
			steps[i-1], steps[i] = steps[i], steps[i-1]
		}
	case "down":
		if i+1 < len(steps) {
			steps[i], steps[i+1] = steps[i+1], steps[i]
		}
	}
	return steps
}

func (m *ui2DecoderModel) finishSteps() {
	m.HashNotLast = 0
	for i := range m.Steps {
		m.Steps[i].Index, m.Steps[i].Num = i, i+1
		m.Steps[i].Keyed = m.Steps[i].Kind == "hash" && strings.HasPrefix(m.Steps[i].Value, "hmac-")
		m.Steps[i].Last = i == len(m.Steps)-1
		if m.Steps[i].Kind == "hash" && i < len(m.Steps)-1 && m.HashNotLast == 0 {
			m.HashNotLast = i + 1
		}
	}
}

// ui2DecView is the API's bytesView shape.
type ui2DecView struct {
	Text      string `json:"text"`
	Len       int    `json:"len"`
	UTF8      bool   `json:"utf8"`
	Truncated bool   `json:"truncated"`
}

// ui2DecRunStep runs one step through its API endpoint.
func (s *Server) ui2DecRunStep(input string, st ui2DecStep) (ui2DecResult, string) {
	res := ui2DecResult{Label: st.Kind + " · " + st.Value}
	var out struct {
		Layers  []string   `json:"layers"`
		Partial bool       `json:"partial"`
		Output  ui2DecView `json:"output"`
	}
	var path string
	body := map[string]any{"input": input}
	switch st.Kind {
	case "decode":
		path = "/api/tools/decode"
		body["encoding"] = st.Value
		if st.Value == "auto" {
			res.Smart, res.Label = true, "decode · smart detect"
			body["guess_alphabets"] = st.Guess
		}
	case "encode":
		path = "/api/tools/encode"
		body["encoding"] = st.Value
	default:
		path = "/api/tools/hash"
		body["algorithm"] = st.Value
		body["output"] = st.Output
		// The API refuses a key on a bare digest, so a stale key field must not turn a plain
		// hash into a 400: the key goes only with the hmac-* family.
		if st.Keyed {
			body["key"] = st.Key
			body["key_encoding"] = st.KeyEnc
		}
	}
	b, _ := json.Marshal(body)
	if errText := s.ui2CollabCall(http.MethodPost, path, b, &out); errText != "" {
		return res, errText
	}
	res.Layers, res.Partial = out.Layers, out.Partial
	res.Output, res.Len, res.UTF8, res.Truncated = out.Output.Text, out.Output.Len, out.Output.UTF8, out.Output.Truncated
	return res, ""
}

// ui2DecSpan resolves the start/end character offsets against the input. Empty, unparsable or
// collapsed offsets fall back to the whole input; the bool says whether a span applies.
func ui2DecSpan(input, startS, endS string) (before, span, after string, ok bool, note string) {
	if strings.TrimSpace(startS) == "" && strings.TrimSpace(endS) == "" {
		return "", input, "", false, ""
	}
	runes := []rune(input)
	start, err1 := strconv.Atoi(strings.TrimSpace(startS))
	end, err2 := strconv.Atoi(strings.TrimSpace(endS))
	if err1 != nil || err2 != nil {
		return "", input, "", false, "the span offsets are not whole numbers, so the whole input was transformed"
	}
	if start > end {
		start, end = end, start
	}
	start = max(0, min(start, len(runes)))
	end = max(0, min(end, len(runes)))
	if start >= end {
		return "", input, "", false, "the span is empty, so the whole input was transformed"
	}
	return string(runes[:start]), string(runes[start:end]), string(runes[end:]), true, ""
}

// ui2DecHexDump renders a capped hex dump of a step's output.
func ui2DecHexDump(text string) string {
	b := []byte(text)
	if len(b) == 0 {
		return "(0 bytes)"
	}
	if len(b) > ui2DecMaxHexDump {
		return hex.Dump(b[:ui2DecMaxHexDump]) + fmt.Sprintf("… %d more bytes not dumped; switch to text for the whole output\n", len(b)-ui2DecMaxHexDump)
	}
	return hex.Dump(b)
}

// ui2DecoderFromRequest builds the model from a POSTed form.
func ui2DecoderFromRequest(r *http.Request) *ui2DecoderModel {
	m := &ui2DecoderModel{
		Input:       r.PostFormValue("input"),
		InputFormat: r.PostFormValue("input_format"),
		SelStart:    r.PostFormValue("sel_start"),
		SelEnd:      r.PostFormValue("sel_end"),
		View:        r.PostFormValue("view"),
		Steps:       ui2DecParseSteps(r),
		Ops:         ui2DecoderOps(),
	}
	if m.InputFormat != "hex" {
		m.InputFormat = "text"
	}
	if m.View != "hex" {
		m.View = "text"
	}
	return m
}

// handleUI2Decoder serves GET /ui2/decoder (the form; ?msg_id= seeds the input with one stored
// message) and POST /ui2/decoder (same as /ui2/decoder/run).
func (s *Server) handleUI2Decoder(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleUI2DecoderRun(w, r)
		return
	}
	m := &ui2DecoderModel{InputFormat: "text", View: "text", Ops: ui2DecoderOps(),
		Steps: []ui2DecStep{ui2DecNewStep("decode", "auto")}}
	if raw := r.URL.Query().Get("msg_id"); raw != "" {
		id, err := strconv.ParseUint(raw, 10, 64)
		var msg struct {
			Text   string `json:"text"`
			Body64 string `json:"body_base64"`
		}
		switch {
		case err != nil:
			m.Error = "msg_id must be a message number"
		default:
			if errText := s.ui2CollabCall(http.MethodGet, "/api/message/"+strconv.FormatUint(id, 10), nil, &msg); errText != "" {
				m.Error = fmt.Sprintf("message %d could not be loaded: %s", id, errText)
			} else {
				m.Input = msg.Text
				m.Seed = fmt.Sprintf("Loaded message #%d into the input.", id)
				if msg.Body64 != "" || !utf8.ValidString(msg.Text) {
					m.Seed += " Its body is not valid UTF-8, so replacement characters stand in for the bytes that were not text."
				}
			}
		}
	}
	m.finishSteps()
	ui2Fragment(w, r, ui2DecoderTitle, "decoder", ui2Exec("decoder_page.html", m))
}

// handleUI2DecoderRun serves POST /ui2/decoder/run: action=run runs the pipeline; add-<kind>,
// remove-<i>, up-<i>, down-<i> and layout edit the steps and re-render without running.
func (s *Server) handleUI2DecoderRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	m := ui2DecoderFromRequest(r)
	action := r.PostFormValue("action")
	if action != "" && action != "run" {
		m.Steps = ui2DecApplyAction(m.Steps, action)
		m.finishSteps()
		ui2Fragment(w, r, ui2DecoderTitle, "decoder", ui2Exec("decoder_page.html", m))
		return
	}
	m.finishSteps()
	switch {
	case len(m.Steps) == 0:
		m.Error = "add a decode, encode or hash step first"
	case m.Input == "":
		m.Error = "paste an input first"
	default:
		s.ui2DecRun(m)
	}
	ui2Fragment(w, r, ui2DecoderTitle, "decoder", ui2Exec("decoder_page.html", m))
}

// ui2DecRun runs the pipeline into the model. A failing step stops the chain but keeps the
// results of the steps that ran.
func (s *Server) ui2DecRun(m *ui2DecoderModel) {
	m.Ran = true
	current := m.Input
	if m.InputFormat == "hex" {
		// The hex input is turned into bytes by the API's own hex layer, not by this page.
		res, errText := s.ui2DecRunStep(current, ui2DecStep{Kind: "decode", Value: "hex"})
		if errText != "" {
			m.Error = "the input is not hex: " + errText
			m.Ran = false
			return
		}
		current = res.Output
		m.InputNote = fmt.Sprintf("Hex input read as %d byte(s).", res.Len)
		if !res.UTF8 {
			m.InputNote += " They are not valid UTF-8, and the tools API takes text, so replacement characters stand in for the bytes that were not text."
		}
	}
	before, span, after, ok, note := ui2DecSpan(current, m.SelStart, m.SelEnd)
	m.Selection, m.SpanNote = ok, note
	if ok {
		m.Before, m.After = before, after
	}
	for i, st := range m.Steps {
		res, errText := s.ui2DecRunStep(span, st)
		if errText != "" {
			m.FailedAt, m.FailMsg = i+1, errText
			break
		}
		res.Index, res.Num = i, i+1
		if m.View == "hex" {
			res.Hex = ui2DecHexDump(m.Before + res.Output + m.After)
		}
		m.Results = append(m.Results, res)
		span = res.Output
	}
	if n := len(m.Results); n > 0 {
		m.Final = m.Before + m.Results[n-1].Output + m.After
	}
}
