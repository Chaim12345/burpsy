package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sequencer"
)

// ---- Sequencer (/ui2/sequencer) --------------------------------------------------------------
//
// Token sources: paste, a loaded file (multipart upload on the analyse form), or a live capture
// (reviewed through the confirmation gate with the full bound body). Every figure in the report
// comes from POST /api/sequencer/analyse; this file only lays the numbers out, including the two
// SVG charts, whose coordinates are computed here and rendered through html/template.

const ui2SeqTitle = "burpsy /ui2/ — Sequencer"

// ui2SeqMaxUpload bounds a loaded token file. A larger file is refused, not truncated: a
// truncated sample analysed under the file's name would be a verdict about different tokens.
const ui2SeqMaxUpload = 16 << 20

// ui2SeqReport is the analyse response as this page reads it. The sub-objects are the engine's
// own types; the top level is restated only because sequencer.Encoding marshals as a string and
// has no unmarshaler.
type ui2SeqReport struct {
	Tokens           int                              `json:"tokens"`
	Encoding         string                           `json:"encoding"`
	EncodingDetected bool                             `json:"encoding_detected"`
	Base64Decoded    bool                             `json:"base64_decoded"`
	Padding          sequencer.Padding                `json:"padding"`
	Characters       sequencer.CharacterAnalysis      `json:"characters"`
	ExtraStats       sequencer.ExtraAnalysis          `json:"extra_stats"`
	Bits             sequencer.BitStats               `json:"bits"`
	Fips             sequencer.FipsReport             `json:"fips"`
	Advanced         sequencer.AdvancedReport         `json:"advanced"`
	EffectiveEntropy sequencer.EffectiveEntropyReport `json:"effective_entropy"`
	FipsPositions    sequencer.FipsPositionReport     `json:"fips_positions"`
	Grade            string                           `json:"grade"`
	Verdict          string                           `json:"verdict"`
	Warnings         []string                         `json:"warnings"`
}

// ui2SeqLevel is one significance level the select offers (Burp's range and named bands).
type ui2SeqLevel struct {
	Value, Label, Band string
}

var ui2SeqLevels = []ui2SeqLevel{
	{"0.001", "0.001%", ""}, {"0.002", "0.002%", "FIPS"}, {"0.005", "0.005%", "FIPS"},
	{"0.01", "0.01%", "FIPS"}, {"0.02", "0.02%", "FIPS"}, {"0.03", "0.03%", "FIPS"},
	{"0.05", "0.05%", ""}, {"0.1", "0.1%", ""}, {"0.2", "0.2%", ""}, {"0.5", "0.5%", ""},
	{"1", "1%", "scientific"}, {"2", "2%", "scientific"}, {"5", "5%", "scientific"}, {"10", "10%", ""},
}

func ui2SeqLevelLabel(p float64) string {
	return strconv.FormatFloat(p, 'f', -1, 64) + "%"
}

// ui2SeqKeyLevel marks the levels labelled on the chart axis and listed by default.
func ui2SeqKeyLevel(p float64) bool {
	switch p {
	case 0.001, 0.002, 0.03, 0.1, 1, 5, 10:
		return true
	}
	return false
}

// ui2SeqOpts is what the analysis runs UNDER: echoed into every form so a re-render keeps it.
type ui2SeqOpts struct {
	Encoding     string // "" detects
	Significance string // "" is the server's default, else the operator's number as typed
	PadMode      string // "" none, start, end
	PadByte      string
}

// ui2SeqOptsFrom reads the options and refuses a value the API would not mean the same way.
func ui2SeqOptsFrom(get func(string) string) (ui2SeqOpts, string) {
	o := ui2SeqOpts{
		Encoding:     get("encoding"),
		Significance: strings.TrimSpace(get("significance")),
		PadMode:      get("pad_mode"),
		PadByte:      get("pad_byte"),
	}
	switch o.Encoding {
	case "", "hex", "base64", "raw":
	default:
		return o, "encoding must be detect, hex, base64 or raw"
	}
	switch o.PadMode {
	case "":
		o.PadByte = ""
	case "start", "end":
		if o.PadByte == "" {
			o.PadByte = "0"
		}
		if len(o.PadByte) != 1 {
			return o, "the pad character must be exactly one byte"
		}
	default:
		return o, "pad mode must be none, start or end"
	}
	if o.Significance != "" {
		f, err := strconv.ParseFloat(o.Significance, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return o, "the significance level must be a number, as a percentage (0.03 means 0.03%)"
		}
	}
	return o, ""
}

// body builds the analyse request: text is split by the API's own TokensFromText; tokens is
// a capture's list as captured.
func (o ui2SeqOpts) body(text *string, tokens []string) map[string]any {
	b := map[string]any{}
	if text != nil {
		b["text"] = *text
	} else {
		if tokens == nil {
			tokens = []string{}
		}
		b["tokens"] = tokens
	}
	if o.Encoding != "" {
		b["encoding"] = o.Encoding
	}
	if o.Significance != "" {
		f, _ := strconv.ParseFloat(o.Significance, 64)
		b["significance_percent"] = f
	}
	if o.PadMode != "" {
		b["pad_mode"] = o.PadMode
		b["pad_byte"] = o.PadByte
	}
	return b
}

func (o ui2SeqOpts) query(v url.Values) {
	for k, val := range map[string]string{"encoding": o.Encoding, "significance": o.Significance, "pad_mode": o.PadMode, "pad_byte": o.PadByte} {
		if val != "" {
			v.Set(k, val)
		}
	}
}

// ---- report view ------------------------------------------------------------------------------

type ui2SeqView struct {
	R           *ui2SeqReport
	Summary     string
	GradeLabel  string
	GradeClass  string
	LengthLabel string
	Effective   *ui2SeqEffective
	FipsRows    []ui2SeqFipsRow
	PosRows     []ui2SeqPosRow
	PosCharts   []ui2SeqPosChart
	Positions   []ui2SeqCharPos
	MorePos     []ui2SeqCharPos
	Repeated    []string
	RepeatedN   int
	RunsZeros   string
	RunsOnes    string
	BitEntropy  string
	Notices     []string // advanced-test notices, "name: text"
}

type ui2SeqFipsRow struct {
	Name, Spec, Observed, Requirement, Blocks, Reason string
	Disabled, Passed                                  bool
}

type ui2SeqPosRow struct {
	Name, Failed, Ranges, Requirement, Reason string
	Disabled, Clean                           bool
}

type ui2SeqCharPos struct {
	Index, Samples, Distinct int
	Entropy                  string
	Counts                   []ui2SeqCount
	More                     int
	Dead                     bool
}

type ui2SeqCount struct{ Label, Pct, Title string }

type ui2SeqEffective struct {
	Headline, Detail  string
	MaxBits           int
	Runs              []string
	Marks             []ui2SeqMark
	Gaps              []ui2SeqMark
	Ticks             []ui2SeqMark
	FirstLabel        string
	LastLabel         string
	Rows, MoreRows    []ui2SeqLevelRow
	SpreadWarn        bool
	Note, Definition  string
	Tests, Agreement  string
	SkippedVar        int
	Truncated         bool
	Examined, CurveN  int
	HasMarks          bool
	DefaultedHeadline bool
}

// ui2SeqMark is one chart point; coordinates are preformatted user units.
type ui2SeqMark struct {
	X, Y, Label, Title string
	Chosen             bool
}

type ui2SeqLevelRow struct {
	Label, Value, Rejected, Expected, Reason string
	Chosen, Computed                         bool
}

type ui2SeqPosChart struct {
	ID, Name, Aria, PassY, Threshold, Method string
	Bars, FailMarks                          []ui2SeqBar
	LastBit                                  int
	Exact                                    bool
}

type ui2SeqBar struct {
	X, Y, W, H, Title string
	Pass              bool
}

const (
	ui2SeqChartW = 640.0
	ui2SeqChartH = 160.0
	ui2SeqPosW   = 640.0
	ui2SeqPosH   = 120.0
	// ui2SeqPositionsShown is how many character positions render before "show all".
	ui2SeqPositionsShown = 24
	ui2SeqCountsShown    = 6
)

func ui2SeqF2(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }

func ui2SeqBuildView(rep *ui2SeqReport, summary string) *ui2SeqView {
	v := &ui2SeqView{R: rep, Summary: summary}
	switch rep.Grade {
	case "pass":
		v.GradeLabel, v.GradeClass = "PASS", "seq-good"
	case "fail":
		v.GradeLabel, v.GradeClass = "FAIL", "seq-bad"
	case "insufficient":
		v.GradeLabel, v.GradeClass = "NOT TESTED", "seq-warn"
	default:
		v.GradeLabel, v.GradeClass = rep.Grade, "seq-warn"
	}
	c := rep.Characters
	if c.MinLen == c.MaxLen {
		v.LengthLabel = strconv.Itoa(c.MaxLen)
	} else {
		v.LengthLabel = fmt.Sprintf("%d–%d", c.MinLen, c.MaxLen)
	}
	v.Effective = ui2SeqBuildEffective(rep.EffectiveEntropy)
	for _, t := range rep.Fips.Tests {
		row := ui2SeqFipsRow{Name: t.Name, Spec: t.Spec, Disabled: t.Disabled, Passed: t.Passed,
			Observed: t.Observed, Requirement: t.Requirement, Reason: t.DisableReason,
			Blocks: fmt.Sprintf("%d / %d", t.BlocksPassed, t.BlocksPassed+t.BlocksFailed)}
		if row.Disabled && row.Reason == "" {
			row.Reason = "switched off in the analysis settings"
		}
		v.FipsRows = append(v.FipsRows, row)
	}
	fp := rep.FipsPositions
	for _, t := range fp.Tests {
		row := ui2SeqPosRow{Name: t.Name, Disabled: t.Disabled, Reason: t.DisableReason, Requirement: t.Requirement,
			Failed: fmt.Sprintf("%d / %d", t.PositionsFailed, t.PositionsPassed+t.PositionsFailed),
			Clean:  t.PositionsFailed == 0, Ranges: "—"}
		if len(t.FailingPositions) > 0 {
			row.Ranges = ui2SeqPositionRanges(t.FailingPositions, 12)
		}
		if row.Disabled && row.Reason == "" {
			row.Reason = "switched off in the analysis settings"
		}
		v.PosRows = append(v.PosRows, row)
		if fp.Computed && !t.Disabled && len(t.Significance) > 0 {
			v.PosCharts = append(v.PosCharts, ui2SeqBuildPosChart(t, fp.ExactIntervals))
		}
	}
	for i, p := range c.Positions {
		cp := ui2SeqCharPos{Index: p.Index, Samples: p.Samples, Distinct: p.Distinct,
			Entropy: ui2SeqF2(p.EntropyBits), Dead: p.Distinct <= 1}
		for j, cnt := range p.Counts {
			if j >= ui2SeqCountsShown {
				cp.More = len(p.Counts) - ui2SeqCountsShown
				break
			}
			cp.Counts = append(cp.Counts, ui2SeqCount{Label: cnt.Label,
				Pct:   strconv.FormatFloat(cnt.Fraction*100, 'f', 0, 64) + "%",
				Title: fmt.Sprintf("%d of %d", cnt.Count, p.Samples)})
		}
		if i < ui2SeqPositionsShown {
			v.Positions = append(v.Positions, cp)
		} else {
			v.MorePos = append(v.MorePos, cp)
		}
	}
	for i, t := range rep.ExtraStats.RepeatedList {
		if i >= 5 {
			break
		}
		if len(t) > 32 {
			t = t[:32]
		}
		v.Repeated = append(v.Repeated, strings.ToValidUTF8(t, "�"))
	}
	if n := len(rep.ExtraStats.RepeatedList); n > 5 {
		v.RepeatedN = n - 5
	}
	join := func(xs [6]int) string {
		parts := make([]string, 0, 6)
		for _, x := range xs {
			parts = append(parts, strconv.Itoa(x))
		}
		return strings.Join(parts, " · ")
	}
	v.RunsZeros, v.RunsOnes = join(rep.Bits.RunsZeros), join(rep.Bits.RunsOnes)
	v.BitEntropy = ui2SeqF2(rep.Bits.BitEntropy*100) + "%"
	for _, t := range rep.Advanced.Tests {
		if t.Tested && len(t.Notices) > 0 {
			v.Notices = append(v.Notices, t.Name+": "+strings.Join(t.Notices, " "))
		}
	}
	return v
}

// ui2SeqBuildEffective lays out the effective-entropy curve. A level the sample cannot answer is
// a gap, never a point at zero, and the line breaks there; the y axis tops out at the bit
// positions examined, so a sample that loses everything draws a floor, not a full chart.
func ui2SeqBuildEffective(e sequencer.EffectiveEntropyReport) *ui2SeqEffective {
	if len(e.Curve) == 0 {
		return nil
	}
	out := &ui2SeqEffective{Examined: e.BitPositionsExamined, CurveN: len(e.Curve),
		Note: e.RobustnessNote, Definition: e.Definition, Tests: strings.Join(e.Tests, "; "),
		Agreement: e.FipsAgreement, SkippedVar: e.BitPositionsSkippedVariableLength, Truncated: e.PositionsTruncated}
	headline := "no answer"
	if e.Chosen.Computed && e.Chosen.Bits != nil {
		headline = fmt.Sprintf("%d of %d bit(s)", *e.Chosen.Bits, e.Chosen.BitsExamined)
	}
	def := ""
	if e.SignificanceDefaulted {
		def = " (default)"
	}
	out.Headline = headline
	out.Detail = fmt.Sprintf("%d token(s) · %d bit position(s) examined · at %s%s: %s",
		e.TokensUsed, e.BitPositionsExamined, ui2SeqLevelLabel(e.SignificancePercent), def, headline)

	var usable []sequencer.EffectiveEntropyPoint
	for _, p := range e.Curve {
		if p.SignificancePercent > 0 && !math.IsInf(p.SignificancePercent, 0) && !math.IsNaN(p.SignificancePercent) {
			usable = append(usable, p)
		}
	}
	lo, hi := math.Inf(1), math.Inf(-1)
	for _, p := range usable {
		l := math.Log10(p.SignificancePercent)
		lo, hi = math.Min(lo, l), math.Max(hi, l)
		if p.BitsExamined > out.MaxBits {
			out.MaxBits = p.BitsExamined
		}
	}
	xFor := func(p float64) float64 {
		if hi-lo == 0 {
			return 0.5 * ui2SeqChartW
		}
		return (math.Log10(p) - lo) / (hi - lo) * ui2SeqChartW
	}
	yFor := func(bits int) float64 {
		if out.MaxBits == 0 {
			return ui2SeqChartH
		}
		return (1 - float64(bits)/float64(out.MaxBits)) * ui2SeqChartH
	}
	var run []string
	flush := func() {
		if len(run) > 0 {
			out.Runs = append(out.Runs, strings.Join(run, " "))
			run = nil
		}
	}
	for _, p := range usable {
		x := xFor(p.SignificancePercent)
		label := ui2SeqLevelLabel(p.SignificancePercent)
		if ui2SeqKeyLevel(p.SignificancePercent) || p.Chosen {
			out.Ticks = append(out.Ticks, ui2SeqMark{X: ui2SeqF2(x), Label: label})
		}
		if !p.Computed || p.Bits == nil {
			flush()
			out.Gaps = append(out.Gaps, ui2SeqMark{X: ui2SeqF2(x), Title: label + ": " + p.Reason})
			continue
		}
		y := yFor(*p.Bits)
		run = append(run, ui2SeqF2(x)+","+ui2SeqF2(y))
		out.Marks = append(out.Marks, ui2SeqMark{X: ui2SeqF2(x), Y: ui2SeqF2(y), Chosen: p.Chosen,
			Title: fmt.Sprintf("%s: %d of %d bit(s)", label, *p.Bits, p.BitsExamined)})
	}
	flush()
	out.HasMarks = len(out.Marks) > 0
	if len(e.Curve) > 0 {
		out.FirstLabel = ui2SeqLevelLabel(e.Curve[0].SignificancePercent)
		out.LastLabel = ui2SeqLevelLabel(e.Curve[len(e.Curve)-1].SignificancePercent)
	}
	minBits, maxBits, maxExpected, answered := math.MaxInt, math.MinInt, 0.0, 0
	for _, p := range e.Curve {
		row := ui2SeqLevelRow{Label: ui2SeqLevelLabel(p.SignificancePercent), Chosen: p.Chosen,
			Computed: p.Computed && p.Bits != nil, Rejected: "—", Expected: "—", Reason: p.Reason}
		if row.Computed {
			row.Value = fmt.Sprintf("%d / %d bit(s)", *p.Bits, p.BitsExamined)
			answered++
			minBits, maxBits = min(minBits, *p.Bits), max(maxBits, *p.Bits)
			if p.BitsRejected != nil {
				row.Rejected = strconv.Itoa(*p.BitsRejected)
			}
			if p.ExpectedChanceRejections != nil {
				row.Expected = ui2SeqF2(*p.ExpectedChanceRejections)
				maxExpected = math.Max(maxExpected, *p.ExpectedChanceRejections)
			}
		}
		if p.Chosen || ui2SeqKeyLevel(p.SignificancePercent) {
			out.Rows = append(out.Rows, row)
		} else {
			out.MoreRows = append(out.MoreRows, row)
		}
	}
	// Movement larger than chance explains is the only spread styled as a warning.
	out.SpreadWarn = answered >= 2 && float64(maxBits-minBits) > maxExpected
	return out
}

// ui2SeqScore is a position's significance on Burp's chart scale, 6 + log10(p), clamped to 0..6.
func ui2SeqScore(p float64) float64 {
	if !(p > 0) {
		return 0
	}
	return math.Min(6, math.Max(0, 6+math.Log10(p)))
}

func ui2SeqBuildPosChart(t sequencer.FipsPositionTest, exact bool) ui2SeqPosChart {
	n := len(t.Significance)
	ch := ui2SeqPosChart{ID: "seq-pos-" + t.ID, Name: t.Name, LastBit: n - 1, Exact: exact,
		Threshold: strconv.FormatFloat(t.Threshold, 'g', -1, 64),
		Aria:      fmt.Sprintf("%s significance at each of %d bit positions; %d failed", t.Name, n, t.PositionsFailed),
		PassY:     ui2SeqF2((1 - math.Min(1, math.Max(0, t.PassLevel/6))) * ui2SeqPosH)}
	w := ui2SeqPosW / float64(n)
	gap := 1.0
	if n > 160 {
		gap = 0
	}
	for i, sig := range t.Significance {
		pass := i < len(t.Passed) && t.Passed[i]
		stat := 0.0
		if i < len(t.Statistic) {
			stat = t.Statistic[i]
		}
		h := math.Max(ui2SeqScore(sig)/6*ui2SeqPosH, 1)
		verdict := "fail"
		if pass {
			verdict = "pass"
		}
		bar := ui2SeqBar{X: ui2SeqF2(float64(i) * w), Y: ui2SeqF2(ui2SeqPosH - h), W: ui2SeqF2(math.Max(w-gap, 0.5)), H: ui2SeqF2(h), Pass: pass,
			Title: fmt.Sprintf("bit %d: %s %s, significance %.2e, %s", i, t.StatisticLabel, strconv.FormatFloat(stat, 'g', 4, 64), sig, verdict)}
		ch.Bars = append(ch.Bars, bar)
		if !pass {
			ch.FailMarks = append(ch.FailMarks, ui2SeqBar{X: bar.X, W: ui2SeqF2(math.Max(w, 2))})
		}
	}
	return ch
}

// ui2SeqPositionRanges folds failing positions into ranges ("0-3, 9"), capped at limit ranges.
func ui2SeqPositionRanges(positions []int, limit int) string {
	var ranges []string
	start, prev := -1, -1
	flush := func() {
		if start < 0 {
			return
		}
		if start == prev {
			ranges = append(ranges, strconv.Itoa(start))
		} else {
			ranges = append(ranges, fmt.Sprintf("%d-%d", start, prev))
		}
	}
	for _, p := range positions {
		if start >= 0 && p == prev+1 {
			prev = p
			continue
		}
		flush()
		start, prev = p, p
	}
	flush()
	if len(ranges) <= limit {
		return strings.Join(ranges, ", ")
	}
	return fmt.Sprintf("%s and %d more range(s)", strings.Join(ranges[:limit], ", "), len(ranges)-limit)
}

// ---- internal API helpers ---------------------------------------------------------------------

// ui2SeqAPIRaw calls one internal JSON API through the mux and returns the body bytes, or the
// API's refusal as display text.
func (s *Server) ui2SeqAPIRaw(method, path string, payload any) ([]byte, string) {
	req := newReq(method, path)
	if payload != nil {
		b, err := ui2Marshal(payload)
		if err != nil {
			return nil, "could not encode the request: " + err.Error()
		}
		req.Header.Set("Content-Type", "application/json")
		req.Body = ioNopCloser(strings.NewReader(string(b)))
	}
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return nil, ui2APIErrorText(strings.TrimSpace(rec.Body.String()))
	}
	return rec.Body.Bytes(), ""
}

// ui2SeqAnalyse runs one analysis through the API and builds the view.
func (s *Server) ui2SeqAnalyse(payload map[string]any) (*ui2SeqView, string) {
	raw, errText := s.ui2SeqAPIRaw(http.MethodPost, "/api/sequencer/analyse", payload)
	if errText != "" {
		return nil, errText
	}
	var rep ui2SeqReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, "unreadable analysis: " + err.Error()
	}
	var generic any
	_ = json.Unmarshal(raw, &generic)
	return ui2SeqBuildView(&rep, ui2RenderSequencerReport(generic)), ""
}

func (s *Server) ui2SeqCaptures() []captureView {
	raw, errText := s.ui2SeqAPIRaw(http.MethodGet, "/api/sequencer/capture/", nil)
	if errText != "" {
		return nil
	}
	var list struct {
		Captures []captureView `json:"captures"`
	}
	_ = json.Unmarshal(raw, &list)
	return list.Captures
}

func (s *Server) ui2SeqCapture(id uint64) (*captureView, string) {
	raw, errText := s.ui2SeqAPIRaw(http.MethodGet, "/api/sequencer/capture/"+strconv.FormatUint(id, 10), nil)
	if errText != "" {
		return nil, errText
	}
	var c captureView
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, "unreadable capture: " + err.Error()
	}
	return &c, ""
}

// ---- page model -------------------------------------------------------------------------------

type ui2SeqStart struct {
	Target, Protocol, Count, DelayMs, Threads, Kind, Name, Pattern, Request, Deviates string
	Auto                                                                              bool
	Seeded                                                                            string
	Names                                                                             []ui2SeqName
}

// ui2SeqName is one token-location name found in a seeded response (a datalist option).
type ui2SeqName struct{ Kind, Name, Excerpt string }

type ui2SeqSettingRow struct {
	Key, Name string
	On        bool
	Locked    bool
}

type ui2SeqSettingsModel struct {
	Rows        []ui2SeqSettingRow
	Base64      bool
	Error, Note string
	Unavailable bool
}

type ui2SeqPage struct {
	Error      string
	Captures   []captureView
	AnyRunning bool
	Start      ui2SeqStart
	FollowID   string
	Follow     *captureView
	FollowErr  string
	Auto       bool
	PollURL    string
	AutoURL    string
	AutoOnURL  string
	AutoOffURL string
	CopyText   string
	Opts       ui2SeqOpts
	Levels     []ui2SeqLevel
	Tokens     string
	LoadNote   string
	Report     *ui2SeqView
	Sample     string
	Source     string
	Settings   ui2SeqSettingsModel
}

func (s *Server) ui2SeqSettingsModel() ui2SeqSettingsModel {
	raw, errText := s.ui2SeqAPIRaw(http.MethodGet, "/api/sequencer/settings", nil)
	if errText != "" {
		return ui2SeqSettingsModel{Unavailable: true, Error: errText}
	}
	var view sequencerSettingsView
	if err := json.Unmarshal(raw, &view); err != nil {
		return ui2SeqSettingsModel{Unavailable: true, Error: "unreadable settings: " + err.Error()}
	}
	m := ui2SeqSettingsModel{Base64: view.TokenHandling.Base64DecodeBeforeAnalyzing}
	for _, key := range ui2SeqSettingKeys(view) {
		row := ui2SeqSettingRow{Key: key, Name: key, On: view.TokenAnalysis[key]}
		if key == sequencer.CountBurpKey {
			row.Name, row.On, row.Locked = "Character count analysis", true, true
		} else {
			for _, t := range sequencer.AnalysisTests {
				if t.BurpKey == key {
					row.Name = t.Name
				}
			}
		}
		m.Rows = append(m.Rows, row)
	}
	return m
}

// ui2SeqSettingOrder is the panel order: the base characterisation, the FIPS four, the extended four.
var ui2SeqSettingOrder = []string{sequencer.CountBurpKey, "fips_monobit", "fips_poker", "fips_runs", "fips_long_run",
	"transitions", "spectral", "correlation", "compression"}

func ui2SeqSettingKeys(view sequencerSettingsView) []string {
	have := map[string]bool{}
	for _, k := range view.Keys {
		have[k] = true
	}
	for k := range view.TokenAnalysis {
		have[k] = true
	}
	var out []string
	for _, k := range ui2SeqSettingOrder {
		if have[k] {
			out = append(out, k)
			delete(have, k)
		}
	}
	var rest []string
	for k := range have {
		rest = append(rest, k)
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// ui2SeqPageModel builds the page with the captures list, settings and the followed capture.
func (s *Server) ui2SeqPageModel(opts ui2SeqOpts, followID string, auto bool) *ui2SeqPage {
	p := &ui2SeqPage{Opts: opts, Levels: ui2SeqLevels, Settings: s.ui2SeqSettingsModel(), Source: "paste",
		Start: ui2SeqStart{Protocol: "http", Kind: "cookie", Count: "100"}}
	p.Captures = s.ui2SeqCaptures()
	for _, c := range p.Captures {
		if c.Capturing {
			p.AnyRunning = true
		}
	}
	_, _, raw := ui2LatestExchange(s)
	p.Start.Request = raw
	p.Start.Target, p.Start.Protocol = ui2SeqTargetOf(raw)
	if followID != "" {
		s.ui2SeqFollow(p, followID, auto)
	}
	return p
}

// ui2SeqFollow attaches the page to one capture: progress, export, and the polling URLs.
func (s *Server) ui2SeqFollow(p *ui2SeqPage, followID string, auto bool) {
	p.FollowID = followID
	id, err := strconv.ParseUint(followID, 10, 64)
	if err != nil {
		p.FollowErr = "a capture id is a whole number"
		return
	}
	c, errText := s.ui2SeqCapture(id)
	if errText != "" {
		p.FollowErr = errText
		return
	}
	p.Follow, p.Auto = c, auto
	p.CopyText = strings.Join(c.Tokens, "\n")
	q := url.Values{"capture": {followID}}
	p.PollURL = "/ui2/sequencer?" + q.Encode()
	p.Opts.query(q)
	p.AutoOffURL = "/ui2/sequencer?" + q.Encode()
	q.Set("auto", "1")
	p.AutoURL = "/ui2/sequencer?" + q.Encode()
	p.AutoOnURL = p.AutoURL
}

// ui2SeqTargetOf derives the capture target and protocol from a request's own line or Host.
func ui2SeqTargetOf(raw string) (target, protocol string) {
	t := ui2HostFromRequest(raw)
	if len(t) >= 8 && strings.EqualFold(t[:8], "https://") {
		return t[8:], "https"
	}
	return t, "http"
}

// ui2SeqSeed fills the capture form from one stored message (?msg_id=): the request to repeat,
// its target, and the cookie/header/form-field names its response actually carries.
func (s *Server) ui2SeqSeed(p *ui2SeqPage, rawID string) {
	id, err := strconv.ParseUint(rawID, 10, 64)
	if err != nil {
		p.Error = "msg_id must be a whole number"
		return
	}
	var ex *core.Exchange
	for _, e := range s.store.Exchanges() {
		if (e.Request != nil && uint64(*e.Request) == id) || (e.Response != nil && uint64(*e.Response) == id) {
			ex = e
			break
		}
	}
	if ex == nil || ex.Request == nil {
		p.Error = fmt.Sprintf("message %d is not part of a captured exchange with a request", id)
		return
	}
	req, err := s.store.Get(*ex.Request)
	if err != nil {
		p.Error = fmt.Sprintf("message %d's request is no longer stored", id)
		return
	}
	p.Start.Request = string(req.Raw())
	p.Start.Target = fmt.Sprintf("%s:%d", ex.Host, ex.Port)
	p.Start.Protocol = "http"
	if ex.TLS {
		p.Start.Protocol = "https"
	}
	p.Start.Seeded = fmt.Sprintf("exchange %d (%s %s%s)", ex.ID, ex.Method, ex.Host, ex.Path)
	if ex.Response != nil {
		if resp, err := s.store.Get(*ex.Response); err == nil {
			p.Start.Names = ui2SeqLocationNames(resp.Raw())
		}
	}
}

var ui2SeqFormField = regexp.MustCompile(`(?is)<input\b[^>]*\bname\s*=\s*["']?([^"'\s>]+)["']?[^>]*>`)
var ui2SeqFormValue = regexp.MustCompile(`(?is)\bvalue\s*=\s*["']?([^"'>]*)`)

// ui2SeqLocationNames lists the names a response actually carries, for the location pickers.
func ui2SeqLocationNames(raw []byte) []ui2SeqName {
	head, body := splitHeadBody(raw)
	var out []ui2SeqName
	seen := map[string]bool{}
	add := func(kind, name, excerpt string) {
		k := kind + "\x00" + strings.ToLower(name)
		if name == "" || seen[k] {
			return
		}
		seen[k] = true
		if len(excerpt) > 40 {
			excerpt = excerpt[:40] + "…"
		}
		out = append(out, ui2SeqName{Kind: kind, Name: name, Excerpt: strings.ToValidUTF8(excerpt, "�")})
	}
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	for _, line := range lines[min(1, len(lines)):] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		add("header", name, value)
		if strings.EqualFold(name, "Set-Cookie") {
			cn, cv, _ := strings.Cut(value, "=")
			cv, _, _ = strings.Cut(cv, ";")
			add("cookie", strings.TrimSpace(cn), cv)
		}
	}
	for _, m := range ui2SeqFormField.FindAllStringSubmatch(string(body), 200) {
		val := ""
		if vm := ui2SeqFormValue.FindStringSubmatch(m[0]); vm != nil {
			val = vm[1]
		}
		add("form_field", m[1], val)
	}
	return out
}

// ---- handlers ---------------------------------------------------------------------------------

func (s *Server) ui2SeqRender(w http.ResponseWriter, r *http.Request, p *ui2SeqPage) {
	ui2Fragment(w, r, ui2SeqTitle, "sequencer", ui2Exec("sequencer_page.html", p))
}

// handleUI2Sequencer serves GET /ui2/sequencer. Query: capture (follow a capture by id), auto
// (re-analyse the followed capture's tokens), msg_id (seed the capture form from an exchange),
// and the analysis options. A live refresh (X-Live-Refresh) gets the captures block alone.
func (s *Server) handleUI2Sequencer(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	opts, optErr := ui2SeqOptsFrom(q.Get)
	p := s.ui2SeqPageModel(opts, strings.TrimSpace(q.Get("capture")), q.Get("auto") == "1")
	p.Error = optErr
	if r.Header.Get("HX-Request") == "true" && r.Header.Get("X-Live-Refresh") != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("sequencer_captures", p)))
		return
	}
	if id := strings.TrimSpace(q.Get("msg_id")); id != "" {
		s.ui2SeqSeed(p, id)
	}
	// Auto-analysis is a read: the followed capture's tokens analysed under the URL's options.
	if p.Auto && p.Follow != nil && len(p.Follow.Tokens) > 0 && optErr == "" {
		p.Source = "capture"
		p.Report, p.Error = s.ui2SeqAnalyse(opts.body(nil, p.Follow.Tokens))
		p.Sample = p.CopyText
	}
	s.ui2SeqRender(w, r, p)
}

// ui2SeqParseUploadForm parses a urlencoded or multipart form under a body bound.
func ui2SeqParseUploadForm(w http.ResponseWriter, r *http.Request, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit+1<<20)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		return r.ParseMultipartForm(8 << 20)
	}
	return r.ParseForm()
}

// ui2SeqReadUpload reads one uploaded file field. ok is false when no file was attached; a file over
// the bound is refused, never truncated.
func ui2SeqReadUpload(r *http.Request, field string, limit int64) (data []byte, name string, ok bool, errText string) {
	if r.MultipartForm == nil {
		return nil, "", false, ""
	}
	f, hdr, err := r.FormFile(field)
	if err != nil {
		return nil, "", false, ""
	}
	defer f.Close()
	if hdr.Size == 0 && hdr.Filename == "" {
		return nil, "", false, ""
	}
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, hdr.Filename, true, "could not read " + hdr.Filename + ": " + err.Error()
	}
	if int64(len(data)) > limit {
		return nil, hdr.Filename, true, fmt.Sprintf("%s is larger than %d MiB; load a smaller sample", hdr.Filename, limit>>20)
	}
	return data, hdr.Filename, true, ""
}

// handleUI2SequencerAnalyse serves POST /ui2/sequencer/analyse (riskRead: the analysis sends
// nothing). source=paste analyses the textarea or an attached token_file; op=load only loads the
// file; source=capture analyses a capture's tokens; redo=1 re-runs the last sample under the
// current options and saved settings.
func (s *Server) handleUI2SequencerAnalyse(w http.ResponseWriter, r *http.Request) {
	if err := ui2SeqParseUploadForm(w, r, ui2SeqMaxUpload); err != nil {
		http.Error(w, "the form could not be read: "+err.Error(), http.StatusBadRequest)
		return
	}
	opts, optErr := ui2SeqOptsFrom(r.PostFormValue)
	followID := strings.TrimSpace(r.PostFormValue("capture_id"))
	p := s.ui2SeqPageModel(opts, followID, r.PostFormValue("auto") == "1")
	p.Tokens = r.PostFormValue("tokens")
	if optErr != "" {
		p.Error = optErr
		s.ui2SeqRender(w, r, p)
		return
	}
	data, name, attached, upErr := ui2SeqReadUpload(r, "token_file", ui2SeqMaxUpload)
	if upErr != "" {
		p.Error = upErr
		s.ui2SeqRender(w, r, p)
		return
	}
	if attached {
		p.Tokens = strings.ToValidUTF8(string(data), "�")
		p.LoadNote = fmt.Sprintf("Loaded %s: %d line(s).", name, len(sequencer.TokensFromText(p.Tokens)))
	}
	if r.PostFormValue("op") == "load" {
		if !attached {
			p.Error = "choose a file to load first"
		}
		s.ui2SeqRender(w, r, p)
		return
	}
	var payload map[string]any
	switch {
	case r.PostFormValue("redo") == "1":
		sample := r.PostFormValue("last_sample")
		p.Source = r.PostFormValue("source")
		payload = opts.body(&sample, nil)
		p.Sample = sample
	case r.PostFormValue("source") == "capture":
		if p.Follow == nil {
			if p.FollowErr == "" {
				p.FollowErr = "name the capture to analyse"
			}
			p.Error = p.FollowErr
			s.ui2SeqRender(w, r, p)
			return
		}
		p.Source = "capture"
		payload = opts.body(nil, p.Follow.Tokens)
		p.Sample = p.CopyText
	default:
		text := p.Tokens
		payload = opts.body(&text, nil)
		p.Sample = text
	}
	p.Report, p.Error = s.ui2SeqAnalyse(payload)
	s.ui2SeqRender(w, r, p)
}

// ui2SequencerCapturePayload builds the /api/sequencer/capture body from the start form.
// Zero-value count/delay/threads are left for the API's own defaults and validation to
// report, so the reviewed body is exactly what the operator typed.
func ui2SequencerCapturePayload(r *http.Request) (map[string]any, string) {
	count, errText := ui2ParseCount("count", r.PostFormValue("count"))
	delay, err := ui2ParseCount("delay_ms", r.PostFormValue("delay_ms"))
	if errText == "" {
		errText = err
	}
	threads, err := ui2ParseCount("threads", r.PostFormValue("threads"))
	if errText == "" {
		errText = err
	}
	deviates, err := ui2ParseCount("length deviation", r.PostFormValue("deviates"))
	if errText == "" {
		errText = err
	}
	loc := map[string]any{"kind": r.PostFormValue("kind")}
	if n := r.PostFormValue("name"); n != "" {
		loc["name"] = n
	}
	if p := r.PostFormValue("pattern"); p != "" {
		loc["pattern"] = p
	}
	body := map[string]any{
		"target":   r.PostFormValue("target"),
		"protocol": r.PostFormValue("protocol"),
		// The textarea round-trips line endings as lone LF; the head must be CRLF on the
		// wire or many servers never answer (the repeater's ui2RestoreHeaderNewlines).
		"request":  ui2RestoreHeaderNewlines(r.PostFormValue("request")),
		"count":    count,
		"delay_ms": delay,
		"threads":  threads,
		"location": loc,
	}
	if deviates > 0 {
		body["length_deviates"] = map[string]any{"enable": true, "chars": deviates}
	}
	return body, errText
}

func ui2SeqStartFrom(r *http.Request) ui2SeqStart {
	return ui2SeqStart{
		Target: r.PostFormValue("target"), Protocol: r.PostFormValue("protocol"), Count: r.PostFormValue("count"),
		DelayMs: r.PostFormValue("delay_ms"), Threads: r.PostFormValue("threads"), Kind: r.PostFormValue("kind"),
		Name: r.PostFormValue("name"), Pattern: r.PostFormValue("pattern"), Request: r.PostFormValue("request"),
		Deviates: r.PostFormValue("deviates"), Auto: r.PostFormValue("auto") == "1",
	}
}

// handleUI2SequencerCapture serves POST /ui2/sequencer/capture/{action}. "confirm" mints the
// one-time review for the exact start call (/api/sequencer/capture is riskAttack - the gate
// must see the same body the operator reviewed); "run" spends it; pause/resume/stop drive a
// running capture through the API's own control verbs, which are riskRead because stopping
// work cannot attack anything.
func (s *Server) handleUI2SequencerCapture(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	opts, _ := ui2SeqOptsFrom(r.PostFormValue)
	switch r.PathValue("action") {
	case "confirm":
		payload, errText := ui2SequencerCapturePayload(r)
		if errText != "" {
			p := s.ui2SeqPageModel(opts, "", false)
			p.Start, p.Error = ui2SeqStartFrom(r), errText
			s.ui2SeqRender(w, r, p)
			return
		}
		body, _ := ui2Marshal(payload)
		token, preview, errText := "", "", ""
		if _, risk, ok := routeRiskFor("/api/sequencer/capture"); !ok || needsConfirmation(risk) {
			token, preview, errText = s.ui2MintConfirm("/api/sequencer/capture", http.MethodPost, "/api/sequencer/capture", body)
		} else {
			preview = "POST /api/sequencer/capture"
		}
		if errText == "" && token == "" {
			errText = "the confirmation gate minted no token - try again"
		}
		model := map[string]any{
			"token": token, "preview": preview, "error": errText,
			// The one-line preview is truncated for display; a confirmation gate has to
			// show the WHOLE exact body it binds, so the sheet carries it in full.
			"full_body": string(body),
			"start":     ui2SeqStartFrom(r),
		}
		ui2Fragment(w, r, ui2SeqTitle, "sequencer", ui2Exec("sequencer_confirm.html", model))
	case "run":
		// No dispatch at all without a token: spending a confirmation on a body the operator
		// never reviewed is the failure this branch exists to prevent.
		var errText string
		var result any
		payload, valErr := ui2SequencerCapturePayload(r)
		switch {
		case valErr != "":
			errText = valErr
		case r.PostFormValue("token") == "":
			errText = "no confirmation token: review the capture first"
		default:
			result, errText = s.ui2DispatchConfirmed(http.MethodPost, "/api/sequencer/capture", payload, r.PostFormValue("token"))
		}
		// The model is built after the dispatch, not before: the operator just started a
		// capture and the response is the first place they look for its row.
		follow := ""
		if m, ok := result.(map[string]any); ok {
			if id, ok := m["id"].(float64); ok {
				follow = strconv.FormatUint(uint64(id), 10)
			}
		}
		auto := r.PostFormValue("auto") == "1"
		p := s.ui2SeqPageModel(opts, follow, auto)
		p.Error = errText
		if errText != "" {
			p.Start = ui2SeqStartFrom(r)
		} else if follow != "" {
			w.Header().Set("HX-Push-Url", p.AutoOffURL)
			if auto {
				w.Header().Set("HX-Push-Url", p.AutoURL)
			}
		}
		s.ui2SeqRender(w, r, p)
	case "pause", "resume", "stop":
		_, errText := s.ui2APIResult(http.MethodPost, "/api/sequencer/capture/"+r.PathValue("action"), map[string]any{})
		p := s.ui2SeqPageModel(opts, strings.TrimSpace(r.PostFormValue("capture_id")), r.PostFormValue("auto") == "1")
		p.Error = ui2APIErrorText(errText)
		s.ui2SeqRender(w, r, p)
	default:
		http.Error(w, "unknown capture action", http.StatusBadRequest)
	}
}

// handleUI2SequencerTokens serves GET /ui2/sequencer/tokens/{id}: one capture's tokens as a
// .txt download (Burp's Save tokens).
func (s *Server) handleUI2SequencerTokens(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "a capture id is a whole number", http.StatusBadRequest)
		return
	}
	c, errText := s.ui2SeqCapture(id)
	if errText != "" {
		http.Error(w, errText, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="sequencer-tokens-%d.txt"`, id))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	for _, t := range c.Tokens {
		_, _ = io.WriteString(w, t+"\n")
	}
}

// ---- analysis settings (PUT /api/sequencer/settings via a held review) ------------------------

// ui2SeqSettingsReviewCap bounds open reviews: a full map is a pileup to refuse and say.
const ui2SeqSettingsReviewCap = 8

type ui2SeqSettingsReview struct {
	token   string
	gated   bool
	body    []byte
	expires time.Time
}

// ui2SeqSettingsEdit builds the PUT body from the form: only the switches that differ from the
// current settings, so a stale page never writes back a switch it did not change.
func ui2SeqSettingsEdit(r *http.Request, cur ui2SeqSettingsModel) (map[string]any, []string, string) {
	ta := map[string]bool{}
	var lines []string
	for _, row := range cur.Rows {
		if row.Locked {
			continue
		}
		want := r.PostFormValue("on_"+row.Key) == "1"
		if want != row.On {
			ta[row.Key] = want
			state := "OFF: the next analysis reports it as not run"
			if want {
				state = "ON: the next analysis runs it"
			}
			lines = append(lines, row.Name+" ("+row.Key+") switched "+state+".")
		}
	}
	edit := map[string]any{}
	if len(ta) > 0 {
		edit["token_analysis"] = ta
	}
	if b64 := r.PostFormValue("b64") == "1"; b64 != cur.Base64 {
		edit["token_handling"] = map[string]bool{"base_64_decode_before_analyzing": b64}
		if b64 {
			lines = append(lines, "Base64-decode before analyzing ON: every later figure describes the decoded bytes, and a token that is not valid base64 is refused.")
		} else {
			lines = append(lines, "Base64-decode before analyzing OFF: tokens are analysed as written.")
		}
	}
	if len(edit) == 0 {
		return nil, nil, "nothing changed: every switch already has the value shown"
	}
	return edit, lines, ""
}

// handleUI2SequencerSettings serves POST /ui2/sequencer/settings/{action}. confirm holds the exact
// PUT server-side and renders it for review; run spends that held call once. The API route is
// riskLocal, so the token is a ui2-local review handle unless the route's risk class ever puts it
// behind the confirmation gate, in which case the gate mints it.
func (s *Server) handleUI2SequencerSettings(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	render := func(m ui2SeqSettingsModel) {
		ui2Fragment(w, r, ui2SeqTitle, "sequencer", ui2Exec("sequencer_settings", m))
	}
	switch r.PathValue("action") {
	case "confirm":
		cur := s.ui2SeqSettingsModel()
		if cur.Unavailable {
			render(cur)
			return
		}
		edit, lines, errText := ui2SeqSettingsEdit(r, cur)
		if errText != "" {
			cur.Error = errText
			render(cur)
			return
		}
		body, _ := json.Marshal(edit)
		_, risk, known := routeRiskFor("/api/sequencer/settings")
		gated := !known || needsConfirmation(risk)
		var token string
		if gated {
			var mintErr string
			token, _, mintErr = s.ui2MintConfirm("/api/sequencer/settings", http.MethodPut, "/api/sequencer/settings", body)
			if mintErr != "" || token == "" {
				cur.Error = "the confirmation gate refused to mint a review - try again"
				render(cur)
				return
			}
		} else {
			t, err := randomHex(16)
			if err != nil {
				cur.Error = "review token: " + err.Error()
				render(cur)
				return
			}
			token = t
		}
		id, err := randomHex(16)
		if err != nil {
			cur.Error = "review id: " + err.Error()
			render(cur)
			return
		}
		now := time.Now()
		open := 0
		s.ui2SequencerSettingsReviews.Range(func(k, v any) bool {
			if e, ok := v.(ui2SeqSettingsReview); ok && now.After(e.expires) {
				s.ui2SequencerSettingsReviews.Delete(k)
			} else {
				open++
			}
			return true
		})
		if open >= ui2SeqSettingsReviewCap {
			cur.Error = "too many reviews are open at once - confirm or let some expire, then try again"
			render(cur)
			return
		}
		s.ui2SequencerSettingsReviews.Store(id, ui2SeqSettingsReview{token: token, gated: gated, body: body, expires: now.Add(ConfirmTTL)})
		pretty, _ := json.MarshalIndent(edit, "", "  ")
		ui2Fragment(w, r, ui2SeqTitle, "sequencer", ui2Exec("sequencer_settings_confirm.html", map[string]any{
			"projection": "PUT /api/sequencer/settings\n" + string(pretty),
			"lines":      lines, "review_id": id, "token": token,
		}))
	case "run":
		v, ok := s.ui2SequencerSettingsReviews.LoadAndDelete(r.PostFormValue("review_id"))
		entry, isReview := v.(ui2SeqSettingsReview)
		fail := func(msg string) {
			m := s.ui2SeqSettingsModel()
			m.Error = msg
			render(m)
		}
		switch {
		case !ok || !isReview:
			fail("that review is unknown or was already used - review the change again")
			return
		case time.Now().After(entry.expires):
			fail("that review expired with the confirmation window - review the change again")
			return
		case subtle.ConstantTimeCompare([]byte(entry.token), []byte(r.PostFormValue("token"))) != 1:
			fail("that review does not match this confirmation - review the change again")
			return
		}
		// The held bytes are dispatched verbatim; nothing typed after the review reaches the PUT.
		req := newReq(http.MethodPut, "/api/sequencer/settings")
		req.Header.Set("Content-Type", "application/json")
		req.Body = ioNopCloser(strings.NewReader(string(entry.body)))
		rec := newRecorder()
		if entry.gated {
			req.Header.Set(ConfirmHeader, entry.token)
			req.Host = "127.0.0.1"
			req.Header.Set("Origin", "http://127.0.0.1")
			s.guarded.ServeHTTP(rec, req)
		} else {
			s.mux.ServeHTTP(rec, req)
		}
		if rec.Code != http.StatusOK {
			fail("the settings API refused the change: " + truncateForDisplay(strings.TrimSpace(rec.Body.String()), 300))
			return
		}
		m := s.ui2SeqSettingsModel()
		m.Note = "Saved. The report on screen was run under the previous settings - Redo analysis re-runs it under these."
		render(m)
	default:
		http.Error(w, "unknown settings action", http.StatusBadRequest)
	}
}

// ui2RenderSequencerReport renders the sequencer analysis JSON as a readable report —
// grade, verdict, entropy figures, per-test outcomes, warnings — never a Go map dump.
// Every partial-analysis fact the API reports (FIPS blocks untested, per-position not
// computed, significance defaulted, warnings) is carried through, not smoothed over.
func ui2RenderSequencerReport(rep any) string {
	m, ok := rep.(map[string]any)
	if !ok {
		return ""
	}
	num := func(v any) float64 {
		f, _ := v.(float64)
		return f
	}
	sub := func(mm map[string]any, k string) map[string]any {
		v, _ := mm[k].(map[string]any)
		return v
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Grade: %s\n", strOf(m["grade"]))
	if v := strOf(m["verdict"]); v != "" {
		fmt.Fprintf(&sb, "Verdict: %s\n", v)
	}
	// Provenance: what the sample went through before any figure was computed.
	// An operator reading a number must know whether the tokens were re-encoded,
	// decoded, or padded first — a figure over transformed input read as a
	// figure over the pasted text is a wrong conclusion with a citation.
	if enc := strOf(m["encoding"]); enc != "" {
		line := "Encoding: " + enc
		if d, _ := m["encoding_detected"].(bool); d {
			line += " (detected from the sample, not chosen by the operator)"
		}
		sb.WriteString(line + "\n")
	}
	if b, _ := m["base64_decoded"].(bool); b {
		sb.WriteString("Base64: tokens were base64-decoded to their underlying bytes before analysis - every figure below describes the decoded bytes, not the base64 text\n")
	}
	if p := sub(m, "padding"); p != nil {
		switch strOf(p["mode"]) {
		case "start", "end":
			fmt.Fprintf(&sb, "Padding: %v token(s) padded at %s with %s (%v byte(s) added; original token lengths %v..%v)\n",
				p["tokens_padded"], strOf(p["mode"]), strOf(p["pad_byte_label"]), p["pad_bytes_added"], p["orig_min_len"], p["orig_max_len"])
		default:
			sb.WriteString("Padding: none - short tokens are excluded from the positions they do not reach rather than padded with invented characters\n")
		}
	}
	if ee := sub(m, "effective_entropy"); ee != nil {
		chosen := sub(ee, "chosen")
		if c, _ := chosen["computed"].(bool); c {
			line := fmt.Sprintf("Effective entropy: %v bit(s) at %v%% significance",
				chosen["bits"], ee["significance_percent"])
			if d, _ := ee["significance_defaulted"].(bool); d {
				line += " (significance defaulted, not chosen)"
			}
			sb.WriteString(line + "\n")
		} else {
			// Computed false means Bits is null: printing the figure line
			// anyway rendered "Effective entropy: <nil>" on samples too small
			// to support an answer. Name the miss and give the engine's reason.
			line := "Effective entropy: not computed on this sample"
			if r := strOf(chosen["reason"]); r != "" {
				line += " - " + r
			}
			sb.WriteString(line + "\n")
		}
	}
	if ws, _ := m["warnings"].([]any); len(ws) > 0 {
		sb.WriteString("Warnings:\n")
		for _, w := range ws {
			fmt.Fprintf(&sb, "- %s\n", strOf(w))
		}
	}
	if c := sub(m, "characters"); c != nil {
		fmt.Fprintf(&sb, "Characters: %v tokens, lengths %v..%v, alphabet %v, %.2f bits/char, %.2f bits total",
			num(c["tokens"]), num(c["min_len"]), num(c["max_len"]), num(c["alphabet_size"]),
			num(c["entropy_bits_per_char"]), num(c["total_entropy_bits"]))
		if a, _ := c["assumes_positional_independence"].(bool); a {
			sb.WriteString(" (positional independence assumed)")
		}
		sb.WriteByte('\n')
	}
	if es := sub(m, "extra_stats"); es != nil {
		fmt.Fprintf(&sb, "Extra stats: chi-square %v, serial correlation %.4f, Monte Carlo pi %v (deviation %.4f), repeated tokens %v\n",
			es["chi_square"], num(es["serial_correlation"]), es["monte_carlo_pi"], num(es["monte_carlo_deviation"]), es["repeated_tokens"])
	}
	if b := sub(m, "bits"); b != nil {
		fmt.Fprintf(&sb, "Bits: %v supplied, bit entropy %.4f, longest run %v\n",
			num(b["bits"]), num(b["bit_entropy"]), num(b["longest_run"]))
	}
	if f := sub(m, "fips"); f != nil {
		fmt.Fprintf(&sb, "FIPS 140-2: %v of %v supplied bits tested (%v-bit blocks, %v complete) - untested bits are not failed bits\n",
			num(f["bits_tested"]), num(f["bits_supplied"]), num(f["block_bits"]), num(f["blocks_tested"]))
	}
	if fp := sub(m, "fips_positions"); fp != nil {
		if c, _ := fp["computed"].(bool); !c {
			fmt.Fprintf(&sb, "Per-position significance: not computed - %s\n", strOf(fp["reason"]))
		}
	}
	if adv := sub(m, "advanced"); adv != nil {
		fmt.Fprintf(&sb, "Extended tests: %s (grade affected: %v)\n", strOf(adv["summary"]), adv["affects_grade"])
		tests, _ := adv["tests"].([]any)
		for _, t := range tests {
			tm, _ := t.(map[string]any)
			if tm == nil {
				continue
			}
			name := strOf(tm["name"])
			if tested, _ := tm["tested"].(bool); !tested {
				fmt.Fprintf(&sb, "  - %s: not testable on this sample - %s\n", name, strOf(tm["reason"]))
			} else if passed, _ := tm["passed"].(bool); passed {
				fmt.Fprintf(&sb, "  - %s: PASS (observed %v, threshold %v)\n", name, tm["observed"], tm["threshold"])
			} else {
				fmt.Fprintf(&sb, "  - %s: FAIL (observed %v, flagged %v of %v examined, threshold %v)\n",
					name, tm["observed"], tm["flagged"], tm["examined"], tm["threshold"])
			}
		}
	}
	return sb.String()
}
