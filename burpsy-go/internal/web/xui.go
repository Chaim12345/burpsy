package web

import (
	"embed"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/web/xui"
	"github.com/starfederation/datastar-go/datastar"
)

// xui is the server-driven console MVP (templ + Datastar). It is read-only: pages and SSE streams
// that patch HTML, never a state-changing route, so it adds nothing the confirmation gate has to
// cover. Probe, Scope, Search and Tools stay in the existing altui until they are migrated.
//
// The bound on data per update lives here, not in the browser: a stream sends at most xuiWindow
// rows plus counts, and pushes at most once per xuiMinPush however fast the capture changes.

//go:embed xui/datastar.js xui/xui.css
var xuiFS embed.FS

const (
	xuiWindow         = 300
	xuiMinPush        = 250 * time.Millisecond
	xuiMessagePreview = 64 << 10
)

func (s *Server) handleXUIMap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	templ.Handler(xui.MapPage()).ServeHTTP(w, r)
}

func (s *Server) handleXUIProve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	templ.Handler(xui.ProvePage()).ServeHTTP(w, r)
}

func (s *Server) handleXUIAsset(name, mime string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := xuiFS.ReadFile("xui/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(data)
	}
}

type xuiSignals struct {
	Q string `json:"q"`
}

// xuiStream runs one patch stream: it sends the first frame at once, then one more per change
// signal, never faster than xuiMinPush. render must not block on the stream.
func (s *Server) xuiStream(w http.ResponseWriter, r *http.Request, render func(sse *datastar.ServerSentEventGenerator, q string) error) {
	var sig xuiSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		http.Error(w, "bad signals", http.StatusBadRequest)
		return
	}
	q := strings.TrimSpace(sig.Q)
	if len(q) > 200 {
		q = q[:200]
	}
	sse := datastar.NewSSE(w, r)
	sub, unsubscribe := s.live.subscribe()
	defer unsubscribe()
	ctx := r.Context()
	_ = sse.PatchElementTempl(xui.Live("live", true))
	last := time.Time{}
	for {
		if wait := xuiMinPush - time.Since(last); wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
		s.live.take(sub)
		last = time.Now()
		if err := render(sse, q); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-sub.signal:
		}
	}
}

func (s *Server) handleXUIMapStream(w http.ResponseWriter, r *http.Request) {
	s.xuiStream(w, r, func(sse *datastar.ServerSentEventGenerator, q string) error {
		rows, total, matched := s.xuiHistoryWindow(q)
		label := fmt.Sprintf("%d requests", total)
		if q != "" {
			label = fmt.Sprintf("%d of %d match", matched, total)
		}
		if matched > len(rows) {
			label += fmt.Sprintf(" (newest %d shown)", len(rows))
		}
		if err := sse.PatchElementTempl(xui.Count(label)); err != nil {
			return err
		}
		return sse.PatchElementTempl(xui.MapRows(rows, total, len(rows)))
	})
}

// xuiHistoryWindow is the newest xuiWindow proxy-history rows matching q (a case-insensitive
// substring of host, path, method or status), the total proxy rows, and the match count.
func (s *Server) xuiHistoryWindow(q string) (rows []xui.Row, total, matched int) {
	exchanges := s.store.Exchanges()
	needle := strings.ToLower(q)
	for i := len(exchanges) - 1; i >= 0; i-- {
		ex := exchanges[i]
		switch ex.Source {
		case core.SourceRepeater, core.SourceIntruder, core.SourceScanner:
			continue
		}
		total++
		v := exchangeView(ex)
		status := ""
		if v.Status != nil {
			status = strconv.Itoa(int(*v.Status))
		}
		if needle != "" {
			hay := strings.ToLower(v.Method + " " + v.Host + " " + v.Path + " " + status)
			if !strings.Contains(hay, needle) {
				continue
			}
		}
		matched++
		if len(rows) < xuiWindow {
			rows = append(rows, xui.Row{ID: uint64(v.ID), Method: v.Method, Host: v.Host, Path: v.Path, Status: status, Size: xuiBytes(v.ResponseLen)})
		}
	}
	return rows, total, matched
}

func xuiBytes(n int) string {
	switch {
	case n <= 0:
		return ""
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f kB", float64(n)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
}

func (s *Server) handleXUIDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid exchange ID", http.StatusBadRequest)
		return
	}
	ex, err := s.store.GetExchange(core.ExchangeID(id))
	if err != nil {
		http.Error(w, "Exchange not found", http.StatusNotFound)
		return
	}
	v := exchangeView(ex)
	d := xui.Detail{Title: fmt.Sprintf("#%d  %s %s", v.ID, v.Method, v.Path)}
	status := "no response"
	if v.Status != nil {
		status = strconv.Itoa(int(*v.Status))
	}
	d.Facts = []xui.Fact{{K: "Host", V: v.Host + ":" + strconv.Itoa(int(v.Port))}, {K: "Status", V: status}, {K: "Response size", V: xuiBytes(v.ResponseLen)}}
	for _, m := range []struct {
		label string
		id    *uint64
	}{{"Request", v.Request}, {"Response", v.Response}} {
		if m.id == nil {
			d.Messages = append(d.Messages, xui.Message{Label: m.label, Text: "(none recorded)"})
			continue
		}
		msg, err := s.message(*m.id)
		if err != nil {
			d.Messages = append(d.Messages, xui.Message{Label: m.label, Text: "(message unavailable)"})
			continue
		}
		raw := msg.Raw()
		note := ""
		if len(raw) > xuiMessagePreview {
			note = fmt.Sprintf("Preview: first %d of %d bytes. The full message is at /api/message/%d.", xuiMessagePreview, len(raw), *m.id)
			raw = raw[:xuiMessagePreview]
		}
		d.Messages = append(d.Messages, xui.Message{Label: m.label, Text: strings.ToValidUTF8(string(raw), "\uFFFD"), Note: note})
	}
	sse := datastar.NewSSE(w, r)
	_ = sse.PatchElementTempl(xui.DetailPane(d))
}

func (s *Server) handleXUIProveStream(w http.ResponseWriter, r *http.Request) {
	s.xuiStream(w, r, func(sse *datastar.ServerSentEventGenerator, q string) error {
		rows, counts, total, matched := s.xuiProveWindow(q)
		var chips []xui.SevCount
		for _, k := range []string{"critical", "high", "medium", "low", "informational"} {
			chips = append(chips, xui.SevCount{Key: k, Label: strings.ToUpper(k), N: counts[k]})
		}
		label := fmt.Sprintf("%d findings", total)
		if q != "" {
			label = fmt.Sprintf("%d of %d match", matched, total)
		}
		if matched > len(rows) {
			label += fmt.Sprintf(" (top %d shown)", len(rows))
		}
		if err := sse.PatchElementTempl(xui.Count(label)); err != nil {
			return err
		}
		if err := sse.PatchElementTempl(xui.SevChips(chips)); err != nil {
			return err
		}
		return sse.PatchElementTempl(xui.ProveRows(rows))
	})
}

// xuiProveCand is the little a finding needs while it competes for a place in the window.
type xuiProveCand struct {
	f    *core.Finding
	rank int
}

// xuiFirstHost is the host of the first occurrence whose request is still in the store, as
// findingToIssueView reports it.
func (s *Server) xuiFirstHost(f *core.Finding) string {
	for _, occ := range f.Occurrences {
		if ex, err := s.store.ExchangeByRequest(core.MsgOrZero(occ.Request)); err == nil {
			return ex.Host
		}
	}
	return ""
}

// xuiProveWindow returns the top xuiWindow findings matching q (severity, then newest first),
// the per-severity counts over all non-isolated, non-false-positive findings, the total of those,
// and how many match q. It does not build the full issue view per finding: the host (an exchange
// lookup) is resolved only for the rows shown, or per candidate when a filter needs it. Rows,
// order, counts and labels are identical to the reference in xui_test.go.
func (s *Server) xuiProveWindow(q string) (rows []xui.Finding, counts map[string]int, total, matched int) {
	needle := strings.ToLower(q)
	counts = map[string]int{}
	var cands []xuiProveCand
	for _, f := range s.findings.All() {
		if s.findingIsolated(f) || f.FalsePositive {
			continue
		}
		total++
		sevName := f.EffectiveSeverity().String()
		sev := strings.ToLower(sevName)
		counts[sev]++
		if needle != "" {
			hay := strings.ToLower(f.Name + " " + s.xuiFirstHost(f) + " " + sevName)
			if !strings.Contains(hay, needle) {
				continue
			}
		}
		cands = append(cands, xuiProveCand{f: f, rank: severityRankOf(sevName)})
	}
	matched = len(cands)
	less := func(a, b xuiProveCand) bool { // a sorts before b
		if a.rank != b.rank {
			return a.rank > b.rank
		}
		return a.f.ID > b.f.ID
	}
	sort.Slice(cands, func(i, j int) bool { return less(cands[i], cands[j]) })
	if len(cands) > xuiWindow {
		cands = cands[:xuiWindow]
	}
	for _, c := range cands {
		rows = append(rows, xui.Finding{ID: c.f.ID, Severity: strings.ToLower(c.f.EffectiveSeverity().String()), Name: c.f.Name, Host: s.xuiFirstHost(c.f), Seen: len(c.f.Occurrences)})
	}
	return rows, counts, total, matched
}

// xuiCap upper-cases the first letter of a lowercase severity name, as core.Severity.String does.
func xuiCap(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
