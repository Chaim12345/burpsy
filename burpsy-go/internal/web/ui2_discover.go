package web

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// ---- Discover (/ui2/discover) ----------------------------------------------------------------
//
// The in-app reference the SPA's pages/discover.tsx renders: what burpsy does not do, the query
// grammar, the BCheck shape, per-tool panels, the hotkey map and the shipped docs. The prose is
// data (ui2/discover/discover_reference.json, exported from the SPA's lib/reference.ts); the
// hotkey panel is read from ui2/app.js itself so the map cannot drift from the keys it binds.
// Regenerate the JSON after editing reference.ts (from internal/web/ui):
//
//	bun -e 'import {LIMITS_PANEL as L,QUERY_PANEL as Q,BCHECK_PANEL as B,TOOL_PANELS as T,DOCS_PANEL as D} from "./src/lib/reference.ts";
//	        console.log(JSON.stringify([L,Q,B,...T,D],null,1))' > ../ui2/discover/discover_reference.json

// ui2RefRow is one term and what it means; Keys renders as <kbd> chips.
type ui2RefRow struct {
	Term   string   `json:"term"`
	Detail string   `json:"detail"`
	Note   string   `json:"note,omitempty"`
	Keys   []string `json:"keys,omitempty"`
}

// ui2RefBlock is a monospace block: a grammar, a file skeleton, a worked example.
type ui2RefBlock struct {
	Label string `json:"label"`
	Body  string `json:"body"`
}

type ui2RefPanel struct {
	ID      string        `json:"id"`
	Title   string        `json:"title"`
	Summary string        `json:"summary"`
	Source  string        `json:"source"`
	Blocks  []ui2RefBlock `json:"blocks,omitempty"`
	Rows    []ui2RefRow   `json:"rows"`
}

// ui2DiscoverPanels is every panel in reading order: the gaps first, the docs last, the hotkey
// map just before them (the SPA's order).
var ui2DiscoverPanels = func() []ui2RefPanel {
	raw, err := ui2FS.ReadFile("ui2/discover/discover_reference.json")
	if err != nil {
		panic(err)
	}
	var panels []ui2RefPanel
	if err := json.Unmarshal(raw, &panels); err != nil {
		panic(err)
	}
	keys := ui2HotkeyPanel()
	for i, p := range panels {
		if p.ID == "docs" {
			return append(panels[:i:i], append([]ui2RefPanel{keys}, panels[i:]...)...)
		}
	}
	return append(panels, keys)
}()

var (
	ui2JSHelpRe  = regexp.MustCompile(`(?s)var HELP = \[(.*?)\];`)
	ui2JSToolsRe = regexp.MustCompile(`var TOOLS = \[(.*?)\];`)
	ui2JSStrRe   = regexp.MustCompile(`'((?:[^'\\]|\\.)*)'`)
)

// ui2HotkeyPanel builds the keyboard panel from app.js's own HELP and TOOLS arrays: the strings
// the ? sheet shows, plus the alt+digit map the handler navigates by.
func ui2HotkeyPanel() ui2RefPanel {
	p := ui2RefPanel{
		ID:      "keys",
		Title:   "Keyboard",
		Summary: "The shortcuts this console binds. mod is ⌘ on macOS and Ctrl elsewhere. Shortcuts other than mod+K are ignored while typing in a field.",
		Source:  "internal/web/ui2/app.js — read from the same HELP and TOOLS lists the ? sheet and the key handler use",
	}
	js, err := ui2FS.ReadFile("ui2/app.js")
	if err != nil {
		return p
	}
	if m := ui2JSHelpRe.FindSubmatch(js); m != nil {
		for _, s := range ui2JSStrRe.FindAllStringSubmatch(string(m[1]), -1) {
			keys, detail, ok := strings.Cut(s[1], " — ")
			if !ok {
				continue
			}
			p.Rows = append(p.Rows, ui2RefRow{Term: keys, Detail: detail, Keys: []string{keys}})
		}
	}
	if m := ui2JSToolsRe.FindSubmatch(js); m != nil {
		for i, s := range ui2JSStrRe.FindAllStringSubmatch(string(m[1]), -1) {
			digit := strconv.Itoa((i + 1) % 10)
			p.Rows = append(p.Rows, ui2RefRow{
				Term: "alt+" + digit, Detail: "Open " + s[1], Keys: []string{"alt", digit},
			})
		}
	}
	return p
}

// ui2FilterPanels mirrors the SPA's filterPanels: a term matching a panel's own title, summary,
// source or blocks keeps the panel whole; otherwise only matching rows survive, and a panel with
// none drops out.
func ui2FilterPanels(panels []ui2RefPanel, term string) []ui2RefPanel {
	needle := strings.ToLower(strings.TrimSpace(term))
	if needle == "" {
		return panels
	}
	var out []ui2RefPanel
	for _, p := range panels {
		text := p.Title + " " + p.Summary + " " + p.Source
		for _, b := range p.Blocks {
			text += " " + b.Label + " " + b.Body
		}
		if strings.Contains(strings.ToLower(text), needle) {
			out = append(out, p)
			continue
		}
		var rows []ui2RefRow
		for _, r := range p.Rows {
			if strings.Contains(strings.ToLower(r.Term+" "+r.Detail+" "+r.Note), needle) {
				rows = append(rows, r)
			}
		}
		if len(rows) > 0 {
			p.Blocks, p.Rows = nil, rows
			out = append(out, p)
		}
	}
	return out
}

func ui2CountRows(panels []ui2RefPanel) int {
	n := 0
	for _, p := range panels {
		n += len(p.Rows)
	}
	return n
}

type ui2DiscoverModel struct {
	Q      string
	Panels []ui2RefPanel
	Shown  int
	Total  int
}

// handleUI2Discover serves GET /ui2/discover: the reference, filtered by q.
func (s *Server) handleUI2Discover(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	panels := ui2FilterPanels(ui2DiscoverPanels, q)
	m := ui2DiscoverModel{Q: q, Panels: panels, Shown: ui2CountRows(panels), Total: ui2CountRows(ui2DiscoverPanels)}
	ui2Fragment(w, r, "burpsy /ui2/ — Discover", "discover", ui2Exec("discover_page.html", m))
}
