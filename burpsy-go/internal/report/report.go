// Package report renders scan findings in the three downloadable formats the
// web UI links to (scanner.ts) and the CLI can emit: plain JSON, SARIF 2.1.0,
// and a self-contained HTML page. The package depends only on core so both the
// web layer and the CLI share one implementation instead of drifting.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Row is one finding, already resolved to its display form. Hosts are resolved
// by the caller (they need a store); the renderers never guess.
type Row struct {
	ID          uint64   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	Hosts       []string `json:"hosts"`
	Occurrences int      `json:"occurrences"`
	// Params is every parameter this finding covers. A finding that merged several observations of
	// one issue at one target reports a single row with several occurrences, and without this the
	// report would say "5 occurrences" while silently dropping which 5 parameters were affected —
	// the one detail that makes the finding reproducible.
	Params []string `json:"params,omitempty"`
	// Advisory is the issue-definition catalogue entry this finding resolved to, or nil when it
	// resolved to none. The catalogue is what turns a one-line check name into something an operator
	// can act on and put in front of a client, so a report that has it and does not print it is
	// throwing away the most useful thing it holds.
	Advisory *Advisory `json:"advisory,omitempty"`
	// AdvisoryNote explains a deliberate absence — a check whose class the catalogue does not carry.
	// Distinguishing "no entry, and here is why" from "nothing looked" is the difference between a
	// report a reader can trust and one with a silent hole in it.
	AdvisoryNote string `json:"advisory_note,omitempty"`
	// Evidence is where this finding was actually observed. A finding with no location is an
	// assertion; a finding with one is a thing someone can go and reproduce.
	Evidence []Evidence `json:"evidence,omitempty"`
}

// Advisory is the catalogue entry backing a finding. DescriptionHTML and RemediationHTML have already
// been through advisory.SanitisedHTML by the caller — the renderers here embed them verbatim, which
// is only safe because of that, and is why the field names say HTML out loud.
type Advisory struct {
	Name            string `json:"name"`
	TypeIndex       string `json:"type_index"`
	TypicalSeverity string `json:"typical_severity"`
	DescriptionHTML string `json:"description_html"`
	RemediationHTML string `json:"remediation_html"`
	References      []Link `json:"references,omitempty"`
	Classifications []Link `json:"classifications,omitempty"`
}

// Link is a titled URL — a further-reading reference or a CWE/CAPEC classification.
type Link struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Evidence is one place a finding was observed.
//
// The message ids are what turn this from a place into a reproduction. They are the two dense
// counters the capture store already indexes, and every consumer here can resolve them back to
// bytes with store.Raw — so a reader holding this file and the capture can rebuild the exact
// request and response (burpsy-react-ui-exiu). They are reported rather than dereferenced because
// the scan-wide exports run over every finding in the store and must not read a request body per
// row; a single-finding report does read them, and that is the export the operator reaches for
// when they want the evidence in the file rather than a reference to it.
type Evidence struct {
	Host   string `json:"host"`
	Path   string `json:"path"`
	Method string `json:"method"`
	Status int    `json:"status,omitempty"`
	// RequestMsgID and ResponseMsgID are message ids, not exchange ids. Both spaces count from
	// zero and they are not interchangeable — the same mistake findingHosts and findingEvidence
	// document, and the reason a reader must not resolve one against the other.
	// No omitempty, deliberately. These ids count from zero, so 0 is the FIRST message the project
	// ever captured and a real thing to name — and omitempty would drop it, leaving an evidence entry
	// that says it has no request when it has the very first one. The id spaces are separate dense
	// counters precisely so they need no "is this set" flag; that is the point of them.
	RequestMsgID  uint64 `json:"request_msg_id"`
	ResponseMsgID uint64 `json:"response_msg_id"`
	// HasRequest and HasResponse say which halves exist, because a zero cannot. An occurrence with
	// no response names one message and a nil response, and the reader needs to tell that from an
	// occurrence whose response is message 0.
	HasRequest  bool `json:"has_request"`
	HasResponse bool `json:"has_response"`
}

// Message is the raw HTTP of one half of an evidence pair, carried by the single-finding report so
// the artefact stands alone. "Relevant extract" versus "full messages" is Burp's
// report-settings.html:98-111 choice, and this is the full-messages end of it — an assessor
// handed a finding needs the request that produced it and the response that came back, not a
// summary of them.
type Message struct {
	// ID is the message id, carried so a reader can match this against an Evidence entry.
	ID   uint64 `json:"id"`
	Raw  string `json:"raw"`
	Note string `json:"note,omitempty"`
}

// FindingReport is one finding and the bytes behind it: the scan-wide report's Row plus the
// messages its evidence names.
//
// Split from Row because the bulk exports must NOT carry this. A scan of a large project has
// thousands of rows and their request bodies between them, and a report that inlined them would be
// unusable as a document and enormous on disk. The single-finding report is the one that pays
// that cost, because it is the one an operator opened deliberately for one issue.
type FindingReport struct {
	Row
	// Messages are the request and response for each evidence entry, in the same order. Paired by
	// position rather than by a foreign key because the list is short and a reader opening the file
	// is looking at one finding — a cross-reference the reader has to resolve is a worse artefact
	// than a short list they can read down.
	Messages []Message `json:"messages,omitempty"`
	// MessagesOmitted counts evidence entries whose bytes could not be read — the capture has been
	// evicted, or the occurrence names a message that is gone. Reported rather than hidden, because
	// a report that silently drops half its evidence reads as "there was no request".
	MessagesOmitted int `json:"messages_omitted,omitempty"`
}

// JSON renders the plain-JSON report.
func JSON(rows []Row) ([]byte, error) {
	return json.MarshalIndent(map[string]interface{}{
		"findings": rows,
		"total":    len(rows),
	}, "", "  ")
}

// sarifLevel maps a severity onto the SARIF "level" vocabulary.
func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "note"
	}
}

// SARIF renders a SARIF 2.1.0 document with one rule+result per finding.
func SARIF(rows []Row) ([]byte, error) {
	rules := make([]map[string]interface{}, 0, len(rows))
	results := make([]map[string]interface{}, 0, len(rows))
	for _, f := range rows {
		ruleID := fmt.Sprintf("BURPSY-%d", f.ID)
		rules = append(rules, map[string]interface{}{
			"id":               ruleID,
			"name":             f.Name,
			"shortDescription": map[string]interface{}{"text": f.Description},
			"help":             map[string]interface{}{"text": f.Remediation},
		})
		result := map[string]interface{}{
			"ruleId":  ruleID,
			"level":   sarifLevel(f.Severity),
			"message": map[string]interface{}{"text": f.Description},
		}
		// A merged finding stands for several observations that differed only in which parameter was
		// affected. SARIF has no first-class field for that, so it goes in the properties bag rather
		// than being dropped: a consumer that ignores it is no worse off, and one that reads it can
		// still tell the five parameters apart.
		if len(f.Params) > 0 {
			result["properties"] = map[string]interface{}{"params": f.Params}
		}
		results = append(results, result)
	}
	doc := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "burpsy",
						"informationUri": "https://github.com/burpsy-go/burpsy",
						"rules":          rules,
					},
				},
				"results": results,
			},
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// severityOrder ranks severities worst-first, which is the order a reader needs and the opposite of
// the order the finding store happens to hold them in.
var severityOrder = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

func severityRank(s string) int {
	up := strings.ToUpper(strings.TrimSpace(s))
	for i, name := range severityOrder {
		if name == up {
			return i
		}
	}
	return len(severityOrder)
}

// reportCSS is the whole stylesheet, inlined so the report stays one file an operator can mail. The
// palette is burpsy's own — the same greys and PortSwigger orange the console uses — so an exported
// report reads as coming from the tool that produced it. It carries a light and a dark rendering
// because the reader's viewer decides, not the tool.
const reportCSS = `
:root{--paper:#ffffff;--raised:#f7f7f8;--line:#d9d9de;--text:#1b1b1f;--muted:#5c5c66;
--accent:#d1490f;--crit:#8b1a1a;--high:#c62828;--med:#96600a;--low:#1565c0;--info:#5c5c66}
@media (prefers-color-scheme:dark){:root{--paper:#232427;--raised:#2b2c30;--line:#3d3e44;
--text:#e6e6e9;--muted:#a6a6b0;--accent:#ff8659;--crit:#ff8a8a;--high:#ff9b98;--med:#c9c33a;
--low:#93bde0;--info:#a6a6b0}}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--text);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
.wrap{max-width:60rem;margin:0 auto;padding:2.5rem 1.5rem 4rem}
header{border-bottom:2px solid var(--accent);padding-bottom:1rem;margin-bottom:1.5rem}
h1{margin:0;font-size:1.6rem;letter-spacing:-.01em}
.meta{color:var(--muted);font-size:.85rem;margin-top:.35rem}
.summary{display:flex;flex-wrap:wrap;gap:.6rem;margin:1.5rem 0 2.5rem}
.tile{flex:1 1 7rem;background:var(--raised);border:1px solid var(--line);border-radius:4px;padding:.7rem .9rem}
.tile .n{font-size:1.5rem;font-weight:700;font-variant-numeric:tabular-nums}
.tile .k{font-size:.7rem;letter-spacing:.09em;text-transform:uppercase;color:var(--muted)}
h2.sev{font-size:.78rem;letter-spacing:.11em;text-transform:uppercase;margin:2.5rem 0 .75rem;
padding-bottom:.3rem;border-bottom:1px solid var(--line)}
article{background:var(--raised);border:1px solid var(--line);border-left-width:4px;
border-radius:4px;padding:1rem 1.15rem;margin-bottom:.9rem}
article h3{margin:0 0 .5rem;font-size:1.05rem}
.pill{display:inline-block;font-size:.68rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;
border:1px solid currentColor;border-radius:999px;padding:.05rem .5rem;margin-right:.4rem;vertical-align:.1em}
.sev-critical{color:var(--crit)} .sev-high{color:var(--high)} .sev-medium{color:var(--med)}
.sev-low{color:var(--low)} .sev-info{color:var(--info)}
article.sev-critical{border-left-color:var(--crit)} article.sev-high{border-left-color:var(--high)}
article.sev-medium{border-left-color:var(--med)} article.sev-low{border-left-color:var(--low)}
article.sev-info{border-left-color:var(--info)}
.label{font-size:.7rem;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);
margin:1rem 0 .3rem;font-weight:700}
.hosts code{background:var(--paper);border:1px solid var(--line);border-radius:3px;
padding:.05rem .35rem;margin-right:.3rem;font-size:.82rem}
table{border-collapse:collapse;width:100%;font-size:.85rem}
th,td{text-align:left;padding:.3rem .55rem;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-size:.7rem;letter-spacing:.08em;text-transform:uppercase}
.scroll{overflow-x:auto}
ul.links{margin:.2rem 0;padding-left:1.1rem}
ul.links li{margin:.15rem 0}
a{color:var(--accent)}
.note{color:var(--muted);font-style:italic}
.empty{background:var(--raised);border:1px solid var(--line);border-radius:4px;padding:2rem;text-align:center;color:var(--muted)}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--line);color:var(--muted);font-size:.78rem}
`

// HTML renders a self-contained report page.
//
// Every operator/attacker-controllable field — the finding's own name, description, remediation, and
// every host and path in the evidence table — is escaped: a finding whose text carries markup lifted
// out of a scanned response must not become script in a file someone opens later.
//
// The one exception is Advisory.DescriptionHTML and Advisory.RemediationHTML, which are embedded
// verbatim. That is safe only because the caller has already put them through
// advisory.SanitisedHTML, which allows a short list of structural elements and no attributes at all.
// The paragraph structure is the point: escaping it would turn the catalogue's remediation advice
// back into the wall of text this renderer exists to stop producing.
func HTML(rows []Row) []byte {
	sorted := make([]Row, len(rows))
	copy(sorted, rows)
	sort.SliceStable(sorted, func(i, j int) bool { return severityRank(sorted[i].Severity) < severityRank(sorted[j].Severity) })

	counts := map[string]int{}
	for _, r := range sorted {
		counts[strings.ToUpper(strings.TrimSpace(r.Severity))]++
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<title>burpsy scan report</title><style>`)
	b.WriteString(reportCSS)
	b.WriteString(`</style></head><body><div class="wrap">`)

	b.WriteString(`<header><h1>burpsy scan report</h1>`)
	b.WriteString(fmt.Sprintf(`<div class="meta">%d finding%s &middot; generated %s</div></header>`,
		len(sorted), plural(len(sorted)), html.EscapeString(time.Now().Format("2006-01-02 15:04 MST"))))

	// Severity tiles first: the summary a reader needs before any detail, and the reason the counts
	// are a partition of the findings rather than a highlight.
	b.WriteString(`<div class="summary">`)
	for _, sev := range severityOrder {
		b.WriteString(fmt.Sprintf(`<div class="tile"><div class="n sev-%s">%d</div><div class="k">%s</div></div>`,
			strings.ToLower(sev), counts[sev], html.EscapeString(sev)))
	}
	b.WriteString(`</div>`)

	if len(sorted) == 0 {
		b.WriteString(`<div class="empty">No findings were recorded in this session.<br>` +
			`An empty report means nothing was found by the checks that ran &mdash; not that the target is clean.</div>`)
	}

	lastSev := ""
	for _, f := range sorted {
		sev := strings.ToUpper(strings.TrimSpace(f.Severity))
		if sev != lastSev {
			b.WriteString(fmt.Sprintf(`<h2 class="sev sev-%s">%s</h2>`, strings.ToLower(sev), html.EscapeString(sev)))
			lastSev = sev
		}
		writeFinding(&b, f, sev)
	}

	b.WriteString(`<footer>Generated by burpsy. Advisory text, where present, comes from the bundled ` +
		`issue-definition catalogue.</footer>`)
	b.WriteString(`</div></body></html>`)
	return []byte(b.String())
}

func writeFinding(b *strings.Builder, f Row, sev string) {
	b.WriteString(fmt.Sprintf(`<article class="sev-%s">`, strings.ToLower(sev)))
	b.WriteString(fmt.Sprintf(`<h3>%s</h3>`, html.EscapeString(f.Name)))
	b.WriteString(fmt.Sprintf(`<span class="pill sev-%s">%s</span>`, strings.ToLower(sev), html.EscapeString(sev)))
	if f.Confidence != "" {
		b.WriteString(fmt.Sprintf(`<span class="pill">%s confidence</span>`, html.EscapeString(f.Confidence)))
	}
	b.WriteString(fmt.Sprintf(`<span class="pill">%d occurrence%s</span>`, f.Occurrences, plural(f.Occurrences)))

	if len(f.Hosts) > 0 {
		b.WriteString(`<div class="label">Affected hosts</div><div class="hosts">`)
		for _, h := range f.Hosts {
			b.WriteString(fmt.Sprintf(`<code>%s</code>`, html.EscapeString(h)))
		}
		b.WriteString(`</div>`)
	}

	// Printed beside the hosts because it answers the same question at the next level down: the hosts
	// say where, these say which input. A merged finding's occurrence count is meaningless to a reader
	// who cannot see what varied between the occurrences.
	if len(f.Params) > 0 {
		b.WriteString(`<div class="label">Affected parameters</div><div class="hosts">`)
		for _, p := range f.Params {
			b.WriteString(fmt.Sprintf(`<code>%s</code>`, html.EscapeString(p)))
		}
		b.WriteString(`</div>`)
	}

	// The finding's own text, always — the catalogue enriches a finding, it never replaces what the
	// check actually reported.
	if f.Description != "" {
		b.WriteString(`<div class="label">Detail</div><p>` + html.EscapeString(f.Description) + `</p>`)
	}
	if f.Remediation != "" {
		b.WriteString(`<div class="label">Remediation</div><p>` + html.EscapeString(f.Remediation) + `</p>`)
	}

	if len(f.Evidence) > 0 {
		b.WriteString(`<div class="label">Evidence</div><div class="scroll"><table><thead><tr>` +
			`<th>Method</th><th>Host</th><th>Path</th><th>Status</th></tr></thead><tbody>`)
		for _, e := range f.Evidence {
			status := ""
			if e.Status != 0 {
				status = strconv.Itoa(e.Status)
			}
			b.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				html.EscapeString(e.Method), html.EscapeString(e.Host),
				html.EscapeString(e.Path), html.EscapeString(status)))
		}
		b.WriteString(`</tbody></table></div>`)
	}

	if f.Advisory != nil {
		writeAdvisory(b, f.Advisory)
	} else if f.AdvisoryNote != "" {
		b.WriteString(`<div class="label">Catalogue</div><p class="note">` +
			html.EscapeString(f.AdvisoryNote) + `</p>`)
	}
	b.WriteString(`</article>`)
}

// writeAdvisory prints the catalogue entry. The two *HTML fields go in verbatim — see HTML's own doc
// for why that is safe and why escaping them would defeat the purpose.
func writeAdvisory(b *strings.Builder, a *Advisory) {
	b.WriteString(fmt.Sprintf(`<div class="label">Issue definition &mdash; %s (%s)</div>`,
		html.EscapeString(a.Name), html.EscapeString(a.TypeIndex)))
	if a.TypicalSeverity != "" {
		b.WriteString(fmt.Sprintf(`<p class="note">This issue class is typically %s severity.</p>`,
			html.EscapeString(strings.ToLower(a.TypicalSeverity))))
	}
	if a.DescriptionHTML != "" {
		b.WriteString(a.DescriptionHTML)
	}
	if a.RemediationHTML != "" {
		b.WriteString(`<div class="label">Recommended remediation</div>`)
		b.WriteString(a.RemediationHTML)
	}
	writeLinks(b, "Classifications", a.Classifications)
	writeLinks(b, "References", a.References)
}

// writeLinks renders titled URLs as real links, from typed data rather than from markup — which is
// why the sanitiser can drop every href it sees and lose nothing.
func writeLinks(b *strings.Builder, label string, links []Link) {
	if len(links) == 0 {
		return
	}
	b.WriteString(fmt.Sprintf(`<div class="label">%s</div><ul class="links">`, html.EscapeString(label)))
	for _, l := range links {
		title := l.Title
		if title == "" {
			title = l.URL
		}
		if safeLinkURL(l.URL) {
			b.WriteString(fmt.Sprintf(`<li><a href="%s" rel="noopener noreferrer">%s</a></li>`,
				html.EscapeString(l.URL), html.EscapeString(title)))
			continue
		}
		// A URL whose scheme is not http(s) is printed as text rather than linked: the catalogue is
		// data, and data that names javascript: is not something to hand a reader's browser.
		b.WriteString(fmt.Sprintf(`<li>%s</li>`, html.EscapeString(title)))
	}
	b.WriteString(`</ul>`)
}

func safeLinkURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
