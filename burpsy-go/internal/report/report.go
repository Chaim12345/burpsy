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
	// Messages carries the evidence pair's HTTP bytes when the operator asked
	// for them (Settings.MessageMode relevant or full — burpsy-react-ui-a9qy).
	// Empty in every bulk export by default: see FindingReport for why a
	// scan-wide report that always carried messages is a defect, not a feature.
	// It is json:"-" because these ride the HTML and XML artefacts, not the
	// JSON export; that export keeps its stable shape and the message ids in
	// Evidence, which is the reproduction a script needs.
	Messages []AttachedMessage `json:"-"`
}

// AttachedMessage is one evidence message attached to a Row for the HTML and
// XML exports. It is not the single-finding report's Message: that type is a
// stand-alone artefact with its own note field, and this one carries the
// truncation flag the settings report needs to print its "[truncated]" marker.
type AttachedMessage struct {
	IsRequest bool
	// Text is the (possibly truncated) bytes as text, for the HTML renderer.
	Text string
	// Raw is the full bytes, carried so the XML export can base64 them. The
	// HTML renderer prints Text; the XML one encodes Raw, because base64 of an
	// already-truncated text would not round-trip to what the operator saw.
	Raw []byte
	// Truncated says MaxMessageLen cut the message, so the renderer prints the
	// explicit marker rather than letting the text read as the whole message.
	Truncated bool
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

// Settings are Burp's report-settings.html choices: the title, how issues are
// organised, how deep the table of contents goes, which issue-detail sections
// are printed, and how HTTP messages appear. Zero value means the defaults the
// settings-free HTML() has always used — organise by severity, everything
// except messages — so the new parameters widen the old report rather than
// replacing it.
type Settings struct {
	// Title replaces "burpsy scan report" as the document's h1 and window title.
	Title string
	// OrganiseBy chooses the primary grouping: "type", "severity" or "url".
	// Anything else (including the empty string) is severity, the reader-first
	// order the report has always used; an unknown value is refused by the
	// route that builds these Settings, not silently coerced here.
	OrganiseBy string
	// TOCDepth is how many levels of detail the table of contents renders.
	// 0 means no TOC at all. Depth 1 lists the primary groups; depth 2 also
	// lists each finding beneath its group; deeper levels would repeat those
	// same rows, so the value is clamped by the route.
	TOCDepth int
	// Sections selects which issue-detail blocks print: "background",
	// "remediation", "detail", "classifications". The zero value prints all of
	// them — the report without a settings step carries everything, and these
	// settings exist to let an operator take things out, not to add a second
	// default that hides content the old report showed.
	Sections []string
	// MessageMode is how evidence messages appear: "none" (the bulk export's
	// rule — messages never ride the scan-wide report by default), "relevant"
	// (an extract around the evidence spans) or "full" (whole messages).
	MessageMode string
	// MaxMessageLen bounds each message at MaxMessageLen bytes once it is
	// included at all, with an explicit "truncated" marker when it bites —
	// Burp's "limit each message to a maximum length" report-settings option.
	// 0 means no bound. Negative is refused by the route.
	MaxMessageLen int
}

// sectionOn says whether one issue-detail section is printed under these
// settings. With no Sections list every section prints; an explicit list is a
// keep-if-match, the same semantics the severity filter on the route uses.
func (s Settings) sectionOn(name string) bool {
	if len(s.Sections) == 0 {
		return true
	}
	for _, want := range s.Sections {
		if want == name {
			return true
		}
	}
	return false
}

// HTMLWithSettings renders the report page under Settings. The grouping order
// is the only structural change from HTML(); message inclusion is decided by
// the caller, which has the store to read the bytes — a Settings here that
// asks for messages the caller did not attach is a settings echo, not a
// report, so the caller (api_report.go) is the one that honours MessageMode.
//
// "By URL" groups by host then path ascending; "by type" groups by the
// finding's name; both keep severity worst-first *within* a group so the
// reader's eye still lands on the worst thing first inside every group.
func HTMLWithSettings(rows []Row, st Settings) []byte {
	switch st.OrganiseBy {
	case "type", "url":
		return renderGroupedHTML(rows, st)
	default:
		// severity — HTML's own order, with the settings applied around it.
		return renderSeverityHTML(rows, st)
	}
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

// renderSeverityHTML is HTML() with a Settings applied. The severity grouping
// and worst-first order are exactly HTML()'s; the settings add the title, the
// TOC, section selection and (via the caller-attached messages on each Row)
// the message extracts. It exists separately from HTML() so the default export
// keeps its own tested shape and cannot drift into carrying settings it was
// never given.
func renderSeverityHTML(rows []Row, st Settings) []byte {
	sorted := make([]Row, len(rows))
	copy(sorted, rows)
	sort.SliceStable(sorted, func(i, j int) bool { return severityRank(sorted[i].Severity) < severityRank(sorted[j].Severity) })
	return renderReportDocument(sorted, st, func(b *strings.Builder) {
		lastSev := ""
		for _, f := range sorted {
			sev := strings.ToUpper(strings.TrimSpace(f.Severity))
			if sev != lastSev {
				b.WriteString(fmt.Sprintf(`<h2 class="sev sev-%s">%s</h2>`, strings.ToLower(sev), html.EscapeString(sev)))
				lastSev = sev
			}
			writeFindingWithSettings(b, f, sev, st)
		}
	})
}

// renderGroupedHTML renders the by-type and by-URL organisations: one h2 per
// group, findings within a group ordered worst-severity-first so the report
// still leads with the worst thing in each section.
func renderGroupedHTML(rows []Row, st Settings) []byte {
	type group struct {
		key   string
		title string
		rows  []Row
	}
	var groups []*group
	byKey := map[string]*group{}
	for _, f := range rows {
		key, title := groupKey(f, st.OrganiseBy)
		g, ok := byKey[key]
		if !ok {
			g = &group{key: key, title: title}
			byKey[key] = g
			groups = append(groups, g)
		}
		g.rows = append(g.rows, f)
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].key < groups[j].key })
	for _, g := range groups {
		sort.SliceStable(g.rows, func(i, j int) bool {
			return severityRank(g.rows[i].Severity) < severityRank(g.rows[j].Severity)
		})
	}
	return renderReportDocument(rows, st, func(b *strings.Builder) {
		for _, g := range groups {
			b.WriteString(fmt.Sprintf(`<h2 class="group">%s</h2>`, html.EscapeString(g.title)))
			for _, f := range g.rows {
				writeFindingWithSettings(b, f, strings.ToUpper(strings.TrimSpace(f.Severity)), st)
			}
		}
	})
}

// groupKey returns the group identity for one row and a display title for it.
// By type groups by the finding's name; by URL groups by host then path, so
// two findings on one page sit together. The evidence table inside the finding
// carries the full detail, so the group key can stay short.
func groupKey(f Row, organiseBy string) (key, title string) {
	if organiseBy == "type" {
		return f.Name, f.Name
	}
	// url
	if len(f.Evidence) > 0 && f.Evidence[0].Host != "" {
		e := f.Evidence[0]
		return e.Host + " " + e.Path, e.Host + e.Path
	}
	if len(f.Hosts) > 0 {
		return f.Hosts[0], f.Hosts[0]
	}
	return "(no location recorded)", "(no location recorded)"
}

// renderReportDocument is the page frame every organisation shares: head,
// title, severity summary, TOC, body, footer. body() writes the grouped
// findings between the summary and the footer.
func renderReportDocument(sorted []Row, st Settings, body func(*strings.Builder)) []byte {
	title := st.Title
	if title == "" {
		title = "burpsy scan report"
	}
	counts := map[string]int{}
	for _, r := range sorted {
		counts[strings.ToUpper(strings.TrimSpace(r.Severity))]++
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(fmt.Sprintf(`<title>%s</title><style>`, html.EscapeString(title)))
	b.WriteString(reportCSS)
	b.WriteString(reportSettingsCSS)
	b.WriteString(`</style></head><body><div class="wrap">`)

	b.WriteString(fmt.Sprintf(`<header><h1>%s</h1>`, html.EscapeString(title)))
	b.WriteString(fmt.Sprintf(`<div class="meta">%d finding%s &middot; generated %s</div></header>`,
		len(sorted), plural(len(sorted)), html.EscapeString(time.Now().Format("2006-01-02 15:04 MST"))))

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

	writeTOC(&b, sorted, st)
	body(&b)

	b.WriteString(`<footer>Generated by burpsy. Advisory text, where present, comes from the bundled ` +
		`issue-definition catalogue.</footer>`)
	b.WriteString(`</div></body></html>`)
	return []byte(b.String())
}

// reportSettingsCSS is the extra stylesheet the settings report needs: the TOC
// and the per-finding message blocks. Kept beside reportCSS so the report is
// still one self-contained file.
const reportSettingsCSS = `
.toc{margin:0 0 2rem;padding:0 1rem;border-left:3px solid var(--line,var(--accent,#f0950f));}
.toc h2{font-size:1rem;margin:.75rem 0 .25rem;}
.toc ul{margin:0;padding-left:1.25rem;}
.toc a{color:inherit;}
.msg{margin:.5rem 0;padding:.5rem .75rem;background:var(--panel,#f4f4f5);border-radius:4px;overflow-x:auto;}
.msg pre{margin:0;white-space:pre-wrap;word-break:break-all;}
.msg .truncated{font-style:italic;}
`

// writeTOC renders the table of contents to the requested depth. Depth 1 lists
// the groups; depth 2 lists each finding under its group. Deeper would repeat
// the same rows, so the caller clamps the value — and this function is
// written to be correct for any non-negative depth anyway.
func writeTOC(b *strings.Builder, sorted []Row, st Settings) {
	if st.TOCDepth <= 0 {
		return
	}
	b.WriteString(`<nav class="toc"><h2>Contents</h2>`)
	switch st.OrganiseBy {
	case "type", "url":
		type group struct {
			title string
			rows  []Row
		}
		var groups []*group
		byTitle := map[string]*group{}
		for _, f := range sorted {
			_, title := groupKey(f, st.OrganiseBy)
			g, ok := byTitle[title]
			if !ok {
				g = &group{title: title}
				byTitle[title] = g
				groups = append(groups, g)
			}
			g.rows = append(g.rows, f)
		}
		sort.SliceStable(groups, func(i, j int) bool { return groups[i].title < groups[j].title })
		for _, g := range groups {
			b.WriteString(fmt.Sprintf(`<h2>%s</h2>`, html.EscapeString(g.title)))
			if st.TOCDepth >= 2 {
				b.WriteString(`<ul>`)
				for _, f := range g.rows {
					b.WriteString(fmt.Sprintf(`<li><a href="#finding-%d">%s</a></li>`, f.ID, html.EscapeString(f.Name)))
				}
				b.WriteString(`</ul>`)
			}
		}
	default:
		// severity: the summary tiles already show the counts, so depth 1 lists
		// the severity bands that have findings; depth 2 names each finding.
		b.WriteString(`<ul>`)
		for _, sev := range severityOrder {
			if n := countSeverity(sorted, sev); n == 0 {
				continue
			}
			b.WriteString(fmt.Sprintf(`<li>%s (%d)`, html.EscapeString(sev), n))
			if st.TOCDepth >= 2 {
				b.WriteString(`<ul>`)
				for _, f := range sorted {
					if strings.ToUpper(strings.TrimSpace(f.Severity)) == sev {
						b.WriteString(fmt.Sprintf(`<li><a href="#finding-%d">%s</a></li>`, f.ID, html.EscapeString(f.Name)))
					}
				}
				b.WriteString(`</ul>`)
			}
			b.WriteString(`</li>`)
		}
		b.WriteString(`</ul>`)
	}
	b.WriteString(`</nav>`)
}

func countSeverity(rows []Row, sev string) int {
	n := 0
	for _, r := range rows {
		if strings.ToUpper(strings.TrimSpace(r.Severity)) == sev {
			n++
		}
	}
	return n
}

// writeFindingWithSettings is writeFinding with the settings applied: the
// heading gains an anchor the TOC points at, and the optional sections and
// message blocks are filtered by st. The always-printed core — name, severity
// pill, affected hosts and parameters, evidence table — is unchanged from the
// settings-free report, because Settings exists to take detail OUT of a report
// the operator finds too dense, not to invent a second default that hides the
// things every report reader needs.
func writeFindingWithSettings(b *strings.Builder, f Row, sev string, st Settings) {
	b.WriteString(fmt.Sprintf(`<article class="sev-%s" id="finding-%d">`, strings.ToLower(sev), f.ID))
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
	if len(f.Params) > 0 {
		b.WriteString(`<div class="label">Affected parameters</div><div class="hosts">`)
		for _, p := range f.Params {
			b.WriteString(fmt.Sprintf(`<code>%s</code>`, html.EscapeString(p)))
		}
		b.WriteString(`</div>`)
	}

	if st.sectionOn("detail") {
		if f.Description != "" {
			b.WriteString(`<div class="label">Detail</div><p>` + html.EscapeString(f.Description) + `</p>`)
		}
	}
	if st.sectionOn("remediation") {
		if f.Remediation != "" {
			b.WriteString(`<div class="label">Remediation</div><p>` + html.EscapeString(f.Remediation) + `</p>`)
		}
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

	// The catalogue sections. "background" covers the whole advisory block the
	// way the settings-free report prints it; "classifications" alone hides
	// only the reference/classification link lists, which are the densest and
	// least load-bearing part for a client-facing copy.
	if f.Advisory != nil {
		if st.sectionOn("background") {
			writeAdvisory(b, f.Advisory)
		} else if st.sectionOn("classifications") {
			writeLinks(b, "Classifications", f.Advisory.Classifications)
			writeLinks(b, "References", f.Advisory.References)
		}
	} else if f.AdvisoryNote != "" && st.sectionOn("background") {
		b.WriteString(`<div class="label">Catalogue</div><p class="note">` +
			html.EscapeString(f.AdvisoryNote) + `</p>`)
	}

	// Messages, when the caller attached them (see Settings.MessageMode).
	for i := range f.Messages {
		m := &f.Messages[i]
		label := "Response"
		if m.IsRequest {
			label = "Request"
		}
		b.WriteString(fmt.Sprintf(`<div class="msg"><div class="label">%s</div><pre>`, label))
		b.WriteString(html.EscapeString(m.Text))
		if m.Truncated {
			b.WriteString(`<span class="truncated">[truncated at ` + strconv.Itoa(st.MaxMessageLen) + ` bytes]</span>`)
		}
		b.WriteString(`</pre></div>`)
	}
	b.WriteString(`</article>`)
}
