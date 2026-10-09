package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/advisory"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/report"
)

// ---- Scanner report export: /api/report/{json|sarif|html} ---------------------------------------

// The UI links to these endpoints as plain downloads (scanner.ts), so each format is generated
// from the finding store's current contents. Rendering lives in the shared report package; this
// handler only resolves hosts against the store and wires the download headers.

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	format := strings.TrimPrefix(r.URL.Path, "/api/report/")
	format = strings.TrimSuffix(format, "/")

	// finding/{id} is Burp's "Report selected issues" (issues.html:195-228) made honest: the
	// scan-wide exports below describe findings, and a description of a finding is not evidence
	// for it. This one carries the bytes — the request that produced the issue and the response
	// that came back — so a single finding becomes a self-contained handoff rather than something
	// an assessor has to reassemble by hand. The ids are already on each occurrence, so this reads
	// messages the store holds rather than storing anything new (burpsy-react-ui-exiu).
	if rest, ok := strings.CutPrefix(format, "finding/"); ok {
		s.reportOneFinding(w, r, rest)
		return
	}

	// The report honours a filter (burpsy-react-ui-8r6): severity as a comma list, host as a
	// substring, and false positives excluded on request — the axes the Issues page already
	// filters by, so "the High and Critical findings on this host" is the query string rather
	// than a manual pass over the whole-store export. An unknown severity value is refused
	// rather than ignored: a filter parameter that silently does not filter would produce a
	// report claiming to be the filtered set while carrying everything.
	query := r.URL.Query()
	var filter reportFilter
	if raw := query.Get("severity"); raw != "" {
		// ParseSeverity coerces an unknown value to informational rather than failing, which is
		// right for captured data and wrong for a filter: a typo would silently produce a report
		// of only-informational findings while claiming to be the filtered set. Matched here,
		// case-insensitively, against the values the engine can actually hold.
		valid := map[string]core.Severity{
			"critical": core.SeverityCritical, "high": core.SeverityHigh, "medium": core.SeverityMedium,
			"low": core.SeverityLow, "informational": core.SeverityInformational,
		}
		for _, name := range strings.Split(raw, ",") {
			sev, ok := valid[strings.ToLower(strings.TrimSpace(name))]
			if !ok {
				http.Error(w, "unknown severity "+strconv.Quote(name)+"; the accepted values are critical, high, medium, low, informational", http.StatusBadRequest)
				return
			}
			filter.severities = append(filter.severities, sev)
		}
	}
	filter.host = strings.TrimSpace(query.Get("host"))
	filter.hideFalsePositives = query.Get("exclude_false_positives") == "true"

	// Parsed and validated for every format, consumed by the two that render
	// settings (html, xml): a typo in message_mode is a 400 whichever format
	// the operator asked for, not a parameter that quietly does nothing
	// because the URL happened to end in /json.
	settings, err := parseReportSettings(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch format {
	case "json":
		s.reportJSON(w, filter)
	case "sarif":
		s.reportSARIF(w, filter)
	case "html":
		s.reportHTML(w, filter, settings)
	case "xml":
		s.reportXML(w, filter, settings)
	default:
		http.NotFound(w, r)
	}
}

// parseReportSettings decodes Burp's report-settings choices
// (burpsy-react-ui-a9qy) from the query string: report-settings.html's
// "Report details" (title, organisation, TOC depth — HTML-only in Burp and
// consumed by the HTML renderer here), the issue-detail sections, and the
// "HTTP messages" mode and length that both message-carrying formats honour.
//
// Every unknown value is refused with a message naming the parameter and the
// accepted values, the same rule the severity filter already follows: a
// settings parameter that silently does nothing would produce a report
// claiming to be the configured one while carrying something else.
func parseReportSettings(query url.Values) (report.Settings, error) {
	var st report.Settings
	st.Title = strings.TrimSpace(query.Get("title"))
	if len(st.Title) > 200 {
		return st, fmt.Errorf("title is %d characters; the report title is capped at 200", len(st.Title))
	}
	if raw := query.Get("organise_by"); raw != "" {
		switch raw {
		case "severity", "type", "url":
			st.OrganiseBy = raw
		default:
			return st, fmt.Errorf("unknown organise_by %q; the accepted values are severity, type, url", raw)
		}
	}
	if raw := query.Get("toc_depth"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return st, fmt.Errorf("toc_depth %q is not a non-negative number", raw)
		}
		// Clamped, not refused: depth 1 lists the groups, depth 2 also lists
		// each finding beneath them, and a deeper value has no further level
		// to invent — the TOC would repeat the same rows. The renderer is
		// written to be correct for any depth anyway; this keeps the document
		// honest about what a level means.
		if n > 2 {
			n = 2
		}
		st.TOCDepth = n
	}
	// Has, not Get: "sections=" present but empty means every detail section
	// is off (Burp's wizard allows unticking all of them), which is not the
	// same state as the parameter being absent (every section on). The
	// renderer distinguishes the two through the nil/empty slice split.
	if query.Has("sections") {
		raw := strings.TrimSpace(query.Get("sections"))
		if raw == "" {
			st.Sections = []string{}
		} else {
			valid := map[string]bool{"background": true, "remediation": true, "detail": true, "classifications": true}
			for _, name := range strings.Split(raw, ",") {
				name = strings.TrimSpace(name)
				if !valid[name] {
					return st, fmt.Errorf("unknown section %q; the accepted values are background, remediation, detail, classifications", name)
				}
				st.Sections = append(st.Sections, name)
			}
		}
	}
	if raw := query.Get("message_mode"); raw != "" {
		switch raw {
		case "none", "relevant", "full":
			st.MessageMode = raw
		default:
			return st, fmt.Errorf("unknown message_mode %q; the accepted values are none, relevant, full", raw)
		}
	}
	if raw := query.Get("max_message_len"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return st, fmt.Errorf("max_message_len %q is not a non-negative number of bytes", raw)
		}
		st.MaxMessageLen = n
	}
	return st, nil
}

// reportOneFinding writes one finding as a self-contained report: the same row the scan-wide export
// would produce, plus the request and response behind each of its evidence entries.
//
// Only JSON. An HTML rendering would need a second renderer for a document that is one finding,
// and a SARIF rendering of a single result is a shape no tool consumes — a file that exists because
// the other two formats exist is not evidence, it is decoration. JSON is what an assessor scripts
// against and what a reader can open.
func (s *Server) reportOneFinding(w http.ResponseWriter, r *http.Request, id string) {
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		http.Error(w, "finding id must be a number", http.StatusBadRequest)
		return
	}
	f, err := s.findings.Get(n)
	if err != nil {
		// 404 and not an empty report: "this finding produced nothing" and "this finding does not
		// exist" are different answers, and returning an empty document for a deleted id would let
		// a stale link read as a clean result.
		http.Error(w, "no finding with id "+id, http.StatusNotFound)
		return
	}
	row := s.reportRow(f)

	out := report.FindingReport{Row: row}
	for _, ev := range row.Evidence {
		if !ev.HasRequest && !ev.HasResponse {
			// An evidence entry with no message ids is a location the store could not resolve to
			// bytes, and saying so beats emitting a message list that looks complete.
			out.MessagesOmitted++
			continue
		}
		if ev.HasRequest {
			out.Messages = appendOrOmit(out.Messages, &out.MessagesOmitted, report.Message{
				ID: ev.RequestMsgID, Raw: s.messageText(ev.RequestMsgID),
			})
		}
		if ev.HasResponse {
			out.Messages = appendOrOmit(out.Messages, &out.MessagesOmitted, report.Message{
				ID: ev.ResponseMsgID, Raw: s.messageText(ev.ResponseMsgID),
			})
		}
	}
	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="burpsy-finding-`+id+`.json"`)
	w.Write(body)
}

// messageText is one stored message's bytes as text, or "" when the store cannot produce it.
//
// The same accessor /api/message/{id} uses, deliberately: two ways to read a message is how a
// single-finding report ends up carrying something the console's own viewer would not show. A
// message whose bytes cannot be read — evicted from the capture, or an id the store does not
// hold — comes back empty here and is counted by the caller rather than being emitted as an
// empty message, which would read as "the request had no content".
func (s *Server) messageText(id uint64) string {
	msg, err := s.message(id)
	if err != nil {
		return ""
	}
	return string(msg.Raw())
}

// appendOrOmit adds a message when it has bytes, and counts it as omitted when it does not.
//
// The split is the point: a report that silently drops unreadable evidence reads as "there was no
// request", which is a claim about the target rather than about the capture, and the two lead an
// assessor to opposite conclusions.
func appendOrOmit(messages []report.Message, omitted *int, m report.Message) []report.Message {
	if m.Raw == "" {
		*omitted++
		return messages
	}
	return append(messages, m)
}

// reportFilter is the subset the export carries, decoded from the query string. Zero value
// means no constraint — the whole store, exactly what the unparameterised URL always meant.
type reportFilter struct {
	severities         []core.Severity
	host               string
	hideFalsePositives bool
}

// applies says whether one finding survives the filter. Every axis is a keep-if-match; an
// empty axis never constrains.
func (f reportFilter) applies(finding *core.Finding, hosts []string) bool {
	if len(f.severities) > 0 {
		kept := false
		for _, sev := range f.severities {
			// EffectiveSeverity, not Severity: the operator's override is the severity this
			// finding HAS. Filtering on the engine's original dropped a finding they had just
			// raised to Critical from a ?severity=critical export, and included it in a
			// ?severity=low one as though the triage never happened (burpsy-react-ui-5qfr).
			if finding.EffectiveSeverity() == sev {
				kept = true
				break
			}
		}
		if !kept {
			return false
		}
	}
	if f.host != "" {
		kept := false
		for _, h := range hosts {
			if strings.Contains(strings.ToLower(h), strings.ToLower(f.host)) {
				kept = true
				break
			}
		}
		if !kept {
			return false
		}
	}
	if f.hideFalsePositives && finding.FalsePositive {
		return false
	}
	return true
}

// reportRows turns the finding store into report rows, resolving each finding's hosts from the
// store's exchanges (left empty rather than guessed when the store cannot resolve them). The
// filter decides which findings are carried; zero value carries everything.
func (s *Server) reportRows(filter reportFilter) []report.Row {
	findings := s.findings.All()
	rows := make([]report.Row, 0, len(findings))
	for _, f := range findings {
		if !filter.applies(f, s.findingHosts(f)) {
			continue
		}
		rows = append(rows, s.reportRow(f))
	}
	return rows
}

// reportRow builds one report row. Extracted from reportRows so the single-finding export cannot
// drift from the scan-wide one: two builders for the same document is how "the same finding
// describes itself differently in two exports" happens, and the advisory comment below records
// that this already went wrong once.
func (s *Server) reportRow(f *core.Finding) report.Row {
	row := report.Row{
		ID:   f.ID,
		Name: f.Name,
		// The same values the Issues page shows (api_capture.go's findingToIssueView), for the
		// same reason: a report is the document the triage exists to produce, so it cannot be
		// the one surface that ignores it.
		Severity:    f.EffectiveSeverity().String(),
		Confidence:  f.EffectiveConfidence().String(),
		Description: f.Description,
		Remediation: f.Remediation,
		Hosts:       s.findingHosts(f),
		Occurrences: len(f.Occurrences),
		Params:      f.Params,
		Evidence:    s.findingEvidence(f),
	}
	// The catalogue was already resolved for /api/issues and then thrown away at the report
	// boundary, so the exported artefact — the thing that actually leaves the tool and gets read
	// by someone who was not driving it — carried the least context of any surface. Same resolver
	// as the API so a finding cannot describe itself one way on screen and another in the file.
	def, note := s.advisories.Resolve(f.Name)
	if def != nil {
		row.Advisory = advisoryForReport(def)
	} else {
		row.AdvisoryNote = note
	}
	return row
}

// advisoryForReport converts a catalogue entry into the renderer's shape, sanitising the two HTML
// fragments here — at the boundary — so the renderer never has to decide whether to trust them.
func advisoryForReport(d *advisory.Definition) *report.Advisory {
	a := &report.Advisory{
		Name:            d.Name,
		TypeIndex:       d.HexIndex(),
		TypicalSeverity: string(d.Severity),
		DescriptionHTML: advisory.SanitisedHTML(d.Description),
		RemediationHTML: advisory.SanitisedHTML(d.Remediation),
	}
	for _, r := range d.References {
		a.References = append(a.References, report.Link{Title: r.Title, URL: r.URL})
	}
	for _, c := range d.Classification {
		a.Classifications = append(a.Classifications, report.Link{Title: c.Title, URL: c.URL})
	}
	return a
}

// findingEvidence lists where a finding was actually observed. A finding with no location is an
// assertion; one with a method, host and path is something a reader can go and reproduce, which is
// the difference between a report that gets acted on and one that gets argued with.
//
// ExchangeByRequest for the same reason findingHosts uses it: an occurrence holds a request *message*
// id, and GetExchange would resolve that number against the exchange id space and return an unrelated
// row.
func (s *Server) findingEvidence(f *core.Finding) []report.Evidence {
	seen := map[string]bool{}
	var out []report.Evidence
	for _, occ := range f.Occurrences {
		// The message ids come off the occurrence, NOT off the resolved exchange, and are read
		// before the lookup. The exchange is a convenience — it supplies the human-readable method,
		// host and path — and a convenience that is missing must not take the evidence with it: the
		// previous shape skipped the whole entry when ExchangeByRequest failed, so a capture whose
		// exchange had been evicted produced a report that said the finding had been seen nowhere.
		e := report.Evidence{}
		// Message ids, not exchange ids, and dereferenced only when present: Occurrence.Request is
		// a *MsgId precisely because a bare zero would name the first message the project ever
		// captured, and a finding attributed to that would point somewhere real and wrong.
		if occ.Request != nil {
			e.RequestMsgID, e.HasRequest = uint64(*occ.Request), true
		}
		if occ.Response != nil {
			e.ResponseMsgID, e.HasResponse = uint64(*occ.Response), true
		}

		ex, err := s.store.ExchangeByRequest(core.MsgOrZero(occ.Request))
		if err != nil {
			// Keep the entry with its ids and no location. The bytes are still behind them, which is
			// the part that makes this evidence rather than a claim, and the report's
			// messages_omitted covers the unreadable case on the other side.
			out = append(out, e)
			continue
		}
		key := ex.Method + " " + ex.Host + ex.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		e.Host = ex.Host
		e.Path = ex.Path
		e.Method = ex.Method
		e.Scheme, e.Port, e.IP = "http", int(ex.Port), ex.ServerIP
		if ex.TLS {
			e.Scheme = "https"
		}
		if ex.Status != nil {
			e.Status = int(*ex.Status)
		}
		out = append(out, e)
	}
	return out
}

// findingHosts lists the hosts a finding was observed on.
//
// ExchangeByRequest, not GetExchange: an occurrence holds a request *message* id, and looking an
// exchange up by it returns an unrelated exchange rather than an error. That put the wrong hostname
// on findings in every exported report — the artefact that leaves the tool and gets acted on.
func (s *Server) findingHosts(f *core.Finding) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, occ := range f.Occurrences {
		ex, err := s.store.ExchangeByRequest(core.MsgOrZero(occ.Request))
		if err != nil {
			continue
		}
		if !seen[ex.Host] {
			seen[ex.Host] = true
			hosts = append(hosts, ex.Host)
		}
	}
	return hosts
}

func (s *Server) reportJSON(w http.ResponseWriter, filter reportFilter) {
	doc, err := report.JSON(s.reportRows(filter))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="burpsy-report.json"`)
	w.Write(doc)
}

func (s *Server) reportSARIF(w http.ResponseWriter, filter reportFilter) {
	doc, err := report.SARIF(s.reportRows(filter))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="burpsy-report.sarif"`)
	w.Write(doc)
}

// reportHTML renders the report under the settings: the bulk export stays
// message-free unless the operator asked for them ("Do not include" is Burp's
// default for a reason — a scan-wide report that inlined every request body
// would be unusable as a document), and every other choice is the wizard's:
// title, organisation, TOC depth, issue-detail sections, message mode and
// length.
func (s *Server) reportHTML(w http.ResponseWriter, filter reportFilter, st report.Settings) {
	rows := s.reportRows(filter)
	if st.MessageMode == "relevant" || st.MessageMode == "full" {
		s.attachEvidenceMessages(rows, st.MessageMode, st.MaxMessageLen)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="burpsy-report.html"`)
	w.Write(report.HTMLWithSettings(rows, st))
}

// reportXML is the Burp-XML issue export (burpsy-react-ui-m7dk): the document
// tooling that ingests Burp's XML expects, carried by the shared report
// package so the CLI could emit the same bytes.
//
// The XML export opts into full messages on its own, where the bulk HTML
// export carries none by default. That is not a special case bolted on here —
// it is what the format is: Burp's XML carries "Base64-encode HTTP requests
// and responses" as its headline option and its requestresponse elements exist
// to hold them, so an XML export with no messages would be the one Burp-shaped
// file that cannot do the job it is opened for. The settings (a9qy) can still
// say none or bound the length once they arrive.
func (s *Server) reportXML(w http.ResponseWriter, filter reportFilter, st report.Settings) {
	// The XML export opts into full messages when the operator said nothing:
	// its requestresponse elements are the reason the format exists, and an
	// XML export with no messages is the one Burp-shaped file that cannot do
	// the job it is opened for. An explicit none or relevant is honoured.
	if st.MessageMode == "" {
		st.MessageMode = "full"
	}
	rows := s.reportRows(filter)
	if st.MessageMode == "relevant" || st.MessageMode == "full" {
		s.attachEvidenceMessages(rows, st.MessageMode, st.MaxMessageLen)
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Disposition", `attachment; filename="burpsy-report.xml"`)
	w.Write(report.BurpXML(rows, st, time.Now()))
}

// attachEvidenceMessages loads each evidence entry's request and response
// bytes onto the rows that asked for them, under the mode and byte bound given.
//
// mode is Burp's report-settings choice (report-settings.html "HTTP
// messages"): "none" attaches nothing, "relevant" attaches the header block
// (see headerBlock for why that and not Burp's highlight window), "full"
// attaches the whole message. maxLen bounds whatever is attached, with the
// truncation flag the renderers print their marker from; 0 means unbounded.
//
// A message the store cannot read is skipped here rather than attached empty:
// the XML export comments those entries and the settings report counts them
// the way the single-finding export counts its omissions — never silently.
func (s *Server) attachEvidenceMessages(rows []report.Row, mode string, maxLen int) {
	if mode == "" {
		mode = "none"
	}
	for i := range rows {
		for j := range rows[i].Evidence {
			ev := &rows[i].Evidence[j]
			if ev.HasRequest {
				if raw, truncated := s.evidenceMessageBytes(ev.RequestMsgID, mode, maxLen); raw != nil {
					rows[i].Messages = append(rows[i].Messages, report.AttachedMessage{
						Evidence: j, IsRequest: true, Raw: raw,
						Truncated: truncated, HeadersOnly: mode == "relevant",
					})
				}
			}
			if ev.HasResponse {
				if raw, truncated := s.evidenceMessageBytes(ev.ResponseMsgID, mode, maxLen); raw != nil {
					rows[i].Messages = append(rows[i].Messages, report.AttachedMessage{
						Evidence: j, IsRequest: false, Raw: raw,
						Truncated: truncated, HeadersOnly: mode == "relevant",
					})
				}
			}
		}
	}
}

// evidenceMessageBytes reads one stored message and applies the mode and the
// bound to it. nil means "nothing to attach" — unreadable in the capture, or
// empty, which the store cannot distinguish from a message that never got
// bytes; either way an empty attachment would print as "the request had no
// content" and that is a claim about the target this has no right to make.
func (s *Server) evidenceMessageBytes(id uint64, mode string, maxLen int) (raw []byte, truncated bool) {
	msg, err := s.message(id)
	if err != nil {
		return nil, false
	}
	raw = msg.Raw()
	if len(raw) == 0 {
		return nil, false
	}
	if mode == "relevant" {
		raw = headerBlock(raw)
	}
	if maxLen > 0 && len(raw) > maxLen {
		raw = raw[:maxLen]
		truncated = true
	}
	return raw, truncated
}

// headerBlock is the "relevant extract" for burpsy's messages: the header
// block, through the blank line that ends it.
//
// Burp's relevant extract is "the parts of the message that are highlighted in
// the in-tool results … and some of the surrounding message, to give context"
// — locations burpsy cannot recover, because no producer populates
// core.Occurrence.Span. The header block is the honest substitute: it is where
// the parameters, headers and cookies a finding names actually are, it is
// deterministic, and the renderers label it as an extract so it cannot read as
// the whole message. Recorded in gaps.md as a deliberate divergence.
func headerBlock(raw []byte) []byte {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[:i+4]
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return raw[:i+2]
	}
	// No body separator at all: the message is headers-only or malformed, and
	// either way the whole of it IS the header block.
	return raw
}
