package web

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// ---- Custom history/Intruder extractor columns (burpsy-react-ui-28n8) ---------------------------
//
// burpsy had both halves of "a custom extractor as a table column" and they never met: the extraction
// primitive (a regex with a capture group, a JSON path, or the whole body — sessionExtractDto, reused
// verbatim here) and a history table with operator-defined columns. An operator reading one field out
// of every response — a CSRF token, a user id, a rate-limit header — opened each response to look.
//
// A named extractor is defined once and rendered as a derived column: each row runs it against its
// stored RESPONSE and shows the captured value. This is Caido Automate's custom-extractor feature.
//
// # Why the values are a separate call, not a field on the history row
//
// /api/history serves an index row per exchange and never a payload — listing 100,000 captures touches
// no response body, which is the property that keeps the cheapest endpoint cheap (see
// core.Exchange.Mime). Running an extractor needs the response bytes, so it would reopen one response
// per row for every row in the list. Instead the console asks for values only for the rows it is
// showing: POST /api/history/extract with those ids reopens at most a page of responses, and a row
// scrolled off screen costs nothing. The saved definitions are the column set; the run is per visible
// page.

// historyExtractorsKey is the settings row the saved definitions live in. Project-level: a CSRF-token
// column means something for this engagement's responses and travels with its database.
const historyExtractorsKey = "history.extractors"

// maxHistoryExtractors bounds the column set — each is a column rendered across every visible row, and
// a hundred of them is a table nobody reads and a hundred extractions per row.
const maxHistoryExtractors = 32

// maxHistoryExtractRows bounds one /extract call, so a request for values cannot reopen the whole
// capture at once.
const maxHistoryExtractRows = 1000

// compileHistoryExtractor turns a definition into a runnable extraction, reusing the session
// extractor's own decoding so one spelling of "regex group / json path / header" serves both.
func compileHistoryExtractor(d sessionExtractDto) (*session.Extraction, error) {
	from, header, err := d.extractFrom()
	if err != nil {
		return nil, err
	}
	how, err := d.extractHow()
	if err != nil {
		return nil, err
	}
	var ex *session.Extraction
	if how.JSONPath != "" {
		ex, err = session.NewJSONPathExtraction(d.Name, from, how.JSONPath)
	} else {
		ex, err = session.NewExtraction(d.Name, from, how.Pattern, how.Group)
	}
	if err != nil {
		return nil, err
	}
	ex.Header = header
	return ex, nil
}

// historyExtractors returns the saved definitions and their compiled form.
func (s *Server) historyExtractors() ([]sessionExtractDto, []*session.Extraction) {
	s.histExtractMu.Lock()
	defer s.histExtractMu.Unlock()
	return append([]sessionExtractDto(nil), s.histExtractDefs...), append([]*session.Extraction(nil), s.histExtractRun...)
}

// restoreHistoryExtractors loads the project's saved extractors — from WithPersist, so they follow a
// project switch. A definition that no longer compiles (an engine that dropped a feature) is dropped
// with a log line rather than failing the restore.
func (s *Server) restoreHistoryExtractors(p *persist.Store) {
	raw, err := p.LoadHistoryExtractors()
	if err != nil {
		s.logger.Warn("failed to restore history extractors", zap.Error(err))
	}
	var defs []sessionExtractDto
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &defs); err != nil {
			s.logger.Warn("stored history extractors do not parse; starting with none", zap.Error(err))
			defs = nil
		}
	}
	kept := defs[:0]
	var runs []*session.Extraction
	for _, d := range defs {
		ex, err := compileHistoryExtractor(d)
		if err != nil {
			s.logger.Warn("dropping a stored history extractor that no longer compiles",
				zap.String("name", d.Name), zap.Error(err))
			continue
		}
		kept = append(kept, d)
		runs = append(runs, ex)
	}
	s.histExtractMu.Lock()
	s.histExtractDefs, s.histExtractRun = kept, runs
	s.histExtractMu.Unlock()
}

// historyExtractorsReq is the request body handleHistoryExtractors decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type historyExtractorsReq struct {
	Extractors []sessionExtractDto `json:"extractors"`
}

// handleHistoryExtractors serves GET/PUT /api/history/extractors — the saved column definitions.
// riskLocal: it reads and writes burpsy's own view configuration and sends nothing.
func (s *Server) handleHistoryExtractors(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		defs, _ := s.historyExtractors()
		if defs == nil {
			defs = []sessionExtractDto{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"extractors": defs})
	case http.MethodPut:
		var body historyExtractorsReq
		if err := requestJSON(w, r, io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, `the body must be {"extractors":[...]}`, http.StatusBadRequest)
			return
		}
		if len(body.Extractors) > maxHistoryExtractors {
			http.Error(w, "too many extractors: a column set this large is a table nobody reads", http.StatusBadRequest)
			return
		}
		runs := make([]*session.Extraction, 0, len(body.Extractors))
		seen := map[string]bool{}
		for _, d := range body.Extractors {
			if d.Name == "" {
				http.Error(w, "an extractor needs a name to be a column", http.StatusBadRequest)
				return
			}
			if seen[d.Name] {
				http.Error(w, "two extractors are named "+d.Name+"; a column name must be unique", http.StatusBadRequest)
				return
			}
			seen[d.Name] = true
			ex, err := compileHistoryExtractor(d)
			if err != nil {
				// Refused whole: a column that cannot run is worse than no column, because it reads as
				// "every row is empty" rather than "this extractor is wrong".
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			runs = append(runs, ex)
		}
		s.histExtractMu.Lock()
		s.histExtractDefs, s.histExtractRun = append([]sessionExtractDto(nil), body.Extractors...), runs
		s.histExtractMu.Unlock()
		if s.persist != nil {
			if blob, err := json.Marshal(body.Extractors); err == nil {
				if err := s.persist.SaveHistoryExtractors(blob); err != nil {
					s.logger.Warn("history extractors persist failed", zap.Error(err))
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"extractors": body.Extractors})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// historyExtractReq is the request body handleHistoryExtract decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type historyExtractReq struct {
	IDs      []core.ExchangeID `json:"ids"`
	Messages []core.MsgId      `json:"messages"`
}

// handleHistoryExtract serves POST /api/history/extract — the saved extractors' values for the named
// rows. riskLocal: it reads stored responses and sends nothing.
//
// Rows are named one of two ways, because the two tables that render these columns hold different
// ids. History rows are exchanges: {"ids":[exchange ids]} answers {"values":{id:{...}}}. An Intruder
// attempt or bucket is not an exchange — it carries the MESSAGE id of its stored response — so
// {"messages":[response message ids]} answers {"messages":{id:{...}}}. The two are separate fields
// rather than one id list with a flag because both are counters from zero: a message id read as an
// exchange id resolves an unrelated exchange and would show its value as the attempt's.
//
// Each row maps extractor name -> value or null. A null is an honest "this response did not yield that
// value" (no match, no such header, a walk that found nothing), distinct from "" which is a value the
// extractor really captured. A row with no stored response is absent from the answer.
func (s *Server) handleHistoryExtract(w http.ResponseWriter, r *http.Request) {
	var body historyExtractReq
	if err := requestJSON(w, r, io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, `the body must be {"ids":[...]} or {"messages":[...]}`, http.StatusBadRequest)
		return
	}
	if len(body.IDs)+len(body.Messages) > maxHistoryExtractRows {
		http.Error(w, "too many rows in one request; ask for the page you are showing", http.StatusBadRequest)
		return
	}
	_, runs := s.historyExtractors()
	values := make(map[string]map[string]*string, len(body.IDs))
	for _, id := range body.IDs {
		ex, err := s.store.GetExchange(id)
		if err != nil || ex.Response == nil {
			continue
		}
		if row, ok := s.extractFromMessage(*ex.Response, runs); ok {
			values[strconv.FormatUint(uint64(id), 10)] = row
		}
	}
	messages := make(map[string]map[string]*string, len(body.Messages))
	for _, id := range body.Messages {
		if row, ok := s.extractFromMessage(id, runs); ok {
			messages[strconv.FormatUint(uint64(id), 10)] = row
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"values": values, "messages": messages})
}

// extractFromMessage runs every extractor over one stored response. ok is false when the message is
// not in the store.
func (s *Server) extractFromMessage(id core.MsgId, runs []*session.Extraction) (map[string]*string, bool) {
	msg, err := s.store.Get(id)
	if err != nil {
		return nil, false
	}
	head, body := splitHeadBody(msg.Raw())
	hdrs := headerMapOf(head)
	row := make(map[string]*string, len(runs))
	for _, extractor := range runs {
		res := extractor.RunResult(hdrs, body)
		if res.Outcome == session.ExtractResolved {
			v := res.Value
			row[extractor.Name] = &v
		} else {
			row[extractor.Name] = nil
		}
	}
	return row, true
}

// headerMapOf parses a response head's headers into the name->value map RunResult takes. A repeated
// header keeps its last value, which is what a single-value map can hold.
func headerMapOf(head []byte) map[string]string {
	out := map[string]string{}
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	for _, line := range lines[min(1, len(lines)):] { // skip the status line
		name, value, ok := strings.Cut(line, ":")
		if ok {
			out[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	return out
}
