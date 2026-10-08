package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Repeater's "Save entire history" (burpsy-react-ui-pznm).
//
// Burp: "Save entire history — Saves the change history for the selected request to a file"
// (desktop/tools/context-menu.html; the menu item is burp.Zgkb's "Save entire history"). Burp's
// on-disk format for this file is not in the evidence we hold — the decompiled writer behind the
// menu id could not be traced to a serializer — so this is a burpsy format, declared in its own
// `format` field, and the divergence is recorded in gaps.md rather than dressed up as Burp's.
//
// # Why the request is ids, never text
//
// A tab's history is component-local state in the browser (pages/repeater.tsx), and every HTTP
// entry in it carries the message ids its send stored. The bytes are exported from the store by
// id, base64-encoded, so a binary (protobuf/gRPC) body round-trips byte-identical — the browser's
// copy of a response is a JS string that already lost any non-UTF-8 byte, and exporting that would
// write a file that differs from what the target sent.
//
// # What is never silently dropped
//
// An entry the store cannot serve — a WebSocket send (no HTTP message ids), a group item that got
// no response, an id the store does not hold — is listed under `skipped` with its position and the
// reason, and an entry whose response half is missing is exported with `response_missing` naming
// why. The counts are in the summary, so "3 of 5 exported" can never read as "all 5".

// maxHistoryExportEntries bounds one export. A tab's history is every send the operator made in
// it; ten thousand is far past any hand-driven session, and the bound keeps one request from
// asking the store to inline an unbounded number of messages.
const maxHistoryExportEntries = 10_000

// historyExportFormat names this file's shape and version.
const historyExportFormat = "burpsy-repeater-history/1"

type historyExportEntryReq struct {
	// RequestMsgID and ResponseMsgID are the ids the send returned. Pointers because message 0 is a
	// real message and absence means "this entry has none" — a WebSocket entry sends neither.
	RequestMsgID  *uint64          `json:"request_msg_id"`
	ResponseMsgID *uint64          `json:"response_msg_id"`
	ExchangeID    *core.ExchangeID `json:"exchange_id,omitempty"`
	// Kind is "http" or "ws"; a ws entry is skipped with its reason rather than refused, because a
	// tab's history may mix both and the operator asked for the whole of it.
	Kind string `json:"kind,omitempty"`
	// SentAt is the browser's clock at send time, carried through as the entry's label.
	SentAt string `json:"sent_at,omitempty"`
}

type historyExportReq struct {
	Tab     string                  `json:"tab"`
	Target  string                  `json:"target"`
	Note    string                  `json:"note,omitempty"`
	Entries []historyExportEntryReq `json:"entries"`
}

type historyExportEntry struct {
	// Index is the entry's position in the tab's history, from 0, so a skipped entry's gap is visible.
	Index           int              `json:"index"`
	ExchangeID      *core.ExchangeID `json:"exchange_id,omitempty"`
	SentAt          string           `json:"sent_at,omitempty"`
	RequestBase64   string           `json:"request_base64"`
	RequestLength   int              `json:"request_length"`
	ResponseBase64  *string          `json:"response_base64"`
	ResponseLength  int              `json:"response_length"`
	Status          int              `json:"status,omitempty"`
	ResponseMissing string           `json:"response_missing,omitempty"`
}

type historyExportSkip struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

type historyExportFile struct {
	Format     string               `json:"format"`
	ExportedAt string               `json:"exported_at"`
	Tab        string               `json:"tab"`
	Target     string               `json:"target"`
	Note       string               `json:"note,omitempty"`
	Requested  int                  `json:"requested"`
	Exported   int                  `json:"exported"`
	Entries    []historyExportEntry `json:"entries"`
	Skipped    []historyExportSkip  `json:"skipped"`
	// MissingResponses counts exported entries whose response half could not be included.
	MissingResponses int `json:"missing_responses"`
}

// historyFilenameUnsafe is every character a filename built from a tab name must not carry.
var historyFilenameUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func (s *Server) handleRepeaterHistoryExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req historyExportReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.Entries) > maxHistoryExportEntries {
		http.Error(w, fmt.Sprintf("refused: %d history entries; one export takes at most %d", len(req.Entries), maxHistoryExportEntries),
			http.StatusBadRequest)
		return
	}
	file := historyExportFile{
		Format:     historyExportFormat,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		Tab:        req.Tab,
		Target:     req.Target,
		Note:       req.Note,
		Requested:  len(req.Entries),
		// Non-nil so an empty history marshals as [] — "nothing to export" — and not as null, which a
		// reader of the file cannot tell from "the field was never written".
		Entries: []historyExportEntry{},
		Skipped: []historyExportSkip{},
	}
	for index, entry := range req.Entries {
		if entry.Kind == "ws" {
			file.Skipped = append(file.Skipped, historyExportSkip{Index: index,
				Reason: "a WebSocket send: its frames are not stored as HTTP messages, so there are no bytes to export by id"})
			continue
		}
		if entry.RequestMsgID == nil {
			file.Skipped = append(file.Skipped, historyExportSkip{Index: index,
				Reason: "no stored request: the send produced no message the store can serve"})
			continue
		}
		reqMsg, err := s.store.Get(core.MsgId(*entry.RequestMsgID))
		if err != nil {
			file.Skipped = append(file.Skipped, historyExportSkip{Index: index,
				Reason: fmt.Sprintf("request message %d is not in the store", *entry.RequestMsgID)})
			continue
		}
		reqRaw := reqMsg.Raw()
		out := historyExportEntry{
			Index:         index,
			ExchangeID:    entry.ExchangeID,
			SentAt:        entry.SentAt,
			RequestBase64: base64.StdEncoding.EncodeToString(reqRaw),
			RequestLength: len(reqRaw),
		}
		switch {
		case entry.ResponseMsgID == nil:
			out.ResponseMissing = "no response was recorded for this send"
		default:
			respMsg, rerr := s.store.Get(core.MsgId(*entry.ResponseMsgID))
			if rerr != nil {
				out.ResponseMissing = fmt.Sprintf("response message %d is not in the store", *entry.ResponseMsgID)
				break
			}
			respRaw := respMsg.Raw()
			encoded := base64.StdEncoding.EncodeToString(respRaw)
			out.ResponseBase64 = &encoded
			out.ResponseLength = len(respRaw)
			out.Status = intOrZero(parseResponseStatus(respRaw))
		}
		if out.ResponseMissing != "" {
			file.MissingResponses++
		}
		file.Entries = append(file.Entries, out)
	}
	file.Exported = len(file.Entries)

	name := historyFilenameUnsafe.ReplaceAllString(strings.TrimSpace(req.Tab), "-")
	name = strings.Trim(name, "-.")
	if name == "" {
		name = "tab"
	}
	if len(name) > 60 {
		name = name[:60]
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="repeater-history-`+name+`.json"`)
	json.NewEncoder(w).Encode(file)
}
