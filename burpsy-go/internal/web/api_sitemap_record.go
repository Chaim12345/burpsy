package web

// POST /api/sitemap/record: record a captured exchange into the site map by id (burpsy-react-ui-4bfp),
// Burp's add_to_sitemap ("Manually records a captured request/response into the sitemap").
//
// In burpsy the map follows the traffic store (sitemap.Follow), so every stored exchange is already on
// it — the proxy's, the crawler's, Repeater's and Intruder's alike — UNLESS a "Delete host / branch /
// item" suppression hides it. So recording by id has two honest outcomes, and the reply says which:
//
//   - already_on_map: nothing to do, and nothing was done;
//   - was_suppressed: a suppression hid it, and the exchange is now pinned onto the map anyway — the
//     operator's explicit "this one" outranks the earlier, broader removal, survives rebuilds, and is
//     dropped again only by a later suppression that covers it.
//
// riskLocal, beside /api/issues/record rather than under /api/sitemap's riskDestructive: adding by id
// writes burpsy's own view and destroys nothing.

import (
	"net/http"

	"github.com/burpsy-go/burpsy/internal/core"
)

// sitemapRecordReq is POST /api/sitemap/record's body.
type sitemapRecordReq struct {
	ExchangeID *core.ExchangeID `json:"exchange_id" required:"true" desc:"the captured exchange (proxy history, logger, or any tool's) to record into the site map"`
}

type sitemapRecordView struct {
	ExchangeID    core.ExchangeID `json:"exchange_id"`
	Recorded      bool            `json:"recorded"`
	AlreadyOnMap  bool            `json:"already_on_map"`
	WasSuppressed bool            `json:"was_suppressed"`
	NodeKey       string          `json:"node_key"`
	Host          string          `json:"host"`
	Port          uint16          `json:"port"`
	TLS           bool            `json:"tls"`
	Path          string          `json:"path"`
	Note          string          `json:"note"`
}

func (s *Server) handleSitemapRecord(w http.ResponseWriter, r *http.Request) {
	var req sitemapRecordReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "body must be JSON {\"exchange_id\": N}", http.StatusBadRequest)
		return
	}
	if req.ExchangeID == nil {
		http.Error(w, "exchange_id is required (0 is a valid id)", http.StatusBadRequest)
		return
	}
	ex, err := s.store.GetExchange(*req.ExchangeID)
	if err != nil {
		http.Error(w, "No captured exchange with that id", http.StatusNotFound)
		return
	}
	res := s.sitemap.Record(ex)
	view := sitemapRecordView{
		ExchangeID:    ex.ID,
		Recorded:      !res.AlreadyOnMap,
		AlreadyOnMap:  res.AlreadyOnMap,
		WasSuppressed: res.WasSuppressed,
		NodeKey:       nodeKey(ex.Host, ex.Port, ex.TLS, ex.Path),
		Host:          ex.Host,
		Port:          ex.Port,
		TLS:           ex.TLS,
		Path:          ex.Path,
	}
	switch {
	case res.AlreadyOnMap:
		view.Note = "the exchange was already on the site map: the map follows every captured exchange, so nothing changed"
	case res.WasSuppressed:
		view.Note = "a Delete host/branch/item suppression hid this exchange; it is now pinned onto the map, and a later suppression covering it removes it again"
	default:
		view.Note = "recorded into the site map"
	}
	if !res.AlreadyOnMap {
		s.live.notify(changeHistory)
	}
	writeJSON(w, http.StatusOK, view)
}
