package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ui2AddChange is one reviewed "save exchange to Organizer": the exchange id, what the
// operator saw of it, and the note and highlight the new item inherits. Install refuses
// when the exchange is gone or its inherited note/highlight changed since review.
type ui2AddChange struct {
	Exchange  int    `json:"exchange"`
	Method    string `json:"method"`
	Host      string `json:"host"`
	Path      string `json:"path"`
	Note      string `json:"note"`
	Highlight string `json:"highlight"`
}

func (s *Server) ui2AddFail(w http.ResponseWriter, r *http.Request, msg string) {
	ui2Fragment(w, r, "burpsy /ui2/ - Organizer", "organizer", ui2Exec("organizer_add_confirm.html", map[string]any{"error": msg}))
}

// handleUI2OrganizerAdd serves POST /ui2/organizer/add/{confirm|run}.
func (s *Server) handleUI2OrganizerAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch r.PathValue("action") {
	case "run":
		s.ui2AddRun(w, r)
		return
	case "confirm":
	default:
		s.ui2AddFail(w, r, "unknown add action")
		return
	}
	if err := ui2ItemOpFields(r, "exchange"); err != nil {
		s.ui2AddFail(w, r, err.Error())
		return
	}
	// Exchange ids count from zero; a blank box is not exchange 0.
	id, err := strconv.Atoi(r.PostFormValue("exchange"))
	if err != nil || id < 0 {
		s.ui2AddFail(w, r, "enter an exchange id - a whole number, counting from 0")
		return
	}
	ex, err := s.store.GetExchange(core.ExchangeID(id))
	if err != nil || ex == nil {
		s.ui2AddFail(w, r, fmt.Sprintf("no exchange %d has been captured", id))
		return
	}
	note, highlight := organizerSeedFrom(ex)
	change := ui2AddChange{Exchange: id, Method: ex.Method, Host: ex.Host, Path: ex.Path, Note: note, Highlight: highlight}
	now := time.Now()
	count := 0
	s.ui2OrgAddReviews.Range(func(k, v any) bool {
		if now.After(v.(ui2CollectionReview).expires) {
			s.ui2OrgAddReviews.Delete(k)
		} else {
			count++
		}
		return true
	})
	if count >= 8 {
		s.ui2AddFail(w, r, "too many add reviews are open; wait for expiry")
		return
	}
	body, _ := json.Marshal(change)
	token, err := s.confirms.issue("ui2-org-add", newCallBinding(http.MethodPost, "/ui2/organizer/add/install", "", body))
	if err != nil {
		s.ui2AddFail(w, r, "could not create review")
		return
	}
	rid, err := randomHex(16)
	if err != nil {
		s.ui2AddFail(w, r, "could not create review id")
		return
	}
	s.ui2OrgAddReviews.Store(rid, ui2CollectionReview{body: body, token: token, expires: now.Add(ConfirmTTL)})
	ui2Fragment(w, r, "burpsy /ui2/ - Organizer", "organizer", ui2Exec("organizer_add_confirm.html", map[string]any{"change": change, "review_id": rid, "token": token}))
}

func (s *Server) ui2AddRun(w http.ResponseWriter, r *http.Request) {
	if err := ui2ItemOpFields(r, "review_id", "token"); err != nil {
		s.ui2AddFail(w, r, err.Error())
		return
	}
	v, ok := s.ui2OrgAddReviews.LoadAndDelete(r.PostFormValue("review_id"))
	if !ok {
		s.ui2OrganizerRender(w, r, "review unknown or already used - review again")
		return
	}
	e := v.(ui2CollectionReview)
	if time.Now().After(e.expires) || !s.confirms.spend(r.PostFormValue("token"), "ui2-org-add", newCallBinding(http.MethodPost, "/ui2/organizer/add/install", "", e.body)) {
		s.ui2OrganizerRender(w, r, "review expired or confirmation does not match - review again")
		return
	}
	var change ui2AddChange
	if json.Unmarshal(e.body, &change) != nil {
		s.ui2OrganizerRender(w, r, "held change is unreadable")
		return
	}
	ex, err := s.store.GetExchange(core.ExchangeID(change.Exchange))
	if err != nil || ex == nil {
		s.ui2OrganizerRender(w, r, fmt.Sprintf("exchange %d is no longer captured - nothing saved", change.Exchange))
		return
	}
	if note, highlight := organizerSeedFrom(ex); note != change.Note || highlight != change.Highlight {
		s.ui2OrganizerRender(w, r, fmt.Sprintf("exchange %d's note or highlight changed since review - nothing saved", change.Exchange))
		return
	}
	item := s.organizerAddSeeded(change.Exchange, change.Note, change.Highlight)
	s.organizerChanged()
	s.ui2OrganizerRenderItem(w, r, fmt.Sprintf("exchange #%d saved to the Inbox as item #%d; no request sent", change.Exchange, item.ID), item.ID)
}
