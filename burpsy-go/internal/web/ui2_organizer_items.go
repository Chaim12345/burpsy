package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/burpsy-go/burpsy/internal/organizer"
)

// ui2ItemChange is one reviewed organizer item operation: one saved item, one op, one
// destination. The held payload binds the full stored item snapshot AND the destination
// collection (id + name), so a changed source or a renamed/deleted destination is
// refused at install instead of applying something the operator did not review.
type ui2ItemChange struct {
	Op     string               `json:"op"`
	Before organizer.Item       `json:"before"`
	Dest   organizer.Collection `json:"dest"`
}

func ui2ItemOpFields(r *http.Request, keys ...string) error {
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("invalid form")
	}
	if len(r.URL.Query()) != 0 {
		return fmt.Errorf("query fields are not permitted")
	}
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
		if len(r.PostForm[k]) != 1 {
			return fmt.Errorf("%s must be a single permitted item field", k)
		}
	}
	for k, v := range r.PostForm {
		if !allowed[k] || len(v) != 1 {
			return fmt.Errorf("%s is not a single permitted item field", k)
		}
	}
	return nil
}

func (s *Server) handleUI2OrganizerItems(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.PathValue("action") == "run" {
		s.ui2ItemOpRun(w, r)
		return
	}
	if r.PathValue("action") != "confirm" {
		s.ui2OrganizerFail(w, r, "unknown item action")
		return
	}
	if err := ui2ItemOpFields(r, "op", "item_id", "form_base", "collection_id"); err != nil {
		s.ui2OrganizerFail(w, r, err.Error())
		return
	}
	change := ui2ItemChange{Op: r.PostFormValue("op")}
	if change.Op != "move" && change.Op != "copy" && change.Op != "delete" {
		s.ui2OrganizerFail(w, r, "unknown item operation")
		return
	}
	id, err := strconv.Atoi(r.PostFormValue("item_id"))
	if err != nil || id <= 0 {
		s.ui2OrganizerFail(w, r, "choose a saved item")
		return
	}
	found := false
	for _, it := range s.organizer.List() {
		if it.ID == id {
			change.Before = it
			found = true
			break
		}
	}
	if !found {
		s.ui2OrganizerFail(w, r, fmt.Sprintf("item %d no longer exists", id))
		return
	}
	if r.PostFormValue("form_base") != ui2WorkflowDigest(change.Before) {
		s.ui2OrganizerFail(w, r, fmt.Sprintf("item %d changed since this form opened - reopen it", id))
		return
	}
	dest := r.PostFormValue("collection_id")
	if change.Op == "delete" {
		if dest != "" && dest != "0" {
			s.ui2OrganizerFail(w, r, "delete takes no destination")
			return
		}
	} else {
		destID, err := strconv.Atoi(dest)
		if err != nil || destID < 0 {
			s.ui2OrganizerFail(w, r, "choose a destination collection")
			return
		}
		if destID != 0 {
			known := false
			for _, c := range s.organizer.Collections() {
				if c.ID == destID {
					change.Dest = c
					known = true
					break
				}
			}
			if !known {
				s.ui2OrganizerFail(w, r, fmt.Sprintf("collection %d no longer exists", destID))
				return
			}
		}
		if change.Op == "move" && destID == change.Before.Collection {
			s.ui2OrganizerFail(w, r, fmt.Sprintf("item %d is already in that collection - nothing to review", id))
			return
		}
	}
	now := time.Now()
	count := 0
	s.ui2ItemReviews.Range(func(k, v any) bool {
		e := v.(ui2CollectionReview)
		if now.After(e.expires) {
			s.ui2ItemReviews.Delete(k)
		} else {
			count++
		}
		return true
	})
	if count >= 8 {
		s.ui2OrganizerFail(w, r, "too many item reviews are open; wait for expiry")
		return
	}
	body, _ := json.Marshal(change)
	binding := newCallBinding(http.MethodPost, "/ui2/organizer/items/install", "", body)
	token, err := s.confirms.issue("ui2-item", binding)
	if err != nil {
		s.ui2OrganizerFail(w, r, "could not create review")
		return
	}
	rid, err := randomHex(16)
	if err != nil {
		s.ui2OrganizerFail(w, r, "could not create review id")
		return
	}
	s.ui2ItemReviews.Store(rid, ui2CollectionReview{body: body, token: token, expires: now.Add(ConfirmTTL)})
	destName := "Inbox"
	if change.Dest.ID != 0 {
		destName = change.Dest.Name
	}
	ui2Fragment(w, r, "burpsy /ui2/ - Organizer", "organizer", ui2Exec("organizer_item_confirm.html", map[string]any{"change": change, "dest_name": destName, "review_id": rid, "token": token}))
}

func (s *Server) ui2ItemOpRun(w http.ResponseWriter, r *http.Request) {
	if err := ui2ItemOpFields(r, "review_id", "token"); err != nil {
		s.ui2OrganizerFail(w, r, err.Error())
		return
	}
	v, ok := s.ui2ItemReviews.LoadAndDelete(r.PostFormValue("review_id"))
	if !ok {
		s.ui2OrganizerRender(w, r, "review unknown or already used - review again")
		return
	}
	e := v.(ui2CollectionReview)
	binding := newCallBinding(http.MethodPost, "/ui2/organizer/items/install", "", e.body)
	if time.Now().After(e.expires) || !s.confirms.spend(r.PostFormValue("token"), "ui2-item", binding) {
		s.ui2OrganizerRender(w, r, "review expired or confirmation does not match - review again")
		return
	}
	var change ui2ItemChange
	if json.Unmarshal(e.body, &change) != nil {
		s.ui2OrganizerRender(w, r, "held change is unreadable")
		return
	}
	destName := "Inbox"
	if change.Dest.ID != 0 {
		destName = change.Dest.Name
	}
	switch change.Op {
	case "move":
		if err := s.organizer.MoveItemIfUnchanged(change.Before, change.Dest); err != nil {
			s.ui2OrganizerRender(w, r, err.Error())
			return
		}
		s.organizerChanged()
		s.ui2OrganizerRenderItem(w, r, fmt.Sprintf("item #%d moved to %s; title, note, highlight and workflow status unchanged; no request sent", change.Before.ID, destName), change.Before.ID)
	case "copy":
		dup, err := s.organizer.CopyItemIfUnchanged(change.Before, change.Dest)
		if err != nil {
			s.ui2OrganizerRender(w, r, err.Error())
			return
		}
		s.organizerChanged()
		s.ui2OrganizerRenderItem(w, r, fmt.Sprintf("item #%d copied to %s as item #%d; the source item is unchanged; no request sent", change.Before.ID, destName, dup.ID), change.Before.ID)
	case "delete":
		if err := s.organizer.DeleteItemIfUnchanged(change.Before); err != nil {
			s.ui2OrganizerRender(w, r, err.Error())
			return
		}
		s.organizerChanged()
		s.ui2OrganizerRender(w, r, fmt.Sprintf("saved item #%d deleted; its exchange and history are kept; collections unchanged; no request sent", change.Before.ID))
	default:
		s.ui2OrganizerRender(w, r, "unknown held operation")
	}
}
