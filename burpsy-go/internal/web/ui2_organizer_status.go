package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/burpsy-go/burpsy/internal/organizer"
	"net/http"
	"strconv"
	"time"
)

type ui2WorkflowChange struct {
	Before organizer.Item   `json:"before"`
	Status organizer.Status `json:"workflow_status"`
}

func ui2WorkflowDigest(it organizer.Item) string {
	b, _ := json.Marshal(it)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func ui2WorkflowFields(r *http.Request, keys ...string) error {
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
			return fmt.Errorf("%s must be a single permitted workflow field", k)
		}
	}
	for k, v := range r.PostForm {
		if !allowed[k] || len(v) != 1 {
			return fmt.Errorf("%s is not a single permitted workflow field", k)
		}
	}
	return nil
}
func (s *Server) ui2WorkflowFail(w http.ResponseWriter, r *http.Request, msg string) {
	ui2Fragment(w, r, "burpsy /ui2/ - Organizer", "organizer", ui2Exec("organizer_status_confirm.html", map[string]any{"error": msg}))
}
func (s *Server) handleUI2OrganizerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.PathValue("action") == "run" {
		s.ui2WorkflowRun(w, r)
		return
	}
	if r.PathValue("action") != "confirm" {
		s.ui2WorkflowFail(w, r, "unknown workflow action")
		return
	}
	if err := ui2WorkflowFields(r, "op", "item_id", "form_base", "status"); err != nil {
		s.ui2WorkflowFail(w, r, err.Error())
		return
	}
	if r.PostFormValue("op") != "status" {
		s.ui2WorkflowFail(w, r, "unknown workflow operation")
		return
	}
	status := organizer.Status(r.PostFormValue("status"))
	if !organizer.ValidStatus(status) {
		s.ui2WorkflowFail(w, r, "workflow status must be new, in_progress, postponed, done or ignored")
		return
	}
	id, err := strconv.Atoi(r.PostFormValue("item_id"))
	if err != nil || id <= 0 {
		s.ui2WorkflowFail(w, r, "choose a saved item")
		return
	}
	var before organizer.Item
	found := false
	for _, it := range s.organizer.List() {
		if it.ID == id {
			before = it
			found = true
			break
		}
	}
	if !found {
		s.ui2WorkflowFail(w, r, fmt.Sprintf("item %d no longer exists", id))
		return
	}
	if r.PostFormValue("form_base") != ui2WorkflowDigest(before) {
		s.ui2WorkflowFail(w, r, fmt.Sprintf("item %d changed since this form opened - reopen it", id))
		return
	}
	if status == before.Status {
		s.ui2WorkflowFail(w, r, fmt.Sprintf("item %d is already %s - nothing to review", id, before.Status))
		return
	}
	now := time.Now()
	count := 0
	s.ui2WorkflowReviews.Range(func(k, v any) bool {
		e := v.(ui2CollectionReview)
		if now.After(e.expires) {
			s.ui2WorkflowReviews.Delete(k)
		} else {
			count++
		}
		return true
	})
	if count >= 8 {
		s.ui2WorkflowFail(w, r, "too many workflow reviews are open; wait for expiry")
		return
	}
	change := ui2WorkflowChange{Before: before, Status: status}
	body, _ := json.Marshal(change)
	token, err := s.confirms.issue("ui2-workflow", newCallBinding(http.MethodPost, "/ui2/organizer/status/install", "", body))
	if err != nil {
		s.ui2WorkflowFail(w, r, "could not create review")
		return
	}
	rid, err := randomHex(16)
	if err != nil {
		s.ui2WorkflowFail(w, r, "could not create review id")
		return
	}
	s.ui2WorkflowReviews.Store(rid, ui2CollectionReview{body: body, token: token, expires: now.Add(ConfirmTTL)})
	ui2Fragment(w, r, "burpsy /ui2/ - Organizer", "organizer", ui2Exec("organizer_status_confirm.html", map[string]any{"change": change, "review_id": rid, "token": token}))
}
func (s *Server) ui2WorkflowRun(w http.ResponseWriter, r *http.Request) {
	if err := ui2WorkflowFields(r, "review_id", "token"); err != nil {
		s.ui2WorkflowFail(w, r, err.Error())
		return
	}
	v, ok := s.ui2WorkflowReviews.LoadAndDelete(r.PostFormValue("review_id"))
	if !ok {
		s.ui2OrganizerRender(w, r, "review unknown or already used - review again")
		return
	}
	e := v.(ui2CollectionReview)
	binding := newCallBinding(http.MethodPost, "/ui2/organizer/status/install", "", e.body)
	if time.Now().After(e.expires) || !s.confirms.spend(r.PostFormValue("token"), "ui2-workflow", binding) {
		s.ui2OrganizerRender(w, r, "review expired or confirmation does not match - review again")
		return
	}
	var change ui2WorkflowChange
	if json.Unmarshal(e.body, &change) != nil {
		s.ui2OrganizerRender(w, r, "held change is unreadable")
		return
	}
	if err := s.organizer.SetStatusIfUnchanged(change.Before, change.Status); err != nil {
		s.ui2OrganizerRender(w, r, err.Error())
		return
	}
	s.organizerChanged()
	s.ui2OrganizerRender(w, r, "workflow status saved; other item fields and memberships unchanged; no traffic sent")
}
