package web

import (
	"encoding/json"
	"fmt"
	"github.com/burpsy-go/burpsy/internal/organizer"
	"net/http"
	"strconv"
	"time"
)

type ui2AnnotationChange struct {
	Before    organizer.Item `json:"before"`
	Title     string         `json:"title"`
	Note      string         `json:"note"`
	Highlight string         `json:"highlight"`
}

func ui2AnnotateFields(r *http.Request, keys ...string) error {
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
			return fmt.Errorf("%s must be a single permitted annotation field", k)
		}
	}
	for k, v := range r.PostForm {
		if !allowed[k] || len(v) != 1 {
			return fmt.Errorf("%s is not a single permitted annotation field", k)
		}
	}
	return nil
}

func (s *Server) ui2AnnotateFail(w http.ResponseWriter, r *http.Request, msg string) {
	ui2Fragment(w, r, "burpsy /ui2/ - Organizer", "organizer", ui2Exec("organizer_annotate_confirm.html", map[string]any{"error": msg}))
}

func (s *Server) handleUI2OrganizerAnnotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.PathValue("action") == "run" {
		s.ui2AnnotateRun(w, r)
		return
	}
	if r.PathValue("action") != "confirm" {
		s.ui2AnnotateFail(w, r, "unknown annotation action")
		return
	}
	if err := ui2AnnotateFields(r, "op", "item_id", "form_base", "title", "note", "highlight"); err != nil {
		s.ui2AnnotateFail(w, r, err.Error())
		return
	}
	if r.PostFormValue("op") != "annotate" {
		s.ui2AnnotateFail(w, r, "unknown annotation operation")
		return
	}
	id, err := strconv.Atoi(r.PostFormValue("item_id"))
	if err != nil || id <= 0 {
		s.ui2AnnotateFail(w, r, "choose a saved item")
		return
	}
	title, note, highlight := r.PostFormValue("title"), r.PostFormValue("note"), r.PostFormValue("highlight")
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
		s.ui2AnnotateFail(w, r, fmt.Sprintf("item %d no longer exists", id))
		return
	}
	if r.PostFormValue("form_base") != ui2WorkflowDigest(before) {
		s.ui2AnnotateFail(w, r, fmt.Sprintf("item %d changed since this form opened - reopen it", id))
		return
	}
	if before.Title == title && before.Note == note && before.Highlight == highlight {
		s.ui2AnnotateFail(w, r, fmt.Sprintf("item %d annotations are unchanged - nothing to review", id))
		return
	}
	if err := organizer.ValidateItemAnnotation(title, note, highlight); err != nil {
		s.ui2AnnotateFail(w, r, err.Error())
		return
	}
	now := time.Now()
	count := 0
	s.ui2AnnotateReviews.Range(func(k, v any) bool {
		e := v.(ui2CollectionReview)
		if now.After(e.expires) {
			s.ui2AnnotateReviews.Delete(k)
		} else {
			count++
		}
		return true
	})
	if count >= 8 {
		s.ui2AnnotateFail(w, r, "too many annotation reviews are open; wait for expiry")
		return
	}
	change := ui2AnnotationChange{Before: before, Title: title, Note: note, Highlight: highlight}
	body, _ := json.Marshal(change)
	token, err := s.confirms.issue("ui2-annotate", newCallBinding(http.MethodPost, "/ui2/organizer/annotate/install", "", body))
	if err != nil {
		s.ui2AnnotateFail(w, r, "could not create review")
		return
	}
	rid, err := randomHex(16)
	if err != nil {
		s.ui2AnnotateFail(w, r, "could not create review id")
		return
	}
	s.ui2AnnotateReviews.Store(rid, ui2CollectionReview{body: body, token: token, expires: now.Add(ConfirmTTL)})
	ui2Fragment(w, r, "burpsy /ui2/ - Organizer", "organizer", ui2Exec("organizer_annotate_confirm.html", map[string]any{"change": change, "review_id": rid, "token": token}))
}

func (s *Server) ui2AnnotateRun(w http.ResponseWriter, r *http.Request) {
	if err := ui2AnnotateFields(r, "review_id", "token"); err != nil {
		s.ui2AnnotateFail(w, r, err.Error())
		return
	}
	v, ok := s.ui2AnnotateReviews.LoadAndDelete(r.PostFormValue("review_id"))
	if !ok {
		s.ui2OrganizerRender(w, r, "review unknown or already used - review again")
		return
	}
	e := v.(ui2CollectionReview)
	binding := newCallBinding(http.MethodPost, "/ui2/organizer/annotate/install", "", e.body)
	if time.Now().After(e.expires) || !s.confirms.spend(r.PostFormValue("token"), "ui2-annotate", binding) {
		s.ui2OrganizerRender(w, r, "review expired or confirmation does not match - review again")
		return
	}
	var change ui2AnnotationChange
	if json.Unmarshal(e.body, &change) != nil {
		s.ui2OrganizerRender(w, r, "held change is unreadable")
		return
	}
	if err := s.organizer.SetAnnotationIfUnchanged(change.Before, change.Title, change.Note, change.Highlight); err != nil {
		s.ui2OrganizerRender(w, r, err.Error())
		return
	}
	s.organizerChanged()
	s.ui2OrganizerRender(w, r, "annotations saved; workflow status, membership and traffic unchanged; no request sent")
}
