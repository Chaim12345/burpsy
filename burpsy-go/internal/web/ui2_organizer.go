package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/organizer"
)

type ui2CollectionChange struct {
	Op     string               `json:"op"`
	Before organizer.Collection `json:"before"`
	Name   string               `json:"name"`
	Note   string               `json:"note"`
}
type ui2CollectionReview struct {
	body    []byte
	token   string
	expires time.Time
}

func ui2CollectionDigest(c organizer.Collection) string {
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (s *Server) ui2OrganizerView(note string) map[string]any {
	collections := s.organizer.Collections()
	names := map[int]string{0: "Inbox"}
	counts := map[int]int{}
	for _, c := range collections {
		names[c.ID] = c.Name
	}
	items := s.organizerView()
	rows := make([]map[string]any, 0, len(items))
	for _, it := range items {
		counts[it.Collection]++
		name, ok := names[it.Collection]
		if !ok {
			name = fmt.Sprintf("Unknown collection #%d", it.Collection)
		}
		rows = append(rows, map[string]any{"item": it, "collection_name": name, "workflow": it.Item.Status, "workflow_base": ui2WorkflowDigest(it.Item)})
	}
	cards := make([]map[string]any, 0, len(collections))
	for _, c := range collections {
		cards = append(cards, map[string]any{"id": c.ID, "name": c.Name, "note": c.Note, "count": counts[c.ID], "base": ui2CollectionDigest(c)})
	}
	return map[string]any{"items": rows, "collections": cards, "inbox_count": counts[0], "note": note}
}
func (s *Server) ui2OrganizerRender(w http.ResponseWriter, r *http.Request, note string) {
	ui2Fragment(w, r, "burpsy /ui2/ - Organizer", "organizer", ui2Exec("organizer.html", s.ui2OrganizerView(note)))
}
func (s *Server) ui2OrganizerFail(w http.ResponseWriter, r *http.Request, msg string) {
	ui2Fragment(w, r, "burpsy /ui2/ - Organizer", "organizer", ui2Exec("organizer_confirm.html", map[string]any{"error": msg}))
}
func ui2CollectionFields(r *http.Request, allowed map[string]bool) error {
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("invalid form")
	}
	if len(r.URL.Query()) != 0 {
		return fmt.Errorf("query fields are not permitted")
	}
	for k, v := range r.PostForm {
		if !allowed[k] || len(v) != 1 {
			return fmt.Errorf("%s is not a single permitted collection field", k)
		}
	}
	return nil
}
func (s *Server) handleUI2OrganizerCollections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.PathValue("action") == "run" {
		s.ui2OrganizerRun(w, r)
		return
	}
	if r.PathValue("action") != "confirm" {
		s.ui2OrganizerFail(w, r, "unknown collection action")
		return
	}
	if err := ui2CollectionFields(r, map[string]bool{"op": true, "collection_id": true, "form_base": true, "name": true, "note": true}); err != nil {
		s.ui2OrganizerFail(w, r, err.Error())
		return
	}
	change := ui2CollectionChange{Op: r.PostFormValue("op"), Name: strings.TrimSpace(r.PostFormValue("name")), Note: r.PostFormValue("note")}
	if err := organizer.ValidateCollectionText(change.Name, change.Note); err != nil {
		s.ui2OrganizerFail(w, r, err.Error())
		return
	}
	switch change.Op {
	case "create":
		if r.PostFormValue("collection_id") != "" || r.PostFormValue("form_base") != "" || change.Note != "" {
			s.ui2OrganizerFail(w, r, "create accepts a name only; edit its note after creation")
			return
		}
	case "edit":
		id, err := strconv.Atoi(r.PostFormValue("collection_id"))
		if err != nil || id <= 0 {
			s.ui2OrganizerFail(w, r, "choose a named collection, not Inbox")
			return
		}
		found := false
		for _, c := range s.organizer.Collections() {
			if c.ID == id {
				change.Before = c
				found = true
				break
			}
		}
		if !found {
			s.ui2OrganizerFail(w, r, fmt.Sprintf("collection %d no longer exists", id))
			return
		}
		if r.PostFormValue("form_base") != ui2CollectionDigest(change.Before) {
			s.ui2OrganizerFail(w, r, fmt.Sprintf("collection %d changed since this form opened - reopen it", id))
			return
		}
		if change.Name == change.Before.Name && change.Note == change.Before.Note {
			s.ui2OrganizerFail(w, r, "collection name and note are unchanged - nothing to review")
			return
		}
	default:
		s.ui2OrganizerFail(w, r, "unknown collection operation")
		return
	}
	for _, c := range s.organizer.Collections() {
		if c.ID != change.Before.ID && c.Name == change.Name {
			s.ui2OrganizerFail(w, r, fmt.Sprintf("a collection named %q already exists", change.Name))
			return
		}
	}
	now := time.Now()
	count := 0
	s.ui2CollectionReviews.Range(func(k, v any) bool {
		e := v.(ui2CollectionReview)
		if now.After(e.expires) {
			s.ui2CollectionReviews.Delete(k)
		} else {
			count++
		}
		return true
	})
	if count >= 8 {
		s.ui2OrganizerFail(w, r, "too many collection reviews are open; wait for expiry")
		return
	}
	body, _ := json.Marshal(change)
	binding := newCallBinding(http.MethodPost, "/ui2/organizer/collections/install", "", body)
	token, err := s.confirms.issue("ui2-collection", binding)
	if err != nil {
		s.ui2OrganizerFail(w, r, "could not create review")
		return
	}
	id, err := randomHex(16)
	if err != nil {
		s.ui2OrganizerFail(w, r, "could not create review id")
		return
	}
	s.ui2CollectionReviews.Store(id, ui2CollectionReview{body: body, token: token, expires: now.Add(ConfirmTTL)})
	ui2Fragment(w, r, "burpsy /ui2/ - Organizer", "organizer", ui2Exec("organizer_confirm.html", map[string]any{"change": change, "projection": string(body), "review_id": id, "token": token}))
}
func (s *Server) ui2OrganizerRun(w http.ResponseWriter, r *http.Request) {
	if err := ui2CollectionFields(r, map[string]bool{"review_id": true, "token": true}); err != nil {
		s.ui2OrganizerFail(w, r, err.Error())
		return
	}
	v, ok := s.ui2CollectionReviews.LoadAndDelete(r.PostFormValue("review_id"))
	if !ok {
		s.ui2OrganizerRender(w, r, "review unknown or already used - review again")
		return
	}
	entry := v.(ui2CollectionReview)
	binding := newCallBinding(http.MethodPost, "/ui2/organizer/collections/install", "", entry.body)
	if time.Now().After(entry.expires) || !s.confirms.spend(r.PostFormValue("token"), "ui2-collection", binding) {
		s.ui2OrganizerRender(w, r, "review expired or confirmation does not match - review again")
		return
	}
	var change ui2CollectionChange
	if json.Unmarshal(entry.body, &change) != nil {
		s.ui2OrganizerRender(w, r, "held change is unreadable")
		return
	}
	if err := organizer.ValidateCollectionText(change.Name, change.Note); err != nil {
		s.ui2OrganizerRender(w, r, err.Error())
		return
	}
	switch change.Op {
	case "create":
		if _, ok := s.organizer.NewCollection(change.Name); !ok {
			s.ui2OrganizerRender(w, r, fmt.Sprintf("a collection named %q already exists - nothing applied", change.Name))
			return
		}
	case "edit":
		if err := s.organizer.EditCollectionIfUnchanged(change.Before, change.Name, change.Note); err != nil {
			s.ui2OrganizerRender(w, r, err.Error())
			return
		}
	default:
		s.ui2OrganizerRender(w, r, "unknown held operation")
		return
	}
	s.organizerChanged()
	s.ui2OrganizerRender(w, r, "collection saved; item membership unchanged")
}
