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

// ui2CollectionChange is one reviewed collection operation. Duplicate and delete also
// bind the member items, so install acts on exactly the items the operator reviewed.
type ui2CollectionChange struct {
	Op      string               `json:"op"`
	Before  organizer.Collection `json:"before"`
	Name    string               `json:"name"`
	Note    string               `json:"note"`
	Members []organizer.Item     `json:"members,omitempty"`
	Items   string               `json:"items,omitempty"` // delete: "inbox" keeps items, "delete" deletes them
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

// ui2MembersDigest binds a collection's member snapshot into its duplicate/delete forms.
func ui2MembersDigest(members []organizer.Item) string {
	if members == nil {
		members = []organizer.Item{}
	}
	b, _ := json.Marshal(members)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
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
	if err := ui2CollectionFields(r, map[string]bool{"op": true, "collection_id": true, "form_base": true, "members_base": true, "name": true, "note": true, "items": true}); err != nil {
		s.ui2OrganizerFail(w, r, err.Error())
		return
	}
	change := ui2CollectionChange{Op: r.PostFormValue("op"), Name: strings.TrimSpace(r.PostFormValue("name")), Note: r.PostFormValue("note")}
	// existing resolves collection_id against the store and checks the form's snapshot.
	existing := func() bool {
		id, err := strconv.Atoi(r.PostFormValue("collection_id"))
		if err != nil || id <= 0 {
			s.ui2OrganizerFail(w, r, "choose a named collection, not Inbox")
			return false
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
			return false
		}
		if r.PostFormValue("form_base") != ui2CollectionDigest(change.Before) {
			s.ui2OrganizerFail(w, r, fmt.Sprintf("collection %d changed since this form opened - reopen it", id))
			return false
		}
		return true
	}
	// withMembers binds the member snapshot the form was rendered with.
	withMembers := func() bool {
		change.Members = s.organizer.Members(change.Before.ID)
		if r.PostFormValue("members_base") != ui2MembersDigest(change.Members) {
			s.ui2OrganizerFail(w, r, fmt.Sprintf("collection %d items changed since this form opened - reopen it", change.Before.ID))
			return false
		}
		return true
	}
	only := func(keys ...string) bool {
		allowed := map[string]bool{"op": true}
		for _, k := range keys {
			allowed[k] = true
		}
		for k := range r.PostForm {
			if !allowed[k] {
				s.ui2OrganizerFail(w, r, fmt.Sprintf("%s is not a field of the %s operation", k, change.Op))
				return false
			}
		}
		return true
	}
	switch change.Op {
	case "create":
		if r.PostFormValue("collection_id") != "" || r.PostFormValue("form_base") != "" || change.Note != "" {
			s.ui2OrganizerFail(w, r, "create accepts a name only; edit its note after creation")
			return
		}
		if !only("name") {
			return
		}
		if err := organizer.ValidateCollectionText(change.Name, change.Note); err != nil {
			s.ui2OrganizerFail(w, r, err.Error())
			return
		}
	case "edit":
		if err := organizer.ValidateCollectionText(change.Name, change.Note); err != nil {
			s.ui2OrganizerFail(w, r, err.Error())
			return
		}
		if !only("collection_id", "form_base", "name", "note") || !existing() {
			return
		}
		if change.Name == change.Before.Name && change.Note == change.Before.Note {
			s.ui2OrganizerFail(w, r, "collection name and note are unchanged - nothing to review")
			return
		}
	case "duplicate":
		if !only("collection_id", "form_base", "members_base", "name") || !existing() || !withMembers() {
			return
		}
		change.Note = change.Before.Note
		if err := organizer.ValidateCollectionText(change.Name, change.Note); err != nil {
			s.ui2OrganizerFail(w, r, err.Error())
			return
		}
	case "delete":
		if !only("collection_id", "form_base", "members_base", "items") || !existing() || !withMembers() {
			return
		}
		change.Items = r.PostFormValue("items")
		if change.Items != "inbox" && change.Items != "delete" {
			s.ui2OrganizerFail(w, r, "choose whether the collection's items go to the Inbox or are deleted")
			return
		}
	default:
		s.ui2OrganizerFail(w, r, "unknown collection operation")
		return
	}
	if change.Op != "delete" {
		for _, c := range s.organizer.Collections() {
			if (change.Op == "duplicate" || c.ID != change.Before.ID) && c.Name == change.Name {
				s.ui2OrganizerFail(w, r, fmt.Sprintf("a collection named %q already exists", change.Name))
				return
			}
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
	done := "collection saved; item membership unchanged"
	switch change.Op {
	case "create", "edit":
		if err := organizer.ValidateCollectionText(change.Name, change.Note); err != nil {
			s.ui2OrganizerRender(w, r, err.Error())
			return
		}
		if change.Op == "create" {
			if _, ok := s.organizer.NewCollection(change.Name); !ok {
				s.ui2OrganizerRender(w, r, fmt.Sprintf("a collection named %q already exists - nothing applied", change.Name))
				return
			}
		} else if err := s.organizer.EditCollectionIfUnchanged(change.Before, change.Name, change.Note); err != nil {
			s.ui2OrganizerRender(w, r, err.Error())
			return
		}
	case "duplicate":
		created, err := s.organizer.DuplicateCollectionIfUnchanged(change.Before, change.Members, change.Name)
		if err != nil {
			s.ui2OrganizerRender(w, r, err.Error())
			return
		}
		done = fmt.Sprintf("collection %q duplicated as %q with %d copied item(s); the source is unchanged; no request sent", change.Before.Name, created.Name, len(change.Members))
	case "delete":
		if change.Items != "inbox" && change.Items != "delete" {
			s.ui2OrganizerRender(w, r, "unknown held item disposition")
			return
		}
		n, err := s.organizer.DeleteCollectionIfUnchanged(change.Before, change.Members, change.Items == "delete")
		if err != nil {
			s.ui2OrganizerRender(w, r, err.Error())
			return
		}
		if change.Items == "delete" {
			done = fmt.Sprintf("collection %q deleted with its %d saved item(s); their exchanges and history are kept; no request sent", change.Before.Name, n)
		} else {
			done = fmt.Sprintf("collection %q deleted; its %d item(s) moved to the Inbox; no request sent", change.Before.Name, n)
		}
	default:
		s.ui2OrganizerRender(w, r, "unknown held operation")
		return
	}
	s.organizerChanged()
	s.ui2OrganizerRender(w, r, done)
}
