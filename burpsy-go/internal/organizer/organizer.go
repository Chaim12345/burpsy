// Package organizer holds the UI's in-memory "shortlist" of saved exchanges.
// It is deliberately ephemeral: state lives for the process lifetime only, in
// both the web layer and the CLI, so the two share one implementation instead
// of drifting. Entries are never persisted.
package organizer

// Status is the user-applied workflow state of one saved exchange — Burp's
// Organizer "Statuses" (tools/organizer/annotate.html: New / In progress /
// Postponed / Done / Ignored), which tell the operator which saved requests
// still need attention and which are already worked through. It is a distinct
// axis from the HTTP status code: "Done" is something the operator decided, a
// 404 is something the server said.
type Status string

// The five workflow statuses. StatusNew is the zero state applied at Add, so a
// freshly saved exchange starts untriaged — the same state Burp models as the
// inbox the flat list already is. The other four are deliberate decisions.
const (
	StatusNew        Status = "new"
	StatusInProgress Status = "in_progress"
	StatusPostponed  Status = "postponed"
	StatusDone       Status = "done"
	StatusIgnored    Status = "ignored"
)

// ValidStatus reports whether s is one of the five workflow statuses. The web
// handler refuses an unrepresentable value rather than storing it and having
// the UI render a status nobody defined — the same refuse-by-default the
// scope and match-replace endpoints take toward enum fields.
func ValidStatus(s Status) bool {
	switch s {
	case StatusNew, StatusInProgress, StatusPostponed, StatusDone, StatusIgnored:
		return true
	}
	return false
}

// Item is one saved exchange.
//
// Status is tagged workflow_status, not status: the resolved view that wraps this item
// (web.organizerItemView) already uses "status" for the HTTP response code, and encoding/json
// resolves the collision in favour of the outer field — the workflow status would be silently
// absent from every response. The name says what it is: the operator's decision, not the server's.
type Item struct {
	ID         int    `json:"id"`
	Exchange   int    `json:"exchange"`
	Title      string `json:"title"`
	Note       string `json:"note"`
	Highlight  string `json:"highlight"`
	Status     Status `json:"workflow_status"`
	Collection int    `json:"collection,omitempty"`
}

// Collection is one named group of saved exchanges — Burp's organizer collections
// (tools/organizer/collections.html): "Collections provide a way to group HTTP messages in a way
// that suits your testing workflow." Collection 0 does not exist; an item whose Collection field
// is 0 sits in the inbox, which is the untriaged state the flat list already models.
type Collection struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Note string `json:"note"`
}

// Store is a mutex-guarded list of saved exchanges. The chan-based lock keeps
// it dependency-free and trivially safe to call from handlers.
type Store struct {
	mu             chan struct{}
	next           int
	nextCollection int
	items          []Item
	collections    []Collection
}

// New creates an empty store.
func New() *Store {
	return &Store{mu: make(chan struct{}, 1)}
}

// Add appends an exchange and returns the new item. A new item starts at
// StatusNew: distinguishing untriaged from worked-through is the whole point
// of the workflow statuses, so the inbox state has to exist as a state.
func (o *Store) Add(exchange int) Item {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	o.next++
	item := Item{ID: o.next, Exchange: exchange, Highlight: "none", Status: StatusNew}
	o.items = append(o.items, item)
	return item
}

// List returns a snapshot of all items.
func (o *Store) List() []Item {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	out := make([]Item, len(o.items))
	copy(out, o.items)
	return out
}

// Update changes title/note/highlight on an item. An empty highlight keeps the
// existing value. Returns false when the id is unknown.
func (o *Store) Update(id int, title, note, highlight string) bool {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	for i := range o.items {
		if o.items[i].ID == id {
			o.items[i].Title = title
			o.items[i].Note = note
			if highlight != "" {
				o.items[i].Highlight = highlight
			}
			return true
		}
	}
	return false
}

// SetStatus applies a workflow status to one item. A dedicated setter rather
// than a field on Update, because Update is the title/note form's write path
// and a status change is one deliberate operator decision applied from the
// item's own menu — Burp keeps them separate too (annotate dialog vs status
// submenu). Returns false when the id is unknown. The API layer validates the
// value with ValidStatus before calling; this method stores what it is given.
func (o *Store) SetStatus(id int, status Status) bool {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	for i := range o.items {
		if o.items[i].ID == id {
			o.items[i].Status = status
			return true
		}
	}
	return false
}

// Remove deletes an item by id. Returns false when the id is unknown.
func (o *Store) Remove(id int) bool {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	for i := range o.items {
		if o.items[i].ID == id {
			o.items = append(o.items[:i], o.items[i+1:]...)
			return true
		}
	}
	return false
}

// ---- Collections --------------------------------------------------------------------------------

// NewCollection creates an empty named collection and returns it. Names are unique across the
// organizer: collections are addressed by name in the UI and Burp's rename flow treats a clash as
// an error, so silently creating two identically named groups would make "move to…" ambiguous.
func (o *Store) NewCollection(name string) (Collection, bool) {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	for _, c := range o.collections {
		if c.Name == name {
			return Collection{}, false
		}
	}
	o.nextCollection++
	c := Collection{ID: o.nextCollection, Name: name}
	o.collections = append(o.collections, c)
	return c, true
}

// Collections returns a snapshot of all collections, inbox-first.
func (o *Store) Collections() []Collection {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	out := make([]Collection, len(o.collections))
	copy(out, o.collections)
	return out
}

// RenameCollection renames one collection. Returns false when the id is unknown or the name is
// taken by another collection — both are refusals, not no-ops, so the caller can answer 404 vs
// 400 honestly.
func (o *Store) RenameCollection(id int, name string) bool {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	found := -1
	for i, c := range o.collections {
		if c.ID == id {
			found = i
			break
		}
	}
	if found < 0 {
		return false
	}
	for i, c := range o.collections {
		if i != found && c.Name == name {
			return false
		}
	}
	o.collections[found].Name = name
	return true
}

// SetCollectionNote attaches the About note to one collection — Burp's "You can also add notes to
// a collection using the About tab". Returns false when the id is unknown.
func (o *Store) SetCollectionNote(id int, note string) bool {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	for i := range o.collections {
		if o.collections[i].ID == id {
			o.collections[i].Note = note
			return true
		}
	}
	return false
}

// DeleteCollection removes a collection. The items are the operator's saved work, so the default
// is Unlink (move back to the inbox), never losing them; WithItems deletes the items with the
// collection, the explicit second choice Burp's dialog offers. Returns false when the id is
// unknown.
func (o *Store) DeleteCollection(id int, withItems bool) (unlinked int, ok bool) {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	found := false
	rest := o.collections[:0]
	for _, c := range o.collections {
		if c.ID == id {
			found = true
			continue
		}
		rest = append(rest, c)
	}
	if !found {
		return 0, false
	}
	o.collections = rest
	if withItems {
		kept := o.items[:0]
		for _, it := range o.items {
			if it.Collection != id {
				kept = append(kept, it)
			}
		}
		o.items = kept
		return 0, true
	}
	for i := range o.items {
		if o.items[i].Collection == id {
			o.items[i].Collection = 0
			unlinked++
		}
	}
	return unlinked, true
}

// MoveToCollection links each named item to a collection — 0 unlinks back to the inbox, Burp's
// "Move to…" with the inbox as one of the destinations. Returns the number of items actually
// moved; moving an item already there is still a success, so a repeated click is idempotent
// rather than an error.
func (o *Store) MoveToCollection(ids []int, collection int) int {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	if collection != 0 {
		known := false
		for _, c := range o.collections {
			if c.ID == collection {
				known = true
				break
			}
		}
		if !known {
			return -1
		}
	}
	moved := 0
	for _, id := range ids {
		for i := range o.items {
			if o.items[i].ID == id && o.items[i].Collection != collection {
				o.items[i].Collection = collection
				moved++
			}
		}
	}
	return moved
}

// ItemsIn reports how many items each collection holds — the count the UI shows beside the name,
// computed here so the web layer cannot drift from the store's own definition of membership.
func (o *Store) ItemsIn(collection int) int {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	n := 0
	for i := range o.items {
		if o.items[i].Collection == collection {
			n++
		}
	}
	return n
}

// SetBaseID is retained for API stability but Restore is the persistence path.
func (o *Store) SetBaseID(id int) {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	if id > o.next {
		o.next = id
	}
}

// Restore replaces the store's contents with a previously persisted snapshot,
// keeping the items' original ids and resuming both id sequences above the
// highest one. This is the load path for the SQLite write-through store.
func (o *Store) Restore(items []Item, collections []Collection) {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	o.items = append([]Item{}, items...)
	for _, it := range items {
		if it.ID > o.next {
			o.next = it.ID
		}
	}
	o.collections = append([]Collection{}, collections...)
	for _, c := range collections {
		if c.ID > o.nextCollection {
			o.nextCollection = c.ID
		}
	}
}
