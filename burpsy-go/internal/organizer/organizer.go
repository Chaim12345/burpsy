// Package organizer holds the UI's in-memory "shortlist" of saved exchanges.
// It is deliberately ephemeral: state lives for the process lifetime only, in
// both the web layer and the CLI, so the two share one implementation instead
// of drifting. Entries are never persisted.
package organizer

// Item is one saved exchange.
type Item struct {
	ID        int    `json:"id"`
	Exchange  int    `json:"exchange"`
	Title     string `json:"title"`
	Note      string `json:"note"`
	Highlight string `json:"highlight"`
}

// Store is a mutex-guarded list of saved exchanges. The chan-based lock keeps
// it dependency-free and trivially safe to call from handlers.
type Store struct {
	mu    chan struct{}
	next  int
	items []Item
}

// New creates an empty store.
func New() *Store {
	return &Store{mu: make(chan struct{}, 1)}
}

// Add appends an exchange and returns the new item.
func (o *Store) Add(exchange int) Item {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	o.next++
	item := Item{ID: o.next, Exchange: exchange, Highlight: "none"}
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

// SetBaseID is retained for API stability but Restore is the persistence path.
func (o *Store) SetBaseID(id int) {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	if id > o.next {
		o.next = id
	}
}

// Restore replaces the store's contents with a previously persisted snapshot,
// keeping the items' original ids and resuming the id sequence above the
// highest one. This is the load path for the SQLite write-through store.
func (o *Store) Restore(items []Item) {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	o.items = append([]Item{}, items...)
	for _, it := range items {
		if it.ID > o.next {
			o.next = it.ID
		}
	}
}
