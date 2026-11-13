package organizer

import (
	"fmt"
	"strings"
)

// Collection duplicate and delete for the server-rendered console's reviewed mutations.
//
// Both bind the collection snapshot AND its member items: duplicate copies exactly the
// items the operator reviewed, and delete either deletes or unlinks exactly those. An
// item moved in or out, or edited, since review refuses the whole change. The plain
// DeleteCollection stays as it is for the JSON API.

// Members returns the items in one collection, in list order.
func (o *Store) Members(collection int) []Item {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	return o.membersLocked(collection)
}

func (o *Store) membersLocked(collection int) []Item {
	var out []Item
	for _, it := range o.items {
		if it.Collection == collection {
			out = append(out, it)
		}
	}
	return out
}

// checkCollectionLocked refuses a collection or membership that drifted since review.
func (o *Store) checkCollectionLocked(before Collection, members []Item) error {
	found := false
	for _, c := range o.collections {
		if c.ID == before.ID {
			if c != before {
				return fmt.Errorf("collection %d name or note changed since review - nothing applied", before.ID)
			}
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("collection %d no longer exists - nothing applied", before.ID)
	}
	now := o.membersLocked(before.ID)
	if len(now) != len(members) {
		return fmt.Errorf("collection %d items changed since review - nothing applied", before.ID)
	}
	for i := range now {
		if now[i] != members[i] {
			return fmt.Errorf("collection %d items changed since review - nothing applied", before.ID)
		}
	}
	return nil
}

// DuplicateCollectionIfUnchanged creates a collection named name carrying the source's
// note, and copies each reviewed member into it under a fresh id. The source and its
// items stay untouched.
func (o *Store) DuplicateCollectionIfUnchanged(before Collection, members []Item, name string) (Collection, error) {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	name = strings.TrimSpace(name)
	if err := ValidateCollectionText(name, before.Note); err != nil {
		return Collection{}, err
	}
	if err := o.checkCollectionLocked(before, members); err != nil {
		return Collection{}, err
	}
	for _, c := range o.collections {
		if c.Name == name {
			return Collection{}, fmt.Errorf("a collection named %q already exists", name)
		}
	}
	o.nextCollection++
	created := Collection{ID: o.nextCollection, Name: name, Note: before.Note}
	o.collections = append(o.collections, created)
	for _, m := range members {
		o.next++
		dup := m
		dup.ID = o.next
		dup.Collection = created.ID
		o.items = append(o.items, dup)
	}
	return created, nil
}

// DeleteCollectionIfUnchanged removes the reviewed collection. withItems deletes the
// reviewed members; otherwise they return to the Inbox. Returns how many items were
// deleted or unlinked.
func (o *Store) DeleteCollectionIfUnchanged(before Collection, members []Item, withItems bool) (int, error) {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	if err := o.checkCollectionLocked(before, members); err != nil {
		return 0, err
	}
	rest := o.collections[:0]
	for _, c := range o.collections {
		if c.ID != before.ID {
			rest = append(rest, c)
		}
	}
	o.collections = rest
	n := 0
	kept := o.items[:0]
	for _, it := range o.items {
		if it.Collection == before.ID {
			n++
			if withItems {
				continue
			}
			it.Collection = 0
		}
		kept = append(kept, it)
	}
	o.items = kept
	return n, nil
}
