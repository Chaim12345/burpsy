package organizer

import "fmt"

// Item move, copy and delete for the server-rendered console's reviewed mutations.
//
// Each op binds the full stored item snapshot, following SetStatusIfUnchanged: a change
// between review and install refuses the whole change rather than applying it to an
// item the operator did not review. Move and copy additionally bind the destination
// collection's id AND name: the operator reviewed "move to 'alpha'", and a rename or
// deletion since then makes the destination something they did not review. The Inbox
// (collection 0) is display-only and cannot be renamed or deleted, so a zero
// Collection means Inbox with nothing to compare.
//
// The plain MoveToCollection and Remove stay as they are: the JSON API composes them
// without a review gate, and changing them would change that contract.

// MoveItemIfUnchanged compares the full stored item and changes only its collection.
// Every other field, every other item and every collection remain untouched.
func (o *Store) MoveItemIfUnchanged(before Item, dest Collection) error {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	if err := o.checkDestinationLocked(dest); err != nil {
		return err
	}
	for i := range o.items {
		if o.items[i].ID != before.ID {
			continue
		}
		if o.items[i] != before {
			return fmt.Errorf("item %d changed since review - nothing applied", before.ID)
		}
		if o.items[i].Collection == dest.ID {
			return fmt.Errorf("item %d is already in that collection - nothing to apply", before.ID)
		}
		o.items[i].Collection = dest.ID
		return nil
	}
	return fmt.Errorf("item %d no longer exists - nothing applied", before.ID)
}

// CopyItemIfUnchanged compares the full stored item and appends a duplicate carrying
// the reviewed fields (exchange, title, note, highlight, workflow status) with a fresh
// id into the destination. The source stays untouched; copying into the same
// collection is how "duplicate" reads. Ids stay monotonic: the copy's id is above
// every existing one, so Restore and ItemsIn keep their invariants.
func (o *Store) CopyItemIfUnchanged(before Item, dest Collection) (Item, error) {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	if err := o.checkDestinationLocked(dest); err != nil {
		return Item{}, err
	}
	for _, it := range o.items {
		if it.ID != before.ID {
			continue
		}
		if it != before {
			return Item{}, fmt.Errorf("item %d changed since review - nothing applied", before.ID)
		}
		o.next++
		dup := before
		dup.ID = o.next
		dup.Collection = dest.ID
		o.items = append(o.items, dup)
		return dup, nil
	}
	return Item{}, fmt.Errorf("item %d no longer exists - nothing applied", before.ID)
}

// DeleteItemIfUnchanged compares the full stored item and removes only that saved
// item. The underlying exchange and history are not part of the store and are not
// touched; no collection is affected.
func (o *Store) DeleteItemIfUnchanged(before Item) error {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	for i := range o.items {
		if o.items[i].ID != before.ID {
			continue
		}
		if o.items[i] != before {
			return fmt.Errorf("item %d changed since review - nothing applied", before.ID)
		}
		o.items = append(o.items[:i], o.items[i+1:]...)
		return nil
	}
	return fmt.Errorf("item %d no longer exists - nothing applied", before.ID)
}

// checkDestinationLocked refuses a destination whose id is unknown or whose name
// drifted since review. Collection 0 is the display-only Inbox: nothing to check.
// Caller holds the lock.
func (o *Store) checkDestinationLocked(dest Collection) error {
	if dest.ID == 0 {
		return nil
	}
	for _, c := range o.collections {
		if c.ID == dest.ID {
			if c.Name != dest.Name {
				return fmt.Errorf("collection %d was renamed since review - nothing applied", dest.ID)
			}
			return nil
		}
	}
	return fmt.Errorf("collection %d no longer exists - nothing applied", dest.ID)
}
