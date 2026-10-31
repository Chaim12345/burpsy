package organizer

import "fmt"

// SetStatusIfUnchanged compares the full stored item and changes only its workflow status.
func (o *Store) SetStatusIfUnchanged(before Item, status Status) error {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	if !ValidStatus(status) {
		return fmt.Errorf("workflow status must be new, in_progress, postponed, done or ignored")
	}
	for i := range o.items {
		if o.items[i].ID != before.ID {
			continue
		}
		if o.items[i] != before {
			return fmt.Errorf("item %d changed since review - nothing applied", before.ID)
		}
		o.items[i].Status = status
		return nil
	}
	return fmt.Errorf("item %d no longer exists - nothing applied", before.ID)
}
