package organizer

import (
	"fmt"
	"strings"
)

const CollectionNameLimit = 120
const CollectionNoteLimit = 4096

// ValidateCollectionText is shared by page review and atomic install. Limits are UTF-8 bytes.
func ValidateCollectionText(name, note string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("a collection needs a nonblank name")
	}
	if strings.EqualFold(strings.TrimSpace(name), "Inbox") {
		return fmt.Errorf("Inbox is reserved for the display-only inbox")
	}
	if len(name) > CollectionNameLimit {
		return fmt.Errorf("collection name exceeds 120 UTF-8 bytes")
	}
	if len(note) > CollectionNoteLimit {
		return fmt.Errorf("collection note exceeds 4096 UTF-8 bytes")
	}
	return nil
}

// EditCollectionIfUnchanged compares and replaces both editable fields under one lock.
// Membership and every other collection remain untouched.
func (o *Store) EditCollectionIfUnchanged(before Collection, name, note string) error {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	name = strings.TrimSpace(name)
	if err := ValidateCollectionText(name, note); err != nil {
		return err
	}
	index := -1
	for i, c := range o.collections {
		if c.ID == before.ID {
			index = i
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("collection %d no longer exists - nothing applied", before.ID)
	}
	if o.collections[index] != before {
		return fmt.Errorf("collection %d name or note changed since review - nothing applied", before.ID)
	}
	for _, c := range o.collections {
		if c.ID != before.ID && c.Name == name {
			return fmt.Errorf("a collection named %q already exists", name)
		}
	}
	o.collections[index].Name, o.collections[index].Note = name, note
	return nil
}
