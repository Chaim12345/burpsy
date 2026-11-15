package organizer

import (
	"fmt"

	"github.com/burpsy-go/burpsy/internal/core"
)

const ItemTitleLimit = 512
const ItemNoteLimit = 4096

// ValidateItemAnnotation is shared by page review and atomic install. Limits are UTF-8
// bytes; title and note are stored verbatim - never trimmed or truncated. The highlight
// vocabulary is the exchange annotation's: the nine named colours or "none" (the stored
// empty value); the blank string is the PATCH wire convention and is refused here.
func ValidateItemAnnotation(title, note, highlight string) error {
	if highlight != "none" && !core.ValidHighlights[highlight] {
		return fmt.Errorf("highlight must be none, red, orange, yellow, green, cyan, blue, pink, magenta or gray")
	}
	if len(title) > ItemTitleLimit {
		return fmt.Errorf("item title exceeds 512 UTF-8 bytes")
	}
	if len(note) > ItemNoteLimit {
		return fmt.Errorf("item note exceeds 4096 UTF-8 bytes")
	}
	return nil
}

// SetAnnotationIfUnchanged compares the full stored item and changes only its title,
// note and highlight. An all-unchanged write is refused before any cap validation, so
// an over-cap legacy value is preserved unless the operator explicitly reviews a
// replacement within limits. Workflow status, membership, exchange and every other
// item remain untouched. Existing Update and the API are unchanged.
func (o *Store) SetAnnotationIfUnchanged(before Item, title, note, highlight string) error {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	for i := range o.items {
		if o.items[i].ID != before.ID {
			continue
		}
		if o.items[i] != before {
			return fmt.Errorf("item %d changed since review - nothing applied", before.ID)
		}
		if o.items[i].Title == title && o.items[i].Note == note && o.items[i].Highlight == highlight {
			return fmt.Errorf("item %d annotations are unchanged - nothing to apply", before.ID)
		}
		if err := ValidateItemAnnotation(title, note, highlight); err != nil {
			return err
		}
		o.items[i].Title, o.items[i].Note, o.items[i].Highlight = title, note, highlight
		return nil
	}
	return fmt.Errorf("item %d no longer exists - nothing applied", before.ID)
}
