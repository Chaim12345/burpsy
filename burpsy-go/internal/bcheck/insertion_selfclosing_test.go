package bcheck

import (
	"strings"
	"testing"
)

// Burp's standalone-tag insertion point (burpsy-react-ui-lzzz): each self-closing element in an XML
// body is an XML point, and a payload opens the element around itself.
func TestASelfClosingXMLElementIsAnInsertionPoint(t *testing.T) {
	req := []byte("POST /api HTTP/1.1\r\nHost: h\r\nContent-Type: application/xml\r\n\r\n" +
		`<order><item id="7"/><note  /></order>`)
	points, _ := Enumerate(req, []string{"any"})
	var item, note *InsertionPoint
	for i := range points {
		switch points[i].Name {
		case "order/item":
			if points[i].BaseValue == "" {
				item = &points[i]
			}
		case "order/note":
			note = &points[i]
		}
	}
	if item == nil || note == nil {
		t.Fatalf("points = %+v, want a standalone point for order/item and order/note", names(points))
	}
	got, err := note.Apply(req, "<x>&", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(got), `<order><item id="7"/><note>&lt;x&gt;&amp;</note></order>`) {
		t.Errorf("applied = %q, want the note element opened around the escaped payload", got)
	}
	got, _ = item.Apply(req, "P", true)
	if !strings.HasSuffix(string(got), `<order><item id="7">P</item><note  /></order>`) {
		t.Errorf("appending applied = %q, want the item opened around the payload, its attribute kept", got)
	}
	// The attribute value is still its own point beside the standalone one.
	found := false
	for _, p := range points {
		if p.Name == "order/item@id" && p.BaseValue == "7" {
			found = true
		}
	}
	if !found {
		t.Error("the self-closing element's attribute lost its point")
	}
}
