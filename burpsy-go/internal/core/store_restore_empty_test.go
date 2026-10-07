package core

import "testing"

// burpsy-react-ui-nagj: restoring an EMPTY project into a store that already held messages — what an
// in-console project switch to a new file does — must reset the id counter. Ids are positions (Get
// resolves by slot), so a counter left at the old project's length handed the next capture id 3 while
// storing it in slot 0: every message captured after the switch was unreadable, and every exchange
// pointing at one rendered as having no bytes.
func TestRestoringAnEmptyProjectResetsMessageIDs(t *testing.T) {
	ts := NewTrafficStore()
	for i := 0; i < 3; i++ {
		if _, err := ts.Put([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), DirectionRequest); err != nil {
			t.Fatal(err)
		}
	}

	ts.Restore(nil, nil) // the incoming project has no messages

	id, err := ts.Put([]byte("GET /after HTTP/1.1\r\nHost: b\r\n\r\n"), DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	if id != 0 {
		t.Errorf("the first message after restoring an empty project got id %d, want 0", id)
	}
	msg, err := ts.Get(id)
	if err != nil {
		t.Fatalf("the message just stored cannot be read back by its own id: %v", err)
	}
	if string(msg.Raw()) != "GET /after HTTP/1.1\r\nHost: b\r\n\r\n" {
		t.Errorf("id %d resolves to the wrong bytes: %q", id, msg.Raw())
	}
}
