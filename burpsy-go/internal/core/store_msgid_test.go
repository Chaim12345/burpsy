package core

// Message ids are slots, and a rejected Put must not consume one.
//
// Get resolves an id by indexing the message slice — position *is* the id, which is what makes an id
// cheap and what the restore path assumes when it sets nextID to len(messages). Put used to take its id
// from the counter and increment it before parsing, so a message the parser rejected burned a slot that
// nothing was ever stored at. Every later message then sat one slot below its own id: exchange rows
// pointed at the message before the one they meant, and the highest id resolved to nothing.
//
// That is a silent corruption of the whole capture after the first malformed message — a proxied
// response with an unreadable start line is enough — so the property is pinned here rather than left to
// be noticed downstream. It was found by internal/proxy's capture-site test, which asserts that every
// exchange row's request id resolves to a request and its response id to a response.

import (
	"strings"
	"testing"
)

func TestARejectedPutDoesNotConsumeAMessageId(t *testing.T) {
	store := NewTrafficStore()

	first, err := store.Put([]byte("GET /first HTTP/1.1\r\nHost: h\r\n\r\n"), DirectionRequest)
	if err != nil {
		t.Fatalf("first Put: %v", err)
	}

	// Two tokens in the start line, which core.Parse refuses.
	if _, err := store.Put([]byte("HTTP/1.1\r\n\r\n"), DirectionResponse); err == nil {
		t.Fatal("Put accepted a message with a malformed start line")
	}

	second, err := store.Put([]byte("GET /second HTTP/1.1\r\nHost: h\r\n\r\n"), DirectionRequest)
	if err != nil {
		t.Fatalf("second Put: %v", err)
	}
	if second != first+1 {
		t.Fatalf("ids %d then %d: the rejected message consumed the slot in between", first, second)
	}

	msg, err := store.Get(second)
	if err != nil {
		t.Fatalf("the id Put returned does not resolve: %v", err)
	}
	if got := string(msg.Raw()); !strings.Contains(got, "/second") {
		t.Errorf("id %d resolves to %q, not the message it was returned for", second, got)
	}

	// Every id in range resolves, and resolves to the message stored at it.
	msgs, _ := store.Count()
	for id := MsgId(0); uint64(id) < uint64(msgs); id++ {
		m, err := store.Get(id)
		if err != nil {
			t.Fatalf("id %d does not resolve, so the index has a hole: %v", id, err)
		}
		if m.ID != id {
			t.Errorf("slot %d holds the message with id %d", id, m.ID)
		}
	}
}
