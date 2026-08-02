package store

import (
	"bytes"
	"testing"
)

func TestStoreParsesRequestAndZeroCopySlicing(t *testing.T) {
	raw := []byte("GET /a?b=1 HTTP/1.1\r\nHost: x.test\r\nX-A: 1\r\n\r\nbody!")
	store := NewTrafficStore()
	id := store.Put(raw, Request)

	msg, ok := store.Get(id)
	if !ok {
		t.Fatalf("could not get stored message")
	}

	if msg.Text(msg.Shape.FirstToken) != "GET" {
		t.Errorf("expected GET, got %s", msg.Text(msg.Shape.FirstToken))
	}
	if msg.Text(msg.Shape.SecondToken) != "/a?b=1" {
		t.Errorf("expected /a?b=1, got %s", msg.Text(msg.Shape.SecondToken))
	}
	if msg.Text(msg.Shape.ThirdToken) != "HTTP/1.1" {
		t.Errorf("expected HTTP/1.1, got %s", msg.Text(msg.Shape.ThirdToken))
	}
	if len(msg.Shape.Headers) != 2 {
		t.Errorf("expected 2 headers, got %d", len(msg.Shape.Headers))
	}
	if !bytes.Equal(msg.Header("host"), []byte("x.test")) {
		t.Errorf("expected x.test, got %s", msg.Header("host"))
	}
	if !bytes.Equal(msg.Body(), []byte("body!")) {
		t.Errorf("expected body!, got %s", msg.Body())
	}
}

func TestStoreMatchesQuery(t *testing.T) {
	store := NewTrafficStore()
	reqID := store.Put([]byte("POST /login HTTP/1.1\r\nHost: x.test\r\n\r\nuser=admin"), Request)
	respID := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}"), Response)

	status := uint16(200)
	ex := Exchange{
		Request:  reqID,
		Response: &respID,
		Host:     "x.test",
		Port:     443,
		TLS:      true,
		Method:   "POST",
		Path:     "/login",
		Status:   &status,
		Protocol: Http1,
	}
	store.AddExchange(ex)

	cases := []struct {
		q     string
		want  bool
		errOk bool
	}{
		{`host == "x.test"`, true, true},
		{`status == 200`, true, true},
		{`method == "POST"`, true, true},
		{`mime == "application/json"`, true, true},
		{`body ~ "admin"`, true, true},
		{`body ~ "\"ok\":true"`, true, true},
		{`body ~ "not_found"`, false, true},
	}

	for _, tc := range cases {
		got, err := store.MatchesQuery(&ex, tc.q)
		if err != nil && tc.errOk {
			t.Errorf("query %q returned unexpected error: %v", tc.q, err)
		}
		if got != tc.want {
			t.Errorf("query %q got %v, want %v", tc.q, got, tc.want)
		}
	}
}
