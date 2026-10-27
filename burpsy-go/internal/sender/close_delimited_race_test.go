package sender

import (
	"sync"
	"testing"
)

// ApplyNetwork clears the close-delimited marks while sends read and write them without s.mu; the
// clear must be in place, not a reassignment that zeroes the map (and its mutex) under them.
// Meaningful under -race (internal/sender runs in CI's race shard).
func TestApplyNetworkClearsCloseDelimitedMarksWithoutRacingSends(t *testing.T) {
	s := NewSender(DefaultSenderConfig())
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 200 {
			s.observeCloseDelimited("h:80", resp)
			s.closeDelimitedAuthorities.Load("h:80")
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			if err := s.ApplyNetwork(s.Network()); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	wg.Wait()
	s.observeCloseDelimited("h:80", resp)
	if err := s.ApplyNetwork(s.Network()); err != nil {
		t.Fatal(err)
	}
	if _, marked := s.closeDelimitedAuthorities.Load("h:80"); marked {
		t.Error("ApplyNetwork left a close-delimited mark from the old network")
	}
}
