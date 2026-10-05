package sender

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// endlessEventStream serves one text/event-stream response that sends a first event and then never
// ends — the shape of a real SSE feed, on a host no one declared as streaming.
func endlessEventStream(t *testing.T) (string, uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n" +
					"d\r\ndata: first\n\n\r\n"))
				time.Sleep(5 * time.Second) // hold the stream open, as a feed does
			}(c)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", uint16(addr.Port)
}

// burpsy-react-ui-v52t: the sender honours "treat text/event-stream responses as streaming" like the
// proxy leg does. Off, an event stream on an undeclared host runs the ordinary read to its deadline
// and comes back as nothing but an error; on, it is recognised by its content type and what arrived
// inside the streaming window is returned — head and event included.
func TestTheSenderTreatsAnUndeclaredEventStreamAsStreamingWhenTheSwitchIsOn(t *testing.T) {
	host, port := endlessEventStream(t)
	raw := []byte("GET /events HTTP/1.1\r\nHost: " + host + "\r\nAccept: text/event-stream\r\n\r\n")

	for _, on := range []bool{false, true} {
		s := NewSender(&SenderConfig{Timeout: 3 * time.Second})
		settings := DefaultNetworkSettings()
		settings.Timeouts.ReadMS = 400
		settings.Streaming.TimeoutMS = 300
		settings.Streaming.UseTextEventStreamHeader = on
		if err := s.ApplyNetwork(settings); err != nil {
			t.Fatalf("ApplyNetwork: %v", err)
		}
		resp, err := s.SendRaw(context.Background(), host, port, false, raw)
		if !on {
			if err == nil {
				t.Errorf("switch off: the endless stream returned %q without error; the ordinary read should have run to its deadline", resp)
			}
			continue
		}
		if err != nil {
			t.Fatalf("switch on: the event stream came back as an error (%v) — the head and the event that arrived were lost", err)
		}
		if !strings.Contains(string(resp), "200 OK") || !strings.Contains(string(resp), "data: first") {
			t.Errorf("switch on: response = %q, want the head and the first event", resp)
		}
	}
}
