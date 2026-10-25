package proxy

// The stress half of the attach regression set (burpsy-react-ui-wuwf review). It is the test that
// catches AtMessageBoundary forgetting an open fragmented message: fragments with interleaved pings,
// writes split at arbitrary offsets, and four injectors racing the relay.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
)

func qaFrame(op core.WsOpcode, fin bool, payload []byte, mask [4]byte) []byte {
	f := core.EncodeWsFrame(op, payload, &mask)
	if !fin {
		f[0] &^= 0x80
	}
	return f
}

func qaRead(br *bufio.Reader) (*core.WsFrameHeader, []byte, error) {
	var head []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			return nil, nil, err
		}
		head = append(head, b)
		hdr, need, perr := core.ParseWsFrameHeader(head)
		if perr != nil {
			return nil, nil, perr
		}
		if need {
			continue
		}
		p := make([]byte, hdr.PayloadLen)
		if _, err := io.ReadFull(br, p); err != nil {
			return nil, nil, err
		}
		if hdr.Masked {
			core.WsUnmask(p, hdr.Mask, 0)
		}
		return hdr, p, nil
	}
}

// Adopted from the independent review of burpsy-react-ui-wuwf: concurrent injection while the client streams frames, including fragmented messages and
// writes split at arbitrary byte positions. The origin must see a well-formed stream: every client
// message intact and in order, no injected frame inside a fragmented message.
func TestInjectionUnderLoadNeverCorruptsTheStream(t *testing.T) {
	f := openLiveWs(t)
	f.client.SetReadDeadline(time.Time{})
	const n = 400
	var stream []byte
	// pauseAt marks stream offsets that fall INSIDE a fragmented message (after its first frame and
	// after the ping between fragments). The writer pauses there, so the injectors — which are paced
	// across the whole stream — reliably find the relay at a frame boundary that is not a message
	// boundary. Without the pauses the window is microseconds wide and the test passes whether or not
	// AtMessageBoundary remembers the open message.
	pauseAt := map[int]bool{}
	for i := 0; i < n; i++ {
		m := [4]byte{byte(i), 1, 2, 3}
		p := []byte(fmt.Sprintf("client-%04d-%s", i, string(make([]byte, i%300))))
		if i%5 == 0 {
			stream = append(stream, qaFrame(core.WsOpcodeText, false, p[:len(p)/2], m)...)
			pauseAt[len(stream)] = true
			stream = append(stream, qaFrame(core.WsOpcodePing, true, []byte("pp"), m)...)
			pauseAt[len(stream)] = true
			stream = append(stream, qaFrame(core.WsOpcodeContinuation, true, p[len(p)/2:], m)...)
		} else {
			stream = append(stream, qaFrame(core.WsOpcodeText, true, p, m)...)
		}
	}
	go func() {
		for off := 0; off < len(stream); {
			end := off + 1 + (off*7)%97
			if end > len(stream) {
				end = len(stream)
			}
			// Never write past a pause point in one go: stop on it, then wait there.
			for k := off + 1; k < end; k++ {
				if pauseAt[k] {
					end = k
					break
				}
			}
			f.client.Write(stream[off:end])
			off = end
			if pauseAt[off] {
				time.Sleep(3 * time.Millisecond)
			} else {
				time.Sleep(20 * time.Microsecond)
			}
		}
	}()
	var wg sync.WaitGroup
	injected := 0
	var mu sync.Mutex
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := f.srv.InjectWsFrame(context.Background(), f.id, false, core.WsOpcodeText, []byte(fmt.Sprintf("inj-%d-%d", g, j))); err == nil {
					mu.Lock()
					injected++
					mu.Unlock()
				} else {
					t.Logf("inject: %v", err)
				}
				// Paced across the stream's lifetime rather than all at its start.
				time.Sleep(time.Millisecond)
			}
		}(g)
	}
	f.origin.conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	next := 0
	var frag []byte
	open := false
	seenInj := 0
	for next < n || seenInj < 200 {
		hdr, p, err := qaRead(f.origin.Reader)
		if err != nil {
			wg.Wait()
			t.Fatalf("origin read after %d client msgs %d injected: %v (injected ok=%d)", next, seenInj, err, injected)
		}
		switch hdr.Opcode {
		case core.WsOpcodePing:
			continue
		case core.WsOpcodeContinuation:
			if !open {
				t.Fatalf("continuation without open message")
			}
			frag = append(frag, p...)
			if hdr.FIN {
				open = false
				p = frag
			} else {
				continue
			}
		default:
			if open {
				t.Fatalf("new data frame %q inside an open fragmented message", p)
			}
			if !hdr.FIN {
				open = true
				frag = append([]byte(nil), p...)
				continue
			}
		}
		s := string(p)
		if len(s) >= 4 && s[:4] == "inj-" {
			seenInj++
			continue
		}
		want := fmt.Sprintf("client-%04d-", next)
		if len(s) < len(want) || s[:len(want)] != want {
			t.Fatalf("message %d corrupted: %q", next, s[:min(len(s), 40)])
		}
		next++
		mu.Lock()
		done := injected
		mu.Unlock()
		if next == n {
			wg.Wait()
			mu.Lock()
			done = injected
			mu.Unlock()
			if seenInj >= done {
				break
			}
		}
	}
	wg.Wait()
	t.Logf("client msgs %d, injected ok %d, seen %d", next, injected, seenInj)
}

// The interception-on half of TestInjectionUnderLoadNeverCorruptsTheStream (burpsy-react-ui-i9ti.3,
// whose acceptance criterion names "-race ... with interception both on and off"). Every client
// message is HELD for the operator before it is relayed, and an auto-resolver forwards each hold as
// it appears, while four injectors race the relay. Held bytes have not reached the wire, so the
// sink's reassembler is the only boundary oracle an injector has: if interception ever let a
// partial frame reach the wire ahead of its hold, or the release path wrote outside the sink, an
// injected frame would land inside a message and the origin's stream would break.
func TestInjectionUnderInterceptionNeverCorruptsTheStream(t *testing.T) {
	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	if err := engine.SetRules(intercept.DirectionWebSocketToServer, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	f := openLiveWsWith(t, engine)
	f.client.SetReadDeadline(time.Time{})

	// The operator: forward every held frame the moment it appears. A hold whose poll loses to a
	// sibling poll is already resolved, so Forward's error is ignored.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, h := range engine.Held() {
				_ = engine.Forward(h.ID, nil, false, nil)
			}
			time.Sleep(500 * time.Microsecond)
		}
	}()

	// Fewer messages than the interception-off half: every one waits out a hold, so the stream's
	// cost is the resolver's poll, not the wire.
	const n = 150
	var stream []byte
	pauseAt := map[int]bool{}
	for i := 0; i < n; i++ {
		m := [4]byte{byte(i), 1, 2, 3}
		p := []byte(fmt.Sprintf("client-%04d-%s", i, string(make([]byte, i%300))))
		if i%5 == 0 {
			stream = append(stream, qaFrame(core.WsOpcodeText, false, p[:len(p)/2], m)...)
			pauseAt[len(stream)] = true
			stream = append(stream, qaFrame(core.WsOpcodePing, true, []byte("pp"), m)...)
			pauseAt[len(stream)] = true
			stream = append(stream, qaFrame(core.WsOpcodeContinuation, true, p[len(p)/2:], m)...)
		} else {
			stream = append(stream, qaFrame(core.WsOpcodeText, true, p, m)...)
		}
	}
	go func() {
		for off := 0; off < len(stream); {
			end := off + 1 + (off*7)%97
			if end > len(stream) {
				end = len(stream)
			}
			for k := off + 1; k < end; k++ {
				if pauseAt[k] {
					end = k
					break
				}
			}
			f.client.Write(stream[off:end])
			off = end
			if pauseAt[off] {
				time.Sleep(3 * time.Millisecond)
			} else {
				time.Sleep(20 * time.Microsecond)
			}
		}
	}()
	var wg sync.WaitGroup
	injected := 0
	var mu sync.Mutex
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if _, err := f.srv.InjectWsFrame(context.Background(), f.id, false, core.WsOpcodeText, []byte(fmt.Sprintf("inj-%d-%d", g, j))); err == nil {
					mu.Lock()
					injected++
					mu.Unlock()
				} else {
					t.Logf("inject: %v", err)
				}
				time.Sleep(time.Millisecond)
			}
		}(g)
	}
	f.origin.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	next := 0
	var frag []byte
	open := false
	seenInj := 0
	for next < n || seenInj < 100 {
		hdr, p, err := qaRead(f.origin.Reader)
		if err != nil {
			wg.Wait()
			t.Fatalf("origin read after %d client msgs %d injected: %v (injected ok=%d)", next, seenInj, err, injected)
		}
		switch hdr.Opcode {
		case core.WsOpcodePing:
			continue
		case core.WsOpcodeContinuation:
			if !open {
				t.Fatalf("continuation without open message")
			}
			frag = append(frag, p...)
			if hdr.FIN {
				open = false
				p = frag
			} else {
				continue
			}
		default:
			if open {
				t.Fatalf("new data frame %q inside an open fragmented message", p)
			}
			if !hdr.FIN {
				open = true
				frag = append([]byte(nil), p...)
				continue
			}
		}
		s := string(p)
		if len(s) >= 4 && s[:4] == "inj-" {
			seenInj++
			continue
		}
		want := fmt.Sprintf("client-%04d-", next)
		if len(s) < len(want) || s[:len(want)] != want {
			t.Fatalf("message %d corrupted: %q", next, s[:min(len(s), 40)])
		}
		next++
		mu.Lock()
		done := injected
		mu.Unlock()
		if next == n {
			wg.Wait()
			mu.Lock()
			done = injected
			mu.Unlock()
			if seenInj >= done {
				break
			}
		}
	}
	wg.Wait()
	t.Logf("client msgs %d, injected ok %d, seen %d", next, injected, seenInj)
}
