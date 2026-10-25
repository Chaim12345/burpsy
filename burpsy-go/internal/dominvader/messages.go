package dominvader

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

const MessageTimeout = 30 * time.Second
const MaxMessageBody = 1 << 20
const MaxHeldMessages = 100

var ErrUnknownHold = errors.New("unknown or expired hold")

// Message is an untrusted page observation, never authority for server commands.
// Body is JSON so replay can preserve strings, arrays and objects. Ports cannot
// be serialized and are explicitly marked non-replayable.
type Message struct {
	ID        uint64    `json:"id"`
	Frame     string    `json:"frame"`
	Tab       int       `json:"tab"`
	Body      string    `json:"body"`
	Origin    string    `json:"origin"`
	State     string    `json:"state"`
	HoldID    string    `json:"hold_id,omitempty"`
	HasPorts  bool      `json:"has_ports"`
	Synthetic bool      `json:"synthetic"`
	Expires   time.Time `json:"expires"`
}

type MessageDecision struct {
	HoldID    string `json:"hold_id"`
	Action    string `json:"action"`
	Body      string `json:"body"`
	Origin    string `json:"origin"`
	Synthetic bool   `json:"synthetic"`
}
type messageFrame struct {
	tab     int
	name    string
	expires time.Time
}
type messageHold struct {
	frame     string
	message   *Message
	decision  *MessageDecision
	delivered bool
}

// MessageStore owns a bounded untrusted log and per-frame decision mailboxes.
// Frame tokens and hold IDs come from the server, never page-supplied IDs.
type MessageStore struct {
	mu     sync.Mutex
	next   uint64
	frames map[string]messageFrame
	held   map[string]*messageHold
	log    []*Message
	// intercept is controller-owned. Only SetIntercept (console route) writes it;
	// no worker report, frame token or message field can change it.
	intercept bool
}

func (s *MessageStore) SetIntercept(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.intercept = on
}
func (s *MessageStore) Intercept() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.intercept
}

func NewMessageStore() *MessageStore {
	return &MessageStore{frames: map[string]messageFrame{}, held: map[string]*messageHold{}}
}
func messageToken() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("cannot create message session token")
	}
	return hex.EncodeToString(b[:])
}

func (s *MessageStore) OpenFrame(tab int, frame string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, f := range s.frames {
		if now.After(f.expires) {
			delete(s.frames, k)
		}
	}
	if len(s.frames) >= 2000 {
		return ""
	}
	token := messageToken()
	s.frames[token] = messageFrame{tab: tab, name: frame, expires: now.Add(time.Hour)}
	return token
}
func (s *MessageStore) frameLocked(token string, now time.Time) (messageFrame, error) {
	f, ok := s.frames[token]
	if !ok || now.After(f.expires) {
		return f, errors.New("unknown or expired frame session")
	}
	return f, nil
}

func (s *MessageStore) Record(token string, m Message, now time.Time) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	f, err := s.frameLocked(token, now)
	if err != nil {
		return Message{}, err
	}
	if len(m.Body) > MaxMessageBody || !json.Valid([]byte(m.Body)) {
		return Message{}, errors.New("message body must be JSON within 1 MiB")
	}
	s.next++
	m.ID = s.next
	m.Tab = f.tab
	m.Frame = f.name
	m.HoldID = ""
	m.Expires = time.Time{}
	m.State = "observed"
	if m.HasPorts {
		m.State = "not-replayable-ports"
	} else if s.intercept {
		if len(s.held) >= MaxHeldMessages {
			m.State = "forwarded-queue-full"
		} else {
			m.State = "held"
			m.HoldID = messageToken()
			m.Expires = now.Add(MessageTimeout)
			s.held[m.HoldID] = &messageHold{frame: token, message: &m}
		}
	}
	s.log = append(s.log, &m)
	if len(s.log) > 2000 {
		// A held observation must remain visible until its timeout/decision.
		// At most 100 rows are held, so a non-held row always exists.
		for i, row := range s.log {
			if row.State != "held" {
				s.log = append(s.log[:i], s.log[i+1:]...)
				break
			}
		}
	}
	return m, nil
}
func (s *MessageStore) expireLocked(now time.Time) {
	for id, h := range s.held {
		if !now.Before(h.message.Expires) {
			switch {
			case h.delivered:
				// The worker received the decision but never reported back.
				h.message.State = h.decision.Action + "-delivered-unacknowledged"
			default:
				h.message.State = "forwarded-on-timeout"
			}
			delete(s.held, id)
		}
	}
}

// ControllerDecide records the operator's decision for a server-issued hold ID.
// It is reachable only from the console controller route. The owning frame is
// resolved from the server-side hold, never from any caller-supplied token, and
// the decision is only delivered to that frame's own Poll.
func (s *MessageStore) ControllerDecide(id string, d MessageDecision, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	h, ok := s.held[id]
	if !ok {
		return ErrUnknownHold
	}
	if h.decision != nil {
		return errors.New("hold already decided")
	}
	if d.Action != "forward" && d.Action != "drop" {
		return fmt.Errorf("action must be forward or drop")
	}
	if d.Action == "forward" && (len(d.Body) > MaxMessageBody || !json.Valid([]byte(d.Body))) {
		return errors.New("forward body must be JSON within 1 MiB")
	}
	d.HoldID = id
	d.Synthetic = d.Action == "forward"
	h.decision = &d
	return nil
}

// Poll hands a frame its own decided holds once. Delivery to the worker is not
// application by the page; the hold stays open for that frame's Acknowledge.
func (s *MessageStore) Poll(token string, now time.Time) []MessageDecision {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	out := []MessageDecision{}
	if _, err := s.frameLocked(token, now); err != nil {
		return out
	}
	for _, h := range s.held {
		if h.frame == token && h.decision != nil && !h.delivered {
			out = append(out, *h.decision)
			h.delivered = true
			h.message.State = h.decision.Action + "-decision-delivered-to-worker"
		}
	}
	return out
}

// Acknowledge is the owning frame's worker reporting that it attempted dispatch.
// It is an untrusted claim about the worker's own action: MAIN-world code can
// still tamper with or ignore the page-side delivery, so no state claims "applied".
func (s *MessageStore) Acknowledge(token, id, outcome string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	if _, err := s.frameLocked(token, now); err != nil {
		return err
	}
	h, ok := s.held[id]
	if !ok || h.frame != token || !h.delivered {
		return errors.New("no delivered decision for this frame")
	}
	if outcome != "dispatched" && outcome != "failed" {
		return errors.New("outcome must be dispatched or failed")
	}
	h.message.State = h.decision.Action + "-worker-reported-" + outcome + "-unverified"
	delete(s.held, id)
	return nil
}
func (s *MessageStore) Messages(now time.Time) []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	out := make([]Message, len(s.log))
	for i, m := range s.log {
		out[i] = *m
	}
	return out
}
