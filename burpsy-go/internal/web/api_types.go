package web

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ExchangeView is the wire shape every exchange-facing endpoint serves. It mirrors the
// `Exchange` interface in the UI's types.ts: ids into the message store rather than payloads,
// `null` (never `0`) for an absent response or status, and a protocol token the UI switches on.
type ExchangeView struct {
	ID          uint64  `json:"id"`
	Request     uint64  `json:"request"`
	Response    *uint64 `json:"response"`
	Host        string  `json:"host"`
	Port        uint16  `json:"port"`
	TLS         bool    `json:"tls"`
	Method      string  `json:"method"`
	Path        string  `json:"path"`
	Status      *uint16 `json:"status"`
	ResponseLen int     `json:"response_len"`
	StartedMs   uint64  `json:"started_ms"`
	DurationMs  uint64  `json:"duration_ms"`
	Notes       *string `json:"notes"`
	Related     []any   `json:"related"`
	Protocol    string  `json:"protocol"`
}

// MessageView is the wire shape for a stored message: id, byte length, and a lossy UTF-8 text
// rendering. The UI's comparer and history viewer slice by byte offsets into this text, so `len`
// is the raw byte count, not the string rune count.
type MessageView struct {
	ID   uint64 `json:"id"`
	Len  int    `json:"len"`
	Text string `json:"text"`
}

// StatsView mirrors the UI's Stats interface.
type StatsView struct {
	Exchanges   int   `json:"exchanges"`
	Messages    int   `json:"messages"`
	StoredBytes int64 `json:"stored_bytes"`
}

// FindingView is the legacy /api/findings wire shape.
type FindingView struct {
	ID          uint64 `json:"id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Description string `json:"description"`
}

func protocolToken(p core.Protocol) string {
	if p == core.ProtocolHTTP2 {
		return "Http2"
	}
	return "Http1"
}

func exchangeView(ex *core.Exchange) *ExchangeView {
	var resp *uint64
	if ex.Response != nil {
		id := uint64(*ex.Response)
		resp = &id
	}
	return &ExchangeView{
		ID:          ex.ID,
		Request:     uint64(ex.Request),
		Response:    resp,
		Host:        ex.Host,
		Port:        ex.Port,
		TLS:         ex.TLS,
		Method:      ex.Method,
		Path:        ex.Path,
		Status:      ex.Status,
		ResponseLen: ex.ResponseLen,
		StartedMs:   ex.StartedMs,
		DurationMs:  ex.DurationMs,
		Notes:       ex.Notes,
		Related:     []any{},
		Protocol:    protocolToken(ex.Protocol),
	}
}

func messageView(msg *core.StoredMessage) *MessageView {
	return &MessageView{
		ID:   uint64(msg.ID),
		Len:  msg.Len(),
		Text: string(msg.Raw()),
	}
}

func (s *Server) message(id uint64) (*core.StoredMessage, error) {
	return s.store.Get(core.MsgId(id))
}

// targetParts splits a UI "target" of the form http://host:port, https://host, or host:port into
// host, port, and whether TLS should be used. Port defaults per scheme.
func targetParts(target string) (host string, port uint16, tls bool, err error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, false, fmt.Errorf("empty target")
	}
	scheme := ""
	if i := strings.Index(target, "://"); i >= 0 {
		scheme = target[:i]
		target = target[i+3:]
	}
	switch strings.ToLower(scheme) {
	case "https":
		tls = true
	case "http", "":
		tls = false
	default:
		return "", 0, false, fmt.Errorf("unknown scheme %q", scheme)
	}

	// Strip any path/query that got pasted in; the tools send raw requests, not URLs.
	if i := strings.IndexAny(target, "/?"); i >= 0 {
		target = target[:i]
	}

	h, p, err := net.SplitHostPort(target)
	if err != nil {
		// Bare host: no port. Keep it as-is; SplitHostPort is only happy with "host:port".
		if strings.Count(target, ":") == 0 {
			h = target
			p = "0"
		} else {
			return "", 0, false, fmt.Errorf("malformed target %q: %w", target, err)
		}
	}
	if p == "0" || p == "" {
		if tls {
			p = "443"
		} else {
			p = "80"
		}
	}
	portInt, err := strconv.Atoi(p)
	if err != nil || portInt < 1 || portInt > 65535 {
		return "", 0, false, fmt.Errorf("invalid port %q", p)
	}
	return h, uint16(portInt), tls, nil
}

// parseRequestTarget extracts scheme/host/port/tls from a target string the way every tool handler
// needs it, returning a ready-to-dial authority.
func parseRequestTarget(target string) (host string, port uint16, tls bool, err error) {
	return targetParts(target)
}

// splitHostPort is a small helper for messages that carry host:port already.
func splitHostPort(hostPort string) (string, uint16) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		if i := strings.LastIndex(hostPort, ":"); i >= 0 {
			return hostPort[:i], atou16(hostPort[i+1:], 80)
		}
		return hostPort, 80
	}
	return host, atou16(portStr, 80)
}

func atou16(s string, def uint16) uint16 {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return def
	}
	return uint16(n)
}

// unescapePathParam decodes a single percent-encoded component without tripping over a '+' that
// was never a space (path segments use %20, query strings use '+').
func unescapePathParam(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}
