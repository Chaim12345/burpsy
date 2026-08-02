package intruder

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"burpsy-go/pkg/store"
)

type Intruder struct {
	Store *store.TrafficStore
}

func NewIntruder(ts *store.TrafficStore) *Intruder {
	return &Intruder{Store: ts}
}

type PointView struct {
	Index   int    `json:"index"`
	Kind    string `json:"kind"`
	Label   string `json:"label"`
	Offset  int    `json:"offset"`
	Len     int    `json:"len"`
	Current string `json:"current"`
}

// Points discovers potential injection points in request path and query/body.
func (intr *Intruder) Points(msgID store.MsgID, all bool) (interface{}, error) {
	msg, ok := intr.Store.Get(msgID)
	if !ok {
		return nil, fmt.Errorf("message not found")
	}

	raw := string(msg.Raw)
	var points []PointView

	// Simple heuristic: find parameters in query string
	firstLine := raw
	if idx := strings.Index(raw, "\n"); idx != -1 {
		firstLine = raw[:idx]
	}

	parts := strings.Fields(firstLine)
	if len(parts) >= 2 {
		pathAndQuery := parts[1]
		if qIdx := strings.Index(pathAndQuery, "?"); qIdx != -1 {
			query := pathAndQuery[qIdx+1:]
			posInRaw := strings.Index(raw, "?") + 1
			for _, param := range strings.Split(query, "&") {
				kv := strings.SplitN(param, "=", 2)
				if len(kv) == 2 {
					valOffset := strings.Index(raw[posInRaw:], kv[1]) + posInRaw
					points = append(points, PointView{
						Index:   len(points),
						Kind:    "query_param",
						Label:   kv[0],
						Offset:  valOffset,
						Len:     len(kv[1]),
						Current: kv[1],
					})
				}
				posInRaw += len(param) + 1
			}
		}
	}

	return points, nil
}

type runReq struct {
	MsgID          uint64     `json:"msg_id"`
	Target         string     `json:"target"`
	Mode           string     `json:"mode"` // "sniper", "battering_ram", "pitchfork", "cluster_bomb"
	Points         []int      `json:"points"`
	PayloadSets    [][]string `json:"payload_sets"`
	Rps            float64    `json:"rps"`
	MaxInFlight    int        `json:"max_in_flight"`
	MaxRequests    int        `json:"max_requests"`
	TimeoutMs      uint64     `json:"timeout_ms"`
}

type AttemptView struct {
	Payload     string  `json:"payload"`
	Status      *uint16 `json:"status"`
	Len         int     `json:"len"`
	DurationMs  uint64  `json:"duration_ms"`
	Error       *string `json:"error"`
	GrepMatched *bool   `json:"grep_matched"`
}

func (intr *Intruder) Run(req interface{}) (interface{}, error) {
	// Re-serialize and decode to strongly-typed struct
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var r runReq
	err = json.Unmarshal(reqBytes, &r)
	if err != nil {
		return nil, err
	}

	msg, ok := intr.Store.Get(store.MsgID(r.MsgID))
	if !ok {
		return nil, fmt.Errorf("base message not found")
	}

	u, err := url.Parse(r.Target)
	if err != nil {
		return nil, fmt.Errorf("bad target url: %v", err)
	}

	host := u.Hostname()
	portStr := u.Port()
	useTLS := u.Scheme == "https"
	if portStr == "" {
		if useTLS {
			portStr = "443"
		} else {
			portStr = "80"
		}
	}
	portVal, _ := strconv.Atoi(portStr)
	port := uint16(portVal)

	// Fetch insertion points
	ptsVal, _ := intr.Points(store.MsgID(r.MsgID), true)
	pointsList := ptsVal.([]PointView)

	// Collect requested injection points
	var selectedPoints []PointView
	for _, idx := range r.Points {
		if idx < len(pointsList) {
			selectedPoints = append(selectedPoints, pointsList[idx])
		}
	}

	if len(selectedPoints) == 0 {
		// Default to first point if none selected
		if len(pointsList) > 0 {
			selectedPoints = append(selectedPoints, pointsList[0])
		} else {
			return nil, fmt.Errorf("no insertion points discovered or selected")
		}
	}

	// Generate payload combinations based on mode
	var combinations [][]string
	mode := strings.ToLower(r.Mode)
	if mode == "" {
		mode = "sniper"
	}

	sets := r.PayloadSets
	if len(sets) == 0 {
		sets = [][]string{{"testpayload"}}
	}

	switch mode {
	case "sniper":
		// For each selected point, inject each payload from set 0 in turn
		for _, pt := range selectedPoints {
			for _, p := range sets[0] {
				// sniper combination represents [pointIndex, payload]
				combinations = append(combinations, []string{strconv.Itoa(pt.Index), p})
			}
		}
	case "battering_ram":
		// Injects same payload into all points simultaneously
		for _, p := range sets[0] {
			comb := make([]string, len(selectedPoints))
			for i := range selectedPoints {
				comb[i] = p
			}
			combinations = append(combinations, comb)
		}
	case "pitchfork":
		// Lockstep
		minLen := len(sets[0])
		for _, set := range sets {
			if len(set) < minLen {
				minLen = len(set)
			}
		}
		for i := 0; i < minLen; i++ {
			comb := make([]string, len(selectedPoints))
			for j := range selectedPoints {
				if j < len(sets) && i < len(sets[j]) {
					comb[j] = sets[j][i]
				}
			}
			combinations = append(combinations, comb)
		}
	case "cluster_bomb":
		// Cartesian product
		combinations = cartesianProduct(sets)
	}

	// Cap requests if max requests is set
	if r.MaxRequests > 0 && len(combinations) > r.MaxRequests {
		combinations = combinations[:r.MaxRequests]
	}

	maxInFlight := r.MaxInFlight
	if maxInFlight <= 0 {
		maxInFlight = 10
	}

	var attempts []AttemptView
	var mu sync.Mutex

	// Dispatch attack requests with rate-limiting using goroutine pool
	sem := make(chan struct{}, maxInFlight)
	var wg sync.WaitGroup

	timeout := time.Duration(r.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	// Calculate RPS sleep delay if configured
	var delay time.Duration
	if r.Rps > 0 {
		delay = time.Duration(1e9/r.Rps) * time.Nanosecond
	}

	for _, comb := range combinations {
		if delay > 0 {
			time.Sleep(delay)
		}

		sem <- struct{}{}
		wg.Add(1)

		go func(c []string) {
			defer func() {
				<-sem
				wg.Done()
			}()

			// Build request payload bytes by replacing insertion point(s)
			reqBytes := splicePayloads(msg.Raw, selectedPoints, c, mode)

			started := time.Now()
			var conn net.Conn
			dialer := &net.Dialer{Timeout: timeout}
			var err error

			if useTLS {
				conn, err = tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, portStr), &tls.Config{
					InsecureSkipVerify: true,
				})
			} else {
				conn, err = dialer.Dial("tcp", net.JoinHostPort(host, portStr))
			}

			var status uint16
			var respBytes []byte

			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(timeout))
				_, err = conn.Write(reqBytes)
				if err == nil {
					reader := bufio.NewReader(conn)
					dummyReq := &http.Request{Method: "GET"}
					resp, err := http.ReadResponse(reader, dummyReq)
					if err == nil {
						status = uint16(resp.StatusCode)
						var respBuf bytes.Buffer
						_ = resp.Write(&respBuf)
						respBytes = respBuf.Bytes()
						resp.Body.Close()
					}
				}
				conn.Close()
			}

			duration := time.Since(started)

			// Store request/response to TrafficStore
			reqID := intr.Store.Put(reqBytes, store.Request)
			var respID store.MsgID
			if len(respBytes) > 0 {
				respID = intr.Store.Put(respBytes, store.Response)
			}

			// Add to exchanges
			method := "GET"
			parts := strings.Fields(string(reqBytes))
			if len(parts) > 0 {
				method = parts[0]
			}
			path := "/"
			if len(parts) > 1 {
				path = parts[1]
			}

			ex := store.Exchange{
				Request:     reqID,
				Host:        host,
				Port:        port,
				TLS:         useTLS,
				Method:      method,
				Path:        path,
				ResponseLen: len(respBytes),
				StartedMs:   uint64(started.UnixNano() / 1e6),
				DurationMs:  uint64(duration.Milliseconds()),
				Protocol:    store.Http1,
			}
			if len(respBytes) > 0 {
				ex.Response = &respID
				ex.Status = &status
			}
			intr.Store.AddExchange(ex)

			// Add attempt record
			payloadRep := strings.Join(c, ",")
			if mode == "sniper" && len(c) == 2 {
				payloadRep = c[1] // For sniper, show only the actual payload value
			}

			att := AttemptView{
				Payload:    payloadRep,
				Len:        len(respBytes),
				DurationMs: uint64(duration.Milliseconds()),
			}
			if status > 0 {
				att.Status = &status
			}
			if err != nil {
				errStr := err.Error()
				att.Error = &errStr
			}

			mu.Lock()
			attempts = append(attempts, att)
			mu.Unlock()

		}(comb)
	}

	wg.Wait()

	// Return flat list of attempts (matching the single-position leg of Burp UI's sniper runner)
	return attempts, nil
}

func splicePayloads(raw []byte, points []PointView, comb []string, mode string) []byte {
	// For sniper, comb has 2 values: [pointIndexStr, payloadValue]
	if mode == "sniper" {
		ptIdx, _ := strconv.Atoi(comb[0])
		var targetPt *PointView
		for _, pt := range points {
			if pt.Index == ptIdx {
				targetPt = &pt
				break
			}
		}
		if targetPt == nil {
			return raw
		}
		res := make([]byte, 0, len(raw)+len(comb[1]))
		res = append(res, raw[:targetPt.Offset]...)
		res = append(res, []byte(comb[1])...)
		res = append(res, raw[targetPt.Offset+targetPt.Len:]...)
		return res
	}

	// For multi-point modes, comb maps 1-to-1 with selected points
	// Let's replace backwards to avoid invalidating offsets!
	res := make([]byte, len(raw))
	copy(res, raw)

	for i := len(points) - 1; i >= 0; i-- {
		if i >= len(comb) {
			continue
		}
		pt := points[i]
		payload := comb[i]

		temp := make([]byte, 0, len(res)-pt.Len+len(payload))
		temp = append(temp, res[:pt.Offset]...)
		temp = append(temp, []byte(payload)...)
		temp = append(temp, res[pt.Offset+pt.Len:]...)
		res = temp
	}

	return res
}

func cartesianProduct(sets [][]string) [][]string {
	if len(sets) == 0 {
		return [][]string{}
	}
	res := [][]string{{}}
	for _, set := range sets {
		var next [][]string
		for _, r := range res {
			for _, item := range set {
				comb := append([]string{}, r...)
				comb = append(comb, item)
				next = append(next, comb)
			}
		}
		res = next
	}
	return res
}

func uint16Ptr(v uint16) *uint16 {
	return &v
}
