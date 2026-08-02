package repeater

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"burpsy-go/pkg/store"
)

type Repeater struct {
	Store *store.TrafficStore
}

func NewRepeater(ts *store.TrafficStore) *Repeater {
	return &Repeater{Store: ts}
}

type SendResp struct {
	Status        uint16 `json:"status"`
	DurationMs    uint64 `json:"duration_ms"`
	Response      string `json:"response"`
	RequestMsgID  uint64 `json:"request_msg_id"`
	ResponseMsgID uint64 `json:"response_msg_id"`
	ExchangeID    uint64 `json:"exchange_id"`
}

func (r *Repeater) Send(target string, raw []byte, timeoutMs uint64, protocol store.Protocol) (interface{}, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("bad target: %v", err)
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

	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	started := time.Now()
	var conn net.Conn
	dialer := &net.Dialer{Timeout: timeout}

	if useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, portStr), &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = dialer.Dial("tcp", net.JoinHostPort(host, portStr))
	}

	if err != nil {
		return nil, fmt.Errorf("send failed to connect: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Write raw request bytes
	_, err = conn.Write(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to write request: %v", err)
	}

	// Read response using bufio and http.ReadResponse to easily fetch status and content
	reader := bufio.NewReader(conn)
	// We pass a dummy request to ReadResponse to parse the response correctly
	dummyReq := &http.Request{Method: "GET"}
	resp, err := http.ReadResponse(reader, dummyReq)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	defer resp.Body.Close()

	// Write the response back to bytes so we have exact copy
	var respBuf bytes.Buffer
	err = resp.Write(&respBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct response: %v", err)
	}

	respBytes := respBuf.Bytes()
	duration := time.Since(started)

	reqID := r.Store.Put(raw, store.Request)
	respID := r.Store.Put(respBytes, store.Response)

	method := "GET"
	parts := strings.Fields(string(raw))
	if len(parts) > 0 {
		method = parts[0]
	}
	path := "/"
	if len(parts) > 1 {
		path = parts[1]
	}

	ex := store.Exchange{
		Request:     reqID,
		Response:    &respID,
		Host:        host,
		Port:        port,
		TLS:         useTLS,
		Method:      method,
		Path:        path,
		Status:      uint16Ptr(uint16(resp.StatusCode)),
		ResponseLen: len(respBytes),
		StartedMs:   uint64(started.UnixNano() / 1e6),
		DurationMs:  uint64(duration.Milliseconds()),
		Protocol:    protocol,
	}

	exID := r.Store.AddExchange(ex)

	return SendResp{
		Status:        uint16(resp.StatusCode),
		DurationMs:    uint64(duration.Milliseconds()),
		Response:      string(respBytes),
		RequestMsgID:  uint64(reqID),
		ResponseMsgID: uint64(respID),
		ExchangeID:    exID,
	}, nil
}

func uint16Ptr(v uint16) *uint16 {
	return &v
}
