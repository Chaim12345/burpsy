package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"burpsy-go/pkg/scope"
	"burpsy-go/pkg/store"
)

type TlsPolicy struct {
	PassthroughHosts []string
	PassthroughPorts []uint16
}

func NewTlsPolicy() *TlsPolicy {
	return &TlsPolicy{
		PassthroughHosts: make([]string, 0),
		PassthroughPorts: make([]uint16, 0),
	}
}

func (tp *TlsPolicy) AddPassthrough(host string) {
	tp.PassthroughHosts = append(tp.PassthroughHosts, strings.ToLower(host))
}

func (tp *TlsPolicy) ShouldPassthrough(host string, port uint16) bool {
	h := strings.ToLower(host)
	for _, p := range tp.PassthroughPorts {
		if p == port {
			return true
		}
	}
	for _, pattern := range tp.PassthroughHosts {
		if pattern == h {
			return true
		}
		if strings.HasPrefix(pattern, "*.") && strings.HasSuffix(h, pattern[2:]) {
			return true
		}
	}
	return false
}

type HeldMessage struct {
	ID        uint64      `json:"id"`
	Direction string      `json:"direction"` // "request" or "response"
	Raw       string      `json:"raw"`
	Host      string      `json:"host"`
	Port      uint16      `json:"port"`
	TLS       bool        `json:"tls"`
	Done      chan []byte `json:"-"`
}

type Interceptor struct {
	mu      sync.Mutex
	Enabled bool
	Held    map[uint64]*HeldMessage
	NextID  uint64
}

func NewInterceptor() *Interceptor {
	return &Interceptor{
		Held: make(map[uint64]*HeldMessage),
	}
}

func (i *Interceptor) Add(dir string, raw []byte, host string, port uint16, tls bool) []byte {
	i.mu.Lock()
	if !i.Enabled {
		i.mu.Unlock()
		return raw
	}
	i.NextID++
	id := i.NextID
	hm := &HeldMessage{
		ID:        id,
		Direction: dir,
		Raw:       string(raw),
		Host:      host,
		Port:      port,
		TLS:       tls,
		Done:      make(chan []byte),
	}
	i.Held[id] = hm
	i.mu.Unlock()

	// Wait for operator decision
	modified := <-hm.Done
	return modified
}

func (i *Interceptor) Forward(id uint64, modified []byte) bool {
	i.mu.Lock()
	hm, ok := i.Held[id]
	if !ok {
		i.mu.Unlock()
		return false
	}
	delete(i.Held, id)
	i.mu.Unlock()

	hm.Done <- modified
	return true
}

func (i *Interceptor) Drop(id uint64) bool {
	i.mu.Lock()
	hm, ok := i.Held[id]
	if !ok {
		i.mu.Unlock()
		return false
	}
	delete(i.Held, id)
	i.mu.Unlock()

	hm.Done <- nil
	return true
}

func (i *Interceptor) List() []*HeldMessage {
	i.mu.Lock()
	defer i.mu.Unlock()
	res := make([]*HeldMessage, 0, len(i.Held))
	for _, hm := range i.Held {
		res = append(res, hm)
	}
	return res
}

type MatchReplaceRule struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"` // "request_header", "response_header", "request_body", "response_body"
	Match   string `json:"match"`
	Replace string `json:"replace"`
}

type MatchReplaceStore struct {
	Mu    sync.Mutex
	Rules []MatchReplaceRule
}

func NewMatchReplaceStore() *MatchReplaceStore {
	return &MatchReplaceStore{
		Rules: make([]MatchReplaceRule, 0),
	}
}

func (s *MatchReplaceStore) Apply(raw []byte, isRequest bool) []byte {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	for _, rule := range s.Rules {
		if !rule.Enabled {
			continue
		}
		isReqRule := strings.HasPrefix(rule.Type, "request")
		if isRequest != isReqRule {
			continue
		}
		raw = bytes.ReplaceAll(raw, []byte(rule.Match), []byte(rule.Replace))
	}
	return raw
}

type Proxy struct {
	BindAddr    string
	Store       *store.TrafficStore
	Scope       *scope.Scope
	CA          *CertAuthority
	Policy      *TlsPolicy
	Intercept   bool
	Interceptor *Interceptor
	MRStore     *MatchReplaceStore
	listener    net.Listener
	closed      chan struct{}
}

func NewProxy(bind string, ts *store.TrafficStore, sc *scope.Scope, ca *CertAuthority, policy *TlsPolicy, intercept bool) *Proxy {
	return &Proxy{
		BindAddr:    bind,
		Store:       ts,
		Scope:       sc,
		CA:          ca,
		Policy:      policy,
		Intercept:   intercept,
		Interceptor: NewInterceptor(),
		MRStore:     NewMatchReplaceStore(),
		closed:      make(chan struct{}),
	}
}

func (p *Proxy) Start() error {
	l, err := net.Listen("tcp", p.BindAddr)
	if err != nil {
		return err
	}
	p.listener = l

	go p.acceptLoop()
	return nil
}

func (p *Proxy) Close() error {
	close(p.closed)
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

func (p *Proxy) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.closed:
				return
			default:
				log.Printf("Proxy accept error: %v", err)
				continue
			}
		}
		go p.handleConnection(conn)
	}
}

func (p *Proxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	// Peek or read initial request line to check if it is a CONNECT request
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method == "CONNECT" {
		p.handleConnect(conn, req)
	} else {
		// Normal plain text HTTP request
		p.handlePlainHTTP(conn, req, reader)
	}
}

func (p *Proxy) handleConnect(clientConn net.Conn, req *http.Request) {
	hostPort := req.URL.Host
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		portStr = "443"
	}
	portVal, _ := strconv.Atoi(portStr)
	port := uint16(portVal)

	// Send 200 Connection Established to client
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	// Determine if we should decrypt or passthrough (blind tunnel)
	shouldPassthrough := !p.Intercept || p.CA == nil || p.Policy.ShouldPassthrough(host, port)

	if shouldPassthrough {
		p.tunnelBlind(clientConn, hostPort)
		return
	}

	// Decrypt via MITM: Generate leaf cert and establish TLS connection to client
	leafCert, err := p.CA.SignCertificate(host)
	if err != nil {
		log.Printf("Failed to sign dynamic certificate for %s: %v", host, err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
	}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	err = tlsClientConn.Handshake()
	if err != nil {
		// Handshake failures are common (e.g. untrusted CA in browser)
		return
	}
	defer tlsClientConn.Close()

	// Establish TLS connection to backend origin server
	targetConn, err := tls.Dial("tcp", hostPort, &tls.Config{
		InsecureSkipVerify: true, // Standard testing proxy behavior; optionally we can trust CA
	})
	if err != nil {
		return
	}
	defer targetConn.Close()

	p.pipeHTTP(tlsClientConn, targetConn, host, port, true, nil, nil)
}

func (p *Proxy) tunnelBlind(clientConn net.Conn, hostPort string) {
	targetConn, err := net.Dial("tcp", hostPort)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// Fully bidirectionally pipe connections
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(targetConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, targetConn)
		done <- struct{}{}
	}()
	<-done
}

func (p *Proxy) handlePlainHTTP(clientConn net.Conn, req *http.Request, reader *bufio.Reader) {
	hostPort := req.Host
	if hostPort == "" {
		hostPort = req.URL.Host
	}
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		portStr = "80"
	}
	portVal, _ := strconv.Atoi(portStr)
	port := uint16(portVal)

	targetConn, err := net.Dial("tcp", hostPort)
	if err != nil {
		resp := &http.Response{
			StatusCode: 502,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Body:       io.NopCloser(strings.NewReader("Bad Gateway: " + err.Error())),
		}
		resp.Write(clientConn)
		return
	}
	defer targetConn.Close()

	p.pipeHTTP(clientConn, targetConn, host, port, false, req, reader)
}

type pendingReq struct {
	reqID     store.MsgID
	inScope   bool
	method    string
	path      string
	startedAt time.Time
}

func (p *Proxy) pipeHTTP(clientConn, targetConn net.Conn, host string, port uint16, tlsConn bool, initialReq *http.Request, clientReader *bufio.Reader) {
	if clientReader == nil {
		clientReader = bufio.NewReader(clientConn)
	}
	targetReader := bufio.NewReader(targetConn)

	// Channel to correlate requests and responses in strict FIFO order
	pendingChan := make(chan pendingReq, 500)
	errChan := make(chan error, 2)

	// Goroutine 1: Read requests from client -> forward to target
	go func() {
		defer close(pendingChan)

		isFirst := initialReq != nil
		var req *http.Request
		var err error

		for {
			if isFirst {
				req = initialReq
				isFirst = false
			} else {
				req, err = http.ReadRequest(clientReader)
				if err != nil {
					errChan <- err
					return
				}
			}

			started := time.Now()
			reqBytes, err := reqToBytes(req)
			if err != nil {
				errChan <- err
				return
			}

			// Apply Match & Replace
			if p.MRStore != nil {
				reqBytes = p.MRStore.Apply(reqBytes, true)
			}

			var reqID store.MsgID
			path := req.URL.Path
			if path == "" {
				path = req.URL.RequestURI()
			}
			inScope := p.Scope.Contains(host, port, path, tlsConn)
			if inScope {
				// Call interceptor
				if p.Interceptor != nil {
					reqBytes = p.Interceptor.Add("request", reqBytes, host, port, tlsConn)
					if reqBytes == nil {
						errChan <- fmt.Errorf("request dropped by operator")
						return
					}
				}

				reqID = p.Store.Put(reqBytes, store.Request)
				pendingChan <- pendingReq{
					reqID:     reqID,
					inScope:   true,
					method:    req.Method,
					path:      path,
					startedAt: started,
				}
			} else {
				pendingChan <- pendingReq{
					reqID:     0,
					inScope:   false,
					method:    "",
					path:      "",
					startedAt: started,
				}
			}

			_, err = targetConn.Write(reqBytes)
			if err != nil {
				errChan <- err
				return
			}

			if req.Close {
				return
			}
		}
	}()

	// Goroutine 2: Read responses from target -> forward to client
	go func() {
		for {
			preq, ok := <-pendingChan
			if !ok {
				return
			}

			method := preq.method
			if method == "" {
				method = "GET"
			}
			reqObj := &http.Request{Method: method}

			resp, err := http.ReadResponse(targetReader, reqObj)
			if err != nil {
				errChan <- err
				return
			}

			duration := time.Since(preq.startedAt)
			respBytes, err := respToBytes(resp)
			if err != nil {
				errChan <- err
				return
			}

			// Apply Match & Replace
			if p.MRStore != nil {
				respBytes = p.MRStore.Apply(respBytes, false)
			}

			if preq.inScope {
				if p.Interceptor != nil {
					respBytes = p.Interceptor.Add("response", respBytes, host, port, tlsConn)
					if respBytes == nil {
						errChan <- fmt.Errorf("response dropped by operator")
						return
					}
				}

				respID := p.Store.Put(respBytes, store.Response)
				ex := store.Exchange{
					Request:     preq.reqID,
					Response:    &respID,
					Host:        host,
					Port:        port,
					TLS:         tlsConn,
					Method:      preq.method,
					Path:        preq.path,
					Status:      uint16Ptr(uint16(resp.StatusCode)),
					ResponseLen: len(respBytes),
					StartedMs:   uint64(preq.startedAt.UnixNano() / 1e6),
					DurationMs:  uint64(duration.Milliseconds()),
					Protocol:    store.Http1,
				}
				p.Store.AddExchange(ex)
			}

			_, err = clientConn.Write(respBytes)
			if err != nil {
				errChan <- err
				return
			}

			if resp.Close {
				return
			}
		}
	}()

	// Block until connection is closed or error occurs
	<-errChan
}

func reqToBytes(req *http.Request) ([]byte, error) {
	var buf bytes.Buffer
	err := req.Write(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func respToBytes(resp *http.Response) ([]byte, error) {
	var buf bytes.Buffer
	err := resp.Write(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func uint16Ptr(v uint16) *uint16 {
	return &v
}

func defaultCADir() string {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "."
	}
	return filepath.Join(home, ".burpsy-go", "ca")
}
