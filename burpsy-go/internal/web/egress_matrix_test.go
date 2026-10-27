package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// Every riskEgress/riskAttack route, aimed at a listener the scope excludes, must open no connection.
func TestEveryEgressAndAttackRouteRefusesAnOutOfScopeTarget(t *testing.T) {
	accepted, total, exercised := driveEgressMatrix(t, false)
	t.Logf("%d egress/attack route-verbs driven, %d answered 2xx", total, exercised)
	if total < 20 {
		t.Fatalf("only %d egress/attack route-verbs found in the manifest; the matrix is not seeing the surface", total)
	}
	if accepted != 0 {
		t.Fatalf("an out-of-scope listener accepted %d connection(s) from routes that must refuse it", accepted)
	}
}

// Positive control: with the listener in scope the same drive must connect.
func TestTheEgressMatrixReachesAnInScopeListener(t *testing.T) {
	accepted, total, _ := driveEgressMatrix(t, true)
	if accepted == 0 {
		t.Fatalf("%d egress/attack route-verbs driven at an IN-scope listener and none connected: the matrix cannot see a send", total)
	}
	t.Logf("in scope: %d connection(s) from %d route-verbs", accepted, total)
}

func driveEgressMatrix(t *testing.T, inScope bool) (accepted int64, total, exercised int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var acceptedN atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			acceptedN.Add(1)
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	target := fmt.Sprintf("http://127.0.0.1:%d/x?q=1", port)
	rawReq := fmt.Sprintf("GET /x?q=1 HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", port)

	scope := core.NewScope()
	scope.AddInclude("allowed.test") // the listener (127.0.0.1) is out of scope...
	if inScope {
		scope.AddInclude("127.0.0.1") // ...except in the positive control
	}
	store := core.NewTrafficStore()
	reqID, _ := store.Put([]byte(rawReq), core.DirectionRequest)
	respID, _ := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), core.DirectionResponse)
	store.AddExchange(&core.Exchange{Host: "127.0.0.1", Port: uint16(port), Method: "GET", Path: "/x?q=1",
		Request: core.MsgPtr(reqID), Response: &respID})
	cfg := sender.DefaultSenderConfig()
	cfg.Timeout = 2 * time.Second
	snd := sender.NewSender(cfg)
	s := NewServer(store, scope).WithSender(snd).WithScanner(scanner.NewActiveScanner(store, zap.NewNop()))

	fill := bodyFiller{target: target, raw: rawReq, port: port}
	var hung []string
	patterns := make([]string, 0, len(manifest))
	for p := range manifest {
		patterns = append(patterns, p)
	}
	sort.Strings(patterns)
	for _, pattern := range patterns {
		r := manifest[pattern]
		if r.risk != riskEgress && r.risk != riskAttack {
			continue
		}
		for _, method := range r.methods {
			if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
				continue
			}
			path := egressMatrixPath(pattern, r.subPath)
			if !strings.HasPrefix(path, "/") {
				continue
			}
			var body []byte
			if tmpl, ok := egressBodyTemplates[method+" "+path]; ok {
				body = []byte(fill.expand(tmpl))
			} else if sch, ok := routeSchemas[method+" "+pattern]; ok && sch.body != nil {
				body, _ = json.Marshal(fill.value(sch.body, "", 0))
			} else {
				body = []byte("{}")
			}
			total++
			before := acceptedN.Load()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			req := httptest.NewRequest(method, path, bytes.NewReader(body)).WithContext(ctx)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { s.mux.ServeHTTP(rec, req); close(done) }()
			select {
			case <-done:
				if rec.Code >= 200 && rec.Code < 300 {
					exercised++
				}
				time.Sleep(150 * time.Millisecond)
				if d := acceptedN.Load() - before; d > 0 && !inScope {
					t.Errorf("%s %s reached the out-of-scope listener (%d connection(s)); answered %d %.160s",
						method, path, d, rec.Code, strings.TrimSpace(rec.Body.String()))
				}
				if testing.Verbose() && inScope {
					t.Logf("%s %s -> %d %.120s", method, path, rec.Code, strings.TrimSpace(rec.Body.String()))
				}
			case <-time.After(5 * time.Second):
				hung = append(hung, method+" "+path)
			}
			cancel()
		}
	}
	time.Sleep(1500 * time.Millisecond) // background tasks a route started get their chance to send
	if len(hung) > 0 {
		t.Logf("still running after 5s: %v", hung)
	}
	return acceptedN.Load(), total, exercised
}

// egressMatrixPath turns a manifest pattern into a requestable path.
func egressMatrixPath(pattern, subPath string) string {
	if subPath != "" {
		return subPath
	}
	var out []string
	for _, seg := range strings.Split(pattern, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			if seg == "{$}" {
				continue
			}
			seg = "0"
		}
		out = append(out, seg)
	}
	return strings.Join(out, "/")
}

// Minimal valid bodies where the generic filler cannot satisfy the handler (enums, base64, specs).
var egressBodyTemplates = map[string]string{
	"POST /api/repeater/send":            `{"request":RAW,"target":ORIGIN}`,
	"POST /api/repeater/send-group":      `{"mode":"sequence_separate_conn","items":[{"request":RAW,"target":ORIGIN,"tab_id":"a"},{"request":RAW,"target":ORIGIN,"tab_id":"b"}]}`,
	"POST /api/repeater/ws-send":         `{"target":ORIGIN,"path":"/x","opcode":"text","payload":"x"}`,
	"POST /api/repeater/browser-reissue": `{"exchange":0}`,
	"POST /api/crawl":                    `{"kind":"crawl","seeds":[TARGET],"max_requests":5}`,
	"POST /api/scanner/audit":            `{"exchange_id":0}`,
	"POST /api/audit/0":                  `{}`,
	"POST /api/audit/selected":           `{"exchange_ids":[0]}`,
	"POST /api/discovery":                `{"target":TARGET,"lists":["builtin-short-files"]}`,
	"POST /api/sequencer/capture":        `{"request":RAW,"target":ORIGIN,"count":2,"location":{"kind":"cookie","name":"s"}}`,
	"POST /api/hidden-inputs":            `{"exchange_id":0,"kinds":["query"],"max_requests":3}`,
	"POST /api/apiscan/fetch":            `{"url":TARGET}`,
	"POST /api/apiscan":                  `{"base_url":ORIGIN,"definition":"openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths: {/x: {get: {}}}"}`,
	"POST /api/protobuf/reflect-decode":  `{"body_base64":"","message":"x.Y","reflect":{"target":HOSTPORT,"service":"x.S"}}`,
	"POST /api/http2/program":            `{"host":"127.0.0.1","port":PORT,"frames":[],"preface":true,"read_for_ms":200}`,
	"POST /api/intruder/run":             `{"msg_id":0,"target":ORIGIN,"payload_sets":[["a"]],"mode":"sniper"}`,
}

func (f bodyFiller) expand(tmpl string) string {
	q := func(v string) string { b, _ := json.Marshal(v); return string(b) }
	origin := strings.TrimSuffix(strings.SplitN(f.target, "/x", 2)[0], "/")
	r := strings.NewReplacer(
		"RAWB64", q(base64.StdEncoding.EncodeToString([]byte(f.raw))),
		"RAW", q(f.raw),
		"TARGET", q(f.target),
		"ORIGIN", q(origin),
		"HOSTPORT", q(strings.TrimPrefix(origin, "http://")),
		"PORT", strconv.Itoa(f.port),
	)
	return r.Replace(tmpl)
}

// bodyFiller builds a request body for a handler's request type, pointing every target-shaped field
// at the excluded listener.
type bodyFiller struct {
	target, raw string
	port        int
}

func (f bodyFiller) value(t reflect.Type, name string, depth int) any {
	if depth > 4 {
		return nil
	}
	n := strings.ToLower(name)
	switch t.Kind() {
	case reflect.Pointer:
		return f.value(t.Elem(), name, depth)
	case reflect.String:
		switch {
		case strings.Contains(n, "url") || strings.Contains(n, "target") || n == "base" || n == "origin":
			return f.target
		case strings.Contains(n, "host"):
			return "127.0.0.1"
		case strings.Contains(n, "raw") || n == "request" || n == "base_request" || n == "template":
			return f.raw
		case n == "method":
			return "GET"
		case strings.Contains(n, "path"):
			return "/x"
		case strings.Contains(n, "port"):
			return strconv.Itoa(f.port)
		}
		return "x"
	case reflect.Bool:
		return false
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if strings.Contains(n, "port") {
			return f.port
		}
		if strings.Contains(n, "id") {
			return 0
		}
		return 1
	case reflect.Float32, reflect.Float64:
		return 1
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return []byte(f.raw)
		}
		return []any{f.value(t.Elem(), strings.TrimSuffix(name, "s"), depth+1)}
	case reflect.Struct:
		obj := map[string]any{}
		for i := 0; i < t.NumField(); i++ {
			fd := t.Field(i)
			if !fd.IsExported() {
				continue
			}
			tag := strings.Split(fd.Tag.Get("json"), ",")[0]
			if tag == "-" {
				continue
			}
			if tag == "" {
				tag = fd.Name
			}
			if fd.Anonymous && tag == fd.Name {
				if m, ok := f.value(fd.Type, "", depth+1).(map[string]any); ok {
					for k, v := range m {
						obj[k] = v
					}
				}
				continue
			}
			obj[tag] = f.value(fd.Type, tag, depth+1)
		}
		return obj
	}
	return nil
}
