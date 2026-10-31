package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/web"
	"go.uber.org/zap"
)

var victimHits int64

func main() {
	// Safe local attack target: a plain HTTP victim on loopback that counts hits.
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt64(&victimHits, 1)
			b, _ := io.ReadAll(r.Body)
			fmt.Printf("VICTIM %s %s body=%q\n", r.Method, r.URL.RequestURI(), string(b))
			time.Sleep(400 * time.Millisecond) // keep the attack visibly running for UAT
			w.WriteHeader(200)
			_, _ = w.Write([]byte("victim-ok"))
		})
		_ = http.ListenAndServe("127.0.0.1:18098", mux)
	}()

	store := core.NewTrafficStore()
	put := func(body string, d core.Direction) uint64 {
		id, err := store.Put([]byte(body), d)
		if err != nil {
			panic(err)
		}
		return uint64(id)
	}
	for i := 0; i < 3; i++ {
		reqID := put(fmt.Sprintf("GET /p%d?a=%d HTTP/1.1\r\nHost: 127.0.0.1:18098\r\nCookie: sid=abc\r\n\r\n", i, i), core.DirectionRequest)
		respID := put("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 11\r\n\r\nhello world", core.DirectionResponse)
		status := uint16(200)
		store.AddExchange(&core.Exchange{Request: core.MsgPtr(core.MsgId(reqID)), Response: (*core.MsgId)(ptr(core.MsgId(respID))),
			Host: "127.0.0.1", Port: 18098, Method: "GET", Path: fmt.Sprintf("/p%d?a=%d", i, i), Status: &status, Source: core.SourceProxy})
	}
	// A JSON API exchange and an HTML page exchange, for the detail pane's syntax views.
	{
		reqID := put("GET /api/users HTTP/1.1\r\nHost: 127.0.0.1:18098\r\nAccept: application/json\r\n\r\n", core.DirectionRequest)
		respID := put("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n\r\n"+`{"users":[{"id":1,"name":"ada","admin":true},{"id":2,"name":"grace","admin":false}],"total":2,"note":null}`, core.DirectionResponse)
		status := uint16(200)
		store.AddExchange(&core.Exchange{Request: core.MsgPtr(core.MsgId(reqID)), Response: (*core.MsgId)(ptr(core.MsgId(respID))),
			Host: "127.0.0.1", Port: 18098, Method: "GET", Path: "/api/users", Status: &status, Source: core.SourceProxy})
	}
	{
		// A minified JavaScript asset: exercises JS detection, re-indenting and regex coloring.
		reqID := put("GET /static/app.js HTTP/1.1\r\nHost: 127.0.0.1:18098\r\n\r\n", core.DirectionRequest)
		respID := put("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"+`function cart(){var items=[];var re=/sku-[0-9]{3,}/g;var tax=1.5e-2;function add(sku){if(re.test(sku)){items.push({sku:sku,qty:1});}}return{add:add,count:function(){return items.length;}}}`, core.DirectionResponse)
		status := uint16(200)
		store.AddExchange(&core.Exchange{Request: core.MsgPtr(core.MsgId(reqID)), Response: (*core.MsgId)(ptr(core.MsgId(respID))),
			Host: "127.0.0.1", Port: 18098, Method: "GET", Path: "/static/app.js", Status: &status, Source: core.SourceProxy})
	}
	{
		reqID := put("GET /home HTTP/1.1\r\nHost: 127.0.0.1:18098\r\n\r\n", core.DirectionRequest)
		respID := put("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"+`<!doctype html><html><head><title>shop</title><style>body{margin:0}.x{color:red}</style></head><body><h1 class="x">Hi</h1><script>var a=1;// demo
function f(){return a}</script></body></html>`, core.DirectionResponse)
		status := uint16(200)
		store.AddExchange(&core.Exchange{Request: core.MsgPtr(core.MsgId(reqID)), Response: (*core.MsgId)(ptr(core.MsgId(respID))),
			Host: "127.0.0.1", Port: 18098, Method: "GET", Path: "/home", Status: &status, Source: core.SourceProxy})
	}
	srv := web.NewServer(store, core.NewScope())
	// A wired scanner so the Collaborator channel can be configured (POST
	// /api/collaborator/server refuses without one) and minted via the two-step page.
	srv.WithScanner(scanner.NewActiveScanner(store, zap.NewNop()))
	t := srv.Tasks().Start(dash.KindCrawl, "https://shop.test/", 10)
	t.Advance(4)
	go func() {
		time.Sleep(300 * time.Millisecond)
		req, _ := http.NewRequest(http.MethodPut, "http://127.0.0.1:18099/api/tools/rules", bytes.NewReader([]byte(`{"rules":[{"rule_type":"request_header","enabled":true,"string_match":"secret-cookie-marker","string_replace":"redacted-marker"}]}`)))
		req.Header.Set("Content-Type", "application/json")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		} else {
			fmt.Println("rules put:", err)
		}
		post := func(path string, body map[string]any) {
			b, _ := json.Marshal(body)
			if resp, err := http.Post("http://127.0.0.1:18099"+path, "application/json", bytes.NewReader(b)); err == nil {
				resp.Body.Close()
			} else {
				fmt.Println("seed post", path, err)
			}
		}
		post("/api/issues/record", map[string]any{"name": "Weak password policy", "description": "prose", "severity": "high", "exchange_id": 0})
	}()
	fmt.Println("listening on 127.0.0.1:18099, victim on 18098")
	if err := http.ListenAndServe("127.0.0.1:18099", srv.MCPGuarded()); err != nil {
		panic(err)
	}
}

func ptr(v core.MsgId) *core.MsgId { return &v }
