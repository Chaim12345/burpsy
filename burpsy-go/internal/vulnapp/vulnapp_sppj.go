package vulnapp

// Server-side prototype pollution fixtures (burpsy-react-ui-0vzb.3), for
// internal/scanner/checks_sppj.go.
//
// The vulnerable endpoint models a Node-style JSON API whose settings object is built by a
// recursive merge that does not drop "__proto__": a posted {"__proto__":{"json spaces":10}}
// lands on the prototype every later serialisation reads, so responses come back indented ten
// spaces where they were compact before; {"__proto__":{"status":510}} makes the endpoint's ERROR
// answers carry 510. Both are the non-destructive detection techniques PortSwigger documents, and
// both revert: a 0 / null value restores the default. The safe twin drops "__proto__" at the
// merge, so the same probes change nothing.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// sppjPrototype is the simulated polluted prototype: process-wide, like Object.prototype.
var sppjPrototype = struct {
	sync.Mutex
	jsonSpaces int
	hasSpaces  bool
	status     int
	hasStatus  bool
}{}

// sppjMerge simulates the vulnerable merge: a top-level "__proto__" member's own members are
// folded into the shared prototype. safe=true drops the member instead.
func sppjMerge(body []byte, safe bool) {
	var doc map[string]json.RawMessage
	if json.Unmarshal(body, &doc) != nil {
		return
	}
	raw, ok := doc["__proto__"]
	if !ok || safe {
		return
	}
	var proto map[string]json.RawMessage
	if json.Unmarshal(raw, &proto) != nil {
		return
	}
	sppjPrototype.Lock()
	defer sppjPrototype.Unlock()
	for k, v := range proto {
		switch k {
		case "json spaces":
			var n int
			if json.Unmarshal(v, &n) == nil {
				sppjPrototype.jsonSpaces, sppjPrototype.hasSpaces = n, true
			}
			if string(v) == "null" {
				sppjPrototype.jsonSpaces, sppjPrototype.hasSpaces = 0, false
			}
		case "status":
			var n int
			if json.Unmarshal(v, &n) == nil {
				sppjPrototype.status, sppjPrototype.hasStatus = n, true
			}
			if string(v) == "null" {
				sppjPrototype.status, sppjPrototype.hasStatus = 0, false
			}
		}
	}
}

func sppjIndent() string {
	sppjPrototype.Lock()
	defer sppjPrototype.Unlock()
	if sppjPrototype.hasSpaces {
		return strings.Repeat(" ", sppjPrototype.jsonSpaces)
	}
	return ""
}

func sppjErrorStatus() int {
	sppjPrototype.Lock()
	defer sppjPrototype.Unlock()
	if sppjPrototype.hasStatus {
		return sppjPrototype.status
	}
	return http.StatusBadRequest
}

// sppjJSON answers the profile read with the prototype's indentation; an unparsable body is the
// error path whose status the pollution moves.
func sppjJSON(w http.ResponseWriter, r *http.Request, safe bool) {
	body := make([]byte, r.ContentLength)
	_, _ = r.Body.Read(body)
	sppjMerge(body, safe)
	var doc map[string]json.RawMessage
	if json.Unmarshal(body, &doc) != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(sppjErrorStatus())
		fmt.Fprint(w, `{"error":"bad json"}`)
		return
	}
	out := map[string]any{"ok": true, "saved": len(doc)}
	var buf []byte
	var err error
	if indent := sppjIndent(); indent != "" {
		buf, err = json.MarshalIndent(out, "", indent)
	} else {
		buf, err = json.Marshal(out)
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(buf)
}

func sppjEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/sppj/json/profile", Method: http.MethodPost, Row: "Server-side prototype pollution",
			Body: `{"name":"carlos","role":"user"}`, ContentType: "application/json",
			Note: "recursive-merge settings API that keeps __proto__ members on the shared prototype"},
		{Path: "/sppj/safe/json/profile", Method: http.MethodPost, Row: "Server-side prototype pollution",
			Safe: true, Body: `{"name":"carlos","role":"user"}`, ContentType: "application/json",
			Note: "the same API, dropping __proto__ at the merge"},
	}
}

func registerSPPJ(mux *http.ServeMux) {
	mux.HandleFunc("/sppj/json/profile", func(w http.ResponseWriter, r *http.Request) { sppjJSON(w, r, false) })
	mux.HandleFunc("/sppj/safe/json/profile", func(w http.ResponseWriter, r *http.Request) { sppjJSON(w, r, true) })
}
