package jsexec

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func baseReq() ScriptRequest {
	return ScriptRequest{Method: "GET", URL: "https://api.test/v1/me", Headers: map[string]string{"Accept": "application/json"}}
}

// The acceptance of burpsy-react-ui-ydmj in one script: read a token from the last response, keep it
// in the store, put it on the request, and sign the request with an HMAC the target can verify.
func TestARequestScriptCanCaptureAToken_SignAndRewrite(t *testing.T) {
	src := `
		var body = JSON.parse(response.body);
		store.set("jwt", body.token);
		request.headers["Authorization"] = "Bearer " + store.get("jwt");
		request.headers["X-Sig"] = burpsy.hmacSha256Hex("k3y", request.method + " " + request.url);
		request.method = "POST";
		request.body = '{"ts":1}';
		delete request.headers["Accept"];
		log("signed", request.url);
	`
	res, err := RunRequestScript(src, baseReq(), &ScriptResponse{Status: 200, Body: `{"token":"abc.def"}`}, nil)
	if err != nil {
		t.Fatalf("RunRequestScript: %v", err)
	}
	if got := res.Request.Headers["Authorization"]; got != "Bearer abc.def" {
		t.Errorf("Authorization = %q", got)
	}
	m := hmac.New(sha256.New, []byte("k3y"))
	m.Write([]byte("GET https://api.test/v1/me"))
	if want := hex.EncodeToString(m.Sum(nil)); res.Request.Headers["X-Sig"] != want {
		t.Errorf("X-Sig = %q, want %q — the helper must compute the real HMAC-SHA256", res.Request.Headers["X-Sig"], want)
	}
	if res.Request.Method != "POST" || res.Request.Body != `{"ts":1}` {
		t.Errorf("method/body = %q %q", res.Request.Method, res.Request.Body)
	}
	if _, ok := res.Request.Headers["Accept"]; ok {
		t.Error("a header the script deleted is still on the request")
	}
	if res.Store["jwt"] != "abc.def" {
		t.Errorf("store = %v, want the captured token", res.Store)
	}
	if len(res.Log) != 1 || !strings.Contains(res.Log[0], "signed") {
		t.Errorf("log = %v", res.Log)
	}
}

// The store carries across runs: what one request captured, the next request reads.
func TestTheStoreCarriesATokenToTheNextRun(t *testing.T) {
	first, err := RunRequestScript(`store.set("n", "1")`, baseReq(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RunRequestScript(`request.headers["X-N"] = store.get("n")`, baseReq(), nil, first.Store)
	if err != nil {
		t.Fatal(err)
	}
	if second.Request.Headers["X-N"] != "1" {
		t.Errorf("X-N = %q; the store did not carry", second.Request.Headers["X-N"])
	}
}

// The sandbox: no network, no filesystem, no process. Asserted by name, because "the script cannot
// send a request" is the claim that makes running operator-written script on every send acceptable.
func TestTheScriptHasNoWayOutOfTheVM(t *testing.T) {
	for _, global := range []string{"require", "fetch", "XMLHttpRequest", "process", "module", "WebSocket", "setTimeout"} {
		res, err := RunRequestScript(`request.headers["X-T"] = typeof `+global, baseReq(), nil, nil)
		if err != nil {
			t.Fatalf("%s: %v", global, err)
		}
		if res.Request.Headers["X-T"] != "undefined" {
			t.Errorf("typeof %s = %q inside the script; it must not exist", global, res.Request.Headers["X-T"])
		}
	}
}

// The response is read-only: the script runs in strict mode and the object is frozen, so writing it
// throws rather than silently doing nothing.
func TestTheResponseIsReadOnly(t *testing.T) {
	_, err := RunRequestScript(`response.status = 500`, baseReq(), &ScriptResponse{Status: 200}, nil)
	if err == nil {
		t.Fatal("assigning to response succeeded; the last response must be read-only")
	}
}

// A script that throws, or never ends, yields an error and NO rewritten request — half a signature
// applied would be a request that looks signed and is not.
func TestAFailingScriptRewritesNothing(t *testing.T) {
	res, err := RunRequestScript(`request.headers["X-Half"] = "1"; throw new Error("boom")`, baseReq(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want the script's own error", err)
	}
	if res.Request.Method != "" || len(res.Request.Headers) != 0 {
		t.Errorf("a thrown script returned a request: %+v", res.Request)
	}
	if _, err := RunRequestScript(`while (true) {}`, baseReq(), nil, nil); !errors.Is(err, ErrTimeout) {
		t.Errorf("a non-terminating script = %v, want ErrTimeout", err)
	}
	if _, err := RunRequestScript(`request.url = ""`, baseReq(), nil, nil); err == nil {
		t.Error("a script that blanked the URL was accepted; a request with no URL cannot be sent")
	}
}

func TestCheckRequestScriptRefusesWhatCannotRun(t *testing.T) {
	if err := CheckRequestScript("request.headers[ = 1"); err == nil {
		t.Error("a syntax error compiled")
	}
	if err := CheckRequestScript("   "); err == nil {
		t.Error("an empty script was accepted")
	}
	if err := CheckRequestScript(strings.Repeat("x", MaxRequestScriptBytes+1)); err == nil {
		t.Error("an oversized script was accepted")
	}
}

// ---------------------------------------------------------------------------
// Sandbox boundary pins (1944 remediation): the script is an untrusted principal, so each bound is
// pinned at the point it is enforced, with the N and the N+1 case.
// ---------------------------------------------------------------------------

// The global object a script can enumerate carries the ECMAScript language, goja's GoError interop
// type, and exactly the five bindings this file installs - nothing else. A future change that binds
// a host object fails this pin by ADDITION; the bindings' presence is asserted too, so a blind
// probe cannot pass by finding nothing at all.
func TestTheGlobalObjectCarriesOnlyTheLanguageAndTheBindings(t *testing.T) {
	res, err := RunRequestScript(`request.body = Object.getOwnPropertyNames(globalThis).sort().join(",")`, baseReq(), nil, nil)
	if err != nil {
		t.Fatalf("enumerating the global object: %v", err)
	}
	language := []string{
		"AggregateError", "Array", "ArrayBuffer", "BigInt", "BigInt64Array", "BigUint64Array",
		"Boolean", "DataView", "Date", "Error", "EvalError", "Float32Array", "Float64Array",
		"Function", "GoError", "Infinity", "Int16Array", "Int32Array", "Int8Array", "JSON",
		"Map", "Math", "NaN", "Number", "Object", "Promise", "Proxy", "RangeError",
		"ReferenceError", "Reflect", "RegExp", "Set", "String", "Symbol", "SyntaxError",
		"TypeError", "URIError", "Uint16Array", "Uint32Array", "Uint8Array", "Uint8ClampedArray",
		"WeakMap", "WeakSet", "decodeURI", "decodeURIComponent", "encodeURI",
		"encodeURIComponent", "escape", "eval", "globalThis", "isFinite", "isNaN",
		"parseFloat", "parseInt", "undefined", "unescape",
	}
	bindings := []string{"request", "response", "store", "log", "burpsy"}
	allowed := map[string]bool{}
	for _, n := range append(language, bindings...) {
		allowed[n] = true
	}
	seen := map[string]bool{}
	for _, n := range strings.Split(res.Request.Body, ",") {
		seen[n] = true
		if !allowed[n] {
			t.Errorf("global %q is not the language and not one of this file's bindings - a host object must never appear here", n)
		}
	}
	for _, n := range bindings {
		if !seen[n] {
			t.Errorf("binding %q missing from the enumeration; the probe must be able to SEE bindings to be evidence their set is complete", n)
		}
	}
}

// Reaching a host capability by construction rather than by name: the Function constructor, eval,
// Reflect and Proxy all evaluate or read within the same host-less VM, so each finds nothing. And
// import() does not even compile - goja here has no module loader.
func TestNoHostCapabilityIsReachableByAnyConstruction(t *testing.T) {
	probes := map[string]string{
		"Function constructor": `Function("return typeof process + ',' + typeof fetch + ',' + typeof require + ',' + typeof XMLHttpRequest + ',' + typeof WebSocket")()`,
		"eval":                 `eval("typeof process + ',' + typeof fetch + ',' + typeof require")`,
		"Reflect.get":          `(function(){ var v = Reflect.get(globalThis, "process"); return typeof v; })()`,
		"Proxy over globalThis": `(function(){ var p = new Proxy(globalThis, {}); return typeof Reflect.get(p, "require"); })()`,
	}
	for name, expr := range probes {
		res, err := RunRequestScript(`request.body = String(`+expr+`)`, baseReq(), nil, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, got := range strings.Split(res.Request.Body, ",") {
			if got != "undefined" {
				t.Errorf("%s reached %q; no construction may reach a host capability", name, res.Request.Body)
			}
		}
	}
	if err := CheckRequestScript(`import("x")`); err == nil {
		t.Error("import() compiled; the sandbox has no module loader and dynamic import must stay impossible")
	}
}

// The store is bounded at WRITE time, inside the host-side set binding: 128 keys, 4 KiB per value,
// 256 KiB in all per run. Overflow throws a script-visible error - catchable, and when uncaught the
// run fails and NOTHING commits. Silent eviction is the xe82 failure shape; a credential store must
// forget nothing without saying so.
func TestTheStoreIsBoundedAtWriteTime(t *testing.T) {
	// N: exactly at each cap, the set succeeds.
	atCaps := `
		for (var i = 0; i < 128; i++) { store.set("k" + i, "v"); }
		store.set("big", "x".repeat(4096));
	`
	if _, err := RunRequestScript(atCaps, baseReq(), nil, nil); err != nil {
		t.Errorf("at the caps every set must succeed: %v", err)
	}
	// N+1 keys.
	if _, err := RunRequestScript(`for (var i = 0; i < 129; i++) { store.set("k" + i, "v"); }`, baseReq(), nil, nil); err == nil || !strings.Contains(err.Error(), "store full") {
		t.Errorf("the 129th key must be refused with a store-full error, got %v", err)
	}
	// N+1 bytes in one value.
	if _, err := RunRequestScript(`store.set("big", "x".repeat(4097))`, baseReq(), nil, nil); err == nil || !strings.Contains(err.Error(), "store full") {
		t.Errorf("a 4097-byte value must be refused with a store-full error, got %v", err)
	}
	// N+1 total bytes: 128 keys x 2 KiB values = 256 KiB of values alone; the keys' own bytes tip it over.
	full := `for (var i = 0; i < 128; i++) { store.set("k" + i, "x".repeat(2048)); }`
	if _, err := RunRequestScript(full, baseReq(), nil, nil); err == nil || !strings.Contains(err.Error(), "store full") {
		t.Errorf("past 256 KiB in all, a set must be refused with a store-full error, got %v", err)
	}
	// Just under the total cap it fits: 120 keys x 2 KiB values + short keys stays below 256 KiB.
	under := `for (var i = 0; i < 120; i++) { store.set("k" + i, "x".repeat(2048)); }`
	if _, err := RunRequestScript(under, baseReq(), nil, nil); err != nil {
		t.Errorf("under the total cap the sets must succeed: %v", err)
	}
	// The overflow error is script-visible AND catchable: a script that catches it runs on.
	caught := `
		var seen = "";
		try { store.set("big", "x".repeat(5000)); } catch (e) { seen = String(e); }
		request.headers["X-Seen"] = seen.indexOf("store full") >= 0 ? "caught" : "missed:" + seen;
	`
	res, err := RunRequestScript(caught, baseReq(), nil, nil)
	if err != nil {
		t.Fatalf("a caught store-full must not fail the run: %v", err)
	}
	if res.Request.Headers["X-Seen"] != "caught" {
		t.Errorf("the script could not catch its store-full error: %q", res.Request.Headers["X-Seen"])
	}
	// Uncaught, the run fails and the store does NOT commit: the next run sees none of it.
	first, err := RunRequestScript(`store.set("a", "1"); store.set("big", "x".repeat(5000))`, baseReq(), nil, nil)
	if err == nil {
		t.Fatal("the uncaught overflow must fail the run")
	}
	if first.Store != nil {
		t.Errorf("a failed run must commit no store, got %v", first.Store)
	}
}

// The log is bounded at write time: 20 entries, 512 characters each.
func TestTheLogIsBoundedAtWriteTime(t *testing.T) {
	res, err := RunRequestScript(`for (var i = 0; i < 25; i++) { log("line " + i); }`, baseReq(), nil, nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(res.Log) != 20 {
		t.Errorf("25 log calls kept %d entries; the cap is 20", len(res.Log))
	}
	res, err = RunRequestScript(`log("x".repeat(600))`, baseReq(), nil, nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(res.Log) != 1 || len([]rune(res.Log[0])) != 512+1 { // 512 chars + the ellipsis
		t.Errorf("a 600-character line must truncate to 512 plus an ellipsis, got %d characters", len([]rune(res.Log[0])))
	}
}
