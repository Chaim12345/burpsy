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
