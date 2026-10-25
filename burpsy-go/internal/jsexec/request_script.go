package jsexec

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// ---------------------------------------------------------------------------
// Pre-request scripts (burpsy-react-ui-ydmj)
// ---------------------------------------------------------------------------
//
// A short script that rewrites an outgoing request just before it is sent — refresh a JWT captured
// from a login response, recompute a request signature, stamp a nonce or a timestamp. Burp does this
// with Montoya pre-request handlers and Caido with pre-request scripts; burpsy had the engine (this
// package) and the hook point (session-rule actions) and nothing joining them.
//
// # The sandbox is the package's own, unchanged
//
// The script runs under run(): a fresh VM, a hard interrupt, and no host binding to the filesystem,
// the network or the process. What it is given is DATA — the request, a read-only view of the last
// response, a small string store — and a handful of PURE helpers (HMAC, SHA-256, base64, random
// bytes) that compute and return values. None of them reaches outside the VM, so the script can sign
// a request but cannot send one.

// RequestScriptTimeout bounds one script run. A pre-request script runs on every matching send, so a
// slow one slows every request the rule covers; anything that needs longer than this is doing more
// than rewriting a request.
const RequestScriptTimeout = 500 * time.Millisecond

// MaxRequestScriptBytes bounds a script's source. A pre-request script is a few lines; the bound
// stops a pasted bundle from being run on every send.
const MaxRequestScriptBytes = 64 * 1024

// maxScriptLog bounds what log() keeps per run, entries and characters, so a script logging in a loop
// cannot grow a trace without bound.
const (
	maxScriptLogEntries = 20
	maxScriptLogChars   = 512
)

// The store's write-time bounds (1944): 128 keys, 4 KiB per value, 256 KiB in all per run,
// enforced inside the set binding below - host-side interception, so a script cannot write past a
// cap and have it caught later. Overflow throws a script-visible TypeError (catchable; uncaught it
// fails the run and NOTHING commits - a credential store forgets nothing silently).
const (
	maxScriptStoreKeys       = 128
	maxScriptStoreValueBytes = 4 * 1024
	maxScriptStoreTotalBytes = 256 * 1024
)

// StoreFullPrefix starts every store-overflow TypeError message; ErrStoreFull wraps the run's
// error when that is what failed it, so a caller can classify the failure without parsing text.
const StoreFullPrefix = "store full: "

// ErrStoreFull marks a run failed by the store's write-time bounds.
var ErrStoreFull = errors.New(StoreFullPrefix + "the store's bounds were exceeded")

// ScriptRequest is the outgoing request as the script sees and returns it.
type ScriptRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// ScriptResponse is the last observed response, read-only to the script. Nil when there is none.
type ScriptResponse struct {
	Status  int
	Headers map[string]string
	Body    string
}

// ScriptResult is what a run produced: the request to send, the store as the script left it, and its
// log lines.
type ScriptResult struct {
	Request ScriptRequest
	Store   map[string]string
	Log     []string
}

// CheckRequestScript compiles a script without running it, so a rule with a syntax error is refused
// when it is installed rather than failing on every request it covers.
func CheckRequestScript(src string) error {
	if strings.TrimSpace(src) == "" {
		return errors.New("the script is empty")
	}
	if len(src) > MaxRequestScriptBytes {
		return fmt.Errorf("the script is %d bytes, above the %d-byte bound for a pre-request script", len(src), MaxRequestScriptBytes)
	}
	if _, err := goja.Compile("pre-request-script", src, true); err != nil {
		return fmt.Errorf("the script does not compile: %v", err)
	}
	return nil
}

// RunRequestScript runs src with `request` (mutable), `response` (frozen, or null), `store` and the
// helpers bound, and returns the request as the script left it.
//
// On any error — a throw, a timeout, a request left in a shape that is not a request — the caller
// gets the error and NO rewritten request: half of a signature recomputation applied is worse than
// none, because it is a request that looks signed and is not.
func RunRequestScript(src string, req ScriptRequest, resp *ScriptResponse, store map[string]string) (ScriptResult, error) {
	if err := CheckRequestScript(src); err != nil {
		return ScriptResult{}, err
	}
	nextStore := make(map[string]string, len(store))
	for k, v := range store {
		nextStore[k] = v
	}
	var out ScriptResult
	var logs []string

	err := run(RequestScriptTimeout, func(vm *goja.Runtime) error {
		reqObj := vm.NewObject()
		_ = reqObj.Set("method", req.Method)
		_ = reqObj.Set("url", req.URL)
		hdrs := vm.NewObject()
		for k, v := range req.Headers {
			_ = hdrs.Set(k, v)
		}
		_ = reqObj.Set("headers", hdrs)
		_ = reqObj.Set("body", req.Body)
		_ = vm.Set("request", reqObj)

		if resp != nil {
			respObj := vm.NewObject()
			_ = respObj.Set("status", resp.Status)
			rh := vm.NewObject()
			for k, v := range resp.Headers {
				_ = rh.Set(k, v)
			}
			_ = respObj.Set("headers", rh)
			_ = respObj.Set("body", resp.Body)
			_ = vm.Set("response", respObj)
			if _, err := vm.RunString(`Object.freeze(response.headers); Object.freeze(response);`); err != nil {
				return err
			}
		} else {
			_ = vm.Set("response", goja.Null())
		}

		storeObj := vm.NewObject()
		_ = storeObj.Set("get", func(k string) goja.Value {
			if v, ok := nextStore[k]; ok {
				return vm.ToValue(v)
			}
			return goja.Null()
		})
		_ = storeObj.Set("set", func(k string, v goja.Value) {
			val := v.String()
			if _, exists := nextStore[k]; !exists && len(nextStore) >= maxScriptStoreKeys {
				panic(vm.NewTypeError(StoreFullPrefix + "the store holds " + fmt.Sprint(maxScriptStoreKeys) + " keys"))
			}
			if len(val) > maxScriptStoreValueBytes {
				panic(vm.NewTypeError(StoreFullPrefix + "a value is over " + fmt.Sprint(maxScriptStoreValueBytes) + " bytes"))
			}
			total := len(k) + len(val)
			for kk, vv := range nextStore {
				if kk != k {
					total += len(kk) + len(vv)
				}
			}
			if total > maxScriptStoreTotalBytes {
				panic(vm.NewTypeError(StoreFullPrefix + "the store is over " + fmt.Sprint(maxScriptStoreTotalBytes) + " bytes in all"))
			}
			nextStore[k] = val
		})
		_ = storeObj.Set("delete", func(k string) { delete(nextStore, k) })
		_ = vm.Set("store", storeObj)

		_ = vm.Set("log", func(call goja.FunctionCall) goja.Value {
			if len(logs) >= maxScriptLogEntries {
				return goja.Undefined()
			}
			parts := make([]string, 0, len(call.Arguments))
			for _, a := range call.Arguments {
				parts = append(parts, a.String())
			}
			line := strings.Join(parts, " ")
			if len(line) > maxScriptLogChars {
				line = line[:maxScriptLogChars] + "…"
			}
			logs = append(logs, line)
			return goja.Undefined()
		})

		helpers := vm.NewObject()
		_ = helpers.Set("hmacSha256Hex", func(key, msg string) string {
			m := hmac.New(sha256.New, []byte(key))
			m.Write([]byte(msg))
			return hex.EncodeToString(m.Sum(nil))
		})
		_ = helpers.Set("hmacSha256Base64", func(key, msg string) string {
			m := hmac.New(sha256.New, []byte(key))
			m.Write([]byte(msg))
			return base64.StdEncoding.EncodeToString(m.Sum(nil))
		})
		_ = helpers.Set("sha256Hex", func(msg string) string {
			sum := sha256.Sum256([]byte(msg))
			return hex.EncodeToString(sum[:])
		})
		_ = helpers.Set("base64Encode", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) })
		_ = helpers.Set("base64UrlEncode", func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) })
		_ = helpers.Set("base64Decode", func(s string) string {
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				if b, err := enc.DecodeString(s); err == nil {
					return string(b)
				}
			}
			panic(vm.NewTypeError("base64Decode: not valid base64"))
		})
		_ = helpers.Set("randomHex", func(n int) string {
			if n <= 0 || n > 256 {
				panic(vm.NewTypeError("randomHex: byte count must be 1-256"))
			}
			b := make([]byte, n)
			_, _ = rand.Read(b)
			return hex.EncodeToString(b)
		})
		_ = vm.Set("burpsy", helpers)

		// The STRICT program, the same one CheckRequestScript compiled: in sloppy mode a write to the
		// frozen response fails silently, so a script that thought it changed the response would run
		// on as though it had. Strict mode makes that write a TypeError the operator is told about.
		prog, err := goja.Compile("pre-request-script", src, true)
		if err != nil {
			return err
		}
		if _, err := vm.RunProgram(prog); err != nil {
			return err
		}

		got, err := readScriptRequest(vm.Get("request"))
		if err != nil {
			return err
		}
		out.Request = got
		return nil
	})
	if err != nil {
		var ex *goja.Exception
		if errors.As(err, &ex) {
			if strings.HasPrefix(ex.Value().String(), "TypeError: "+StoreFullPrefix) {
				return ScriptResult{Log: logs}, fmt.Errorf("%w (%s)", ErrStoreFull, ex.Value().String())
			}
			return ScriptResult{Log: logs}, fmt.Errorf("the script threw: %s", ex.Value().String())
		}
		return ScriptResult{Log: logs}, err
	}
	out.Store = nextStore
	out.Log = logs
	return out, nil
}

// readScriptRequest reads the request back out of the VM, refusing a shape that is not a request: a
// missing method or URL, or a headers value that is not an object. A request the script broke is
// reported, not sent.
func readScriptRequest(v goja.Value) (ScriptRequest, error) {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return ScriptRequest{}, errors.New("the script removed `request`")
	}
	obj, ok := v.Export().(map[string]interface{})
	if !ok {
		return ScriptRequest{}, errors.New("`request` is no longer an object")
	}
	str := func(k string) string {
		if x, ok := obj[k]; ok && x != nil {
			return fmt.Sprint(x)
		}
		return ""
	}
	out := ScriptRequest{Method: strings.TrimSpace(str("method")), URL: strings.TrimSpace(str("url")), Body: str("body")}
	if out.Method == "" || out.URL == "" {
		return ScriptRequest{}, errors.New("the script left the request without a method or URL")
	}
	out.Headers = map[string]string{}
	switch h := obj["headers"].(type) {
	case nil:
	case map[string]interface{}:
		for k, x := range h {
			if x == nil {
				continue
			}
			out.Headers[k] = fmt.Sprint(x)
		}
	default:
		return ScriptRequest{}, errors.New("`request.headers` must be an object of name: value")
	}
	return out, nil
}
