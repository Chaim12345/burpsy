package extension

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// A real plugin process, for tests that need one.
//
// # Why the test binary re-execs itself
//
// The host's whole contract is with a child process: spawn it, speak newline-delimited JSON-RPC over
// its pipes, bound what it produces, notice when it dies. A fake that replaced session.spawn with an
// in-process pipe would exercise the dispatcher and none of the parts that have actually broken in
// this shape of code — pipe ordering against cmd.Wait, a child that exits mid-handshake, stderr
// arriving after stdout closed. So the tests run a genuine process, and the process is this test
// binary re-invoked with -test.run=TestHelperPlugin and BURPSY_TEST_PLUGIN naming a behaviour.
//
// The alternative was `go build` a helper into t.TempDir() from TestMain. That works and is slower by
// a compile per package run, and it needs a toolchain on the machine running the tests — which the
// re-exec does not, because the binary is already built. This is the os/exec package's own test
// pattern for the same reason.
//
// os.Exit at the end of every branch is load-bearing: it stops the testing framework printing "PASS"
// on the child's stdout, which the host would correctly record as a plugin that does not speak the
// protocol.

// helperEnv names the behaviour a re-exec should perform.
const helperEnv = "BURPSY_TEST_PLUGIN"

// helper builds the spec that launches this test binary as plugin `behaviour`.
func helper(behaviour string) PluginSpec {
	return PluginSpec{
		Path: os.Args[0],
		Args: []string{"-test.run=^TestHelperPlugin$"},
		Env:  []string{helperEnv + "=" + behaviour},
	}
}

// TestHelperPlugin is the entry point of every helper process. It is a no-op in a normal test run.
func TestHelperPlugin(t *testing.T) {
	behaviour := os.Getenv(helperEnv)
	if behaviour == "" {
		t.Skip("not a helper invocation; set " + helperEnv + " to run a plugin")
	}
	runHelperPlugin(behaviour)
}

// emit writes one JSON-RPC line to stdout.
func emit(msg map[string]any) {
	encoded, err := json.Marshal(msg)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stdout, string(encoded))
}

func reply(id json.RawMessage, result map[string]any) {
	emit(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "result": result})
}

// manifestFor is the initialize result each behaviour answers with.
func manifestFor(behaviour string) map[string]any {
	switch behaviour {
	case "protocol-mismatch":
		// A plugin built against a protocol this host does not speak. Answers initialize perfectly and
		// must still be refused.
		return map[string]any{"name": "future", "version": "9.0", "type": "node", "protocol": 99}
	case "bad-registrations":
		return map[string]any{
			"name": "sloppy", "version": "0.1", "type": "python", "protocol": ProtocolVersion,
			"registrations": []map[string]any{
				{"id": "ok", "kind": "menu", "label": "A working action"},
				{"id": "", "kind": "menu", "label": "No id"},
				{"id": "ok", "kind": "menu", "label": "Duplicate id"},
				{"id": "swing", "kind": "suite-tab", "label": "A Swing component"},
				{"id": "unlabelled", "kind": "menu", "label": ""},
			},
		}
	case "bad-hotkeys":
		return map[string]any{
			"name": "hasty", "version": "0.3", "type": "python", "protocol": ProtocolVersion,
			"registrations": []map[string]any{
				{"id": "no-chord", "kind": "hotkey", "label": "No chord declared"},
				{"id": "meta-chord", "kind": "hotkey", "label": "Asks for the meta key", "chord": "Meta+K"},
				{"id": "survives", "kind": "menu", "label": "An unrelated action"},
			},
		}
	case "collision-test":
		return map[string]any{
			"name": "collider", "version": "0.1", "type": "python", "protocol": ProtocolVersion,
			"registrations": []map[string]any{
				{"id": "valid", "kind": "hotkey", "label": "A valid hotkey", "chord": "Ctrl+Shift+K"},
				{"id": "palette-collision", "kind": "hotkey", "label": "Collides with palette", "chord": "Ctrl+K"},
				{"id": "repeater-collision", "kind": "hotkey", "label": "Collides with Repeater", "chord": "Ctrl+R"},
			},
		}
	case "payloads":
		return map[string]any{
			"name": "payloader", "version": "0.1", "type": "go-test", "protocol": ProtocolVersion,
			"registrations": []map[string]any{
				{"id": "tokens", "kind": "payload-generator", "label": "Signed tokens"},
				{"id": "upper", "kind": "payload-processor", "label": "Upper-case"},
			},
		}
	case "hooks":
		return map[string]any{
			"name": "hooker", "version": "0.1", "type": "go-test", "protocol": ProtocolVersion,
			"registrations": []map[string]any{
				{"id": "http", "kind": "http-handler", "label": "Sign requests"},
				{"id": "proxy", "kind": "proxy-handler", "label": "Proxy rules"},
				{"id": "ws", "kind": "websocket-handler", "label": "WS fuzz"},
			},
		}
	case "no-registrations":
		return map[string]any{"name": "quiet", "version": "1.0", "type": "shell", "protocol": ProtocolVersion}
	default:
		return map[string]any{
			"name": "probe", "version": "1.2.3", "type": "go-test", "protocol": ProtocolVersion,
			"registrations": []map[string]any{
				{"id": "ctx", "kind": "context-menu", "label": "Inspect exchange", "hint": "on a selected row"},
				{"id": "act", "kind": "menu", "label": "Run the action"},
				{"id": "tab", "kind": "editor-tab", "label": "Derived view"},
				{"id": "key", "kind": "hotkey", "label": "Run from the keyboard", "chord": "Ctrl+Shift+K"},
			},
		}
	}
}

// runHelperPlugin is the plugin. It never returns.
func runHelperPlugin(behaviour string) {
	if behaviour == "cannot-start" {
		// Nothing to do: the spec for this behaviour points at a path that does not exist, so this
		// branch is never reached. Named so the switch below is exhaustive to a reader.
		os.Exit(0)
	}

	reader := bufio.NewScanner(os.Stdin)
	reader.Buffer(make([]byte, 0, 4<<10), 4<<20)
	for reader.Scan() {
		line := strings.TrimSpace(reader.Text())
		if line == "" {
			continue
		}
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			os.Exit(70)
		}

		if behaviour == "host-caller" && msg.Method == "menu.invoke" {
			// Makes the plugin->host request the invocation's `selection` field describes
			// ({"method": ..., "params": ...}), waits for the host's answer on stdin and returns
			// that answer verbatim as the invocation's output.
			var call struct {
				Selection string `json:"selection"`
			}
			_ = json.Unmarshal(msg.Params, &call)
			var want struct {
				Method string          `json:"method"`
				Params json.RawMessage `json:"params"`
			}
			if err := json.Unmarshal([]byte(call.Selection), &want); err != nil {
				os.Exit(71)
			}
			emit(map[string]any{"jsonrpc": "2.0", "id": 9001, "method": want.Method, "params": want.Params})
			if !reader.Scan() {
				os.Exit(72)
			}
			reply(msg.ID, map[string]any{"output": strings.TrimSpace(reader.Text())})
			continue
		}

		switch msg.Method {
		case "initialize":
			switch behaviour {
			case "silent":
				// Reads the request and answers nothing, which is what a plugin wedged on its own
				// startup looks like. The host's LoadTimeout is the only thing that ends this.
				continue
			case "die-in-handshake":
				os.Exit(3)
			case "long-line":
				// One line past the host's message bound. The host cannot resynchronise a stream it
				// read half a message of, so this must end the session rather than be skipped.
				fmt.Fprintln(os.Stdout, strings.Repeat("x", 64<<10))
				continue
			}
			if behaviour == "noisy" {
				// The plugin author's first mistake, on purpose: a bare line on stdout before the
				// handshake reply. It must be recorded as a protocol violation and must not stop the
				// reply after it from being read.
				fmt.Fprintln(os.Stdout, "print debugging, straight to stdout")
				fmt.Fprintln(os.Stderr, "a runtime warning on stderr")
				emit(map[string]any{"jsonrpc": "2.0", "method": "log",
					"params": map[string]any{"stream": "output", "message": "hello from the plugin"}})
				emit(map[string]any{"jsonrpc": "2.0", "method": "log",
					"params": map[string]any{"stream": "error", "message": "and a problem the plugin found"}})
				emit(map[string]any{"jsonrpc": "2.0", "method": "somethingElse",
					"params": map[string]any{}})
			}
			reply(msg.ID, manifestFor(behaviour))
			if behaviour == "crash-after-load" {
				// Exits without being asked to, which is the difference between StateUnloaded and
				// StateCrashed. Flushed by the process exit; the host reads what is already in the pipe.
				os.Exit(9)
			}

		case "contextMenu.invoke", "menu.invoke", "hotkey.invoke", "sessionAction.invoke":
			if behaviour == "invoke-fails" {
				emit(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(msg.ID),
					"error": map[string]any{"code": -32000, "message": "the plugin declined"}})
				continue
			}
			reply(msg.ID, map[string]any{"output": "method=" + msg.Method + " params=" + string(msg.Params)})

		case "http.handle", "proxy.handle", "websocket.handle":
			var in struct {
				Phase string `json:"phase"`
				Raw   string `json:"raw"`
			}
			_ = json.Unmarshal(msg.Params, &in)
			name := os.Getenv("BURPSY_PLUGIN_NAME")
			switch in.Raw {
			case "hang":
				select {}
			case "crash":
				os.Exit(5)
			case "garbage":
				reply(msg.ID, map[string]any{"action": "explode"})
			case "drop":
				reply(msg.ID, map[string]any{"action": "drop"})
			case "intercept":
				reply(msg.ID, map[string]any{"action": "intercept"})
			case "binary":
				reply(msg.ID, map[string]any{"action": "continue", "raw": "/wCA", "encoding": "base64"})
			case "noop":
				reply(msg.ID, map[string]any{"action": "continue"})
			case "echo":
				reply(msg.ID, map[string]any{"action": "continue", "raw": in.Raw})
			default:
				reply(msg.ID, map[string]any{"action": "continue", "raw": in.Raw + "[" + name + ":" + in.Phase + "]"})
			}

		case "payload.generate":
			var in struct {
				Position int `json:"position"`
			}
			_ = json.Unmarshal(msg.Params, &in)
			switch {
			case in.Position >= 3:
				reply(msg.ID, map[string]any{"done": true})
			case in.Position == 1:
				// Not valid UTF-8 as text, so it travels as base64.
				reply(msg.ID, map[string]any{"payload": "/wCA", "encoding": "base64"})
			default:
				reply(msg.ID, map[string]any{"payload": fmt.Sprintf("tok-%d", in.Position)})
			}

		case "payload.process":
			var in struct {
				Payload   string `json:"payload"`
				BaseValue string `json:"base_value"`
			}
			_ = json.Unmarshal(msg.Params, &in)
			switch in.Payload {
			case "drop":
				reply(msg.ID, map[string]any{"action": "skip"})
			case "boom":
				emit(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(msg.ID),
					"error": map[string]any{"code": -32000, "message": "processor failed"}})
			default:
				reply(msg.ID, map[string]any{"payload": strings.ToUpper(in.Payload) + "|" + in.BaseValue})
			}

		case "editor.render":
			reply(msg.ID, map[string]any{"text": "method=" + msg.Method + " params=" + string(msg.Params)})

		case "shutdown":
			reply(msg.ID, map[string]any{})
			if behaviour == "ignores-shutdown" {
				// Answers and keeps running. Closing stdin is what ends it: the read loop below sees
				// EOF and falls out of the loop.
				continue
			}
			os.Exit(0)

		default:
			emit(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(msg.ID),
				"error": map[string]any{"code": -32601, "message": "no such method " + msg.Method}})
		}
	}
	os.Exit(0)
}
