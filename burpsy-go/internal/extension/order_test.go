package extension

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for the operator's ordering of the allowlist (burpsy-react-ui-d3gj).
//
// The claim these defend is behavioural and not decorative: moving a plugin up must change which
// plugin's code runs first, not just which row is drawn first. So the ordering test does not assert
// on a slice of names. It loads two real plugin processes, has each of them write its own name to a
// shared ledger file whenever it is invoked, walks the served list the way the console walks it, and
// reads the ledger back. A Move that reordered only the table would leave the ledger unchanged and
// fail here.
//
// What the walk is, and what it is not: burpsy has no HTTP-handler registration kind, so no request
// ever passes through a plugin and there is no host pipeline to order. The consumer of the order is
// the console, which builds the palette group, the context-menu group and the editor tab strip by
// walking the rows of GET /api/extensions in the order they arrive
// (internal/web/ui/src/lib/plugin-registrations.ts). invokeInServedOrder below is that walk, and it
// is deliberately order-blind — it reads the order out of List() and never sorts, so the only thing
// that can change its answer is the served order itself.

// orderLedgerEnv names the file an order-helper appends its own name to on every invocation.
const orderLedgerEnv = "BURPSY_TEST_PLUGIN_LEDGER"

// orderHelper builds the spec that launches this test binary as a ledger-writing plugin.
//
// A second helper entry point rather than a new behaviour on plugin_helper_test.go's: that file is
// shared with the host tests and with another slice's in-flight work, and a test that needs one more
// plugin shape should not be a reason to edit it.
func orderHelper(ledger string) PluginSpec {
	return PluginSpec{
		Path: os.Args[0],
		Args: []string{"-test.run=^TestHelperOrderPlugin$"},
		Env:  []string{orderLedgerEnv + "=" + ledger},
	}
}

// TestHelperOrderPlugin is a plugin that records the fact that it ran. A no-op in a normal test run.
//
// It learns its own name from the initialize params rather than from its argv, because the name is
// the operator's allowlist key and the host is the only side that knows it — which is also what
// makes the ledger meaningful: the line in the file was written by the child, about itself.
func TestHelperOrderPlugin(t *testing.T) {
	ledger := os.Getenv(orderLedgerEnv)
	if ledger == "" {
		t.Skip("not a helper invocation; set " + orderLedgerEnv + " to run a ledger-writing plugin")
	}

	self := "unnamed"
	reader := bufio.NewScanner(os.Stdin)
	reader.Buffer(make([]byte, 0, 4<<10), 1<<20)
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

		switch msg.Method {
		case "initialize":
			var params InitializeParams
			if err := json.Unmarshal(msg.Params, &params); err == nil && params.Plugin != "" {
				self = params.Plugin
			}
			reply(msg.ID, map[string]any{
				"name": "ledger", "version": "1.0", "type": "go-test", "protocol": ProtocolVersion,
				"registrations": []map[string]any{
					{"id": "ctx", "kind": "context-menu", "label": "Record that " + self + " ran"},
				},
			})

		case "contextMenu.invoke":
			appendLedger(ledger, self)
			reply(msg.ID, map[string]any{"output": self})

		case "shutdown":
			reply(msg.ID, map[string]any{})
			os.Exit(0)

		default:
			emit(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(msg.ID),
				"error": map[string]any{"code": -32601, "message": "no such method " + msg.Method}})
		}
	}
	// os.Exit rather than returning: a return lets the testing framework print PASS on this
	// process's stdout, which the host would correctly record as a plugin that does not speak the
	// protocol.
	os.Exit(0)
}

// appendLedger writes one line. O_APPEND so two processes sharing the file cannot truncate each
// other; a failure exits the child, because a plugin that silently failed to record its own
// invocation would make this test pass for the wrong reason.
func appendLedger(path, name string) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(71)
	}
	if _, err := file.WriteString(name + "\n"); err != nil {
		os.Exit(72)
	}
	if err := file.Close(); err != nil {
		os.Exit(73)
	}
}

// readLedger returns the names in the order they were recorded, and empties the file so the next
// walk starts from nothing.
func readLedger(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("reading the invocation ledger: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("emptying the invocation ledger: %v", err)
	}
	var names []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line != "" {
			names = append(names, line)
		}
	}
	return names
}

// invokeInServedOrder is the console's walk: take the rows as served, and invoke every context-menu
// registration on each in the order it appears. It never sorts and never looks a plugin up by name,
// so the order it dispatches in is exactly the order it was given.
func invokeInServedOrder(t *testing.T, host *Host) {
	t.Helper()
	for _, row := range host.List().Extensions {
		for _, registration := range row.Registrations {
			if registration.Kind != KindContextMenu {
				continue
			}
			if _, err := host.Invoke(context.Background(), row.Name, InvokeParams{Registration: registration.ID}); err != nil {
				t.Fatalf("invoking %s/%s: %v", row.Name, registration.ID, err)
			}
		}
	}
}

// servedNames is the order as it crosses the wire, read back out of the marshalled JSON rather than
// off the struct: the console sees the JSON, and a nil slice and an empty one are the same struct
// and different documents.
func servedNames(t *testing.T, view ListView) []string {
	t.Helper()
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshalling the extension list: %v", err)
	}
	var decoded struct {
		Extensions []struct {
			Name string `json:"name"`
		} `json:"extensions"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("reading back the marshalled extension list: %v", err)
	}
	names := make([]string, 0, len(decoded.Extensions))
	for _, row := range decoded.Extensions {
		names = append(names, row.Name)
	}
	return names
}

func Test_moving_a_plugin_up_changes_which_plugin_is_invoked_first(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "invocations.log")
	host := NewHost(Config{Plugins: map[string]PluginSpec{
		"alpha": orderHelper(ledger),
		"zeta":  orderHelper(ledger),
	}})
	t.Cleanup(host.Close)
	for _, name := range []string{"alpha", "zeta"} {
		if _, err := host.Load(name); err != nil {
			t.Fatalf("loading %s: %v", name, err)
		}
	}

	if got := servedNames(t, host.List()); !equalNames(got, []string{"alpha", "zeta"}) {
		t.Fatalf("a fresh allowlist should be served alphabetically, because Config.Plugins is a map and the command line's order is gone by the time the host sees it; got %v", got)
	}
	invokeInServedOrder(t, host)
	if got := readLedger(t, ledger); !equalNames(got, []string{"alpha", "zeta"}) {
		t.Fatalf("the plugins should have run in the order they were served, alpha then zeta; the plugins themselves recorded %v", got)
	}

	list, err := host.Move("zeta", MoveUp)
	if err != nil {
		t.Fatalf("moving zeta up: %v", err)
	}

	if got := servedNames(t, list); !equalNames(got, []string{"zeta", "alpha"}) {
		t.Fatalf("Move should answer with the whole list in its new order, zeta then alpha; got %v", got)
	}
	if got := servedNames(t, host.List()); !equalNames(got, []string{"zeta", "alpha"}) {
		t.Fatalf("the new order should be what every later read serves, not just what Move answered; a second List gave %v", got)
	}

	invokeInServedOrder(t, host)
	if got := readLedger(t, ledger); !equalNames(got, []string{"zeta", "alpha"}) {
		t.Fatalf("after moving zeta up, zeta's process must be the one that runs first: a reorder that changed only the table and not what dispatches is the defect this route exists to avoid. The plugins recorded %v", got)
	}
}

func Test_moving_a_plugin_past_the_end_of_the_list_is_refused_and_not_clamped(t *testing.T) {
	host := NewHost(Config{Plugins: map[string]PluginSpec{
		"alpha": helper("no-registrations"),
		"zeta":  helper("no-registrations"),
	}})
	t.Cleanup(host.Close)

	if _, err := host.Move("alpha", MoveUp); !errors.Is(err, ErrAlreadyFirst) {
		t.Fatalf("moving the first plugin up must refuse with ErrAlreadyFirst; a 200 with an unchanged list would be a button an operator can press forever while believing the order changed. Got %v", err)
	}
	if _, err := host.Move("zeta", MoveDown); !errors.Is(err, ErrAlreadyLast) {
		t.Fatalf("moving the last plugin down must refuse with ErrAlreadyLast rather than silently doing nothing; got %v", err)
	}
	if got := servedNames(t, host.List()); !equalNames(got, []string{"alpha", "zeta"}) {
		t.Fatalf("a refused move must leave the order exactly as it was; got %v", got)
	}
}

func Test_a_move_names_what_it_could_not_accept(t *testing.T) {
	host := NewHost(Config{Plugins: map[string]PluginSpec{"alpha": helper("no-registrations")}})
	t.Cleanup(host.Close)

	_, err := host.Move("alpha", MoveDirection("sideways"))
	if !errors.Is(err, ErrBadDirection) {
		t.Fatalf("an unrecognised direction must be refused as one rather than treated as down; got %v", err)
	}
	if !strings.Contains(err.Error(), `"sideways"`) {
		t.Fatalf("the refusal must quote the value it was given, so a caller that sent \"sideways\" is told that and not that its request was generally unreadable; got %q", err.Error())
	}

	if _, err := host.Move("nowhere", MoveUp); !errors.Is(err, ErrUnknownPlugin) {
		t.Fatalf("moving a name that is not on the allowlist must be ErrUnknownPlugin, which the route maps to 404: an order is a property of the allowlist and a name outside it has no position. Got %v", err)
	}
}

func equalNames(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
