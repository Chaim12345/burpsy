package scanner

// Console checks (kbu1) on a scanner started without --bchecks: an imported check runs, and the
// built-in header and cookie checks keep running beside it — importing one custom check must not
// switch the built-ins off.

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

func TestAConsoleCheckRunsBesideTheBuiltInsWithoutABChecksDir(t *testing.T) {
	store := core.NewTrafficStore()
	ps := NewPassiveScanner(store, zap.NewNop())
	src := "metadata:\n  language: v2-beta\n  name: \"token leak\"\ngiven response then\n  if {latest.response.body} matches \"secret-token\" then\n    report issue:\n      severity: low\n      confidence: firm\n  end if\n"
	if _, err := ps.ImportCheck(src, false); err != nil {
		t.Fatal(err)
	}
	reqID, _ := store.Put([]byte("GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"), core.DirectionRequest)
	respID, _ := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 12\r\n\r\nsecret-token"), core.DirectionResponse)
	ex := &core.Exchange{Host: "a.test", Port: 80, Method: "GET", Path: "/", Request: core.MsgPtr(reqID), Response: core.MsgPtr(respID)}
	store.AddExchange(ex)

	var names []string
	for _, f := range ps.Scan(ex) {
		names = append(names, f.Name)
	}
	joined := strings.Join(names, "|")
	if !strings.Contains(joined, "Missing") {
		t.Errorf("the built-in header checks stopped running after an import: %v", names)
	}
	if ps.Loaded() != 1 || ps.Coverage().Checks[0].Ran != 1 {
		t.Errorf("the imported check did not run: loaded %d, coverage %+v", ps.Loaded(), ps.Coverage().Checks)
	}
	if err := ps.RemoveCheck("token leak"); err != nil || ps.Loaded() != 0 {
		t.Errorf("remove: %v, loaded %d", err, ps.Loaded())
	}
}
