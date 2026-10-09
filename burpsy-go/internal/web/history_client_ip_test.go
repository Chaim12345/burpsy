package web

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The client that sent a proxied request reaches the History list (burpsy-react-ui-3bkn). The key is
// unconditional: "" is the honest value for a row that did not come from a listener, and an absent key
// could not be told apart from an older server.
func Test_history_rows_carry_the_client_ip(t *testing.T) {
	s := newTestServer()
	s.store.AddExchange(&core.Exchange{Host: "a.test", Port: 80, Method: "GET", Path: "/", ClientIP: "192.0.2.7", ListenerPort: 8080})
	s.store.AddExchange(&core.Exchange{Host: "a.test", Port: 80, Method: "GET", Path: "/repeater"})
	body := get(t, s, "/api/history").Body.String()
	if !strings.Contains(body, `"client_ip":"192.0.2.7"`) || !strings.Contains(body, `"client_ip":""`) {
		t.Errorf("history rows lack client_ip: %s", body)
	}
}
