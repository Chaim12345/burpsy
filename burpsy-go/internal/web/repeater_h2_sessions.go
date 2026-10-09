package web

import (
	"time"

	"github.com/burpsy-go/burpsy/internal/sender"
)

// Repeater's HTTP/2 connection reuse pool (burpsy-react-ui-adkx). One per server, keyed per tab and
// authority inside sender.H2Sessions. The bounds are the pool's whole lifecycle: the server is never
// told when a tab closes, so an idle connection is released by the TTL, and the count cap keeps forty
// tabs against forty hosts from holding forty sockets open indefinitely.
const (
	repeaterH2SessionMax = 32
	repeaterH2SessionTTL = 60 * time.Second
)

// repeaterH2Sessions is this server's pool, made on first use.
func (s *Server) repeaterH2Sessions() *sender.H2Sessions {
	s.repeaterH2Once.Do(func() {
		s.repeaterH2 = sender.NewH2Sessions(repeaterH2SessionMax, repeaterH2SessionTTL)
	})
	return s.repeaterH2
}
