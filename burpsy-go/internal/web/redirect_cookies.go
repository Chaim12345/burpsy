package web

import (
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
)

// This file adapts the session coordinator's cookie store to the interface the redirect follower wants,
// so a followed chain can replay the cookies each hop set (burpsy-react-ui-mr83).
//
// # Why an adapter and not a direct hand-over
//
// The two sides do not match, and both differences are meaningful:
//
//   - internal/session imports internal/sender, so sender cannot import it. The follower takes a
//     two-method interface for the same reason internal/sender's ClientCerts is one.
//   - The coordinator's CookieHeader takes a PATH and returns a string, because its jar honours
//     Path scoping for a browser-shaped request. The follower knows the path — it just resolved the
//     Location — and the empty string it would otherwise pass is exactly the "no path" case that jar
//     treats as "everything", so the path is threaded through rather than dropped.
//
// The two-method shape also means this adapter is the ONLY place that knows the coordinator's
// signatures changed, instead of every follower call site.

type sessionCookieJar struct {
	coord *session.Coordinator
}

// CookieHeader implements sender.CookieJar.
//
// path is the hop's request path, which the jar scopes by. A cookie with Path=/ does not go to
// /admin/secret, and passing "" would ask the jar for every cookie the host holds — which is the
// opposite of what the hop's URL says.
func (j sessionCookieJar) CookieHeader(host string, port uint16, tls bool, path string) (string, bool) {
	if j.coord == nil {
		return "", false
	}
	header := j.coord.CookieHeader(host, port, tls, path)
	if header == "" {
		return "", false
	}
	return header, true
}

// AbsorbResponseCookies implements sender.CookieJar.
func (j sessionCookieJar) AbsorbResponseCookies(host string, port uint16, tls bool, setCookie []string) {
	if j.coord == nil {
		return
	}
	for _, value := range setCookie {
		j.coord.AbsorbCookie(host, port, tls, value)
	}
}

// withSessionCookieJar gives a sender the shared session jar as its redirect-cookie store.
//
// The session coordinator is the operator's own jar — the one whose cookies the Session page shows
// and the Repeater's own spliced requests already carry (api_tools.go). A separate jar for the
// redirect follower would mean the login a chain performed is invisible on every other surface, which
// is the half-fixed state this wiring is meant to end.
func withSessionCookieJar(send *sender.Sender, coord *session.Coordinator) *sender.Sender {
	if send == nil || coord == nil {
		return send
	}
	return send.WithCookieJar(sessionCookieJar{coord: coord})
}
