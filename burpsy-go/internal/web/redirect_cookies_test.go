package web

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// A login performed by following a redirect must land in the jar the Session page shows and the other
// tools send from. With the jar un-attached the chain would establish a session nothing else can see,
// and the next tool send would start from scratch — the half-fixed state burpsy-react-ui-mr83 exists to
// end.
//
// The sender's own tests cannot catch this: they attach their own jar, so they pass whether or not the
// real one is wired. This is the only place that knows the production wiring, so it is the only place
// the claim can be checked.

// The adapter must actually satisfy the follower's interface. A signature drift on either side turns
// into a jar that silently remembers nothing — the defect this whole path is about.
var _ sender.CookieJar = sessionCookieJar{}

// WithSessionCoordinator hands the sender the session jar. A nil sender is tolerated rather than
// panicked, matching every other With* on this type, and a nil coordinator leaves the sender without
// one — which is the honest state for a Server assembled with neither.
func TestWithSessionCoordinatorGivesTheSenderTheSessionJar(t *testing.T) {
	if withSessionCookieJar(nil, session.NewCoordinator(zap.NewNop())) != nil {
		t.Error("a nil sender came back non-nil; every caller would then send through a sender that does not exist")
	}
}

// The wiring, end to end: a server given a coordinator hands that coordinator's jar to the sender it
// already holds, in place.
func TestTheSessionJarReachesTheSenderTheServerAlreadyHolds(t *testing.T) {
	coord := session.NewCoordinator(zap.NewNop())
	// The jar holds something, so the adapter has something to hand over.
	coord.SetCookie("example.test", 443, true, "sid", "abc123")

	// The production order, from cmd/burpsy/main.go: the sender first, then the coordinator. Getting
	// it the other way round is why the wiring is MUTATED rather than replaced — a server handed a
	// coordinator before a sender would attach the jar to nothing.
	srv := NewServer(core.NewTrafficStore(), core.NewScopeAllowEverything()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithSessionCoordinator(coord)

	if srv.sender == nil {
		t.Fatal("the server has no sender; the wiring under test could not have happened")
	}
	jar := srv.sender.CookieJar()
	if jar == nil {
		t.Fatal("the sender carries no cookie jar after the coordinator was attached: a login performed by " +
			"following a redirect would land in a store nothing else reads, and the Session page would " +
			"not show the session the chain just established (burpsy-react-ui-mr83)")
	}

	// And the jar it carries really is that coordinator's — the cookies in it are the ones written
	// through the coordinator, which is the whole point of sharing rather than having a second store.
	header, ok := jar.CookieHeader("example.test", 443, true, "/")
	if !ok {
		t.Error("the attached jar holds none of the cookies the coordinator was given; a second store " +
			"rather than the shared one was attached")
	}
	if header == "" {
		t.Error("the attached jar answered with an empty header for a cookie that was just set")
	}
}

// The adapter passes the hop's PATH through. A cookie set with Path=/admin does not go to /other, and
// a jar asked about "" takes that as "no path given" and answers with everything the host holds.
func TestTheAdapterPassesTheHopsPathSoCookiesArePathScoped(t *testing.T) {
	coord := session.NewCoordinator(zap.NewNop())
	// Absorbed as full Set-Cookie values so each carries its own Path, which is the only way the jar
	// has something to scope by. SetCookie stores a bare name=value pair and both then match every
	// path, which is correct and would make this assertion vacuous.
	coord.AbsorbCookie("example.test", 443, true, "root_cookie=1; Path=/")
	coord.AbsorbCookie("example.test", 443, true, "admin_cookie=2; Path=/admin")

	jar := sessionCookieJar{coord: coord}

	scoped, ok := jar.CookieHeader("example.test", 443, true, "/admin/secret")
	if !ok {
		t.Fatal("no cookies for a path under /admin")
	}
	// /admin/secret is UNDER /admin, so both cookies legitimately apply here: Path=/admin matches
	// every path beneath it. The scoping claim is not that fewer cookies arrive — it is that the
	// admin one does not appear where it must not.
	if !strings.Contains(scoped, "admin_cookie=2") {
		t.Errorf("at /admin/secret the jar answered %q, want the Path=/admin cookie: a path beneath the "+
			"cookie's own Path is exactly where it must be sent", scoped)
	}

	// /other is NOT under /admin, and this is where the scoping has to bite: a Path=/admin cookie
	// arriving here is a credential a Location header could aim at any path on the host.
	elsewhere, ok := jar.CookieHeader("example.test", 443, true, "/other")
	if !ok {
		t.Fatal("no cookies for /other")
	}
	if elsewhere != "root_cookie=1" {
		t.Errorf("at /other the jar answered %q, want only the Path=/ cookie: a Path-scoped cookie "+
			"reaching a path it was not set for is a credential a Location could aim", elsewhere)
	}
}

// A nil coordinator is a real state — a Server assembled without a session — and must answer rather
// than panic on the follower's hot path.
func TestTheAdapterToleratesANilCoordinator(t *testing.T) {
	jar := sessionCookieJar{}
	if _, ok := jar.CookieHeader("example.test", 443, true, "/"); ok {
		t.Error("a nil coordinator produced cookies")
	}
	// Absorbing into nothing is a no-op, not a panic: this runs once per hop.
	jar.AbsorbResponseCookies("example.test", 443, true, []string{"sid=1"})
}
