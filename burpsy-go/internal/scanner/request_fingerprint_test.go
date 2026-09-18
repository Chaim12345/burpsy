package scanner

// The request-content fingerprint in the audit ledger's unit keys (burpsy-react-ui-6n4d).
//
// The defect: the URL-keyed scopes keyed by host/path alone, so a second capture of the same
// URL with changed parameters or a changed body collapsed as "already covered" — silently
// deduped. Burp keys live-audit items by URL with request-content change detection; the
// smallest honest shape here is the fingerprint in the unit key.
//
// What these tests pin:
//
//   - same URL, changed content -> DIFFERENT unit key (re-admitted, re-audited, counted);
//   - same URL, same content -> SAME unit key (still collapsed — cross-task dedup's pairing
//     with apfh is preserved: apfh suppresses the same content, this admits the changed);
//   - zero fingerprint (a hand-built or restored exchange) keys as before;
//   - the per-request/insertion scopes are untouched — they key by id already;
//   - the fingerprint itself: deterministic over the same bytes, different over any change
//     (body, parameter, header, method), and the whole request is the content.
import (
	"fmt"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func fpExchange(t *testing.T, host string, path string, rawRequest []byte) *core.Exchange {
	t.Helper()
	ex := &core.Exchange{Host: host, Port: 443, TLS: true, Method: "POST", Path: path}
	ex.RequestFP = core.RequestFingerprint(rawRequest)
	return ex
}

func TestChangedContentAtTheSameURLIsADifferentUnit(t *testing.T) {
	first := fpExchange(t, "app.test", "/search", []byte("POST /search HTTP/1.1\r\nHost: app.test\r\n\r\nq=first"))
	second := fpExchange(t, "app.test", "/search", []byte("POST /search HTTP/1.1\r\nHost: app.test\r\n\r\nq=changed"))

	for _, scope := range []DispatchScope{DispatchScopePerHost, DispatchScopePerPath, DispatchScopePerUrl} {
		k1, ok1 := scope.UnitKey(first)
		k2, ok2 := scope.UnitKey(second)
		if !ok1 || !ok2 {
			t.Fatalf("%s: UnitKey refused an exchange", scope.Label())
		}
		if k1 == k2 {
			t.Errorf("%s: two captures of /search with different bodies keyed the same unit %q — the changed request was silently deduped, the exact defect this exists to fix", scope.Label(), k1)
		}
	}
}

func TestIdenticalContentAtTheSameURLIsStillOneUnit(t *testing.T) {
	// The same request captured twice: the same unit, so the ledger still collapses it —
	// cross-task dedup (apfh) keeps its whole point. Two raw byte strings that differ only
	// in incidental bytes (a retried capture is byte-identical here) fingerprint equal.
	raw := []byte("POST /search HTTP/1.1\r\nHost: app.test\r\n\r\nq=same")
	first := fpExchange(t, "app.test", "/search", raw)
	second := fpExchange(t, "app.test", "/search", raw)

	for _, scope := range []DispatchScope{DispatchScopePerHost, DispatchScopePerPath, DispatchScopePerUrl} {
		k1, _ := scope.UnitKey(first)
		k2, _ := scope.UnitKey(second)
		if k1 != k2 {
			t.Errorf("%s: byte-identical requests keyed different units (%q vs %q) — identical work must stay collapsed", scope.Label(), k1, k2)
		}
	}
}

func TestAZeroFingerprintKeysTheWayItAlwaysDid(t *testing.T) {
	// Exchanges minted without the capture seam (restored sessions, hand-built tests) carry
	// RequestFP 0: their key must not carry a suffix, so identity does not change mid-run.
	ex := &core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "GET", Path: "/x"}
	k, ok := DispatchScopePerUrl.UnitKey(ex)
	if !ok || k != "https://app.test:443/x" {
		t.Fatalf("per-URL key = %q, %v — a zero fingerprint must key exactly as before", k, ok)
	}
}

func TestThePerRequestScopesAreUntouched(t *testing.T) {
	// They key by ex.ID, which a new capture always has a new one of — content changes come
	// with a new id for free, and appending the fingerprint would only lengthen the key.
	ex := fpExchange(t, "app.test", "/x", []byte("GET /x HTTP/1.1\r\n\r\n"))
	ex.ID = 7
	k, ok := DispatchScopePerRequest.UnitKey(ex)
	if !ok || k != "https://app.test:443#7" {
		t.Fatalf("per-request key = %q, %v — this scope must not change", k, ok)
	}
}

func TestTheFingerprintCoversTheWholeRequest(t *testing.T) {
	// "Changed content" is not only the body: a changed parameter, a changed header, a
	// changed method on the same path are all semantic changes the checks must see again.
	base := []byte("POST /search HTTP/1.1\r\nHost: app.test\r\nX-Token: a\r\n\r\nq=1")
	baseFP := core.RequestFingerprint(base)

	changedBody := []byte("POST /search HTTP/1.1\r\nHost: app.test\r\nX-Token: a\r\n\r\nq=2")
	changedHeader := []byte("POST /search HTTP/1.1\r\nHost: app.test\r\nX-Token: b\r\n\r\nq=1")
	changedMethod := []byte("PUT /search HTTP/1.1\r\nHost: app.test\r\nX-Token: a\r\n\r\nq=1")

	for name, raw := range map[string][]byte{
		"a changed body":   changedBody,
		"a changed header": changedHeader,
		"a changed method": changedMethod,
	} {
		if core.RequestFingerprint(raw) == baseFP {
			t.Errorf("the fingerprint did not notice %s — the request IS the content; splitting it would re-open the silent dedup for everything outside the split", name)
		}
	}
	if core.RequestFingerprint([]byte("GET /other HTTP/1.1\r\n\r\n")) == baseFP {
		t.Error("the fingerprint collided across unrelated requests")
	}
	// and determinism: the same bytes, the same answer, every time.
	if core.RequestFingerprint(base) != baseFP {
		t.Error("the fingerprint is not deterministic over the same bytes")
	}
}

func TestTheLedgerReAdmitsAChangedContentUnitAndCountsIt(t *testing.T) {
	// The end-to-end contract: the first capture's unit is covered; the changed request's
	// unit is a different key, so Admit answers true and the audit counts it as dispatched —
	// never as AlreadyCovered, never silently.
	ledger := NewAuditLedger()
	first := fpExchange(t, "app.test", "/search", []byte("POST /search HTTP/1.1\r\n\r\nq=first"))
	second := fpExchange(t, "app.test", "/search", []byte("POST /search HTTP/1.1\r\n\r\nq=changed"))

	k1, _ := DispatchScopePerUrl.UnitKey(first)
	k2, _ := DispatchScopePerUrl.UnitKey(second)

	const check = 3
	// Admit answers TRUE when the pair runs, FALSE when the ledger already covered it.
	if !ledger.Admit(k1, check) {
		t.Fatal("the first capture was not admitted — control case broken")
	}
	if ledger.Admit(k1, check) {
		t.Error("identical content was admitted twice — the collapse this bead must NOT break is broken")
	}
	if !ledger.Admit(k2, check) {
		t.Errorf("changed content was refused by the ledger — the re-audit was silently deduped: %q vs %q", k1, k2)
	}
	// and the admitted count says three units-of-work considered, two distinct runs.
	if got := ledger.Admitted(); got != 2 {
		t.Errorf("ledger admitted = %d, want 2 distinct units (first + changed)", got)
	}
	_ = fmt.Sprint()
}
