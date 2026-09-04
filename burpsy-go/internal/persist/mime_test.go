package persist

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// The media type survives the durable round trip, and the two kinds of empty survive it distinctly.
//
// The distinction is the point of the test, not the value. A row with a type, a row whose response
// declared none, and a row with no response at all are three different facts, and before the mime
// column existed the wire reported all three as the same blank cell — which is what let the History
// type filter ship against a field nothing populated.
func TestExchangeMimeRoundTrips(t *testing.T) {
	p := newTestStore(t)
	store := core.NewTrafficStore()
	store.SetPersistenceSinks(p.SaveMessage, p.SaveExchange)
	req, resp := putPair(t, store)

	store.AddExchange(&core.Exchange{
		Request: req, Response: &resp, Host: "typed.test", Port: 80, Method: "GET", Path: "/page",
		Mime: "text/html",
	})
	store.AddExchange(&core.Exchange{
		Request: req, Response: &resp, Host: "untyped.test", Port: 80, Method: "GET", Path: "/blob",
		Mime: "",
	})
	// No response at all — the blind-tunnel shape. Its Mime is empty for a different reason, and
	// Response is what says so.
	store.AddExchange(&core.Exchange{
		Request: req, Host: "tunnel.test", Port: 443, TLS: true, Method: "CONNECT", Path: "tunnel.test:443",
	})

	loaded, err := p.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	if len(loaded) != 3 {
		t.Fatalf("loaded %d exchanges, want 3", len(loaded))
	}
	typed, untyped, tunnel := loaded[0], loaded[1], loaded[2]

	if typed.Mime != "text/html" {
		t.Errorf("the typed exchange came back with Mime %q, want %q", typed.Mime, "text/html")
	}
	if untyped.Mime != "" {
		t.Errorf("the untyped exchange came back with Mime %q, want the empty string", untyped.Mime)
	}
	if untyped.Response == nil {
		t.Error("the untyped exchange lost its response, so it is no longer distinguishable from the tunnel")
	}
	if tunnel.Mime != "" {
		t.Errorf("the tunnel came back with Mime %q, want the empty string", tunnel.Mime)
	}
	if tunnel.Response != nil {
		t.Error("the tunnel came back with a response, which is the shape it exists to not have")
	}
}

// A row written before the mime column existed loads as "" and does not fail the restore.
//
// The table is created with the exact pre-mime column list, so this fails if the migration stops
// being additive or if the load path ever scans mime into a bare string — NULL into a string is an
// error, and it would take down the restore of the whole database rather than one cell of it.
func TestAnOldDatabaseWithoutTheMimeColumnStillLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "premime.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE exchanges (
		id            INTEGER PRIMARY KEY,
		request_msg   INTEGER NOT NULL,
		response_msg  INTEGER,
		host          TEXT NOT NULL,
		port          INTEGER NOT NULL,
		tls           INTEGER NOT NULL,
		method        TEXT NOT NULL,
		path          TEXT NOT NULL,
		status        INTEGER,
		response_len  INTEGER NOT NULL,
		started_ms    INTEGER NOT NULL,
		duration_ms   INTEGER NOT NULL,
		notes         TEXT,
		protocol      INTEGER NOT NULL,
		related       TEXT,
		duration_us   INTEGER,
		highlight     TEXT,
		source        TEXT
	)`); err != nil {
		t.Fatalf("create pre-mime table: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO exchanges (id, request_msg, response_msg, host, port, tls, method, path, status,
		                        response_len, started_ms, duration_ms, notes, protocol, related,
		                        duration_us, highlight, source)
		 VALUES (0, 0, 1, 'old.test', 80, 0, 'GET', '/', 200, 12, 0, 3, NULL, 0, NULL, NULL, NULL, 'proxy')`,
	); err != nil {
		t.Fatalf("insert pre-mime row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw sqlite: %v", err)
	}

	p, err := Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("Open a pre-mime database: %v", err)
	}
	defer p.Close()

	loaded, err := p.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges from a pre-mime database: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d rows, want 1", len(loaded))
	}
	if loaded[0].Mime != "" {
		t.Errorf("a legacy row read back Mime %q; it must read back as the empty string, not a guess",
			loaded[0].Mime)
	}
	// And the rest of the row is intact, so the added column did not shift the scan.
	if loaded[0].Host != "old.test" || loaded[0].Status == nil || *loaded[0].Status != 200 {
		t.Errorf("the legacy row came back garbled: host=%q status=%v", loaded[0].Host, loaded[0].Status)
	}
}

// The extractor and the capture sites agree: what MimeEssence reads off response bytes is what ends
// up on the restored row. This is the seam that the History column actually depends on, and testing
// the two halves separately would not catch a site that stored a raw header value complete with its
// charset parameter.
func TestExchangeMimeStoresTheStrippedEssenceNotTheRawHeader(t *testing.T) {
	p := newTestStore(t)
	store := core.NewTrafficStore()
	store.SetPersistenceSinks(p.SaveMessage, p.SaveExchange)
	req, resp := putPair(t, store)

	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/HTML; charset=utf-8\r\n\r\n<html>"
	store.AddExchange(&core.Exchange{
		Request: req, Response: &resp, Host: "essence.test", Port: 80, Method: "GET", Path: "/",
		Mime: core.MimeEssence([]byte(raw)),
	})

	loaded, err := p.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d rows, want 1", len(loaded))
	}
	if loaded[0].Mime != "text/html" {
		t.Errorf("stored Mime is %q, want %q — the charset parameter must not reach the row",
			loaded[0].Mime, "text/html")
	}
}
