package scanner

// The SQL-injection row against a real SQLite engine. OWASP Juice Shop's product search
// concatenates `q` into a LIKE clause and renders the driver's error into a 500 page; the error
// bank carried no SQLite wording, so a full audit of that exact request reported nothing and
// called itself complete. These tests run the same query shape through modernc.org/sqlite, so
// the error text is the engine's own rather than a string the test chose to match.
import (
	"context"
	"database/sql"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

// sqliteSearchServer serves /rest/products/search?q= the way Juice Shop does. With
// parameterized set the query binds q instead of concatenating it — the safe twin.
func sqliteSearchServer(t *testing.T, parameterized bool) *httptest.Server {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE Products (id INTEGER, name TEXT, description TEXT, deletedAt TEXT);
		INSERT INTO Products VALUES (1, 'Apple Juice', 'The all-time classic.', NULL),
		                            (2, 'Banana Juice', 'Monkeys love it.', NULL);`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		var rows *sql.Rows
		var err error
		if parameterized {
			rows, err = db.Query(`SELECT name FROM Products WHERE ((name LIKE ? OR description LIKE ?) AND deletedAt IS NULL)`,
				"%"+q+"%", "%"+q+"%")
		} else {
			rows, err = db.Query(`SELECT name FROM Products WHERE ((name LIKE '%` + q + `%' OR description LIKE '%` + q +
				`%') AND deletedAt IS NULL)`)
		}
		if err != nil {
			// Juice Shop's error handler: the message, HTML-escaped, in a 500 page.
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "<html><head><title>Error: "+html.EscapeString(err.Error())+"</title></head></html>")
			return
		}
		defer rows.Close()
		var names []string
		for rows.Next() {
			var n string
			_ = rows.Scan(&n)
			names = append(names, strconv.Quote(n))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":[`+strings.Join(names, ",")+`]}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sqliteSearchAudit(t *testing.T, parameterized bool) []*Finding {
	t.Helper()
	srv := sqliteSearchServer(t, parameterized)
	const path = "/rest/products/search?q=apple"
	host, portStr, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	res, err := srv.Client().Get(srv.URL + path)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()

	store := core.NewTrafficStore()
	reqID, err := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+string(body)),
		core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID,
		Host: host, Port: uint16(port), Method: "GET", Path: path}
	store.AddExchange(ex)

	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: time.Minute, CheckSqli: true})
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{ex.ID}, AuditConfig{})
	return sqliFindingsNamed(findings, sqlInjectionIssue)
}

func TestSQLiFindsTheJuiceShopSearchInjectionOnSQLite(t *testing.T) {
	if got := sqliteSearchAudit(t, false); len(got) == 0 {
		t.Fatalf("no %q finding against a concatenated SQLite LIKE query", sqlInjectionIssue)
	}
}

func TestSQLiReportsNothingOnTheParameterizedSQLiteTwin(t *testing.T) {
	if got := sqliteSearchAudit(t, true); len(got) != 0 {
		t.Fatalf("the parameterized twin reported %d %q finding(s): %+v", len(got), sqlInjectionIssue, got)
	}
}

// The engine's own messages, as each payload in sqlErrorProbePayloads provokes them, must be
// recognised — pinned at the classifier so a pruned bank fails here, not only end to end.
func TestSQLiteErrorMessagesAreRecognised(t *testing.T) {
	for _, msg := range []string{
		`SQLITE_ERROR: near "%": syntax error`,
		`SQL logic error: near "'%'": syntax error (1)`,
		`unrecognized token: "'%') AND deletedAt IS NULL)" (1)`,
		`sqlite3.OperationalError: near "x": syntax error`,
		`org.sqlite.SQLiteException: [SQLITE_ERROR] SQL error or missing database`,
	} {
		page := "<title>Error: " + html.EscapeString(msg) + "</title>"
		if got := ClassifySQLError("<title>ok</title>", page); got.Evidence != InjectionEvidenceErrorSignature {
			t.Errorf("%q: evidence = %v, want ErrorSignature", msg, got.Evidence)
		}
	}
}
