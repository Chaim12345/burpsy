package scanner

// The SQL-injection row against a real SQLite engine. OWASP Juice Shop's product search
// concatenates `q` into a LIKE clause and renders the driver's error into a 500 page, and its
// login concatenates the JSON `email` into a WHERE clause behind a bare "Error" page. Against the
// real application a full audit of both requests reported nothing and called itself complete.
// These tests run the same query shapes through modernc.org/sqlite, so every error, every row
// count and every status is the engine's own rather than something the test chose to match.
import (
	"context"
	"database/sql"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

// juiceShopDB is an in-memory SQLite database seeded with the two tables the endpoints query.
func juiceShopDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE Products (id INTEGER, name TEXT, description TEXT, deletedAt TEXT);
		INSERT INTO Products VALUES (1, 'Apple Juice', 'The all-time classic.', NULL),
		                            (2, 'Banana Juice', 'Monkeys love it.', NULL);
		CREATE TABLE Users (id INTEGER, email TEXT, password TEXT, deletedAt TEXT);
		INSERT INTO Users VALUES (1, 'admin@juice-sh.op', 'secret-hash', NULL);`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return db
}

// errorPage is Juice Shop's error handler: with verbose set, the driver's message HTML-escaped into
// the title, as the search endpoint shows it; without, a bare "Error", as the login shows it.
func errorPage(w http.ResponseWriter, err error, verbose bool) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusInternalServerError)
	title := "Error"
	if verbose {
		title += ": " + html.EscapeString(err.Error())
	}
	_, _ = io.WriteString(w, "<html><head><title>"+title+"</title></head></html>")
}

// searchHandler serves /rest/products/search?q= the way Juice Shop does. parameterized binds q
// instead of concatenating it — the safe twin.
func searchHandler(db *sql.DB, parameterized, verboseErrors bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			errorPage(w, err, verboseErrors)
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
	}
}

// loginHandler serves POST /rest/user/login the way Juice Shop does: the JSON email concatenated
// into the WHERE clause, a bare error page on a broken query, 401 on no row, a token on a row.
// It records every email it was sent so a test can say which probes reached it.
type loginHandler struct {
	db            *sql.DB
	parameterized bool
	mu            sync.Mutex
	emails        []string
}

func (l *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct{ Email, Password string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	l.mu.Lock()
	l.emails = append(l.emails, body.Email)
	l.mu.Unlock()
	var row *sql.Row
	if l.parameterized {
		row = l.db.QueryRow(`SELECT id FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL`, body.Email, body.Password)
	} else {
		row = l.db.QueryRow(`SELECT id FROM Users WHERE email = '` + body.Email + `' AND password = '` + body.Password +
			`' AND deletedAt IS NULL`)
	}
	var id int
	switch err := row.Scan(&id); {
	case err == sql.ErrNoRows:
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "Invalid email or password.")
	case err != nil:
		errorPage(w, err, false)
	default:
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"authentication":{"token":"eyJ0eXAiOiJKV1Qi.user`+strconv.Itoa(id)+`","umail":"admin@juice-sh.op"}}`)
	}
}

func (l *loginHandler) sawEmailContaining(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.emails {
		if strings.Contains(strings.ToLower(e), sub) {
			return true
		}
	}
	return false
}

// auditOne seeds one exchange for rawReq against srv (sending it once for the baseline response)
// and runs the SQL-injection family over it under cfg.
func auditOne(t *testing.T, srv *httptest.Server, method, path, contentType, body string, cfg AuditConfig) []*Finding {
	t.Helper()
	host, portStr, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	raw := method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\n"
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
		raw += "Content-Type: " + contentType + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n"
	}
	raw += "\r\n" + body
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	respBody, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()

	store := core.NewTrafficStore()
	reqID, err := store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respRaw := "HTTP/1.1 " + strconv.Itoa(res.StatusCode) + " " + http.StatusText(res.StatusCode) +
		"\r\nContent-Length: " + strconv.Itoa(len(respBody)) + "\r\n\r\n" + string(respBody)
	respID, err := store.Put([]byte(respRaw), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID,
		Host: host, Port: uint16(port), Method: method, Path: path}
	store.AddExchange(ex)

	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: time.Minute, CheckSqli: true})
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{ex.ID}, cfg)
	return sqliFindingsNamed(findings, sqlInjectionIssue)
}

const searchPath = "/rest/products/search?q=apple"

func TestSQLiFindsTheJuiceShopSearchInjectionOnSQLite(t *testing.T) {
	srv := httptest.NewServer(searchHandler(juiceShopDB(t), false, true))
	t.Cleanup(srv.Close)
	if got := auditOne(t, srv, "GET", searchPath, "", "", AuditConfig{}); len(got) == 0 {
		t.Fatalf("no %q finding against a concatenated SQLite LIKE query", sqlInjectionIssue)
	}
}

func TestSQLiReportsNothingOnTheParameterizedSQLiteTwin(t *testing.T) {
	srv := httptest.NewServer(searchHandler(juiceShopDB(t), true, true))
	t.Cleanup(srv.Close)
	if got := auditOne(t, srv, "GET", searchPath, "", "", AuditConfig{}); len(got) != 0 {
		t.Fatalf("the parameterized twin reported %d %q finding(s): %+v", len(got), sqlInjectionIssue, got)
	}
}

// With the driver's message hidden, the error bank has nothing to read and the search injection
// has to be found by the boolean technique — which needs a pair that survives the LIKE pattern's
// trailing `%'`. Before the LIKE pairs, every pair rendered false in both halves.
func TestSQLiFindsALikeClauseInjectionByBooleanWhenErrorsAreHidden(t *testing.T) {
	srv := httptest.NewServer(searchHandler(juiceShopDB(t), false, false))
	t.Cleanup(srv.Close)
	got := auditOne(t, srv, "GET", searchPath, "", "", AuditConfig{})
	if len(got) == 0 {
		t.Fatalf("no %q finding against a LIKE-clause injection behind a generic error page", sqlInjectionIssue)
	}
}

const loginBody = `{"email":"nobody@example.com","password":"wrong"}`

// Juice Shop's login: no database text on error, and a baseline that matched no row. Only a
// widening `or` pair can tell, and it does: `' or 1=2-- ` stays 401, `' or 1=1-- ` logs in.
func TestSQLiFindsTheJuiceShopLoginInjectionWithAWideningPair(t *testing.T) {
	db := juiceShopDB(t)
	srv := httptest.NewServer(&loginHandler{db: db})
	t.Cleanup(srv.Close)
	if got := auditOne(t, srv, "POST", "/rest/user/login", "application/json", loginBody, AuditConfig{}); len(got) == 0 {
		t.Fatalf("no %q finding against a concatenated login query", sqlInjectionIssue)
	}
}

func TestSQLiReportsNothingOnTheParameterizedLoginTwin(t *testing.T) {
	srv := httptest.NewServer(&loginHandler{db: juiceShopDB(t), parameterized: true})
	t.Cleanup(srv.Close)
	if got := auditOne(t, srv, "POST", "/rest/user/login", "application/json", loginBody, AuditConfig{}); len(got) != 0 {
		t.Fatalf("the parameterized login reported %d %q finding(s): %+v", len(got), sqlInjectionIssue, got)
	}
}

// An `or 1=1` is a write to every row when the statement is an UPDATE or DELETE, so a run that
// leaves the intrusive tier off must not send one — not merely not report one.
func TestSQLiSendsNoWideningPairWhenTheIntrusiveTierIsOff(t *testing.T) {
	h := &loginHandler{db: juiceShopDB(t)}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	on := OptUint32{Set: true, Value: 1}
	cfg := AuditConfig{LightActiveChecks: on, MediumActiveChecks: on, IntrusiveActiveChecks: OptUint32{Set: true}}
	if got := auditOne(t, srv, "POST", "/rest/user/login", "application/json", loginBody, cfg); len(got) != 0 {
		t.Errorf("reported %d finding(s) with the intrusive tier off; only a widening pair can see this login", len(got))
	}
	if !h.sawEmailContaining("'") {
		t.Fatalf("the login saw no quote at all: the SQL-injection check never probed it, so this test proves nothing")
	}
	if h.sawEmailContaining(" or 1=1") {
		t.Fatalf("an `or 1=1` probe reached the target with the intrusive tier off")
	}
}

// The MySQL and Oracle timing banks are rendered with their dialect gates, and the zero-delay
// control renders the same statement with the sleep set to zero.
func TestTheMySQLAndOracleTimingPayloadsAreRenderedAndGated(t *testing.T) {
	var mysql, oracle int
	for _, tp := range sqlTimingPayloads(5 * time.Second) {
		switch {
		case strings.Contains(tp.payload, "sysdate(),sleep(5)"):
			mysql++
			if !strings.Contains(tp.render(0), "sysdate(),sleep(0)") || !containsMethod(tp.methods, MethodMySQLSpecific) {
				t.Errorf("MySQL payload %q: render(0)=%q methods=%v", tp.payload, tp.render(0), tp.methods)
			}
		case strings.Contains(tp.payload, "dbms_pipe.receive_message(('a'),5)"):
			oracle++
			if !containsMethod(tp.methods, MethodOracleSpecific) {
				t.Errorf("Oracle payload %q: methods=%v", tp.payload, tp.methods)
			}
		}
	}
	if mysql != 3 || oracle != 2 {
		t.Fatalf("rendered %d MySQL and %d Oracle timing payloads, want 3 and 2", mysql, oracle)
	}
}

func containsMethod(methods []string, want string) bool {
	for _, m := range methods {
		if m == want {
			return true
		}
	}
	return false
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

// One message per engine the extended bank adds, each as the engine or its driver prints it.
func TestTheExtendedErrorBankRecognisesEachEngine(t *testing.T) {
	for _, msg := range []string{
		"You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version",
		"Warning: mysqli_query(): (42000/1064)",
		`ERROR:  syntax error at or near "'"`,
		`PG::SyntaxError: ERROR:  unterminated quoted string at or near "'"`,
		"System.Data.SqlClient.SqlException (0x80131904): Unclosed quotation mark after the character string",
		"ORA-01756: quoted string not properly terminated",
		"DB2 SQL error: SQLCODE=-104, SQLSTATE=42601",
		"org.h2.jdbc.JdbcSQLSyntaxErrorException: Syntax error in SQL statement",
		"SQLSTATE[42000]: Syntax error or access violation: 1064",
		"SequelizeDatabaseError: SQLITE_ERROR: near \"x\": syntax error",
		"Code: 62. DB::Exception: Syntax error: failed at position 1",
	} {
		if got := ClassifySQLError("<p>ok</p>", "<p>"+html.EscapeString(msg)+"</p>"); got.Evidence != InjectionEvidenceErrorSignature {
			t.Errorf("%q: evidence = %v, want ErrorSignature", msg, got.Evidence)
		}
	}
}

// A point that both errors and differentiates is reported at the error's (firm) confidence, not
// the differential's (tentative): Juice Shop's search does both.
func TestAnErrorSignatureOutranksABooleanDifferential(t *testing.T) {
	best, confirmed := BestEvidence([]InjectionProbe{
		{Payload: "bool", Evidence: InjectionEvidenceBooleanDifferential},
		{Payload: "err", Evidence: InjectionEvidenceErrorSignature},
	})
	if !confirmed || best.Payload != "err" {
		t.Fatalf("best = %+v, want the error-signature probe", best)
	}
}
