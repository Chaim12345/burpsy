package web

// The Repeater GraphQL editor's wire contract (burpsy-react-ui-4xqt.3): validation parses with
// the pinned gqlparser, and the query replace changes exactly one string's content - the edit
// is the query and nothing else.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

const graphQLDraft = "POST /graphql HTTP/1.1\r\n" +
	"Host: shop.example\r\n" +
	"Content-Type: application/json\r\n" +
	"Content-Length: 118\r\n" +
	"X-Trace: keep-me\r\n" +
	"\r\n" +
	`{"query": "{ book(title: \"Dune\") { author } }",  "variables": {"x": 1}, "operationName": null}`

func TestRepeaterGraphQLValidateParsesWithThePinnedParser(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/repeater/graphql-validate", map[string]any{"query": "{ book { author } }"})
	if rec.Code != http.StatusOK {
		t.Fatalf("validate: %d %s", rec.Code, rec.Body.String())
	}
	var ok repeaterGraphQLValidateResp
	json.Unmarshal(rec.Body.Bytes(), &ok)
	if !ok.OK || len(ok.Errors) != 0 {
		t.Errorf("a valid document did not validate: %+v", ok)
	}

	rec = postJSON(t, s, "/api/repeater/graphql-validate", map[string]any{"query": "{ book { author }"})
	var bad repeaterGraphQLValidateResp
	json.Unmarshal(rec.Body.Bytes(), &bad)
	if bad.OK || len(bad.Errors) == 0 {
		t.Fatalf("a broken document validated: %+v", bad)
	}
	if bad.Errors[0].Line == 0 {
		t.Errorf("the error carries no position for the editor to place: %+v", bad.Errors[0])
	}
}

func TestRepeaterGraphQLQueryReplacesOnlyTheQueryContent(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/repeater/graphql-query", map[string]any{
		"request": graphQLDraft, "index": 0, "query": "{ book { title } }",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("replace: %d %s", rec.Code, rec.Body.String())
	}
	var resp repeaterGraphQLQueryResp
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Source != "body" {
		t.Errorf("source = %q, want body", resp.Source)
	}
	if !strings.Contains(resp.Request, `"{ book { title } }"`) {
		t.Errorf("the new query is not in the draft:\n%s", resp.Request)
	}
	// The edit is the query and nothing else: variables' spacing, operationName, the header
	// block and the trace header are byte-identical.
	for _, kept := range []string{`"variables": {"x": 1}`, `"operationName": null}`, "X-Trace: keep-me"} {
		if !strings.Contains(resp.Request, kept) {
			t.Errorf("the edit changed bytes it was not asked to change (%q):\n%s", kept, resp.Request)
		}
	}
	head, body, _ := splitRequestHead(resp.Request)
	want := "Content-Length: " + strconv.Itoa(len(body))
	if !strings.Contains(head, want) {
		t.Errorf("Content-Length was not moved to the new body (want %q):\n%s", want, head)
	}
}

func TestRepeaterGraphQLQueryPicksTheNamedBatchOperation(t *testing.T) {
	s := newTestServer()
	raw := "POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Length: 90\r\n\r\n" +
		`[{"query":"{ a }"},{"query":"{ b }","variables":{}}]`
	rec := postJSON(t, s, "/api/repeater/graphql-query", map[string]any{
		"request": raw, "index": 1, "query": "{ c }",
	})
	var resp repeaterGraphQLQueryResp
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !strings.Contains(resp.Request, `{"query":"{ a }"}`) || !strings.Contains(resp.Request, `{"query":"{ c }","variables":{}}`) {
		t.Errorf("the wrong operation was edited:\n%s", resp.Request)
	}
}

func TestRepeaterGraphQLQueryEditsTheURLCarrierWithCodecParity(t *testing.T) {
	s := newTestServer()
	raw := "GET /graphql?query=%7B%20a%20%7D&token=a+b%26c HTTP/1.1\r\nHost: shop.example\r\n\r\n"
	rec := postJSON(t, s, "/api/repeater/graphql-query", map[string]any{
		"request": raw, "index": 0, "query": "{ b(c: \"x+y\") }",
	})
	var resp repeaterGraphQLQueryResp
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Source != "params" {
		t.Errorf("source = %q, want params", resp.Source)
	}
	// The new query rides the parameter percent-encoded with '+' escaped (data, not space);
	// the neighbouring token's bytes are untouched.
	if !strings.Contains(resp.Request, "query=%7B%20b(c:%20%22x%2By%22)%20%7D&token=a+b%26c") {
		t.Errorf("the URL carrier was not rewritten with codec parity:\n%s", resp.Request)
	}
}

func TestRepeaterGraphQLQueryRefusesWhatItCannotName(t *testing.T) {
	s := newTestServer()
	plain := "POST /search HTTP/1.1\r\nHost: shop.example\r\nContent-Length: 17\r\n\r\n" + `{"queryx": "{ a }"}`
	rec := postJSON(t, s, "/api/repeater/graphql-query", map[string]any{"request": plain, "index": 0, "query": "{ b }"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no GraphQL carrier") {
		t.Errorf("a non-carrier was not refused by name: %d %s", rec.Code, rec.Body.String())
	}
	rec = postJSON(t, s, "/api/repeater/graphql-query", map[string]any{"request": graphQLDraft, "index": 3, "query": "{ b }"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "names no operation") {
		t.Errorf("an out-of-range index was not refused by name: %d %s", rec.Code, rec.Body.String())
	}
	// A "query" key inside variables is data, not the document: a draft whose only query-shaped
	// key is nested has no carrier.
	nested := "POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Length: 40\r\n\r\n" + `{"variables": {"query": "{ a }"}}`
	rec = postJSON(t, s, "/api/repeater/graphql-query", map[string]any{"request": nested, "index": 0, "query": "{ b }"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a nested query key was edited as the document: %d %s", rec.Code, rec.Body.String())
	}
}

// The review fixes (burpsy-react-ui-4xqt.3, pre-review ruling): the server indexes only what
// the UI would list, refuses ambiguous framing by name, reads every JSON-legal whitespace, and
// names the carriers it will not edit.

func TestRepeaterGraphQLQueryIndexesOnlyGraphQLDocuments(t *testing.T) {
	s := newTestServer()
	// The UI lists only the entries whose query looks like a GraphQL document, so a batch
	// [not-graphql, {b}] shows ONE operation and sends index 0 for it. The server must index
	// the same list or the edit lands on the wrong operation.
	raw := "POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Length: 42\r\n\r\n" +
		`[{"query":"not graphql"},{"query":"{b}"}]`
	rec := postJSON(t, s, "/api/repeater/graphql-query", map[string]any{
		"request": raw, "index": 0, "query": "{c}",
	})
	var resp repeaterGraphQLQueryResp
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if strings.Contains(resp.Request, `"query":"{c}"},{"query":"{b}"`) {
		t.Errorf("index 0 hit the not-GraphQL entry the UI never listed:\n%s", resp.Request)
	}
	if !strings.Contains(resp.Request, `{"query":"not graphql"},{"query":"{c}"}`) {
		t.Errorf("Apply did not hit {b}, the operation the UI shows at index 0:\n%s", resp.Request)
	}

	// A URL query parameter whose value is not a GraphQL document is not the carrier either:
	// the JSON body behind it is.
	mixed := "POST /graphql?query=notgraphql HTTP/1.1\r\nHost: shop.example\r\nContent-Length: 16\r\n\r\n" +
		`{"query":"{a}"}`
	rec = postJSON(t, s, "/api/repeater/graphql-query", map[string]any{
		"request": mixed, "index": 0, "query": "{c}",
	})
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Source != "body" || !strings.Contains(resp.Request, `{"query":"{c}"}`) || !strings.Contains(resp.Request, "query=notgraphql") {
		t.Errorf("a not-GraphQL URL parameter shadowed the body's carrier: source=%q\n%s", resp.Source, resp.Request)
	}
}

func TestRepeaterGraphQLQueryRefusesAmbiguousFramingByName(t *testing.T) {
	s := newTestServer()
	// Duplicate Content-Length is the smuggling shape: the edit rewrites framing bytes, and
	// which length a server trusts is not this route's guess to make.
	dup := "POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Length: 14\r\nContent-Length: 14\r\n\r\n" +
		`{"query":"{a}"}`
	rec := postJSON(t, s, "/api/repeater/graphql-query", map[string]any{"request": dup, "index": 0, "query": "{b}"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Content-Length") {
		t.Errorf("duplicate Content-Length was not refused by name: %d %s", rec.Code, rec.Body.String())
	}
	// Any Transfer-Encoding on the edit path: the edit rewrites Content-Length and does not
	// re-frame chunks.
	te := "POST /graphql HTTP/1.1\r\nHost: shop.example\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"e\r\n{\"query\":\"{a}\"}\r\n0\r\n\r\n"
	rec = postJSON(t, s, "/api/repeater/graphql-query", map[string]any{"request": te, "index": 0, "query": "{b}"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Transfer-Encoding") {
		t.Errorf("Transfer-Encoding was not refused by name: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRepeaterGraphQLQueryReadsEveryJSONWhitespaceAroundTheColon(t *testing.T) {
	s := newTestServer()
	// JSON-legal whitespace is space, tab, LF and CR - all four can sit around the colon.
	raw := "POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Length: 20\r\n\r\n" +
		"{\"query\"\n:\r\t\"{a}\"}"
	rec := postJSON(t, s, "/api/repeater/graphql-query", map[string]any{
		"request": raw, "index": 0, "query": "{b}",
	})
	var resp repeaterGraphQLQueryResp
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || !strings.Contains(resp.Request, "\"query\"\n:\r\t\"{b}\"") {
		t.Errorf("a carrier written with LF/CR/tab around the colon was not read: %d\n%s", rec.Code, resp.Request)
	}
}

func TestRepeaterGraphQLQueryNamesTheCarriersItWillNotEdit(t *testing.T) {
	s := newTestServer()
	// application/graphql: the body IS the document. The typed view reads it; edit-apply does
	// not rewrite it, and says so by name rather than with a generic no-carrier.
	gql := "POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/graphql\r\nContent-Length: 4\r\n\r\n{a} "
	rec := postJSON(t, s, "/api/repeater/graphql-query", map[string]any{"request": gql, "index": 0, "query": "{b}"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "application/graphql") {
		t.Errorf("the application/graphql carrier was not refused by name: %d %s", rec.Code, rec.Body.String())
	}
	// A form body carrying query= is half-recognized: named, not "no GraphQL carrier".
	form := "POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 17\r\n\r\nquery=%7Ba%7D&x=1"
	rec = postJSON(t, s, "/api/repeater/graphql-query", map[string]any{"request": form, "index": 0, "query": "{b}"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "url-encoded") {
		t.Errorf("the form carrier was not refused by name: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRepeaterGraphQLQueryCountsDuplicateKeysLikeJSONParse(t *testing.T) {
	s := newTestServer()
	// JSON.parse reads a duplicate key last-wins, so the console's list carries {b}; the
	// server's index 0 must name the same operation, not the shadowed {a}.
	raw := "POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Length: 32\r\n\r\n" +
		`{"query":"{a}","query":"{b}"}`
	rec := postJSON(t, s, "/api/repeater/graphql-query", map[string]any{
		"request": raw, "index": 0, "query": "{c}",
	})
	var resp repeaterGraphQLQueryResp
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !strings.Contains(resp.Request, `{"query":"{a}","query":"{c}"}`) {
		t.Errorf("a duplicate key did not resolve last-wins like JSON.parse:\n%s", resp.Request)
	}
	// Inside a batch the rule is per element: the shadowed key of element one does not
	// shift element two.
	batch := "POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Length: 52\r\n\r\n" +
		`[{"query":"{a}","query":"{b}"},{"query":"{c}"}]`
	rec = postJSON(t, s, "/api/repeater/graphql-query", map[string]any{
		"request": batch, "index": 1, "query": "{d}",
	})
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !strings.Contains(resp.Request, `[{"query":"{a}","query":"{b}"},{"query":"{d}"}]`) {
		t.Errorf("a duplicate key in one batch element shifted the next element's index:\n%s", resp.Request)
	}
	// A trailing duplicate that is not a document EMPTIES the slot (JSON.parse would hand
	// the console a non-operation): the first key is not editable either.
	shadowed := "POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Length: 33\r\n\r\n" +
		`{"query":"{a}","query":"note"}`
	rec = postJSON(t, s, "/api/repeater/graphql-query", map[string]any{
		"request": shadowed, "index": 0, "query": "{c}",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a shadowed query key stayed editable: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRepeaterGraphQLQueryAShadowedKeyDoesNotAppendTheObjectTwice(t *testing.T) {
	s := newTestServer()
	// valid -> non-document -> valid inside one element: the slot empties on the shadow and
	// refills on the last key, but the object still holds ONE index - JSON.parse's list is
	// [{b}, {c}], so index 1 must name {c} and index 2 must name nothing.
	raw := "POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Length: 60\r\n\r\n" +
		`[{"query":"{a}","query":"note","query":"{b}"},{"query":"{c}"}]`
	rec := postJSON(t, s, "/api/repeater/graphql-query", map[string]any{
		"request": raw, "index": 1, "query": "{d}",
	})
	var resp repeaterGraphQLQueryResp
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !strings.Contains(resp.Request, `[{"query":"{a}","query":"note","query":"{b}"},{"query":"{d}"}]`) {
		t.Errorf("index 1 did not name the second element:\n%s", resp.Request)
	}
	rec = postJSON(t, s, "/api/repeater/graphql-query", map[string]any{
		"request": raw, "index": 2, "query": "{d}",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("index 2 named an operation in a two-operation list: %d %s", rec.Code, rec.Body.String())
	}
}
