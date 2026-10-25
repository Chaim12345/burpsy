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
