package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/crawler"
	"github.com/burpsy-go/burpsy/internal/httputil"
	"github.com/burpsy-go/burpsy/pkg/graphqlmap"
)

// Save GraphQL queries to site map (burpsy-react-ui-7v1e).
//
// Burp (desktop/testing-workflow/working-with-graphql.html, burp.Zu6): after an introspection query
// has been sent, "Save GraphQL queries to site map" on the response turns the schema into one request
// per QUERY and MUTATION root field and adds each to the site map without sending it. The request
// keeps the original's endpoint and headers and carries the generated operation in the same place
// the introspection query was carried — the JSON body, or the `query` URL parameter, which is Burp's
// default when the original carried it nowhere it recognises.
//
// burpsy records each generated request as an exchange with no response and Source "schema"
// (core.SourceSchema): the site map is built from exchanges, so that is how an item reaches it, and
// the source keeps it from ever reading as traffic. Nothing is sent — the route is riskLocal.

type graphqlSitemapReq struct {
	// ExchangeID is the exchange whose response is the introspection answer and whose request names
	// the endpoint. A pointer because exchange 0 is a real exchange.
	ExchangeID *core.ExchangeID `json:"exchange_id" desc:"the exchange whose response is an introspection answer; its request supplies the endpoint and headers"`
}

type graphqlSitemapOp struct {
	Kind       string           `json:"kind"`
	Field      string           `json:"field"`
	Name       string           `json:"name"`
	ExchangeID core.ExchangeID  `json:"exchange_id"`
	Path       string           `json:"path"`
	Parent     *core.ExchangeID `json:"parent,omitempty"`
}

type graphqlSitemapResp struct {
	Endpoint string `json:"endpoint"`
	// Placement is where each generated operation was written: "body" (a JSON body) or "url" (the
	// query parameter).
	Placement  string             `json:"placement"`
	Operations []graphqlSitemapOp `json:"operations"`
	// Truncated is true when the schema declared more operations than crawler.MaxGraphQLOperations
	// and the rest were not generated — reported, never silent.
	Truncated bool `json:"truncated"`
	Limit     int  `json:"limit"`
}

func (s *Server) handleGraphQLSitemap(w http.ResponseWriter, r *http.Request) {
	var req graphqlSitemapReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil || req.ExchangeID == nil {
		http.Error(w, `body must be JSON {"exchange_id": n} naming the exchange whose response is the introspection answer`, http.StatusBadRequest)
		return
	}
	ex, err := s.store.GetExchange(*req.ExchangeID)
	if err != nil {
		http.Error(w, fmt.Sprintf("No exchange %d has been captured", *req.ExchangeID), http.StatusNotFound)
		return
	}
	if ex.Request == nil || ex.Response == nil {
		http.Error(w, "refused: this exchange has no request and response pair — send the introspection query first", http.StatusBadRequest)
		return
	}
	reqMsg, rerr := s.store.Get(*ex.Request)
	respMsg, perr := s.store.Get(*ex.Response)
	if rerr != nil || perr != nil {
		http.Error(w, "the exchange's messages are not in the store", http.StatusNotFound)
		return
	}
	schema, reason := introspectionSchemaFrom(respMsg.Raw())
	if schema == nil {
		http.Error(w, "refused: "+reason, http.StatusBadRequest)
		return
	}
	ops, truncated := schema.Operations(crawler.MaxGraphQLOperations)

	original := reqMsg.Raw()
	placement := graphqlPlacementOf(original)
	resp := graphqlSitemapResp{
		Endpoint:   ex.Host + firstLinePath(string(original)),
		Placement:  placement,
		Operations: []graphqlSitemapOp{},
		Truncated:  truncated,
		Limit:      crawler.MaxGraphQLOperations,
	}
	parent := ex.ID
	for _, op := range ops {
		raw, err := withGraphQLOperation(original, placement, op)
		if err != nil {
			http.Error(w, "could not write the operation into the request: "+err.Error(), http.StatusBadRequest)
			return
		}
		// One capture-gate hold across the message and its row (burpsy-react-ui-capture-split-web).
		hold := s.store.HoldCapture()
		msgID, err := hold.Put(raw, core.DirectionRequest)
		if err != nil {
			hold.Release()
			http.Error(w, "could not store a generated request: "+err.Error(), http.StatusInternalServerError)
			return
		}
		row := &core.Exchange{
			Host:      ex.Host,
			Port:      ex.Port,
			TLS:       ex.TLS,
			Method:    firstLineMethod(string(raw)),
			Path:      firstLinePath(string(raw)),
			StartedMs: uint64(time.Now().UnixMilli()),
			Request:   core.MsgPtr(msgID),
			ParentID:  s.validParent(&parent),
			Source:    core.SourceSchema,
		}
		hold.AddExchange(row)
		hold.Release()
		resp.Operations = append(resp.Operations, graphqlSitemapOp{
			Kind: op.Kind, Field: op.Field, Name: op.Name, ExchangeID: row.ID, Path: row.Path, Parent: row.ParentID,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// introspectionSchemaFrom reads an introspection answer out of a response, unwrapping chunking and a
// supported Content-Encoding first. The reason names why a body is not one, so the refusal says
// which of "not JSON", "GraphQL with introspection off" and "no schema" it was.
func introspectionSchemaFrom(raw []byte) (*graphqlmap.Schema, string) {
	head, body := splitHeadBody(raw)
	if strings.EqualFold(firstHeaderValue(head, "Transfer-Encoding"), "chunked") {
		if plain, ok := dechunkForView(body); ok {
			body = plain
		}
	}
	if enc := firstHeaderValue(head, "Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		if !httputil.Unpackable(enc) {
			return nil, "the response is " + enc + "-encoded and this build cannot decode it"
		}
		plain, err := httputil.DecodeBody(enc, body)
		if err != nil {
			return nil, "the " + enc + " body could not be decoded: " + err.Error()
		}
		body = plain
	}
	var answer struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &answer); err != nil {
		return nil, "the response body is not a GraphQL answer (not JSON: " + err.Error() + ")"
	}
	if len(answer.Data) == 0 || string(answer.Data) == "null" {
		if len(answer.Errors) > 0 {
			return nil, "the GraphQL endpoint answered with errors rather than a schema: " + answer.Errors[0].Message
		}
		return nil, "the response is JSON but carries no data.__schema — it is not an introspection answer"
	}
	var probe struct {
		Schema json.RawMessage `json:"__schema"`
	}
	if json.Unmarshal(answer.Data, &probe) != nil || len(probe.Schema) == 0 || string(probe.Schema) == "null" {
		return nil, "the response carries data but no __schema — it is not an introspection answer"
	}
	var env struct {
		Schema struct {
			QueryType    *struct{ Name string } `json:"queryType"`
			MutationType *struct{ Name string } `json:"mutationType"`
			Types        []graphqlmap.Type      `json:"types"`
		} `json:"__schema"`
	}
	if err := json.Unmarshal(answer.Data, &env); err != nil {
		return nil, "the __schema could not be read: " + err.Error()
	}
	// A schema with no types is still a schema — an empty API — and yields operations [], not a
	// refusal: "introspection worked and there is nothing to call" is a true answer.
	schema := &graphqlmap.Schema{Types: env.Schema.Types}
	if env.Schema.QueryType != nil {
		schema.QueryType = env.Schema.QueryType.Name
	}
	if env.Schema.MutationType != nil {
		schema.MutationType = env.Schema.MutationType.Name
	}
	return schema, ""
}

// graphqlPlacementOf reports where the request carries its GraphQL query: "body" for a JSON body
// with a query member, "url" otherwise — the query parameter, Burp's own default (Zg6r.URL_PARAM).
func graphqlPlacementOf(raw []byte) string {
	_, body := splitHeadBody(raw)
	var probe map[string]json.RawMessage
	if json.Unmarshal(bytes.TrimSpace(body), &probe) == nil {
		if _, ok := probe["query"]; ok {
			return "body"
		}
	}
	return "url"
}

// withGraphQLOperation writes one generated operation into a copy of the request at the placement.
// Every header and the start line's method and version are kept, in the request's own line ending
// (an operator-typed request in Repeater is often bare LF, and the copy must be the same request
// with one thing changed, not a normalised one); a body placement rewrites the body as
// {"operationName","query","variables"} and recomputes Content-Length; a URL placement sets the
// query, variables and operationName parameters and keeps the others.
func withGraphQLOperation(raw []byte, placement string, op graphqlmap.Operation) ([]byte, error) {
	vars, err := json.Marshal(op.Variables)
	if err != nil {
		return nil, err
	}
	head, eol, ok := requestHeadOf(raw)
	if !ok {
		return nil, fmt.Errorf("the request has no header terminator")
	}
	lines := strings.Split(head, eol)
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("the start line %q is not METHOD TARGET VERSION", lines[0])
	}
	_, body := splitHeadBody(raw)
	if placement == "body" {
		newBody, err := json.Marshal(map[string]json.RawMessage{
			"operationName": graphqlJSONString(op.Name),
			"query":         graphqlJSONString(op.Document),
			"variables":     vars,
		})
		if err != nil {
			return nil, err
		}
		kept := lines[:1]
		for _, line := range lines[1:] {
			if name, _, found := strings.Cut(line, ":"); found && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
				continue
			}
			kept = append(kept, line)
		}
		kept = append(kept, "Content-Length: "+strconv.Itoa(len(newBody)))
		return append([]byte(strings.Join(kept, eol)+eol+eol), newBody...), nil
	}
	path, rawQuery, _ := strings.Cut(parts[1], "?")
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		values = url.Values{}
	}
	values.Set("query", op.Document)
	values.Set("variables", string(vars))
	values.Set("operationName", op.Name)
	lines[0] = parts[0] + " " + path + "?" + values.Encode() + " " + parts[2]
	return append([]byte(strings.Join(lines, eol)+eol+eol), body...), nil
}

// requestHeadOf returns the request's head (start line and headers, without the blank line) and the
// line ending it uses: CRLF when the head is CRLF-terminated, bare LF otherwise.
func requestHeadOf(raw []byte) (head, eol string, ok bool) {
	text := string(raw)
	if i := strings.Index(text, "\r\n\r\n"); i >= 0 {
		return text[:i], "\r\n", true
	}
	if i := strings.Index(text, "\n\n"); i >= 0 {
		return text[:i], "\n", true
	}
	return "", "", false
}

func graphqlJSONString(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}
