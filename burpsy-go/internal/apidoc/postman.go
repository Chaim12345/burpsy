package apidoc

// Postman Collection v2.0 / v2.1 (burpsy-react-ui-r39r): Burp's API scan accepts a Postman Collection
// as well as OpenAPI, and burpsy refused one by name. Each request in the collection — folders walked
// depth-first, in the collection's own order — becomes one Operation, with the same provenance rules
// as the OpenAPI reader: a value the collection states is an example, and a `{{variable}}` the
// collection never defines is a placeholder, counted as one.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// FormatPostman is a Postman Collection (schema v2.0 or v2.1).
const FormatPostman Format = "postman-2"

// isPostman recognises a collection by its info block: a Postman schema URL or a _postman_id, or the
// v2 shape of an info object beside an item list.
func isPostman(root map[string]any) bool {
	info, _ := root["info"].(map[string]any)
	if info == nil {
		return false
	}
	if schema, _ := info["schema"].(string); strings.Contains(schema, "getpostman.com") || strings.Contains(schema, "postman") {
		return true
	}
	if _, ok := info["_postman_id"]; ok {
		return true
	}
	_, items := root["item"].([]any)
	return items
}

var postmanVarRe = regexp.MustCompile(`\{\{\s*([^{}\s]+)\s*\}\}`)

type postmanReader struct {
	vars    map[string]string
	servers []string
	seen    map[string]bool
	ops     []Operation
}

// subst replaces every {{name}} with the collection's value, or with the name itself when the
// collection does not define it; the second case is reported to the caller as a placeholder.
func (r *postmanReader) subst(s string) (string, []string) {
	var missing []string
	out := postmanVarRe.ReplaceAllStringFunc(s, func(m string) string {
		name := postmanVarRe.FindStringSubmatch(m)[1]
		if v, ok := r.vars[name]; ok {
			return v
		}
		missing = append(missing, name)
		return name
	})
	return out, missing
}

func parsePostman(root map[string]any) (*Document, error) {
	info, _ := root["info"].(map[string]any)
	doc := &Document{Format: FormatPostman, SpecVersion: "2.1"}
	if schema, _ := info["schema"].(string); strings.Contains(schema, "v2.0") {
		doc.SpecVersion = "2.0"
	}
	doc.Title, _ = info["name"].(string)
	if v, ok := info["version"]; ok {
		doc.Version = scalarString(v)
	}
	r := &postmanReader{vars: map[string]string{}, seen: map[string]bool{}}
	if list, ok := root["variable"].([]any); ok {
		for _, raw := range list {
			if v, _ := raw.(map[string]any); v != nil {
				if k, _ := v["key"].(string); k != "" {
					r.vars[k] = scalarString(v["value"])
				}
			}
		}
	}
	collectionAuth, _ := root["auth"].(map[string]any)
	items, _ := root["item"].([]any)
	if err := r.walk(items, collectionAuth); err != nil {
		return nil, err
	}
	if len(r.ops) == 0 {
		return nil, fmt.Errorf("the Postman collection holds no requests, so there is nothing to scan")
	}
	doc.Servers = r.servers
	doc.Operations = r.ops
	return doc, nil
}

func (r *postmanReader) walk(items []any, inherited map[string]any) error {
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		if item == nil {
			continue
		}
		auth := inherited
		if a, _ := item["auth"].(map[string]any); a != nil {
			auth = a
		}
		if sub, ok := item["item"].([]any); ok {
			if err := r.walk(sub, auth); err != nil {
				return err
			}
			continue
		}
		if err := r.request(item, auth); err != nil {
			return err
		}
	}
	return nil
}

func (r *postmanReader) request(item map[string]any, auth map[string]any) error {
	name, _ := item["name"].(string)
	op := Operation{OperationID: name, Summary: name, Method: "GET"}
	var req map[string]any
	switch v := item["request"].(type) {
	case string:
		req = map[string]any{"url": v}
	case map[string]any:
		req = v
	default:
		return nil
	}
	if a, _ := req["auth"].(map[string]any); a != nil {
		auth = a
	}
	if m, _ := req["method"].(string); m != "" {
		op.Method = strings.ToUpper(m)
	}
	note := func(in, pname, value string, missing []string) {
		src := ValueExample
		if len(missing) > 0 || value == "" {
			src = ValuePlaceholder
		}
		op.Parameters = append(op.Parameters, Parameter{Name: pname, In: in, Value: value, Source: src})
	}

	// The URL: the raw string where the collection kept one, else assembled from its parts.
	rawURL, pathVars := postmanURL(req["url"])
	template := rawURL
	full, missing := r.subst(rawURL)
	for k, v := range pathVars {
		full = strings.ReplaceAll(full, ":"+k, v)
	}
	server, rest := splitServer(full)
	if server == "" && len(missing) > 0 && strings.HasPrefix(rawURL, "{{") {
		// A leading {{baseUrl}} the collection never defines: the request is relative to a base the
		// caller supplies (the API scan's base URL), so it is stripped rather than sent as a host.
		_, after, _ := strings.Cut(full, missing[0])
		rest = after
		missing = missing[1:]
	}
	if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}
	if server != "" && !r.seen[server] {
		r.seen[server] = true
		r.servers = append(r.servers, server)
	}
	op.Path = rest
	_, tmplRest := splitServer(template)
	if tmplRest == "" {
		tmplRest = rest
	}
	op.Template = strings.SplitN(tmplRest, "?", 2)[0]
	for _, m := range missing {
		note("path", m, m, []string{m})
	}
	if u, err := url.Parse(rest); err == nil {
		for _, k := range sortedQueryKeys(u.Query()) {
			for _, v := range u.Query()[k] {
				note("query", k, v, nil)
			}
		}
	}

	// Headers, with disabled entries left out as Postman does.
	contentType := ""
	if hs, ok := req["header"].([]any); ok {
		for _, raw := range hs {
			h, _ := raw.(map[string]any)
			if h == nil || truthy(h["disabled"]) {
				continue
			}
			k, _ := h["key"].(string)
			v, miss := r.subst(scalarString(h["value"]))
			if k == "" {
				continue
			}
			if strings.EqualFold(k, "Content-Type") {
				contentType = v
				continue
			}
			op.Header = append(op.Header, Parameter{Name: k, In: "header", Value: v, Source: exampleOr(miss)})
			note("header", k, v, miss)
		}
	}
	for _, h := range r.authHeaders(auth) {
		op.Header = append(op.Header, h)
		op.Parameters = append(op.Parameters, h) // so an undefined {{token}} counts as a placeholder
	}

	if body, _ := req["body"].(map[string]any); body != nil && !truthy(body["disabled"]) {
		b, ct := r.body(body)
		if len(b) > 0 {
			op.Body = b
			if contentType == "" {
				contentType = ct
			}
		}
	}
	op.ContentType = contentType
	r.ops = append(r.ops, op)
	return nil
}

func exampleOr(missing []string) ValueSource {
	if len(missing) > 0 {
		return ValuePlaceholder
	}
	return ValueExample
}

func truthy(v any) bool {
	b, _ := v.(bool)
	return b
}

// postmanURL returns a request's URL as a string and its path variables (`:id` -> value).
func postmanURL(v any) (string, map[string]string) {
	vars := map[string]string{}
	switch u := v.(type) {
	case string:
		return u, vars
	case map[string]any:
		if list, ok := u["variable"].([]any); ok {
			for _, raw := range list {
				if pv, _ := raw.(map[string]any); pv != nil {
					if k, _ := pv["key"].(string); k != "" {
						vars[k] = scalarString(pv["value"])
					}
				}
			}
		}
		if raw, _ := u["raw"].(string); raw != "" {
			return raw, vars
		}
		join := func(x any, sep string) string {
			switch p := x.(type) {
			case string:
				return p
			case []any:
				parts := make([]string, 0, len(p))
				for _, s := range p {
					parts = append(parts, scalarString(s))
				}
				return strings.Join(parts, sep)
			}
			return ""
		}
		s := join(u["host"], ".")
		if proto, _ := u["protocol"].(string); proto != "" && s != "" {
			s = proto + "://" + s
		}
		if port := scalarString(u["port"]); port != "" {
			s += ":" + port
		}
		s += "/" + strings.TrimPrefix(join(u["path"], "/"), "/")
		if q, ok := u["query"].([]any); ok {
			var pairs []string
			for _, raw := range q {
				if qp, _ := raw.(map[string]any); qp != nil && !truthy(qp["disabled"]) {
					k, _ := qp["key"].(string)
					pairs = append(pairs, k+"="+scalarString(qp["value"]))
				}
			}
			if len(pairs) > 0 {
				s += "?" + strings.Join(pairs, "&")
			}
		}
		return s, vars
	}
	return "", vars
}

// splitServer separates "https://host:port" from the path of an absolute URL; a relative URL has no
// server.
func splitServer(s string) (string, string) {
	i := strings.Index(s, "://")
	if i < 0 {
		return "", s
	}
	rest := s[i+3:]
	j := strings.IndexAny(rest, "/?")
	if j < 0 {
		return s, "/"
	}
	return s[:i+3] + rest[:j], rest[j:]
}

func sortedQueryKeys(q url.Values) []string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// authHeaders turns the collection's (or the request's) auth into the header Postman would send:
// bearer, basic, and an apikey placed in a header. Other types are left to the operator.
func (r *postmanReader) authHeaders(auth map[string]any) []Parameter {
	if auth == nil {
		return nil
	}
	typ, _ := auth["type"].(string)
	field := func(key string) (string, []string) {
		list, _ := auth[typ].([]any)
		for _, raw := range list {
			if f, _ := raw.(map[string]any); f != nil && f["key"] == key {
				return r.subst(scalarString(f["value"]))
			}
		}
		return "", nil
	}
	switch typ {
	case "bearer":
		tok, miss := field("token")
		return []Parameter{{Name: "Authorization", In: "header", Value: "Bearer " + tok, Source: exampleOr(miss)}}
	case "basic":
		u, m1 := field("username")
		p, m2 := field("password")
		return []Parameter{{Name: "Authorization", In: "header", Value: "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p)), Source: exampleOr(append(m1, m2...))}}
	case "apikey":
		k, m1 := field("key")
		v, m2 := field("value")
		if in, _ := field("in"); in == "query" || k == "" {
			return nil
		}
		return []Parameter{{Name: k, In: "header", Value: v, Source: exampleOr(append(m1, m2...))}}
	}
	return nil
}

// body renders a request body the way Postman sends it, with the content type its mode implies.
func (r *postmanReader) body(body map[string]any) ([]byte, string) {
	mode, _ := body["mode"].(string)
	switch mode {
	case "raw":
		raw, _ := r.subst(scalarString(body["raw"]))
		ct := "text/plain"
		if opts, _ := body["options"].(map[string]any); opts != nil {
			if rawOpts, _ := opts["raw"].(map[string]any); rawOpts != nil {
				switch lang, _ := rawOpts["language"].(string); lang {
				case "json":
					ct = "application/json"
				case "xml":
					ct = "application/xml"
				case "html":
					ct = "text/html"
				case "javascript":
					ct = "application/javascript"
				}
			}
		}
		return []byte(raw), ct
	case "urlencoded":
		list, _ := body["urlencoded"].([]any)
		var pairs []string
		for _, raw := range list {
			if f, _ := raw.(map[string]any); f != nil && !truthy(f["disabled"]) {
				k, _ := f["key"].(string)
				v, _ := r.subst(scalarString(f["value"]))
				pairs = append(pairs, url.QueryEscape(k)+"="+url.QueryEscape(v))
			}
		}
		return []byte(strings.Join(pairs, "&")), "application/x-www-form-urlencoded"
	case "formdata":
		list, _ := body["formdata"].([]any)
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		for _, raw := range list {
			f, _ := raw.(map[string]any)
			if f == nil || truthy(f["disabled"]) || f["type"] == "file" {
				continue // a file part names a file on the author's machine, which this build cannot read
			}
			k, _ := f["key"].(string)
			v, _ := r.subst(scalarString(f["value"]))
			_ = w.WriteField(k, v)
		}
		_ = w.Close()
		return buf.Bytes(), w.FormDataContentType()
	case "graphql":
		g, _ := body["graphql"].(map[string]any)
		q, _ := r.subst(scalarString(g["query"]))
		payload := map[string]any{"query": q}
		if vs, _ := g["variables"].(string); strings.TrimSpace(vs) != "" {
			var vars any
			if json.Unmarshal([]byte(vs), &vars) == nil {
				payload["variables"] = vars
			}
		}
		out, _ := json.Marshal(payload)
		return out, "application/json"
	}
	return nil, ""
}
