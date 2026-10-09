package apidoc

// Parameter overrides for the API-details review step (burpsy-react-ui-vuw7): Burp's parameters table
// lets the operator replace a value before the scan. An override re-renders only the part of the
// request it touches — the path from the template, the query from the query parameters, or one
// header — so everything the operator did not change is sent exactly as the document produced it.

import (
	"net/url"
	"strings"
)

// Key names an operation the way the review table does: "METHOD template".
func (op *Operation) Key() string { return op.Method + " " + op.Template }

// SetParameter replaces a parameter's value, marking it as the operator's. It reports whether the
// operation has such a parameter.
func (op *Operation) SetParameter(in, name, value string) bool {
	found := false
	for i := range op.Parameters {
		p := &op.Parameters[i]
		if p.In == in && p.Name == name {
			p.Value, p.Source, found = value, ValueOperator, true
		}
	}
	if !found {
		return false
	}
	switch in {
	case "path":
		values := map[string]string{}
		for _, p := range op.Parameters {
			if p.In == "path" {
				values[p.Name] = p.Value
			}
		}
		pathPart, query, hasQuery := strings.Cut(op.Path, "?")
		if strings.Contains(op.Template, "{") {
			pathPart = fillTemplate(op.Template, values)
		}
		op.Path = pathPart
		if hasQuery {
			op.Path += "?" + query
		}
	case "query":
		for i := range op.Query {
			if op.Query[i].Name == name {
				op.Query[i].Value = value
			}
		}
		pathPart, _, _ := strings.Cut(op.Path, "?")
		var pairs []string
		for _, p := range op.Parameters {
			if p.In == "query" {
				pairs = append(pairs, url.QueryEscape(p.Name)+"="+url.QueryEscape(p.Value))
			}
		}
		op.Path = pathPart
		if len(pairs) > 0 {
			op.Path += "?" + strings.Join(pairs, "&")
		}
	case "header":
		for i := range op.Header {
			if op.Header[i].Name == name {
				op.Header[i].Value, op.Header[i].Source = value, ValueOperator
			}
		}
	}
	return true
}
