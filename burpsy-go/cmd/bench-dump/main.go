// bench-dump prints the vulnapp manifest as JSON for benchmark truth tables. Benchmark tooling, not shipped.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

type row struct {
	Path        string `json:"path"`
	Row         string `json:"row"`
	Method      string `json:"method"`
	Safe        bool   `json:"safe"`
	DOM         bool   `json:"dom"`
	Stored      bool   `json:"stored"`
	Body        string `json:"body"`
	ContentType string `json:"content_type"`
	Note        string `json:"note"`
}

func main() {
	eps := vulnapp.Vulnerabilities()
	out := make([]row, 0, len(eps))
	for _, e := range eps {
		out = append(out, row{Path: e.Path, Row: e.Row, Method: e.Method, Safe: e.Safe, DOM: e.DOM, Stored: e.Stored, Body: e.Body, ContentType: e.ContentType, Note: e.Note})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
