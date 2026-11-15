package web

import (
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
)

// Shared aliases so ui2_pages.go and ui2.go use the same types without redefinition.
type templateHTMLAlias = template.HTML
type recorderAlias = httptest.ResponseRecorder

func newRecorder() *recorderAlias            { return httptest.NewRecorder() }
func ui2JSONUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
func ui2JSONMarshal(v any) ([]byte, error)   { return json.Marshal(v) }

type ioReadCloser struct{ *strings.Reader }

func (ioReadCloser) Close() error { return nil }

var _ = io.EOF
var _ = http.MethodGet
