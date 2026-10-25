package web

// Burp's Target analyzer (desktop/tools/engagement-tools/target-analyzer.html, burpsy-react-ui-dnvi):
// "how many static and dynamic URLs a target web application contains, and how many parameters
// each URL takes", over the content already captured for a selected host or branch.
//
// A URL is scheme, authority and path, without the query. It is dynamic when any captured request
// to it carries a parameter — in the query string, or in a urlencoded or multipart body — and static
// otherwise; its parameters are the union of the names its requests carried. The summary is Burp's
// four numbers: dynamic URLs, static URLs, parameters (each dynamic URL's distinct names, summed) and
// unique parameter names. format=html is Burp's "Save report".

import (
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

type analyzerURL struct {
	URL      string   `json:"url"`
	Methods  []string `json:"methods"`
	Params   []string `json:"params"`
	Requests int      `json:"requests"`
	// ExchangeID is the most recent capture of the URL, for opening its request and response.
	ExchangeID core.ExchangeID `json:"exchange_id"`
}

type analyzerParam struct {
	Name     string   `json:"name"`
	URLCount int      `json:"url_count"`
	URLs     []string `json:"urls"`
}

type analyzerSummary struct {
	DynamicURLs          int `json:"dynamic_urls"`
	StaticURLs           int `json:"static_urls"`
	Parameters           int `json:"parameters"`
	UniqueParameterNames int `json:"unique_parameter_names"`
}

type analyzerReport struct {
	Host       string          `json:"host"`
	Path       string          `json:"path"`
	Summary    analyzerSummary `json:"summary"`
	Dynamic    []analyzerURL   `json:"dynamic"`
	Static     []analyzerURL   `json:"static"`
	Parameters []analyzerParam `json:"parameters"`
}

func (s *Server) handleTargetAnalyze(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := strings.ToLower(strings.TrimSpace(q.Get("host")))
	if host == "" {
		http.Error(w, "host is required: the analyzer reports on one host or a branch under it", http.StatusBadRequest)
		return
	}
	path := strings.TrimSpace(q.Get("path"))
	if path != "" && !strings.HasPrefix(path, "/") {
		http.Error(w, "path must start with /", http.StatusBadRequest)
		return
	}
	var port *uint16
	if raw := q.Get("port"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 65535 {
			http.Error(w, "port must be 1-65535", http.StatusBadRequest)
			return
		}
		p := uint16(n)
		port = &p
	}
	var tls *bool
	switch q.Get("tls") {
	case "":
	case "true":
		v := true
		tls = &v
	case "false":
		v := false
		tls = &v
	default:
		http.Error(w, "tls must be true or false", http.StatusBadRequest)
		return
	}
	report := s.analyzeTarget(host, path, port, tls)
	switch q.Get("format") {
	case "", "json":
		writeJSON(w, http.StatusOK, report)
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="target-analysis-`+sanitiseFilename(host)+`.html"`)
		_ = analyzerHTML.Execute(w, report)
	default:
		http.Error(w, "format must be json or html", http.StatusBadRequest)
	}
}

func sanitiseFilename(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '_'
	}, s)
}

func (s *Server) analyzeTarget(host, path string, port *uint16, tls *bool) analyzerReport {
	type acc struct {
		methods map[string]bool
		params  []string
		seen    map[string]bool
		count   int
		last    core.ExchangeID
	}
	urls := map[string]*acc{}
	for _, ex := range s.store.Exchanges() {
		if ex == nil || ex.Request == nil || strings.ToLower(ex.Host) != host {
			continue
		}
		if port != nil && ex.Port != *port || tls != nil && ex.TLS != *tls {
			continue
		}
		exPath, _, _ := strings.Cut(ex.Path, "?")
		if path != "" && !strings.HasPrefix(exPath, path) {
			continue
		}
		scheme := "http"
		if ex.TLS {
			scheme = "https"
		}
		key := scheme + "://" + ex.Host + ":" + strconv.Itoa(int(ex.Port)) + exPath
		a := urls[key]
		if a == nil {
			a = &acc{methods: map[string]bool{}, seen: map[string]bool{}}
			urls[key] = a
		}
		a.count++
		a.methods[ex.Method] = true
		if ex.ID >= a.last {
			a.last = ex.ID
		}
		if msg, err := s.store.Get(*ex.Request); err == nil {
			for _, name := range core.RequestParameterNames(msg.Raw()) {
				if !a.seen[name] {
					a.seen[name] = true
					a.params = append(a.params, name)
				}
			}
		}
	}
	report := analyzerReport{Host: host, Path: path, Dynamic: []analyzerURL{}, Static: []analyzerURL{}, Parameters: []analyzerParam{}}
	byName := map[string][]string{}
	for url, a := range urls {
		methods := make([]string, 0, len(a.methods))
		for m := range a.methods {
			methods = append(methods, m)
		}
		sort.Strings(methods)
		row := analyzerURL{URL: url, Methods: methods, Params: append([]string{}, a.params...), Requests: a.count, ExchangeID: a.last}
		if len(a.params) == 0 {
			report.Static = append(report.Static, row)
			continue
		}
		report.Dynamic = append(report.Dynamic, row)
		report.Summary.Parameters += len(a.params)
		for _, name := range a.params {
			byName[name] = append(byName[name], url)
		}
	}
	sort.Slice(report.Dynamic, func(i, j int) bool { return report.Dynamic[i].URL < report.Dynamic[j].URL })
	sort.Slice(report.Static, func(i, j int) bool { return report.Static[i].URL < report.Static[j].URL })
	for name, list := range byName {
		sort.Strings(list)
		report.Parameters = append(report.Parameters, analyzerParam{Name: name, URLCount: len(list), URLs: list})
	}
	sort.Slice(report.Parameters, func(i, j int) bool {
		if report.Parameters[i].URLCount != report.Parameters[j].URLCount {
			return report.Parameters[i].URLCount > report.Parameters[j].URLCount
		}
		return report.Parameters[i].Name < report.Parameters[j].Name
	})
	report.Summary.DynamicURLs = len(report.Dynamic)
	report.Summary.StaticURLs = len(report.Static)
	report.Summary.UniqueParameterNames = len(report.Parameters)
	return report
}

var analyzerHTML = template.Must(template.New("analyzer").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Target analysis: {{.Host}}{{.Path}}</title>
<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse;margin-bottom:2em}td,th{border:1px solid #999;padding:4px 8px;text-align:left}code{font-size:90%}</style></head>
<body><h1>Target analysis: {{.Host}}{{.Path}}</h1>
<h2>Summary</h2>
<table><tr><th>Dynamic URLs</th><td>{{.Summary.DynamicURLs}}</td></tr><tr><th>Static URLs</th><td>{{.Summary.StaticURLs}}</td></tr>
<tr><th>Parameters</th><td>{{.Summary.Parameters}}</td></tr><tr><th>Unique parameter names</th><td>{{.Summary.UniqueParameterNames}}</td></tr></table>
<h2>Dynamic URLs</h2>
<table><tr><th>URL</th><th>Methods</th><th>Parameters</th><th>Requests</th></tr>{{range .Dynamic}}
<tr><td><code>{{.URL}}</code></td><td>{{range $i, $m := .Methods}}{{if $i}}, {{end}}{{$m}}{{end}}</td><td>{{range $i, $p := .Params}}{{if $i}}, {{end}}{{$p}}{{end}}</td><td>{{.Requests}}</td></tr>{{end}}</table>
<h2>Static URLs</h2>
<table><tr><th>URL</th><th>Methods</th><th>Requests</th></tr>{{range .Static}}
<tr><td><code>{{.URL}}</code></td><td>{{range $i, $m := .Methods}}{{if $i}}, {{end}}{{$m}}{{end}}</td><td>{{.Requests}}</td></tr>{{end}}</table>
<h2>Parameters</h2>
<table><tr><th>Name</th><th>URLs</th></tr>{{range .Parameters}}
<tr><td><code>{{.Name}}</code></td><td>{{.URLCount}}: {{range $i, $u := .URLs}}{{if $i}}, {{end}}<code>{{$u}}</code>{{end}}</td></tr>{{end}}</table>
</body></html>
`))
