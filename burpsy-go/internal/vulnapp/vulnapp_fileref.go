package vulnapp

// File references without traversal (burpsy-react-ui-0vzb.33): a file parameter confined to one
// directory but with no allowlist, and an XML parser that disables external GENERAL entities only.
//
// Corresponding scanner code: internal/scanner/checks_path_equivalence.go and
// internal/scanner/xxe_param_entity.go.
//
//   - /fr/documents refuses "..", resolves the name as a path under its document directory, and
//     serves whatever file is there, including one the page never links to. No traversal reaches
//     outside the directory, so the file-content technique is silent; path equivalence ("./name"
//     names the same file, "missing-dir/name" and ".name" do not) is what shows the raw path.
//     Its safe twins are the three lookups that answer some of those spellings alike for a reason
//     other than a filesystem path: an exact allowlist, a basename flattener and a word search.
//   - /fr/xml/import resolves external parameter entities (it fetches the DTD a `%name;` names) but
//     not external general entities, so a `<!ENTITY x SYSTEM "file:…">` probe expands to nothing.
//     Its safe twin resolves no external entity of either kind.

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

func fileRefEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/fr/documents?name=report.txt", Row: "File path manipulation",
			Note: "refuses \"..\" but resolves name as a path inside its document directory and serves any file there (no allowlist)"},
		{Path: "/fr/safe/documents?name=report.txt", Row: "File path manipulation", Safe: true,
			Note: "exact allowlist lookup: the name is a key, never a path, so \"./report.txt\" is not found"},
		{Path: "/fr/safe/basename?name=report.txt", Row: "File path manipulation", Safe: true,
			Note: "keeps only the last path component, so every directory spelling names the same allowlisted file"},
		{Path: "/fr/safe/search?q=report.txt", Row: "File path manipulation", Safe: true,
			Note: "word search over document titles: punctuation is discarded, so \"./x\" and \".x\" are the same query"},

		{Path: "/fr/xml/import", Row: "XML external entity injection", Method: "POST",
			Body: "<book><title>seed</title><isbn>1</isbn></book>", ContentType: "application/xml",
			Note: "external general entities disabled, external parameter entities still resolved: a %pe; loads a remote DTD whose entities expand"},
		{Path: "/fr/safe/xml/import", Row: "XML external entity injection", Method: "POST", Safe: true,
			Body: "<book><title>seed</title><isbn>1</isbn></book>", ContentType: "application/xml",
			Note: "same import, every external entity (general and parameter) ignored; echoes the document"},
	}
}

func registerFileRef(mux *http.ServeMux) {
	mux.HandleFunc("/fr/documents", serveDocumentByPath)
	mux.HandleFunc("/fr/safe/documents", safeServeDocumentByKey)
	mux.HandleFunc("/fr/safe/basename", safeServeDocumentByBasename)
	mux.HandleFunc("/fr/safe/search", safeSearchDocuments)
	mux.HandleFunc("/fr/xml/import", func(w http.ResponseWriter, r *http.Request) { importBookXML(w, r, true) })
	mux.HandleFunc("/fr/safe/xml/import", func(w http.ResponseWriter, r *http.Request) { importBookXML(w, r, false) })
}

// frDocuments is the document directory, keyed by path relative to it. "internal/payroll.txt" is
// the file nobody links to.
var frDocuments = map[string]string{
	"report.txt":           "Quarterly report: revenue grew four percent.",
	"summary.txt":          "Summary: two new offices opened this year.",
	"internal/payroll.txt": "Payroll export (confidential).",
}

const frDocRoot = "/srv/documents"

// serveDocumentByPath is the vulnerable lookup: a ".." filter, then the name resolved as a path.
func serveDocumentByPath(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/plain")
	if strings.Contains(name, "..") {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "invalid document name\n")
		return
	}
	p := path.Clean(frDocRoot + "/" + name)
	content, ok := frDocuments[strings.TrimPrefix(p, frDocRoot+"/")]
	if !strings.HasPrefix(p, frDocRoot+"/") || !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "document not found\n")
		return
	}
	fmt.Fprintln(w, content)
}

// frAllowlist is the safe twins' set: the linked documents only.
var frAllowlist = map[string]bool{"report.txt": true, "summary.txt": true}

func frServeAllowed(w http.ResponseWriter, key, asked string) {
	w.Header().Set("Content-Type", "text/plain")
	if !frAllowlist[key] {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "document %q not found\n", asked)
		return
	}
	fmt.Fprintln(w, frDocuments[key])
}

func safeServeDocumentByKey(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	frServeAllowed(w, name, name)
}

func safeServeDocumentByBasename(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	frServeAllowed(w, path.Base(strings.ReplaceAll(name, `\`, "/")), name)
}

var frWord = regexp.MustCompile(`[a-z0-9]+`)

// safeSearchDocuments matches every word of the query against the linked documents' titles and
// bodies (AND semantics), the way a search box does.
func safeSearchDocuments(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	w.Header().Set("Content-Type", "text/plain")
	words := frWord.FindAllString(strings.ToLower(q), -1)
	var hits []string
	for key := range frAllowlist {
		hay := strings.ToLower(key + " " + frDocuments[key])
		all := len(words) > 0
		for _, wd := range words {
			if !strings.Contains(hay, wd) {
				all = false
				break
			}
		}
		if all {
			hits = append(hits, key+": "+frDocuments[key])
		}
	}
	sort.Strings(hits)
	fmt.Fprintf(w, "%d result(s)\n%s\n", len(hits), strings.Join(hits, "\n"))
}

// ---------------------------------------------------------------------------
// XML import: external parameter entities
// ---------------------------------------------------------------------------

var (
	frDoctype      = regexp.MustCompile(`(?s)<!DOCTYPE\s+[A-Za-z_][\w.-]*\s*\[(.*?)\]\s*>`)
	frGeneralDecl  = regexp.MustCompile(`<!ENTITY\s+([A-Za-z_][\w.-]*)\s+(?:SYSTEM\s+"([^"]*)"|"([^"]*)")\s*>`)
	frParamDecl    = regexp.MustCompile(`<!ENTITY\s+%\s+([A-Za-z_][\w.-]*)\s+SYSTEM\s+"([^"]*)"\s*>`)
	frParamRef     = regexp.MustCompile(`%([A-Za-z_][\w.-]*);`)
	frEntityRef    = regexp.MustCompile(`&([A-Za-z_][\w.-]*);`)
	frPredefEntity = map[string]bool{"lt": true, "gt": true, "amp": true, "quot": true, "apos": true}
)

// importBookXML parses the DOCTYPE's internal subset the way a SAX parser does with
// external-general-entities off: internal general entities expand, external general entities expand
// to nothing, and - when paramEntities is true - an external parameter entity referenced as %name;
// is fetched and its declarations become part of the DTD. An undeclared entity is a fatal error.
func importBookXML(w http.ResponseWriter, r *http.Request, paramEntities bool) {
	doc := docText(r)
	w.Header().Set("Content-Type", "text/plain")
	subset := ""
	body := doc
	if m := frDoctype.FindStringSubmatchIndex(doc); m != nil {
		subset = doc[m[2]:m[3]]
		body = doc[m[1]:]
	}
	dtd := subset
	if paramEntities {
		params := map[string]string{}
		for _, m := range frParamDecl.FindAllStringSubmatch(subset, -1) {
			params[m[1]] = m[2]
		}
		for _, m := range frParamRef.FindAllStringSubmatch(subset, -1) {
			if uri, ok := params[m[1]]; ok {
				dtd += "\n" + fetchExternalDTD(uri)
			}
		}
	}
	values := map[string]string{}
	for _, m := range frGeneralDecl.FindAllStringSubmatch(dtd, -1) {
		if m[2] != "" {
			values[m[1]] = "" // external general entities are disabled: declared, never loaded
			continue
		}
		values[m[1]] = m[3]
	}
	var undeclared string
	out := frEntityRef.ReplaceAllStringFunc(body, func(ref string) string {
		name := ref[1 : len(ref)-1]
		if frPredefEntity[name] {
			return ref
		}
		v, ok := values[name]
		if !ok && undeclared == "" {
			undeclared = name
		}
		return v
	})
	if undeclared != "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "import failed: the document is not well-formed\n")
		return
	}
	fmt.Fprintf(w, "imported:\n%s\n", out)
}

// fetchExternalDTD loads a DTD over http from a loopback address only: the fixture demonstrates the
// parser's configuration, and must not become a request primitive against anything else.
func fetchExternalDTD(uri string) string {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" {
		return ""
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return ""
	}
	c := &http.Client{Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(u.String())
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return string(b)
}
