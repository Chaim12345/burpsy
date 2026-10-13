package vulnapp

// The server-side parameter pollution family (burpsy-react-ui-0vzb.3). Each front end calls an
// in-process "internal API" — a function handed the request the front end built, as a string — so
// the defect is the real mechanism: the vulnerable fronts build that request by concatenation and
// the internal API parses what it is given; the safe twins encode the value for its position.
//
// Internal APIs:
//
//   - the user search (query string): name, field. Configurable on duplicates (first or last wins,
//     or refused), on unknown parameters (ignored or refused) and on a missing field (default email,
//     or refused). Answers like PortSwigger's lab: "Parameter is not supported", "Field not
//     specified", "Duplicate parameter", "User not found".
//   - the user record (REST path): /internal/v1/users/{name}/field/{field}, the path cleaned of dot
//     segments before routing (as most routers and proxies do); any other route is "Invalid route".
//   - the profile store (JSON body): decodes the document (a later duplicate key wins, unknown keys
//     are kept or ignored), looks the user up, and answers "Malformed JSON" for a broken document.
//
// Vulnerable:
//
//   - GET /sspp/query/search pastes name into ?name=<v>&field=email (first wins, unknown refused,
//     field required): `&name=x` after the value keeps the answer, `#` drops the field;
//   - POST /sspp/query/reset pastes the username into ?username=<v>&field=email (last wins, unknown
//     ignored, field optional): `&x=y`, `x&username=<v>` and `#` all keep the answer;
//   - GET /sspp/query/strict refuses duplicates and unknown parameters and requires the field: no
//     probe keeps the answer, but an unknown parameter and a repeated one are refused differently;
//   - GET /sspp/path/user pastes name into /internal/v1/users/<v>/field/email: `/x/..` is cleaned
//     away, `?` and `#` leave a route the API does not have;
//   - POST /sspp/json/profile pastes name into {"name":"<v>","role":"user"} and returns what the
//     store saved, so an injected member comes back as a member;
//   - POST /sspp/json/lookup (JSON) pastes user into {"username":"<v>","scope":"public"} and returns
//     only the profile: an injected member is ignored, a bare quote breaks the document.
//
// Safe twins (each vulnerable endpoint's front encoding its value), and negative controls:
//
//   - /sspp/safe/query/{search,reset,strict} URL-encode the value; /sspp/safe/path/user path-escapes
//     it; /sspp/safe/json/{profile,lookup} build the document with a serialiser;
//   - /sspp/safe/validator/{query,path,json} refuse any value containing & # ? / " or \ with a
//     message naming the character, before any internal call: every delimiter changes the answer
//     and its literal spelling does not, yet nothing reaches an internal request;
//   - /sspp/safe/path/file looks a document up by path.Clean("/docs/" + name): a dot-segment walk
//     is normalised away exactly as in an internal path, but `?` and `#` are only characters;
//   - /sspp/safe/query/truncate keeps only the value's leading letters and digits before an encoded
//     call, so a probe and its literal control are cut at the same place;
//   - /sspp/safe/path/normalise does the same but refuses a percent sign first, so every delimiter
//     probe answers like the original value while its literal control is refused: only the rule that
//     the literal control must answer like a plain value stops it;
//   - /sspp/safe/json/cut cuts the value at its first double quote: the injected member and the bare
//     quote both answer like the original value, so the document never broke;
//   - /sspp/safe/path/fetch requests a URL the client supplied whole (no network: a fixed table), so a
//     `?` or `#` the client adds is its own and the fetch honours it;
//   - /sspp/safe/query/delete-alias is the vulnerable search behind a path naming a destructive
//     operation, which the check must not probe at all;
//   - /sspp/safe/json/echo builds its own JSON RESPONSE by concatenation (a different flaw) while the
//     internal call is serialised: an injected member appears in the response, but the bare quote
//     breaks the response document itself, which is what tells it apart.

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const (
	rowSSPPQuery = "Server-side parameter pollution (query string)"
	rowSSPPPath  = "Server-side parameter pollution (REST path)"
	rowSSPPJSON  = "Server-side parameter pollution (structured data)"
)

func ssppEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/sspp/query/search?name=carlos", Row: rowSSPPQuery,
			Note: "pastes name into the internal query ?name=<v>&field=email; first duplicate wins, so name=carlos&name=x " +
				"still finds carlos, and # drops the required field"},
		{Path: "/sspp/query/reset", Method: http.MethodPost, Row: rowSSPPQuery, Body: "username=carlos",
			ContentType: "application/x-www-form-urlencoded",
			Note:        "pastes username into ?username=<v>&field=email; unknown parameters ignored, last duplicate wins"},
		{Path: "/sspp/query/strict?name=carlos", Row: rowSSPPQuery,
			Note: "pastes name into a strict internal query that refuses unknown and duplicate parameters differently"},
		{Path: "/sspp/path/user?name=carlos", Row: rowSSPPPath,
			Note: "pastes name into /internal/v1/users/<v>/field/email, cleaned of dot segments before routing"},
		{Path: "/sspp/json/profile", Method: http.MethodPost, Row: rowSSPPJSON, Body: "name=carlos",
			ContentType: "application/x-www-form-urlencoded",
			Note:        "pastes name into {\"name\":\"<v>\",\"role\":\"user\"} and returns the saved document"},
		{Path: "/sspp/json/lookup", Method: http.MethodPost, Row: rowSSPPJSON, Body: `{"user":"carlos"}`,
			ContentType: "application/json",
			Note:        "pastes user into {\"username\":\"<v>\",\"scope\":\"public\"}; returns only the profile"},

		{Path: "/sspp/safe/query/search?name=carlos", Row: rowSSPPQuery, Safe: true,
			Note: "URL-encodes name before building the internal query"},
		{Path: "/sspp/safe/query/reset", Method: http.MethodPost, Row: rowSSPPQuery, Safe: true, Body: "username=carlos",
			ContentType: "application/x-www-form-urlencoded",
			Note:        "URL-encodes username before building the internal query"},
		{Path: "/sspp/safe/query/strict?name=carlos", Row: rowSSPPQuery, Safe: true,
			Note: "URL-encodes name before building the strict internal query"},
		{Path: "/sspp/safe/query/truncate?name=carlos", Row: rowSSPPQuery, Safe: true,
			Note: "keeps only the leading letters and digits, then encodes: a probe and its literal control are cut alike"},
		{Path: "/sspp/safe/query/delete-alias?name=carlos", Row: rowSSPPQuery, Safe: true,
			Note: "the vulnerable search behind a path naming a destructive operation: the check must send it no probe"},
		{Path: "/sspp/safe/validator/query?name=carlos", Row: rowSSPPQuery, Safe: true,
			Note: "refuses & # ? / \" \\ with a message per character before any internal call"},
		{Path: "/sspp/safe/path/user?name=carlos", Row: rowSSPPPath, Safe: true,
			Note: "path-escapes name before building the internal path"},
		{Path: "/sspp/safe/path/file?name=carlos", Row: rowSSPPPath, Safe: true,
			Note: "a document lookup by path.Clean: a dot-segment walk normalises, ? and # are only characters"},
		{Path: "/sspp/safe/path/normalise?name=carlos", Row: rowSSPPPath, Safe: true,
			Note: "refuses any percent sign, then keeps only the leading letters and digits: every delimiter probe answers " +
				"like the original value, and every literal control is refused"},
		{Path: "/sspp/safe/path/fetch?src=https%3A%2F%2Fcdn.example.test%2Flogo.png", Row: rowSSPPPath, Safe: true,
			Note: "requests the URL the client supplied, whole: its own ? and # are the client's, and a fetch " +
				"honouring them is not pollution of a URL the server composed"},
		{Path: "/sspp/safe/validator/path?name=carlos", Row: rowSSPPPath, Safe: true,
			Note: "refuses & # ? / \" \\ with a message per character before any internal call"},
		{Path: "/sspp/safe/json/profile", Method: http.MethodPost, Row: rowSSPPJSON, Safe: true, Body: "name=carlos",
			ContentType: "application/x-www-form-urlencoded",
			Note:        "serialises the internal document"},
		{Path: "/sspp/safe/json/lookup", Method: http.MethodPost, Row: rowSSPPJSON, Safe: true, Body: `{"user":"carlos"}`,
			ContentType: "application/json",
			Note:        "serialises the internal document"},
		{Path: "/sspp/safe/json/echo", Method: http.MethodPost, Row: rowSSPPJSON, Safe: true, Body: "name=carlos",
			ContentType: "application/x-www-form-urlencoded",
			Note:        "serialises the internal document but concatenates its own JSON response, so a bare quote breaks the response"},
		{Path: "/sspp/safe/json/cut", Method: http.MethodPost, Row: rowSSPPJSON, Safe: true, Body: "name=carlos",
			ContentType: "application/x-www-form-urlencoded",
			Note: "cuts the value at its first double quote, then serialises: an injected member and a bare quote both " +
				"answer like the original value"},
		{Path: "/sspp/safe/validator/json", Method: http.MethodPost, Row: rowSSPPJSON, Safe: true, Body: "name=carlos",
			ContentType: "application/x-www-form-urlencoded",
			Note:        "refuses & # ? / \" \\ with a message per character before any internal call"},
	}
}

// ---------------------------------------------------------------------------
// data
// ---------------------------------------------------------------------------

type ssppUser struct{ email, phone string }

var ssppUsers = map[string]ssppUser{
	"carlos":        {"carlos@carlos-montoya.example", "+1 555 0100"},
	"wiener":        {"wiener@normal-user.example", "+1 555 0101"},
	"administrator": {"admin@internal.example", "+1 555 0199"},
}

// ---------------------------------------------------------------------------
// the internal APIs
// ---------------------------------------------------------------------------

// ssppQueryAPI is the internal user search. key is its name parameter.
type ssppQueryAPI struct {
	key           string
	lastWins      bool
	refuseDup     bool
	refuseUnknown bool
	fieldRequired bool
}

// call parses the request the front end built, as an HTTP server would: the fragment is not part
// of the request, and each query pair is percent-decoded once.
func (a ssppQueryAPI) call(raw string) (int, string) {
	u, err := url.Parse(raw)
	if err != nil {
		return http.StatusBadRequest, "Malformed internal request."
	}
	vals := map[string][]string{}
	for _, pair := range strings.Split(u.RawQuery, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		k, err1 := url.QueryUnescape(k)
		v, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			return http.StatusBadRequest, "Malformed internal request."
		}
		if k != a.key && k != "field" {
			if a.refuseUnknown {
				return http.StatusBadRequest, "Parameter is not supported."
			}
			continue
		}
		vals[k] = append(vals[k], v)
	}
	pick := func(k string) (string, bool) {
		vs := vals[k]
		if len(vs) == 0 {
			return "", false
		}
		if a.lastWins {
			return vs[len(vs)-1], true
		}
		return vs[0], true
	}
	if a.refuseDup {
		for _, vs := range vals {
			if len(vs) > 1 {
				return http.StatusBadRequest, "Duplicate parameter."
			}
		}
	}
	name, ok := pick(a.key)
	if !ok {
		return http.StatusBadRequest, "Name not specified."
	}
	field, ok := pick("field")
	if !ok {
		if a.fieldRequired {
			return http.StatusBadRequest, "Field not specified."
		}
		field = "email"
	}
	user, found := ssppUsers[name]
	if !found {
		return http.StatusNotFound, "User not found."
	}
	switch field {
	case "email":
		return http.StatusOK, user.email
	case "phone":
		return http.StatusOK, user.phone
	}
	return http.StatusBadRequest, "Invalid field."
}

// ssppPathAPI is the internal user record API, routed on the escaped path after dot segments are
// cleaned, with each segment then decoded once.
func ssppPathAPI(raw string) (int, string) {
	u, err := url.Parse(raw)
	if err != nil {
		return http.StatusBadRequest, "Malformed internal request."
	}
	p := path.Clean(u.EscapedPath())
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(segs) != 6 || segs[0] != "internal" || segs[1] != "v1" || segs[2] != "users" || segs[4] != "field" {
		return http.StatusNotFound, "Invalid route. Known: /internal/v1/users/{username}/field/{field}"
	}
	name, err1 := url.PathUnescape(segs[3])
	field, err2 := url.PathUnescape(segs[5])
	if err1 != nil || err2 != nil {
		return http.StatusBadRequest, "Malformed internal request."
	}
	user, found := ssppUsers[name]
	if !found {
		return http.StatusNotFound, "User not found."
	}
	if field == "email" {
		return http.StatusOK, user.email
	}
	return http.StatusBadRequest, "Invalid field."
}

// ssppJSONAPI is the internal profile store. It decodes the document the front end built (a later
// duplicate key overwrites an earlier one, as in most decoders) and looks the user up under key. With
// echo it answers with the whole saved document; without, only the profile.
func ssppJSONAPI(doc, key string, echo bool) (int, any) {
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		return http.StatusBadRequest, map[string]any{"error": "Malformed JSON in internal request."}
	}
	name, _ := m[key].(string)
	user, found := ssppUsers[name]
	var email any
	if found {
		email = user.email
	}
	if echo {
		return http.StatusOK, map[string]any{"saved": m, "email": email}
	}
	if !found {
		return http.StatusNotFound, map[string]any{"error": "User not found."}
	}
	return http.StatusOK, map[string]any{"username": name, "email": email}
}

// ---------------------------------------------------------------------------
// fronts
// ---------------------------------------------------------------------------

func ssppPage(w http.ResponseWriter, title string, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><h1>%s</h1><p class=\"result\">Lookup status %d: %s</p></body></html>",
		html.EscapeString(title), status, html.EscapeString(msg))
}

func ssppJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ssppRefused names the first delimiter in v, or "".
func ssppRefused(v string) string {
	for _, c := range []struct{ ch, name string }{
		{"&", "an ampersand"}, {"#", "a hash sign"}, {"?", "a question mark"}, {"/", "a slash"},
		{`"`, "a double quote"}, {`\`, "a backslash"},
	} {
		if strings.Contains(v, c.ch) {
			return c.name
		}
	}
	return ""
}

// ssppLeadingWord is the value's leading run of ASCII letters and digits.
func ssppLeadingWord(v string) string {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return v[:i]
		}
	}
	return v
}

func ssppJSONUser(r *http.Request) string {
	var body struct {
		User string `json:"user"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	return body.User
}

func registerSSPP(mux *http.ServeMux) {
	search := ssppQueryAPI{key: "name", refuseUnknown: true, fieldRequired: true}
	reset := ssppQueryAPI{key: "username", lastWins: true}
	strict := ssppQueryAPI{key: "name", refuseUnknown: true, refuseDup: true, fieldRequired: true}

	queryFront := func(api ssppQueryAPI, form string, encode func(string) string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			v := r.FormValue(form)
			status, msg := api.call("/internal/users/search?" + api.key + "=" + encode(v) + "&field=email")
			ssppPage(w, "User lookup", status, msg)
		}
	}
	raw := func(v string) string { return v }
	mux.HandleFunc("/sspp/query/search", queryFront(search, "name", raw))
	mux.HandleFunc("/sspp/query/reset", queryFront(reset, "username", raw))
	mux.HandleFunc("/sspp/query/strict", queryFront(strict, "name", raw))
	mux.HandleFunc("/sspp/safe/query/search", queryFront(search, "name", url.QueryEscape))
	mux.HandleFunc("/sspp/safe/query/reset", queryFront(reset, "username", url.QueryEscape))
	mux.HandleFunc("/sspp/safe/query/strict", queryFront(strict, "name", url.QueryEscape))
	mux.HandleFunc("/sspp/safe/query/delete-alias", queryFront(search, "name", raw))
	mux.HandleFunc("/sspp/safe/path/fetch", func(w http.ResponseWriter, r *http.Request) {
		u, err := url.Parse(r.FormValue("src"))
		if err == nil && u.Scheme == "https" && u.Host == "cdn.example.test" && u.Path == "/logo.png" {
			ssppPage(w, "Image", http.StatusOK, "64x64 PNG")
			return
		}
		ssppPage(w, "Image", http.StatusNotFound, "No such image.")
	})
	mux.HandleFunc("/sspp/safe/path/normalise", func(w http.ResponseWriter, r *http.Request) {
		v := r.FormValue("name")
		if strings.Contains(v, "%") {
			ssppPage(w, "Invalid input", http.StatusBadRequest, "Encoded characters are not allowed.")
			return
		}
		status, msg := ssppPathAPI("/internal/v1/users/" + url.PathEscape(ssppLeadingWord(v)) + "/field/email")
		ssppPage(w, "User record", status, msg)
	})
	mux.HandleFunc("/sspp/safe/query/truncate", queryFront(search, "name", func(v string) string {
		return url.QueryEscape(ssppLeadingWord(v))
	}))

	pathFront := func(encode func(string) string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			status, msg := ssppPathAPI("/internal/v1/users/" + encode(r.FormValue("name")) + "/field/email")
			ssppPage(w, "User record", status, msg)
		}
	}
	mux.HandleFunc("/sspp/path/user", pathFront(raw))
	mux.HandleFunc("/sspp/safe/path/user", pathFront(url.PathEscape))
	docs := map[string]string{"/docs/carlos": "Carlos's onboarding notes", "/docs/wiener": "Wiener's notes"}
	mux.HandleFunc("/sspp/safe/path/file", func(w http.ResponseWriter, r *http.Request) {
		key := path.Clean("/docs/" + r.FormValue("name"))
		if d, ok := docs[key]; ok {
			ssppPage(w, "Document", http.StatusOK, d)
			return
		}
		ssppPage(w, "Document", http.StatusNotFound, "No such document.")
	})

	quote := func(v string) string { b, _ := json.Marshal(v); return string(b) }
	pasted := func(v string) string { return `"` + v + `"` }
	profile := func(enc func(string) string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			status, out := ssppJSONAPI(`{"name":`+enc(r.FormValue("name"))+`,"role":"user"}`, "name", true)
			ssppJSON(w, status, out)
		}
	}
	lookup := func(enc func(string) string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			status, out := ssppJSONAPI(`{"username":`+enc(ssppJSONUser(r))+`,"scope":"public"}`, "username", false)
			ssppJSON(w, status, out)
		}
	}
	mux.HandleFunc("/sspp/json/profile", profile(pasted))
	mux.HandleFunc("/sspp/json/lookup", lookup(pasted))
	mux.HandleFunc("/sspp/safe/json/profile", profile(quote))
	mux.HandleFunc("/sspp/safe/json/lookup", lookup(quote))
	mux.HandleFunc("/sspp/safe/json/cut", func(w http.ResponseWriter, r *http.Request) {
		v, _, _ := strings.Cut(r.FormValue("name"), `"`)
		status, out := ssppJSONAPI(`{"username":`+quote(v)+`,"scope":"public"}`, "username", false)
		ssppJSON(w, status, out)
	})
	mux.HandleFunc("/sspp/safe/json/echo", func(w http.ResponseWriter, r *http.Request) {
		v := r.FormValue("name")
		_, out := ssppJSONAPI(`{"name":`+quote(v)+`}`, "name", true)
		email, _ := out.(map[string]any)["email"].(string)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"query":"%s","email":"%s"}`, v, email)
	})

	validator := func(next func(w http.ResponseWriter, v string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			v := r.FormValue("name")
			if what := ssppRefused(v); what != "" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusBadRequest)
				ssppPage(w, "Invalid input", http.StatusBadRequest, "Names may not contain "+what+".")
				return
			}
			next(w, v)
		}
	}
	mux.HandleFunc("/sspp/safe/validator/query", validator(func(w http.ResponseWriter, v string) {
		status, msg := search.call("/internal/users/search?name=" + url.QueryEscape(v) + "&field=email")
		ssppPage(w, "User lookup", status, msg)
	}))
	mux.HandleFunc("/sspp/safe/validator/path", validator(func(w http.ResponseWriter, v string) {
		status, msg := ssppPathAPI("/internal/v1/users/" + url.PathEscape(v) + "/field/email")
		ssppPage(w, "User record", status, msg)
	}))
	mux.HandleFunc("/sspp/safe/validator/json", validator(func(w http.ResponseWriter, v string) {
		status, out := ssppJSONAPI(`{"name":`+quote(v)+`,"role":"user"}`, "name", true)
		ssppJSON(w, status, out)
	}))
}
