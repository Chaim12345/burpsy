package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

// graphQLBodyRequest renders a GraphQL-over-HTTP JSON body POST carrying doc as the query
// field, the encoding every GraphQL client uses by default.
func graphQLBodyRequest(doc string) []byte {
	esc := strings.ReplaceAll(strings.ReplaceAll(doc, `\`, `\\`), `"`, `\"`)
	body := `{"query":"` + esc + `"}`
	return []byte(fmt.Sprintf("POST /graphql HTTP/1.1\r\nHost: target.test\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
}

func graphQLPointNames(points []bcheck.InsertionPoint) []string {
	var out []string
	for _, p := range points {
		if strings.Contains(p.Name, "[graphql:") {
			out = append(out, p.Name)
		}
	}
	return out
}

func enumerateBodyPoints(t *testing.T, raw []byte) []bcheck.InsertionPoint {
	t.Helper()
	points, _ := bcheck.EnumerateWith(raw, []string{"body"}, bcheck.EnumerateOptions{Max: 100})
	return points
}

// A document no GraphQL server would parse yields no argument insertion points at
// ingestion: probing inside a document the server rejects measures the parser's error
// path, never the resolver. The flat parent point stays.
func TestGraphQLIngestRejectsMalformedDocuments(t *testing.T) {
	malformed := []string{
		`{book(title: "Dune"){author}} trailing-junk`, // garbage after the operation
		`{book(9title: "Dune"){author}}`,              // argument name starts with a digit
		`query { book(title: "Dune") {author} } garbage`,
	}
	for _, doc := range malformed {
		t.Run(doc, func(t *testing.T) {
			points := enumerateBodyPoints(t, graphQLBodyRequest(doc))
			if got := graphQLPointNames(points); len(got) == 0 {
				t.Fatalf("fixture broken: bcheck derived no GraphQL argument points from %q", doc)
			}
			filtered := filterGraphQLPointsByValidation(points)
			if got := graphQLPointNames(filtered); len(got) != 0 {
				t.Fatalf("malformed document kept its argument points after ingestion validation: %v", got)
			}
			flat := false
			for _, p := range filtered {
				if p.Name == "query" {
					flat = true
				}
			}
			if !flat {
				t.Fatal("the flat parent point went with the rejected argument points: a whole-document payload must still be probeable")
			}
		})
	}
}

// A document the grammar accepts keeps every position the enumerator derived - including
// the stray-comma shape a hand rule would wrongly refuse, because GraphQL commas are
// insignificant.
func TestGraphQLIngestKeepsValidDocuments(t *testing.T) {
	valid := []string{
		`{book(title: "Dune"){author}}`,
		`{book(title: "Dune" ,,){author}}`,
		`mutation M($x: Int){book(title: "Dune"){author}}`,
		"{book(title: \"Dune\"){author}}\n# a trailing comment",
	}
	for _, doc := range valid {
		t.Run(doc, func(t *testing.T) {
			points := enumerateBodyPoints(t, graphQLBodyRequest(doc))
			filtered := filterGraphQLPointsByValidation(points)
			if len(filtered) != len(points) {
				t.Fatalf("valid document lost points: had %d, kept %d", len(points), len(filtered))
			}
			for i := range points {
				if filtered[i].Name != points[i].Name {
					t.Fatalf("valid document's points reordered or renamed at %d: %q -> %q", i, points[i].Name, filtered[i].Name)
				}
			}
			// The gate validates what the enumerator derived; it does not widen recognition.
			// A document bcheck's recogniser declined (a trailing comment is outside its
			// leading-comment grammar) has no argument points to keep - identity is the
			// requirement there; survival is required only when points existed.
			if before := graphQLPointNames(points); len(before) > 0 {
				if got := graphQLPointNames(filtered); len(got) != len(before) {
					t.Fatalf("valid document's argument points did not survive ingestion validation: %v -> %v", before, got)
				}
			}
		})
	}
}

// A request carrying no GraphQL document never reaches the parser: points in, points out,
// byte for byte.
func TestGraphQLIngestLeavesNonGraphQLItemsUnchanged(t *testing.T) {
	raws := [][]byte{
		[]byte("POST /api HTTP/1.1\r\nHost: target.test\r\nContent-Type: application/json\r\nContent-Length: 29\r\n\r\n{\"username\":\"bob\",\"role\":\"user\"}"),
		[]byte("POST /form HTTP/1.1\r\nHost: target.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 17\r\n\r\nuser=bob&pass=h0ly"),
		[]byte("GET /plain?q=hello HTTP/1.1\r\nHost: target.test\r\n\r\n"),
	}
	for i, raw := range raws {
		points, _ := bcheck.EnumerateWith(raw, nil, bcheck.EnumerateOptions{Max: 100})
		filtered := filterGraphQLPointsByValidation(points)
		if len(filtered) != len(points) {
			t.Fatalf("request %d: non-GraphQL item changed shape: %d -> %d points", i, len(points), len(filtered))
		}
		for j := range points {
			if filtered[j] != points[j] {
				t.Fatalf("request %d: point %d changed (%q -> %q)", i, j, points[j].Name, filtered[j].Name)
			}
		}
	}
}

// The dispatch-side wiring: the probe harness a check enumerates through must not carry
// argument points for a document gqlparser rejects, must carry them for a valid document,
// and with the switch off the gate is inert - the string-scan behaviour ships unchanged.
func TestGraphQLIngestGateAtDispatch(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"book":{"author":"Herbert"}}}`)
	})
	malformed := vulnapp.Endpoint{Path: "/graphql-mal", Method: http.MethodPost, ContentType: "application/json",
		Body: `{"query":"{book(title: \"Dune\"){author}} trailing-junk"}`}
	valid := vulnapp.Endpoint{Path: "/graphql-ok", Method: http.MethodPost, ContentType: "application/json",
		Body: `{"query":"{book(title: \"Dune\"){author}}"}`}

	cfgOn := &ScanConfig{MaxConcurrency: 2, Timeout: time.Minute} // gate on by the zero value
	ct := newCheckTarget(t, handler, cfgOn, malformed, valid)

	harnessPoints := func(path string) []bcheck.InsertionPoint {
		ex, err := ct.rt.store.GetExchange(ct.rt.exchanges[path])
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		h, err := NewProbeHarness(ctx, NewCheckContext(ct.scan, ex, nil), nil)
		if err != nil {
			t.Fatal(err)
		}
		return h.Points()
	}

	if got := graphQLPointNames(harnessPoints("/graphql-mal")); len(got) != 0 {
		t.Fatalf("dispatch carries argument points for a malformed document: %v", got)
	}
	if got := graphQLPointNames(harnessPoints("/graphql-ok")); len(got) != 1 {
		t.Fatalf("dispatch lost the valid document's argument point: %v", got)
	}

	ctOff := newCheckTarget(t, handler, &ScanConfig{DisableGraphQLIngest: true, MaxConcurrency: 2, Timeout: time.Minute}, malformed)
	ex, err := ctOff.rt.store.GetExchange(ctOff.rt.exchanges["/graphql-mal"])
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, err := NewProbeHarness(ctx, NewCheckContext(ctOff.scan, ex, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := graphQLPointNames(h.Points()); len(got) == 0 {
		t.Fatal("with the switch off the gate changed the dispatch anyway")
	}
}

// The gate survives a zero-value ScanConfig: WithConfig(&ScanConfig{}) replaces the whole
// struct, so a default-on switch declared as a bare bool would silently go off. The gate is
// ingestion hygiene, not a check family - it must take a deliberate DisableGraphQLIngest to
// audit the unvalidated string-scan shape.
func TestGraphQLIngestSurvivesZeroValueConfig(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"book":{"author":"Herbert"}}}`)
	})
	malformed := vulnapp.Endpoint{Path: "/graphql-mal", Method: http.MethodPost, ContentType: "application/json",
		Body: `{"query":"{book(title: \"Dune\"){author}} trailing-junk"}`}
	ct := newCheckTarget(t, handler, &ScanConfig{}, malformed)
	ex, err := ct.rt.store.GetExchange(ct.rt.exchanges["/graphql-mal"])
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, err := NewProbeHarness(ctx, NewCheckContext(ct.scan, ex, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := graphQLPointNames(h.Points()); len(got) != 0 {
		t.Fatalf("zero-value ScanConfig switched the gate off; dispatch carries argument points for a malformed document: %v", got)
	}
}

// The gate decodes the way bcheck decodes (internal/bcheck/insertion.go percentDecode,
// insertion_graphql.go jsonStringContentDecode): '+' is NOT a space, and malformed escapes
// survive verbatim. url.QueryUnescape drifts on both - it would translate the '+' in
// `title:+"Dune"` into the whitespace that makes the document parse, keeping argument points
// bcheck's own decode of the wire value never probes.
func TestGraphQLIngestDecodesLikeBcheck(t *testing.T) {
	// '+' preserved: {book(title:+"Dune"){author}} is not valid GraphQL, and only a
	// plus-to-space translation makes it one.
	if graphQLDocumentValid(`{book(title:+"Dune"){author}}`) {
		t.Fatal("the decoder translated '+' to space; url.QueryUnescape semantics are not bcheck's")
	}
	// Malformed escapes preserved: %2G survives verbatim, so the document stays malformed.
	if graphQLDocumentValid(`{book(title:%2G){author}}`) {
		t.Fatal("a malformed percent escape vanished; the decoder must preserve it verbatim")
	}
	// Legitimate escapes still decode: %22 quotes make the document valid under bcheck's
	// decoder too.
	if !graphQLDocumentValid(`{book(title:%22Dune%22){author}}`) {
		t.Fatal("a valid percent-encoded document lost its argument points; the decoder overcorrected")
	}
}
