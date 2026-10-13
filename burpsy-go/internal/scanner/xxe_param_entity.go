package scanner

// XXE through an external PARAMETER entity (burpsy-react-ui-0vzb.33).
//
// # The gap this closes
//
// checkXXE's probes declare an external GENERAL entity (`<!ENTITY x SYSTEM "file:///…">` and `&x;`).
// A parser configured with only external-general-entities turned off — the half-measure, and a
// common one, because it is the feature most hardening guides name first — ignores that probe and
// reads as clean, while it still resolves external PARAMETER entities (`<!ENTITY % p SYSTEM "…"> %p;`).
// A parameter entity loads an external DTD, and whatever that DTD declares is in force for the
// document: file exfiltration through a nested parameter entity, SSRF, and denial of service all
// follow. The parser is vulnerable; only the probe was missing.
//
// # The evidence
//
// The probe plants a parameter entity whose SYSTEM identifier is a DTD this scanner serves on a
// loopback listener of its own. That DTD declares an INTERNAL general entity holding a random marker,
// and the document references it inside the element the base body already uses. Disabling external
// general entities does not stop it: the entity that reaches the document is internal, declared by
// the DTD the parameter entity pulled in. Two independent observations are required:
//
//   - the listener served the DTD (the target made the request), and
//   - the marker is in the response. The marker never appears in the request, only in what the
//     listener returns, so neither an echo of the document nor a reflected URL can produce it.
//
// A parser that refuses external parameter entities never fetches the DTD, the referenced entity is
// undeclared, and the document fails or comes back without the marker.
//
// # Same-host only, and its own opt-in
//
// The listener binds 127.0.0.1, exactly like the in-band SSRF canary and for the same reasons
// (ssrf_inband.go, "Same-host only"): a remote target reaches its own loopback and the probe is silent
// there, never wrong. Because the probe makes the target request a URL this scanner chose, it runs
// only under the in-band SSRF switch (CheckSSRFInBand), the operator's opt-in for exactly that.
//
// # Safety
//
// The DTD declares one internal entity with a literal value: no file is read, no further URL is
// fetched, no entity nests. Nothing the target does with it costs more than parsing a string.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// xxeDTDServer serves one DTD at one unguessable path on loopback and counts its fetches.
type xxeDTDServer struct {
	srv    *http.Server
	addr   string
	path   string
	entity string
	marker string
	hits   atomic.Int64
}

func startXXEDTDServer() (*xxeDTDServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("xxe dtd listener: %w", err)
	}
	s := &xxeDTDServer{
		addr:   ln.Addr().String(),
		path:   "/burpsy-xxe-" + newProbeCanary("") + ".dtd",
		entity: "bsyxpe" + strings.ToLower(randomLetters(8)),
		marker: "bsyXPE" + newProbeCanary(""),
	}
	s.srv = &http.Server{Handler: http.HandlerFunc(s.serve), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

func (s *xxeDTDServer) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != s.path {
		http.NotFound(w, r)
		return
	}
	s.hits.Add(1)
	w.Header().Set("Content-Type", "application/xml-dtd")
	_, _ = w.Write([]byte(xxeDTDBody(s.entity, s.marker)))
}

// xxeDTDBody is the served DTD: one internal general entity with a literal value.
func xxeDTDBody(entity, marker string) string {
	return `<!ENTITY ` + entity + ` "` + marker + `">`
}

func (s *xxeDTDServer) URL() string { return "http://" + s.addr + s.path }

func (s *xxeDTDServer) Close() {
	if s == nil || s.srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.srv.Shutdown(ctx)
}

// xxeParameterEntityDocument is the base body with a DOCTYPE that loads dtdURL through a parameter
// entity, and a reference to entity (which only that DTD declares) in its first text element.
func xxeParameterEntityDocument(baseBody, dtdURL, entity string) string {
	return xxeWrap(baseBody, entity, `<!ENTITY % bsydtd SYSTEM "`+dtdURL+`"> %bsydtd;`)
}

// xxeParameterEntityProbe plants the document at every point and returns a finding once one is
// confirmed. Points are those checkXXE already chose, so the cap is the same.
func xxeParameterEntityProbe(ctx context.Context, cc *CheckContext, h *ProbeHarness, points []bcheck.InsertionPoint,
	baseBody string) (*Finding, error) {
	s, err := startXXEDTDServer()
	if err != nil {
		// No listener is no capability; it is never a clean result.
		return nil, err
	}
	defer s.Close()
	payload := xxeParameterEntityDocument(baseBody, s.URL(), s.entity)
	for _, point := range points {
		before := s.hits.Load()
		res, err := h.Send(ctx, point, payload)
		if err != nil {
			continue
		}
		fetched := s.hits.Load() - before
		if fetched == 0 || !strings.Contains(res.Body, s.marker) {
			continue
		}
		return buildHeaderFinding(cc, "XML external entity injection", "high", "certain",
			"XXE via external parameter entity: "+payload,
			fmt.Sprintf("%s %q: the parser fetched the external DTD named by a parameter entity (%d request(s) to "+
				"this scanner's loopback listener) and expanded the entity that DTD declared: its random marker %q, "+
				"which is not in the request, is in the response. External parameter entities are resolved even if "+
				"external general entities are not.", point.Kind, point.Name, fetched, s.marker)), nil
	}
	return nil, nil
}
