package web

// The structured Repeater send (burpsy-react-ui-vuxy): POST /api/repeater/send with from_message /
// from_exchange as the base, ordered edits, an HTTP-version pin, and dry_run.
//
// Burp's send_request takes request_id + edits (+ http_version), so a model tampers with a captured
// request by naming what to change instead of re-typing every byte. burpsy's send took raw text only.
//
// What this path adds beyond the plain send, deliberately:
//
//   - The scope is authorised against the bytes actually sent (core.Scope.AuthoriseRaw: host, port and
//     the PATH on the final request line), not only at host level as the plain send does. An edit can
//     move the path into a path-scoped exclude, and a structured send is how an agent reaches this
//     route; the plain send keeps its documented host-level gate for the operator typing in the panel.
//   - dry_run answers the exact bytes that would go out (base64 and text), the target and that scope
//     verdict, and sends nothing — the preview a confirmation can show (e0yq) and the way an agent
//     checks its edits before spending a request.
//   - The stored base is never modified ("fork on edit"): the edited request is stored as a new message
//     when it is sent, and the exchange records the base exchange as its parent.

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/reqedit"
)

// structured reports that the request uses any of the structured-send fields.
func (q repeaterSendReq) structured() bool {
	return q.FromMessage != nil || len(q.Edits) > 0 || q.HTTPVersion != "" || q.DryRun ||
		(q.FromExchange != nil && q.Request == "" && q.RequestBase64 == "")
}

// repeaterPreview is a dry run's answer.
type repeaterPreview struct {
	DryRun        bool              `json:"dry_run"`
	Target        string            `json:"target"`
	Host          string            `json:"host"`
	Port          uint16            `json:"port"`
	TLS           bool              `json:"tls"`
	HTTPVersion   string            `json:"http_version"`
	Request       string            `json:"request"`
	RequestBase64 string            `json:"request_base64"`
	RequestUTF8   bool              `json:"request_utf8"`
	EditsApplied  []reqedit.Applied `json:"edits_applied"`
	Scope         repeaterScope     `json:"scope"`
}

// repeaterScope is the scope verdict on the bytes that would be sent.
type repeaterScope struct {
	// Allowed is the structured send's own gate: AuthoriseRaw on the final bytes.
	Allowed     bool   `json:"allowed"`
	Explanation string `json:"explanation"`
}

// baseRequest resolves the request to edit: typed text first, then from_message, then from_exchange's
// own request. It also answers the target a stored base implies, for a call that names none.
func (s *Server) baseRequest(req repeaterSendReq, typed string) (raw string, impliedTarget string, parent *core.ExchangeID, err error) {
	parent = req.FromExchange
	if typed != "" {
		return typed, "", parent, nil
	}
	if req.FromMessage != nil {
		msg, merr := s.store.Get(*req.FromMessage)
		if merr != nil {
			return "", "", nil, fmt.Errorf("from_message %d: no stored message with that id", *req.FromMessage)
		}
		// The exchange whose request this is, if any, supplies the target.
		for _, ex := range s.store.Exchanges() {
			if ex.Request != nil && *ex.Request == *req.FromMessage {
				impliedTarget = targetOf(ex)
				if parent == nil {
					id := ex.ID
					parent = &id
				}
				break
			}
		}
		return string(msg.Raw()), impliedTarget, parent, nil
	}
	if req.FromExchange != nil {
		ex, xerr := s.store.GetExchange(*req.FromExchange)
		if xerr != nil || ex.Request == nil {
			return "", "", nil, fmt.Errorf("from_exchange %d: no captured exchange with a request", *req.FromExchange)
		}
		msg, merr := s.store.Get(*ex.Request)
		if merr != nil {
			return "", "", nil, fmt.Errorf("from_exchange %d: its request message is not readable", *req.FromExchange)
		}
		return string(msg.Raw()), targetOf(ex), parent, nil
	}
	return "", "", nil, fmt.Errorf("name the request: request, request_base64, from_message or from_exchange")
}

func targetOf(ex *core.Exchange) string {
	scheme := "http"
	if ex.TLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, ex.Host, ex.Port)
}

// httpVersionPreference maps http_version onto the options' protocol pin.
func httpVersionPreference(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "auto":
		return "", nil
	case "1.1", "http1", "http_1", "http/1.1":
		return "http1", nil
	case "2", "http2", "http_2", "h2", "http/2":
		return "http2", nil
	}
	return "", fmt.Errorf("http_version must be auto, 1.1 or 2; got %q", v)
}

func (s *Server) repeaterStructuredSend(w http.ResponseWriter, r *http.Request, req repeaterSendReq, typed string) {
	base, implied, from, err := s.baseRequest(req, typed)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target := req.Target
	if strings.TrimSpace(target) == "" {
		target = implied
	}
	edited := []byte(base)
	applied := []reqedit.Applied{}
	if len(req.Edits) > 0 {
		out, did, eerr := reqedit.Apply(edited, req.Edits)
		if eerr != nil {
			http.Error(w, "refused: "+eerr.Error(), http.StatusBadRequest)
			return
		}
		edited, applied = out, did
	}
	opts := repeaterSendOptions{}
	if req.Options != nil {
		opts = *req.Options
	}
	pref, perr := httpVersionPreference(req.HTTPVersion)
	if perr != nil {
		http.Error(w, perr.Error(), http.StatusBadRequest)
		return
	}
	if pref != "" {
		if opts.ProtocolPreference != "" && opts.ProtocolPreference != pref {
			http.Error(w, fmt.Sprintf("http_version %q contradicts options.protocol_preference %q", req.HTTPVersion, opts.ProtocolPreference), http.StatusBadRequest)
			return
		}
		opts.ProtocolPreference = pref
	}
	spec, code, err := s.prepareRepeaterSend(target, req.Protocol, string(edited), &opts, from)
	if err != nil && !(req.DryRun && code == http.StatusForbidden) {
		http.Error(w, err.Error(), code)
		return
	}
	if err != nil {
		// A dry run reports the refusal as its verdict rather than failing; prepareRepeaterSend refused
		// on scope, so rebuild the spec's addressing for the preview.
		host, port, tls, _ := targetParts(target)
		spec = repeaterSendSpec{Host: host, Port: port, TLS: tls, Raw: edited, AsWritten: string(edited), Options: opts}
	}
	verdict := repeaterScope{Allowed: true, Explanation: s.scope.Explain(spec.Host, spec.Port, firstLinePath(string(spec.Raw)), spec.TLS)}
	if aerr := s.scope.AuthoriseRaw(spec.Host, spec.Port, spec.TLS, spec.Raw); aerr != nil {
		verdict = repeaterScope{Allowed: false, Explanation: aerr.Error()}
	}

	version := req.HTTPVersion
	if version == "" {
		version = "auto"
	}
	if req.DryRun {
		writeJSON(w, http.StatusOK, repeaterPreview{
			DryRun: true, Target: target, Host: spec.Host, Port: spec.Port, TLS: spec.TLS, HTTPVersion: version,
			Request: string(spec.Raw), RequestBase64: base64.StdEncoding.EncodeToString(spec.Raw),
			RequestUTF8: utf8.Valid(spec.Raw), EditsApplied: applied, Scope: verdict,
		})
		return
	}
	if !verdict.Allowed {
		http.Error(w, "refused: "+verdict.Explanation, http.StatusForbidden)
		return
	}
	// The tab's note, Override SNI and h2 reuse key ride a structured send exactly as they ride a raw
	// one (handleRepeaterSend validated the note before branching here).
	spec.Note = req.Note
	if err := validRepeaterSNI("sni", req.SNI, spec.TLS); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	spec.SNI = req.SNI
	spec.TabID = req.TabID
	resp, err := s.sendOneRepeaterRequest(r.Context(), spec)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	resp.EditsApplied = applied
	writeJSON(w, http.StatusOK, resp)
}
