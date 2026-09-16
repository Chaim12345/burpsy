package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/burpsy-go/burpsy/internal/extension"
)

// The EXTENDER surface: /api/extensions/*.
//
// # What this serves, and what it deliberately does not
//
// Burp's Extender tab has four sub-tabs. Three of them have something to serve here — the installed
// list with its per-extension consoles, the options that govern loading, and the API contract a plugin
// author writes against. The fourth is the BApp Store, and there is no route for it: nothing in this
// process fetches, resolves or installs anything, so a route answering `{"extensions": []}` would be a
// machine-readable claim that a catalogue exists and happens to be empty. The absence is stated
// instead — in the policy view's `registry: null` and its `registry_detail`, which the Options tab
// renders.
//
// # Why load is its own risk class
//
// Every other write on this API changes burpsy's own state or sends a request. POST
// /api/extensions/load starts a process from the operator's allowlist and speaks JSON-RPC to it, which
// means it executes operator-supplied code in this process's own privileges. That is not "local-write"
// and it is not "egress"; it is the class scanner's `run tool` would have needed if it had a route. See
// riskExecute in route_manifest_test.go.
//
// The gate is the same one internal/scanner/toolrunner.go uses and it is the whole safety model: the
// request names an allowlist key, never a path. A name the operator did not pass to -plugins answers
// 404 with the allowlist's own reason, and no amount of body content reaches exec.
//
// # Routes are exact, not a subtree
//
// Six exact patterns rather than one "/api/extensions/" catch-all. The subtree would have to dispatch
// on a path segment and then decide a method per segment, which makes one handler answer 405 for four
// different reasons; the manifest can only carry one methods list per pattern, so a wrong-verb bug
// under one action would be invisible. The /api/tools/* family is registered the same way.

// extensionHost returns the plugin host, building an empty one on first use.
//
// Lazy for the same reason captureSet() is: every test in this package constructs a Server directly,
// and a nil host there would make these routes panic rather than report an empty allowlist. An empty
// host is also the correct production default — a burpsy started without -plugins has an allowlist of
// zero and must say so, not 503.
func (s *Server) extensionHost() *extension.Host {
	s.extensionOnce.Do(func() {
		if s.extensions == nil {
			s.extensions = extension.NewHost(extension.Config{Logger: s.logger})
		}
	})
	return s.extensions
}

// extensionNameRequest is the body every write takes: an allowlist key, and nothing that could name a
// path or an argument. A plugin's argv comes from the operator's command line, never from a request.
type extensionNameRequest struct {
	Name string `json:"name"`
}

// handleExtensions serves GET /api/extensions: every allowlisted plugin, the state breakdown across
// them, and the policy in force.
//
// The policy travels with the list rather than living only on its own route because the empty case
// needs it: a list of no plugins is only readable next to "here is the flag that admits one".
func (s *Server) handleExtensions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.extensionHost().List())
}

// handleExtensionLoad serves POST /api/extensions/load: start one allowlisted plugin.
//
// A failed load answers 502 with the plugin's row in the body rather than a bare error string, because
// the row is where the reason is: state "failed", a detail saying whether the executable was missing,
// the handshake timed out or the protocol did not match, and an error console carrying whatever the
// child said on its way down.
func (s *Server) handleExtensionLoad(w http.ResponseWriter, r *http.Request) {
	name, ok := decodeExtensionName(w, r)
	if !ok {
		return
	}
	view, err := s.extensionHost().Load(name)
	if err != nil {
		writeJSON(w, extensionStatus(err, http.StatusBadGateway), map[string]any{
			"error":     err.Error(),
			"extension": view,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"extension": view})
}

// handleExtensionUnload serves POST /api/extensions/unload: stop one running plugin.
//
// Answers 409 when the plugin is not running. Not 200-with-a-note: an unload that reported success
// against a plugin that was never started would make a crashed plugin look like one the operator had
// stopped, and those are the two states this surface works hardest to keep apart.
func (s *Server) handleExtensionUnload(w http.ResponseWriter, r *http.Request) {
	name, ok := decodeExtensionName(w, r)
	if !ok {
		return
	}
	view, err := s.extensionHost().Unload(name)
	if err != nil {
		writeJSON(w, extensionStatus(err, http.StatusConflict), map[string]any{
			"error":     err.Error(),
			"extension": view,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"extension": view})
}

// handleExtensionConsole serves GET /api/extensions/console?name=&limit=: one plugin's two consoles.
//
// Both streams in one response, with the drop counts and the bound in force. Two routes would let a UI
// render an output console from one instant and an error console from another, and the interesting case
// — a plugin that logged a line and then died — is exactly where those two disagree.
func (s *Server) handleExtensionConsole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "a console needs the name of an allowlisted plugin: ?name=<name>", http.StatusBadRequest)
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			http.Error(w, "limit must be a number of lines", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	view, err := s.extensionHost().Console(name, limit)
	if err != nil {
		http.Error(w, err.Error(), extensionStatus(err, http.StatusInternalServerError))
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleExtensionAPIs serves GET /api/extensions/apis: the protocol contract.
//
// Generated from extension.MethodSpecs, which the extension package's own tests check against the
// methods it actually dispatches. That is the point of serving it rather than writing the same thing
// into the UI: a hand-maintained copy of a wire protocol drifts, and a plugin author cannot tell that
// it has.
func (s *Server) handleExtensionAPIs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, extension.API())
}

// extensionInvokeRequest is one invocation of one registration.
//
// Exchange and Message are pointers because exchange 0 and message 0 are real ids in this engine, so
// "the first exchange" and "no exchange" must not serialise the same — the same reason
// extension.InvokeParams carries pointers.
type extensionInvokeRequest struct {
	Name         string `json:"name"`
	Registration string `json:"registration"`
	Exchange     *int   `json:"exchange,omitempty"`
	Message      *int   `json:"message,omitempty"`
	Raw          string `json:"raw,omitempty"`
	Selection    string `json:"selection,omitempty"`
}

// handleExtensionInvoke serves POST /api/extensions/invoke: run one registration the plugin declared.
//
// This route exists because the three registration points are the whole reason the host has a protocol,
// and a registration an operator can see in a table and cannot invoke from anywhere is the same defect
// as a capability with no route. It is riskExecute for the same reason load is: the code on the other
// end is the operator's, and this hands it engagement data.
//
// What it does not do is fetch the message itself. The bytes come from the request, so the plugin is
// given what the caller already had rather than this route growing a second way to read the traffic
// store — and a plugin still has no route to that store at all, which is what UnsupportedCapabilities
// says on the APIs tab.
func (s *Server) handleExtensionInvoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req extensionInvokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "unreadable invocation: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Registration == "" {
		http.Error(w, "an invocation needs a plugin name and a registration id", http.StatusBadRequest)
		return
	}
	result, err := s.extensionHost().Invoke(r.Context(), req.Name, extension.InvokeParams{
		Registration: req.Registration,
		Exchange:     req.Exchange,
		Message:      req.Message,
		Raw:          req.Raw,
		Selection:    req.Selection,
	})
	if err != nil {
		// The plugin's own error text, verbatim, and the row beside it: an invocation that failed
		// because the plugin has since crashed is a different problem from one it declined, and the
		// state field is what separates them.
		body := map[string]any{"error": err.Error()}
		if view, lookupErr := extensionRow(s.extensionHost(), req.Name); lookupErr == nil {
			body["extension"] = view
		}
		writeJSON(w, extensionStatus(err, http.StatusBadGateway), body)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": result})
}

// extensionOrderRequest is one move: which plugin, and which way.
type extensionOrderRequest struct {
	Name      string `json:"name"`
	Direction string `json:"direction"`
}

// handleExtensionOrder serves POST /api/extensions/order: move one allowlisted plugin one place in
// the order the console offers its registrations in (burpsy-react-ui-d3gj).
//
// riskLocal, not riskExecute: this permutes a slice in this process. Nothing is spawned and no
// plugin is called — which is also why it works on an unloaded plugin, whose position an operator
// will want set before they load it.
//
// The edges refuse rather than clamp. Up on the first plugin answers 409 with "already first"
// instead of 200 and an unchanged list, because a control that reports success and changes nothing
// is the defect this route exists to avoid: the reordering has to be the thing that dispatches, and
// an operator has to be able to tell a move that happened from one that could not.
func (s *Server) handleExtensionOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req extensionOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "unreadable move: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name the allowlisted plugin to move: {\"name\": \"<name>\", \"direction\": \"up\"}", http.StatusBadRequest)
		return
	}
	list, err := s.extensionHost().Move(req.Name, extension.MoveDirection(req.Direction))
	if err != nil {
		http.Error(w, err.Error(), extensionOrderStatus(err))
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// extensionOrderStatus maps this route's own refusals. An unknown direction is 400 because the
// request was malformed; an edge of the list is 409 because the request was well formed and about a
// position the plugin is not in — the same distinction load and unload draw.
func extensionOrderStatus(err error) int {
	switch {
	case errors.Is(err, extension.ErrBadDirection):
		return http.StatusBadRequest
	case errors.Is(err, extension.ErrAlreadyFirst), errors.Is(err, extension.ErrAlreadyLast):
		return http.StatusConflict
	default:
		return extensionStatus(err, http.StatusInternalServerError)
	}
}

// decodeExtensionName reads and validates the {name} body shared by load and unload.
func decodeExtensionName(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return "", false
	}
	var req extensionNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "unreadable request: "+err.Error(), http.StatusBadRequest)
		return "", false
	}
	if req.Name == "" {
		http.Error(w, "name the allowlisted plugin: {\"name\": \"<name>\"}", http.StatusBadRequest)
		return "", false
	}
	return req.Name, true
}

// extensionStatus maps the host's sentinels to status codes.
//
// Sentinels rather than substrings, so the mapping is a type decision: an unknown name is 404 because
// the resource does not exist, and "already loaded" / "not loaded" are 409 because the request was
// about a state the plugin is not in. fallback covers the rest — a launch failure, a handshake that
// timed out — which is a fault on the far side of the exec and not a fault in the request.
func extensionStatus(err error, fallback int) int {
	switch {
	case errors.Is(err, extension.ErrUnknownPlugin):
		return http.StatusNotFound
	case errors.Is(err, extension.ErrUnknownRegistration):
		return http.StatusNotFound
	case errors.Is(err, extension.ErrAlreadyLoaded), errors.Is(err, extension.ErrNotLoaded):
		return http.StatusConflict
	default:
		return fallback
	}
}

// extensionRow finds one plugin's row in the list, for error bodies that want the state alongside the
// message. The host has no single-plugin read; List is cheap and this is an error path.
func extensionRow(host *extension.Host, name string) (extension.PluginView, error) {
	for _, row := range host.List().Extensions {
		if row.Name == name {
			return row, nil
		}
	}
	return extension.PluginView{}, extension.ErrUnknownPlugin
}
