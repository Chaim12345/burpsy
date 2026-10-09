package web

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The unattended-caller gate (burpsy-react-ui-ejp5).
//
// # What this is for
//
// Every route in route_manifest.go carries a riskClass, and until this file existed that
// classification was enforced by exactly one thing: a test. The console's own confirmation dialog
// stood between an operator and an attack route, and a dialog is browser-side. A script, an MCP
// client, an agent, a replayed request — none of them see it. So the routes that send unbounded
// traffic to a client's production system were, to any caller that was not the console, unguarded.
//
// This is the server-side half. A confirmation-worthy route requires a signal that a human meant
// it, and the signal has to come from the operator rather than from the tool that is being
// supervised: an agent that can supply the confirm itself has learned nothing from being asked.
//
// # The policy, in one place
//
// needsConfirmation (in agent_tools.go) is the set. It is deliberately NOT the escalation tier:
// ALWAYS_ESCALATE covers riskLocal and riskExecute, which a dialog is the right control for, while
// the classes here are the ones where a dialog is insufficient because the dialog is not the only
// caller. Read riskClass for what each class means; the four listed in needsConfirmation are the
// ones that can destroy evidence, remove the scope that says no, generate unbounded traffic, or
// hand out a credential.

// ConfirmHeader is the header a caller sets to confirm one gated call.
//
// A header rather than a JSON body field, because the gated routes take their real payload in the
// body and a confirmation smuggled into that same body is a field an attacker can set as easily as
// the confirmation. A header is set by the client, not by the payload.
const ConfirmHeader = "X-Burpsy-Confirm"

// ConfirmTTL is how long a confirmation stays valid.
//
// Long enough for a human to click through a dialog, short enough that a token captured from a log
// is not a standing licence. This is a deliberate trade toward refusal: a stale token means the
// operator confirms again, which costs a click.
const ConfirmTTL = 60 * time.Second

// confirmStore holds the one-time tokens handed out by a confirm request and spent by the call
// they authorise.
//
// One-time because a confirmation that authorises N calls is not a confirmation. A captured token
// that replayed would be indistinguishable from a caller the operator meant to allow.
type confirmStore struct {
	mu     sync.Mutex
	tokens map[string]confirmEntry
}

// confirmEntry is a minted token's expiry, the route it confirms, and the one call it confirms.
type confirmEntry struct {
	expires time.Time
	// route is the pattern the token was minted for, normalised by confirmRouteKey so a subtree pair
	// (/api/x and /api/x/, which share one /confirm endpoint) is one route.
	route string
	// call is the digest of the resolved call the approver was shown (callBinding.digest): method,
	// concrete path, canonical query and canonical body hash. A token bound only to its route let a
	// confirmation for one request authorise any other request to the same route — a crawl of the
	// in-scope host confirmed a crawl of any host, an export of the certificate confirmed an export
	// of the private key (burpsy-react-ui-e0yq).
	call string
}

func newConfirmStore() *confirmStore {
	return &confirmStore{tokens: make(map[string]confirmEntry)}
}

// confirmRouteKey is the route identity a token is bound to. A manifest subtree pattern and its exact
// sibling ("/api/session/rules" and "/api/session/rules/") are minted through ONE confirm path, and
// the mint cannot know which of the two the caller is about to spend on — so binding to the pair is
// the only binding that is both strict across routes and never refuses the caller's own route
// (burpsy-react-ui-r9b5).
func confirmRouteKey(pattern string) string { return strings.TrimSuffix(pattern, "/") }

// issue mints a token bound to one route pattern and one resolved call, and returns it.
func (c *confirmStore) issue(pattern string, call callBinding) (string, error) {
	raw, err := randomHex(16)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Expired entries are swept on issue rather than on spend, so a long-idle server does not
	// accumulate them. A store that only cleaned on spend would grow without bound for a
	// caller that never spends what it asks for.
	now := time.Now()
	for k, e := range c.tokens {
		if now.After(e.expires) {
			delete(c.tokens, k)
		}
	}
	c.tokens[raw] = confirmEntry{expires: now.Add(ConfirmTTL), route: confirmRouteKey(pattern), call: call.digest()}
	return raw, nil
}

// spend redeems a token for the pattern and the call it was issued against. False means absent,
// expired, issued for a different route, or issued for a different call on this route — all four are
// refusals and none of them says which, so the error a caller sees cannot be used to probe for a live
// token.
func (c *confirmStore) spend(token, pattern string, call callBinding) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.tokens[token]
	if !ok {
		return false
	}
	// Burned whatever the outcome, including a spend on the wrong route: a token tried against another
	// route is a token in the wrong hands, and leaving it live would let a caller probe route after
	// route with one confirmation. Before burpsy-react-ui-r9b5 the route was recorded at mint and
	// never compared, so a confirmation for a cheap gated call (a crawl) confirmed any other gated call
	// (a project switch, a CA private-key export) within the TTL.
	//
	// The same holds for a spend on the right route with a different call: the token was shown to an
	// approver as one request, and a caller presenting it with another is either confused or swapping
	// the request after approval. Either way the approval does not carry, and it is not left live for
	// a second try. The digest comparison is constant-time because the digest is derived from what the
	// approver saw, and a timing difference over it is a needless signal.
	delete(c.tokens, token)
	return time.Now().Before(e.expires) && e.route == confirmRouteKey(pattern) && constantTimeEqual(e.call, call.digest())
}

// pending reports whether a token exists and has not expired, without consuming it. Used by the
// UI to ask "is this call still confirmed?" without spending the answer.
func (c *confirmStore) pending(token string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.tokens[token]
	return ok && time.Now().Before(e.expires)
}

// gate wraps h so a confirmation-worthy route cannot execute without a confirmed token.
//
// The same shape as sameOriginOnly, and installed beside it for the same reason: a check in
// ListenAndServe would be exercised by no test and verified by nothing. A security control the
// suite cannot see is a comment rather than a control.
//
// confirmMux is consulted FIRST and outside the gate entirely. A mint request is itself a mutating
// POST on a gated pattern, so gating it would make the gate unsatisfiable — the one failure mode
// that looks exactly like working, because every dangerous call is refused and nothing can change
// that.
func (s *Server) confirmationGate(h, confirmMux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The mint endpoint is matched FIRST and independently of the risk resolution below.
		//
		// Checking it after is a real bug, not a style preference: a request for
		// "/api/sequencer/capture/confirm" resolves by longest match to "/api/sequencer/capture/",
		// which is riskRead — the read subtree under an attack route. Ungated, so the mint fell
		// through to the main mux, which has no such route, and the answer was 405. A gated route
		// whose mint endpoint 405s is a gate that forbids the route.
		minted := confirmPatternFor(r.URL.Path)
		if minted != r.URL.Path {
			if _, risk, ok := routeRiskFor(minted); ok && needsConfirmation(risk) {
				confirmMux.ServeHTTP(w, r)
				return
			}
		}
		pattern, risk, ok := routeRiskFor(r.URL.Path)
		// Reads and safe methods are not gated: a GET on a gated route is a read of state the gate
		// is protecting, not the protected act itself — /api/scope is riskScope and answers GET
		// with the scope list. Gating reads would mean the console could not display the thing
		// the operator is about to confirm, which is the dialog this gate exists to back up.
		if !ok || !needsConfirmation(risk) || !methodMutates(r.Method) {
			h.ServeHTTP(w, r)
			return
		}
		// The cross-site gate is OUTER (see setupRoutes), so by the time a request is here it has
		// already been shown to be same-origin. That is what lets this refusal be specific — it can
		// name the route and the header, because reaching this line already means the caller is not
		// a hostile page. The ordering is load-bearing and the tests below hold it: with the gates
		// the other way round, a cross-site caller received this 428 and learned which header to
		// try next.
		token := r.Header.Get(ConfirmHeader)
		if token == "" {
			s.refuseUnconfirmed(w, pattern, risk, true)
			return
		}
		// The body is read here, in full, so the call can be compared with the one the token was
		// minted for, and then handed to the route unchanged. Only when a token is presented: an
		// unconfirmed call is refused without the gate reading a byte of it. The cap is the server's
		// own request cap, so the gate buffers nothing a handler could not have been sent anyway.
		call, body, err := bindingOfRequest(r)
		if err != nil {
			// The token is burned as a spend would burn it: a presented token whose call cannot be
			// read is not left live for a second attempt.
			s.confirms.burn(token)
			http.Error(w, "could not read the request body to check it against its confirmation: "+err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if !s.confirms.spend(token, pattern, call) {
			s.refuseUnconfirmed(w, pattern, risk, false)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// methodMutates reports whether a verb can change state or cause egress.
//
// The safe set is spelled out rather than the unsafe one, so a verb Go adds later is treated as
// mutating until someone says otherwise. A new HTTP method defaulting to "harmless" is the wrong
// direction for a gate that stands in front of an attack route.
func methodMutates(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}

// refuseUnconfirmed answers a gated call that carried no usable confirmation.
//
// 428 Precondition Required rather than 403: the request is well-formed and may well be
// permitted, it is missing a precondition. 403 would tell a caller "no" about a thing it has not
// tried yet, and 401 would imply an authentication problem this console does not have.
func (s *Server) refuseUnconfirmed(w http.ResponseWriter, pattern string, risk riskClass, missing bool) {
	detail := "this route needs an explicit confirmation of this exact call; POST " + strings.TrimSuffix(pattern, "/") +
		`/confirm with {"method":…,"url":…,"body":…} describing the call to get one`
	if !missing {
		detail = "the confirmation for this call is not valid: it has expired, was already used, or was issued for a different route or a different request (method, path, query or body)"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPreconditionRequired)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":        detail,
		"route":        pattern,
		"risk":         string(risk),
		"confirm_with": ConfirmHeader,
		"expires_in":   int(ConfirmTTL.Seconds()),
	})
}

// handleConfirm mints a one-time confirmation for one concrete call to the route named in the path.
//
// Registered as a SUBTREE under each gated pattern, so the pattern is taken from the request rather
// than from a table entry — a caller cannot be handed a token for one route and spend it on
// another, because the token is issued FOR this path and the gate spends it against this path.
//
// The body describes the call the token will authorise (confirmCall), and the answer echoes back
// what the server resolved it to (confirmPreview) — the request an approver is agreeing to, as the
// gate will compare it, not as the caller summarised it. Before burpsy-react-ui-e0yq the mint took
// no body: the approver signed a route name, and the token it produced authorised any request to
// that route. A mint with no call described is refused rather than defaulted to "any call": an
// unbound token is exactly the thing this binding removes.
//
// The gate does not consult this handler's response for anything but the token. A caller that can
// POST here without a human present has the same problem as a caller that can set the header
// itself, and no server-side scheme fixes that on its own: it is why the confirm endpoint is the
// right place for the console's own auth to sit, and why that auth is a separate bead (console
// auth, not this one). What this gate DOES guarantee is that the dangerous call is never reached
// by accident, never reached by a tool acting on the operator's earlier, unrelated instruction, and
// never reached by a request other than the one that was shown.
func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "confirmation is minted with POST", http.StatusMethodNotAllowed)
		return
	}
	// The suffix is stripped and the trailing slash restored, so a token is issued against the SAME
	// pattern string the gate spends it against. A subtree pattern registered as "/api/x/" and a
	// request for "/api/x/confirm" would otherwise mint against "/api/x" and never match.
	pattern := confirmPatternFor(r.URL.Path)
	_, risk, ok := routeRiskFor(pattern)
	if !ok {
		http.Error(w, "no such route", http.StatusNotFound)
		return
	}
	if !needsConfirmation(risk) {
		http.Error(w, "this route does not require confirmation", http.StatusBadRequest)
		return
	}
	var desc confirmCall
	if err := requestJSON(w, r, http.MaxBytesReader(w, r.Body, maxConfirmDescriptionBytes)).Decode(&desc); err != nil {
		msg := "describe the call this confirmation is for: " + `{"method":"POST","url":"` + pattern + `…","body":"<the exact request body>"}`
		if !errors.Is(err, io.EOF) {
			msg += " (" + err.Error() + ")"
		}
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	call, err := desc.resolve(pattern)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token, err := s.confirms.issue(pattern, call)
	if err != nil {
		http.Error(w, "could not mint a confirmation: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// A preview may carry request content; it is the caller's own request echoed back, and it is not
	// a response anything should cache.
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(confirmMinted{
		ConfirmWith: ConfirmHeader,
		Token:       token,
		Route:       pattern,
		ExpiresIn:   int(ConfirmTTL.Seconds()),
		Binding:     call.digest(),
		Call:        call.preview(),
	})
}

// routeRiskFor resolves a request path to its manifest pattern and risk class.
//
// Longest-prefix, because ServeMux does the same thing and the gate has to agree with it: a gate
// that resolved "/api/audit/" to "/api/audit" would read a different risk for the same route the
// mux routed.
func routeRiskFor(path string) (string, riskClass, bool) {
	best, bestRisk, found := "", riskClass(""), false
	for pattern, r := range manifest {
		if pattern != "/" && !pathHasPrefix(path, pattern) {
			continue
		}
		if !found || len(pattern) > len(best) {
			best, bestRisk, found = pattern, r.risk, true
		}
	}
	return best, bestRisk, found
}

// confirmPatternFor strips the /confirm suffix a confirmation request carries, and restores a
// trailing slash when the manifest entry had one.
//
// Restoring it is what makes the token match. A token is issued against the manifest pattern string
// and spent against the same string, so "/api/sequencer/capture" (minted) would not match
// "/api/sequencer/capture/" (resolved for the call) and every confirmation would be refused.
func confirmPatternFor(path string) string {
	const suffix = "/confirm"
	if len(path) > len(suffix) && path[len(path)-len(suffix):] == suffix {
		stripped := path[:len(path)-len(suffix)]
		// A manifest subtree pattern is registered WITH its trailing slash, so the token has to be
		// minted against that exact string. The one signal available is that the stripped path is a
		// prefix of a registered gated pattern; restoring the slash when one matches is what keeps
		// the mint and the spend on the same key.
		for pattern, r := range manifest {
			if needsConfirmation(r.risk) && (pattern == stripped || pattern == stripped+"/") {
				return pattern
			}
		}
		return stripped
	}
	return path
}

// pathHasPrefix is strings.HasPrefix with the segment boundary, so "/api/audit" does not match
// "/api/audit-elsewhere". The manifest is full of subtree patterns and one prefix rule too loose
// would gate a route the manifest never classified.
func pathHasPrefix(path, pattern string) bool {
	if len(path) < len(pattern) {
		return false
	}
	if path[:len(pattern)] != pattern {
		return false
	}
	return len(path) == len(pattern) || pattern[len(pattern)-1] == '/' || path[len(pattern)] == '/'
}

// confirmBody is the shape the console reads. Exported so a caller building a request does not
// have to guess the field names, which is the same reason the type exists for every other wire
// shape in this package.
type confirmBody struct {
	Token string `json:"token"`
}

// confirmMinted is a mint's answer: the token, and the call it is bound to as the server resolved it.
type confirmMinted struct {
	ConfirmWith string `json:"confirm_with"`
	Token       string `json:"token"`
	Route       string `json:"route"`
	ExpiresIn   int    `json:"expires_in"`
	// Binding is the digest the gate compares a spend against. A client that shows the preview and
	// mints again later (say, after the operator took longer than the TTL to answer) compares the two
	// digests to prove the second token authorises the request the operator saw.
	Binding string         `json:"binding"`
	Call    confirmPreview `json:"call"`
}

// randomHex is a 2n-character lowercase hex string from crypto/rand.
//
// crypto/rand rather than math/rand because this value IS the authorisation: a token from a
// predictable generator is a token an attacker can guess, and a guessed token turns the gate into
// the thing it was built to prevent.
func randomHex(n int) (string, error) {
	const hexdigits = "0123456789abcdef"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("reading %d random bytes: %w", n, err)
	}
	out := make([]byte, 0, n*2)
	for _, b := range buf {
		out = append(out, hexdigits[b>>4], hexdigits[b&0x0f])
	}
	return string(out), nil
}

// constantTimeEqual is used where a comparison's timing could leak a secret. Kept as a named
// function so the intent is visible at the call site rather than buried in a subtle package.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// confirmTTLSeconds is what the wire reports, as a number a caller can compare against its own
// clock expectations without parsing a duration.
func confirmTTLSeconds() int { return int(ConfirmTTL / time.Second) }

// confirmCount reports how many live confirmations exist. For the console's own debug view; a
// count is not a secret and a length is not an enumeration.
func (s *Server) confirmCount() int {
	s.confirms.mu.Lock()
	defer s.confirms.mu.Unlock()
	now := time.Now()
	n := 0
	for _, e := range s.confirms.tokens {
		if now.Before(e.expires) {
			n++
		}
	}
	return n
}

// registerConfirmationRoutes builds the mux that mints one-time confirmations, one endpoint per
// gated pattern, and returns it.
//
// A SEPARATE mux rather than more patterns on s.mux, and that is load-bearing twice over. The mint
// endpoint is what makes a token, so a gated route that swallowed its own /confirm suffix would
// leave a gate with no way to satisfy it. And a minted pattern derived from the manifest would
// otherwise land in route_manifest_test.go's remit, where Test_every_route_pattern_is_a_literal
// refuses a non-literal HandleFunc argument — correctly, since a pattern built from a variable is
// invisible to the manifest. The mint endpoints are not manifest routes and are deliberately
// outside it, so they are registered here rather than by weakening that test.
//
// TrimSuffix before appending, or a subtree pattern ending in "/" yields "//confirm", which
// ServeMux treats as a distinct path no caller ever types — the consequence was a gated route
// whose mint endpoint answered 405, i.e. a gate that forbade the route.
//
// Deduped, because the manifest legitimately holds BOTH "/api/pools" and "/api/pools/" (an exact
// route and the subtree under it, both gated) and the two trim to one path. Registering both is a
// ServeMux panic, not a no-op.
func (s *Server) registerConfirmationRoutes() http.Handler {
	mux := http.NewServeMux()
	seen := make(map[string]bool)
	for _, pattern := range gatedRoutePatterns() {
		path := strings.TrimSuffix(pattern, "/") + "/confirm"
		if seen[path] {
			continue
		}
		seen[path] = true
		mux.HandleFunc(path, s.handleConfirm)
	}
	return mux
}
