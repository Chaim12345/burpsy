package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// ---- Access-control testing (burpsy-react-ui-cr37) -----------------------------------------------
//
// Autorize/AuthMatrix for burpsy: re-send one request under several named identities and say, per
// identity, whether access control held. The verdict engine is scanner.Baseline — N-sample
// calibration of the high-privilege identity, then each other identity's one response diffed against
// it, so an endpoint whose body carries a timestamp does not read as an anomaly every time.
//
// An identity is a credential bundle an operator pastes (the cookie of a logged-in low-priv user, a
// second user's bearer token), which is Autorize's model — OR, since burpsy-react-ui-q7f8, a reference
// to a session rule: a logged-in session the operator already holds in the session store becomes a
// role without copy-paste, and its cookie is refreshed by running the rule's login macro before the
// test rather than pasted stale. See resolveSessionIdentities.

// authzIdentity is one named role: the cookies and headers that make a request act as that identity.
type authzIdentity struct {
	// Label names the identity in the verdict table ("admin", "low-priv user", "no auth").
	Label string `json:"label"`
	// Baseline marks the high-privilege identity the others are compared against. Exactly one is the
	// baseline; the request as captured defines it when none is marked.
	Baseline bool `json:"baseline"`
	// Cookie replaces the request's Cookie header for this identity. Empty strips it (the no-auth
	// identity), which is the point of a no-auth row.
	Cookie string `json:"cookie"`
	// Headers are extra request headers set for this identity (Authorization, X-API-Key, …). They
	// replace any header of the same name already on the request.
	Headers map[string]string `json:"headers"`
	// StripCookie, when true, removes the Cookie header entirely rather than replacing it — the
	// explicit no-auth identity, distinct from "leave the captured cookie" (which is Cookie=="" and
	// StripCookie false meaning "unchanged").
	StripCookie bool `json:"strip_cookie"`
	// SessionRuleID, when set, sources this identity from a session rule (burpsy-react-ui-q7f8) instead
	// of a pasted Cookie: before the test, the rule's login macro is run so its jar is fresh, and the
	// Cookie that jar would attach to the target request is this identity's cookie. A pointer because
	// rule 0 is a real id, so "no rule" cannot be spelled as 0. Headers still apply on top (a bearer
	// token the operator adds by hand); Cookie/StripCookie are ignored when this is set.
	SessionRuleID *int64 `json:"session_rule_id,omitempty"`
}

// maxAuthzIdentities bounds the set — each is a full re-send of the request, calibration included.
const maxAuthzIdentities = 16

// authzState holds the project's identities.
type authzState struct {
	mu         sync.Mutex
	identities []authzIdentity
}

func (s *Server) restoreAuthzIdentities(p *persist.Store) {
	raw, err := p.LoadAuthzIdentities()
	if err != nil {
		s.logger.Warn("failed to restore access-control identities", zap.Error(err))
	}
	var ids []authzIdentity
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &ids); err != nil {
			s.logger.Warn("stored access-control identities do not parse; starting with none", zap.Error(err))
			ids = nil
		}
	}
	s.authz.mu.Lock()
	s.authz.identities = ids
	s.authz.mu.Unlock()
}

func (s *Server) authzIdentities() []authzIdentity {
	s.authz.mu.Lock()
	defer s.authz.mu.Unlock()
	return append([]authzIdentity(nil), s.authz.identities...)
}

// handleAuthzIdentities serves GET/PUT /api/authz/identities. riskLocal: it reads and writes
// burpsy's own saved role bundles and sends nothing.
func (s *Server) handleAuthzIdentities(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ids := s.authzIdentities()
		if ids == nil {
			ids = []authzIdentity{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"identities": ids})
	case http.MethodPut:
		var body struct {
			Identities []authzIdentity `json:"identities"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, `the body must be {"identities":[...]}`, http.StatusBadRequest)
			return
		}
		if len(body.Identities) > maxAuthzIdentities {
			http.Error(w, "too many identities", http.StatusBadRequest)
			return
		}
		seen := map[string]bool{}
		baselines := 0
		for _, id := range body.Identities {
			if strings.TrimSpace(id.Label) == "" {
				http.Error(w, "an identity needs a label", http.StatusBadRequest)
				return
			}
			if seen[id.Label] {
				http.Error(w, "two identities are named "+id.Label+"; a label must be unique", http.StatusBadRequest)
				return
			}
			seen[id.Label] = true
			if id.Baseline {
				baselines++
			}
			// A session-sourced identity (q7f8) is refused at save time if its rule does not exist, so a
			// typo'd reference is a clear error here rather than an Ambiguous row at test time.
			if id.SessionRuleID != nil {
				if s.sessionCoordinator == nil {
					http.Error(w, "this instance has no session store, so an identity cannot be sourced from a session rule", http.StatusBadRequest)
					return
				}
				if s.sessionCoordinator.Rule(session.RuleID(*id.SessionRuleID)) == nil {
					http.Error(w, fmt.Sprintf("identity %q references session rule %d, which does not exist", id.Label, *id.SessionRuleID), http.StatusBadRequest)
					return
				}
			}
		}
		if len(body.Identities) > 0 && baselines != 1 {
			http.Error(w, "exactly one identity must be the baseline (the high-privilege role the others are compared against)", http.StatusBadRequest)
			return
		}
		s.authz.mu.Lock()
		s.authz.identities = append([]authzIdentity(nil), body.Identities...)
		s.authz.mu.Unlock()
		if s.persist != nil {
			if blob, err := json.Marshal(body.Identities); err == nil {
				if err := s.persist.SaveAuthzIdentities(blob); err != nil {
					s.logger.Warn("access-control identities persist failed", zap.Error(err))
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"identities": body.Identities})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// authzVerdict is one identity's result.
type authzVerdict struct {
	Label string `json:"label"`
	// Verdict is Enforced (access denied / different from baseline), Bypassed (the identity received
	// the baseline's privileged content), Ambiguous (the send failed or the baseline was too thin to
	// judge), or Baseline (this is the reference identity).
	Verdict string `json:"verdict"`
	Status  int    `json:"status"`
	BodyLen int    `json:"body_len"`
	// Reasons are the engine's signal explanations (status changed, length deviates, new body hash),
	// so the table says why rather than only what.
	Reasons []string `json:"reasons,omitempty"`
	// RequestID / ResponseID are the stored message ids of this identity's exchange, so the console
	// can one-click diff two identities' responses in the existing Comparer.
	RequestID  *uint64 `json:"request_id,omitempty"`
	ResponseID *uint64 `json:"response_id,omitempty"`
	// Error is set when this identity could not be sent.
	Error string `json:"error,omitempty"`
}

// authzRawSender sends one exchange's request under one identity through the shared authorised
// sender, storing each exchange so a verdict can be diffed in the Comparer. It is the BaselineSender
// the engine drives.
type authzRawSender struct {
	s         *Server
	ex        *core.Exchange
	rawReq    []byte
	ids       map[string]authzIdentity // label -> identity, so the engine's AuthContext.Label resolves
	lastReqID map[string]uint64
	lastRspID map[string]uint64
	mu        sync.Mutex
}

func (a *authzRawSender) Send(ctx context.Context, auth scanner.AuthContext) (int, string, time.Duration, error) {
	id := a.ids[auth.Label]
	raw := applyIdentity(a.rawReq, id)
	if aerr := a.s.scope.AuthoriseRaw(a.ex.Host, a.ex.Port, a.ex.TLS, raw); aerr != nil {
		return 0, "", 0, fmt.Errorf("refused: %w", aerr)
	}
	started := time.Now()
	respBytes, _, err := a.s.sender.SendRawOutcome(ctx, a.ex.Host, a.ex.Port, a.ex.TLS, raw, sender.ProtocolPreferenceAuto)
	elapsed := time.Since(started)
	if err != nil {
		return 0, "", elapsed, err
	}
	// Store both halves so the Comparer can load them; the last ids per label are what the verdict
	// reports (calibration sends the baseline N times — the last is representative).
	reqID, rerr := a.s.store.Put(raw, core.DirectionRequest)
	rspID, perr := a.s.store.Put(respBytes, core.DirectionResponse)
	if rerr == nil && perr == nil {
		exID := &core.Exchange{Host: a.ex.Host, Port: a.ex.Port, TLS: a.ex.TLS, Method: a.ex.Method, Path: a.ex.Path,
			Request: core.MsgPtr(reqID), Response: &rspID}
		a.s.store.AddExchange(exID)
		a.mu.Lock()
		a.lastReqID[auth.Label] = uint64(reqID)
		a.lastRspID[auth.Label] = uint64(rspID)
		a.mu.Unlock()
	}
	status := authzStatus(respBytes)
	body := string(responseBodyBytes(respBytes))
	return status, body, elapsed, nil
}

// handleAuthzTest serves POST /api/authz/test. riskAttack: it re-sends a captured request to its
// target several times under different credentials — traffic to the target, and the whole point.
func (s *Server) handleAuthzTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.sender == nil {
		http.Error(w, "no sender is configured, so a request cannot be re-sent", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		ExchangeID core.ExchangeID `json:"exchange_id"`
		Samples    int             `json:"samples"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, `the body must be {"exchange_id":N,"samples"?:M}`, http.StatusBadRequest)
		return
	}
	identities := s.authzIdentities()
	if len(identities) < 2 {
		http.Error(w, "define at least two identities (a baseline and one other) before testing", http.StatusBadRequest)
		return
	}
	ex, err := s.store.GetExchange(body.ExchangeID)
	if err != nil || ex.Request == nil {
		http.Error(w, "no such exchange, or it has no stored request", http.StatusNotFound)
		return
	}
	reqMsg, err := s.store.Get(*ex.Request)
	if err != nil {
		http.Error(w, "the exchange's request is not in the store", http.StatusNotFound)
		return
	}
	samples := body.Samples
	if samples <= 0 {
		samples = 5
	}
	if samples > 20 {
		samples = 20
	}

	ctx := r.Context()

	// Session-sourced identities (q7f8): run each referenced rule's login macro so its jar is current,
	// then resolve the Cookie that jar would attach to this target into the identity's own Cookie, so
	// the rest of the test treats it exactly like a pasted one. A rule that is gone or could not log in
	// yields sessionErrs[label], which the verdict loop reports as Ambiguous rather than sending a
	// request with no credentials and calling the result a bypass.
	sessionErrs := s.resolveSessionIdentities(ctx, ex, identities)

	var baseline authzIdentity
	for _, id := range identities {
		if id.Baseline {
			baseline = id
		}
	}
	// A baseline that could not be logged in makes every verdict meaningless — the others would be
	// compared against an unauthenticated reference — so this is a whole-test failure, not one row.
	if msg := sessionErrs[baseline.Label]; msg != "" {
		http.Error(w, "the baseline identity's session rule could not be logged in: "+msg, http.StatusBadGateway)
		return
	}
	idMap := map[string]authzIdentity{}
	for _, id := range identities {
		idMap[id.Label] = id
	}
	raw := append([]byte(nil), reqMsg.Raw()...)
	snd := &authzRawSender{s: s, ex: ex, rawReq: raw, ids: idMap, lastReqID: map[string]uint64{}, lastRspID: map[string]uint64{}}
	// Access control is a question about CONTENT, not latency: a role that gets the baseline's body
	// and status has bypassed the control however fast the server answered. Timing deviation is noise
	// here (it flagged a faster low-priv response as "different" and so Enforced), so it is neutered —
	// a huge sigma that no real duration reaches — leaving status, length and body-hash as the signals.
	threshold := scanner.DefaultDeviationThreshold()
	threshold.TimingSigma = 1e9
	baseAuth := scanner.AuthContext{Label: baseline.Label, HasCredentials: baseline.Cookie != "" || len(baseline.Headers) > 0}
	base, _, berr := scanner.RunBaselineCalibration(ctx, snd, baseAuth, samples)
	if berr != nil {
		http.Error(w, "calibrating the baseline identity failed: "+berr.Error(), http.StatusBadGateway)
		return
	}

	verdicts := make([]authzVerdict, 0, len(identities))
	for _, id := range identities {
		v := authzVerdict{Label: id.Label}
		if reqID, ok := snd.lastReqID[id.Label]; ok {
			v.RequestID = &reqID
		}
		if rspID, ok := snd.lastRspID[id.Label]; ok {
			v.ResponseID = &rspID
		}
		if id.Baseline {
			v.Verdict = "Baseline"
			v.Status = base.ModalStatus()
			v.BodyLen = int(base.AvgBodyLen())
			verdicts = append(verdicts, v)
			continue
		}
		// A session identity that could not be logged in is reported as Ambiguous, not sent: a request
		// with no credentials would look like the no-auth row and its result would be read as a bypass.
		if msg := sessionErrs[id.Label]; msg != "" {
			v.Verdict = "Ambiguous"
			v.Error = "session rule could not be logged in: " + msg
			verdicts = append(verdicts, v)
			continue
		}
		auth := scanner.AuthContext{Label: id.Label, HasCredentials: id.Cookie != "" || len(id.Headers) > 0}
		status, bodyText, duration, serr := snd.Send(ctx, auth)
		// The send above stored a fresh exchange; refresh the ids for the verdict.
		if reqID, ok := snd.lastReqID[id.Label]; ok {
			v.RequestID = &reqID
		}
		if rspID, ok := snd.lastRspID[id.Label]; ok {
			v.ResponseID = &rspID
		}
		if serr != nil {
			v.Verdict = "Ambiguous"
			v.Error = serr.Error()
			verdicts = append(verdicts, v)
			continue
		}
		dev := base.DiffAccessControl(scanner.NewBaselineSample(status, bodyText, duration), threshold)
		v.Status = status
		v.BodyLen = len(bodyText)
		v.Reasons = dev.Comparison.Reasons
		// Matched == the other identity received what the baseline can see == access control bypassed.
		if dev.Matched {
			v.Verdict = "Bypassed"
		} else {
			v.Verdict = "Enforced"
		}
		verdicts = append(verdicts, v)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"exchange_id": body.ExchangeID,
		"samples":     samples,
		"verdicts":    verdicts,
	})
}

// resolveSessionIdentities turns every session-sourced identity (q7f8) into a cookie-bearing one, in
// place: for each identity with a SessionRuleID, it runs the rule's login macro (so the jar is fresh
// rather than whatever a previous test left) and sets the identity's Cookie to what that jar would
// attach to ex's target. The returned map carries, per label, why an identity could not be resolved —
// the rule was deleted, or the login macro failed — so the caller reports it rather than sending an
// unauthenticated request.
//
// ex's path is used for the jar lookup because a cookie's Path attribute scopes which requests it
// rides; the access-control test re-sends ex, so ex's path is the one that matters.
func (s *Server) resolveSessionIdentities(ctx context.Context, ex *core.Exchange, identities []authzIdentity) map[string]string {
	errs := map[string]string{}
	if s.sessionCoordinator == nil {
		for _, id := range identities {
			if id.SessionRuleID != nil {
				errs[id.Label] = "no session store is wired"
			}
		}
		return errs
	}
	runner := s.macroRunner(ctx)
	for i := range identities {
		if identities[i].SessionRuleID == nil {
			continue
		}
		rule := s.sessionCoordinator.Rule(session.RuleID(*identities[i].SessionRuleID))
		if rule == nil {
			errs[identities[i].Label] = fmt.Sprintf("no session rule with id %d", *identities[i].SessionRuleID)
			continue
		}
		// A rule with a login macro is logged in first; one with no macro (a rule that only threads a
		// jar the operator populated elsewhere) is used as-is. EnsureLoggedIn on a macro-less rule would
		// report GaveUp, which is not a failure here — the jar may already hold the cookie.
		if len(rule.Steps) > 0 {
			if out := s.sessionCoordinator.EnsureLoggedIn(rule, runner); out.Kind == session.LoginMacroFailed {
				errs[identities[i].Label] = "the rule's login macro failed"
				continue
			}
		}
		cookie := s.sessionCoordinator.CookieHeader(ex.Host, ex.Port, ex.TLS, ex.Path)
		if cookie == "" {
			errs[identities[i].Label] = "the session rule's jar holds no cookie for this target after login"
			continue
		}
		// Sourced from the session, not pasted: take the resolved cookie, and never strip (that is the
		// no-auth row's job, and a session identity is the opposite of no-auth).
		identities[i].Cookie = cookie
		identities[i].StripCookie = false
	}
	return errs
}

// applyIdentity renders the request under one identity: the Cookie header replaced or stripped, and
// each extra header set.
func applyIdentity(raw []byte, id authzIdentity) []byte {
	out := append([]byte(nil), raw...)
	if id.StripCookie {
		out = stripHeader(out, "Cookie")
	} else if id.Cookie != "" {
		out = replaceCookieHeader(out, id.Cookie)
	}
	for name, value := range id.Headers {
		out = upsertHeader(out, name, value)
	}
	return out
}

// responseBodyBytes returns the body of a raw HTTP response.
func responseBodyBytes(raw []byte) []byte {
	_, body := splitHeadBody(raw)
	return body
}

// authzStatus parses the status code off a raw response's status line, 0 when unreadable.
func authzStatus(raw []byte) int {
	line := string(raw)
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		var code int
		if _, err := fmt.Sscanf(fields[1], "%d", &code); err == nil {
			return code
		}
	}
	return 0
}

// stripHeader removes every header with the given name (case-insensitive).
func stripHeader(raw []byte, name string) []byte {
	head, body := splitHead(raw)
	lines := strings.Split(string(head), "\r\n")
	kept := lines[:0]
	for i, l := range lines {
		if i > 0 && strings.EqualFold(strings.TrimSpace(strings.SplitN(l, ":", 2)[0]), name) {
			continue
		}
		kept = append(kept, l)
	}
	return []byte(strings.Join(kept, "\r\n") + string(body))
}

// upsertHeader sets name: value, replacing an existing header of that name or inserting one before
// the head's terminating blank line.
func upsertHeader(raw []byte, name, value string) []byte {
	head, body := splitHead(raw)
	lines := strings.Split(string(head), "\r\n")
	for i, l := range lines {
		if i > 0 && strings.EqualFold(strings.TrimSpace(strings.SplitN(l, ":", 2)[0]), name) {
			lines[i] = name + ": " + value
			return []byte(strings.Join(lines, "\r\n") + string(body))
		}
	}
	insertAt := len(lines)
	for i, l := range lines {
		if l == "" {
			insertAt = i
			break
		}
	}
	lines = append(lines[:insertAt], append([]string{name + ": " + value}, lines[insertAt:]...)...)
	return []byte(strings.Join(lines, "\r\n") + string(body))
}
