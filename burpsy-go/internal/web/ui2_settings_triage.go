package web

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ---- Triage (LLM) settings editing via the confirm gate --------------------------------------
//
// PUT /api/settings/triage is riskCredential: it stores an API key. The gate binds the exact
// body, and the gate's store is digest-only by design, so a ui2 review sheet cannot recover the
// minted bytes from the gate to display them. The bounded review map below closes that: the
// confirm step mints the token, holds the exact minted body bytes here, and renders a redacted
// projection of those same bytes. The run step dispatches the held bytes verbatim - the run
// form carries only the review id and token, never re-serialized form fields, so nothing typed
// after the review can change what is written (the collaborator preview spends the same way).
//
// The API key never leaves the server in any direction but the reviewed PUT: it is not in the
// review HTML (the projection redacts it), not in URLs, not in logs, and the key field is a
// password input the live-refresh dirty capture refuses to carry across swaps (app.js).
//
// ui2TriageReviewCap bounds the map so an open-tab pileup cannot grow it without limit. The
// reviewer approved cap 8 with sweep-on-issue: enough for a few open tabs, small enough that a
// full map is a sign to refuse and say so rather than silently drop somebody's review.
const ui2TriageReviewCap = 8

// ui2TriageReview is one minted triage-settings change held for review. The entry dies with the
// gate's ConfirmTTL so a stale review refuses alongside its token, and the run step spends it
// atomically (LoadAndDelete) so a double-confirm cannot dispatch twice.
type ui2TriageReview struct {
	token   string
	body    []byte // the exact minted call body - dispatched verbatim on run
	expires time.Time
}

// ui2TriageBody builds the exact PUT body from the form. A blank key is OMITTED (the API then
// keeps the stored key); the ack is a ui2-local gate, never part of the body.
func ui2TriageBody(enabled bool, baseURL, model, apiKey string) []byte {
	m := map[string]any{"enabled": enabled, "base_url": baseURL, "model": model}
	if apiKey != "" {
		m["api_key"] = apiKey
	}
	b, _ := json.Marshal(m)
	return b
}

// ui2TriageProjection renders the redacted review copy from the exact minted bytes: parse,
// blank the key, re-marshal. The projection is derived from what the token binds, not from a
// second serialization of the form, so the review cannot drift from the dispatch.
func ui2TriageProjection(body []byte) string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return "PUT /api/settings/triage (body unreadable for display)"
	}
	if _, has := m["api_key"]; has {
		m["api_key"] = "(hidden - the token binds the exact value you typed)"
	}
	b, _ := json.Marshal(m)
	return "PUT /api/settings/triage\n" + string(b)
}

// ui2ValidateTriageBaseURL rejects base URLs this UI will not mint. Secret-bearing URLs
// (userinfo, query) and fragments are refused here rather than sanitized, because the engine
// appends /chat/completions to the configured value verbatim and the operator should see and
// fix that in the console, not have this page quietly reshape it. Errors name the rejected
// PART, never its value.
func ui2ValidateTriageBaseURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "the base URL is not a full URL (scheme and host are required)"
	}
	// https only for real destinations: the engine sends the configured key as a bearer
	// token with no scheme check of its own, so a remote http:// base URL would put the key on
	// the wire in cleartext. The API itself still accepts http (preexisting behavior, reported
	// separately); THIS page refuses to mint it. Loopback http stays allowed so local synthetic
	// fixtures can exercise the flow in tests and UAT.
	if u.Scheme == "http" {
		h := u.Hostname()
		if ip := net.ParseIP(h); h == "localhost" || (ip != nil && ip.IsLoopback()) {
			return ""
		}
		return "this page only saves https base URLs - http would send the API key in cleartext (loopback http, 127.0.0.1/::1/localhost, is allowed for local testing)"
	}
	if u.Scheme != "https" {
		return "the base URL scheme must be https"
	}
	if u.User != nil {
		return "base URLs with embedded credentials (user:pass@host) are not accepted here - move the credential into the API key field"
	}
	if u.RawQuery != "" {
		return "base URLs with a query string are not accepted here - the endpoint path is appended to the base URL"
	}
	if u.Fragment != "" {
		return "base URLs with a fragment are not accepted here"
	}
	return ""
}

// handleUI2SettingsTriage serves POST /ui2/settings/triage/{action}: confirm mints and renders
// the review; run spends the held entry and dispatches the reviewed bytes.
func (s *Server) handleUI2SettingsTriage(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("action") {
	case "confirm":
		s.ui2TriageConfirm(w, r)
	case "run":
		s.ui2TriageRun(w, r)
	default:
		http.Error(w, "unknown settings triage action", http.StatusBadRequest)
	}
}

// ui2TriageConfirm validates the form, mints the gate token, holds the exact bytes, and renders
// the review sheet with the redacted projection.
func (s *Server) ui2TriageConfirm(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	fail := func(msg string) {
		model := map[string]any{"error": msg}
		ui2Fragment(w, r, "burpsy /ui2/ — Settings", "settings", ui2Exec("settings_triage_confirm.html", model))
	}
	enabled := r.PostFormValue("enabled") != ""
	baseURL := strings.TrimSpace(r.PostFormValue("base_url"))
	model := strings.TrimSpace(r.PostFormValue("model"))
	apiKey := r.PostFormValue("api_key") // password field; never trimmed, never echoed back
	if msg := ui2ValidateTriageBaseURL(baseURL); msg != "" {
		fail(msg)
		return
	}
	// Preserve-changed: a blank key with a CHANGED base URL forwards the stored key to a new
	// destination. That is a credential transfer, so it needs the operator's explicit
	// acknowledgement (the default-unchecked checkbox) before a token is minted - a review
	// sheet warning alone would still have minted a one-click transfer. An unchanged URL is
	// exempt: the key is already going there today.
	if apiKey == "" {
		stored, err := s.persist.LoadTriageSettings()
		if err != nil {
			fail("could not read the current triage settings: " + err.Error())
			return
		}
		// A transfer needs something TO transfer: the ack gate and its warning apply only when
		// a stored key exists. On a fresh configuration a blank key means "no key at all" -
		// saying one would be forwarded would be a false alarm (reviewer catch on 751447d).
		if stored.APIKey != "" && baseURL != stored.BaseURL && r.PostFormValue("allow_key_forward") == "" {
			fail("the base URL changed but no API key was entered: the stored key would be sent to the new URL. Enter a key, revert the URL, or tick the acknowledgement on the form")
			return
		}
	}
	body := ui2TriageBody(enabled, baseURL, model, apiKey)
	// Mint via the gate (the token binds these exact bytes); keep ONLY the token from the
	// mint response - its echoed call body carries the key and is never stored or rendered.
	call, _ := json.Marshal(map[string]any{"method": http.MethodPut, "url": "/api/settings/triage", "body": string(body)})
	mintReq := newReq(http.MethodPost, "/api/settings/triage/confirm")
	mintReq.Header.Set("Content-Type", "application/json")
	mintReq.Body = ioNopCloser(strings.NewReader(string(call)))
	mintRec := newRecorder()
	s.confirmMux.ServeHTTP(mintRec, mintReq)
	var minted struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(mintRec.Body.Bytes(), &minted); err != nil || minted.Token == "" {
		fail("the confirmation gate refused to mint a review - try again")
		return
	}
	id, err := randomHex(16)
	if err != nil {
		fail("review id: " + err.Error())
		return
	}
	// Sweep expired entries on issue, then refuse when the map is still full - a full map
	// means eight open reviews, which is a pileup to surface, not to paper over.
	now := time.Now()
	s.ui2TriageReviews.Range(func(k, v any) bool {
		if e, ok := v.(ui2TriageReview); ok && now.After(e.expires) {
			s.ui2TriageReviews.Delete(k)
		}
		return true
	})
	count := 0
	s.ui2TriageReviews.Range(func(_, _ any) bool { count++; return true })
	if count >= ui2TriageReviewCap {
		fail("too many reviews are open at once - confirm or let some expire, then try again")
		return
	}
	s.ui2TriageReviews.Store(id, ui2TriageReview{token: minted.Token, body: body, expires: now.Add(ConfirmTTL)})
	review := map[string]any{
		"review_id":  id,
		"token":      minted.Token,
		"projection": ui2TriageProjection(body),
		"base_url":   baseURL,
	}
	switch {
	case apiKey != "":
		review["key_replaces"] = true
	default:
		stored, _ := s.persist.LoadTriageSettings()
		if stored.APIKey == "" {
			review["key_absent"] = true
		} else if baseURL != stored.BaseURL {
			review["key_preserves_changed"] = true
			review["old_base_url"] = stored.BaseURL
		} else {
			review["key_preserves_same"] = true
		}
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Settings", "settings", ui2Exec("settings_triage_confirm.html", review))
}

// ui2TriageRun spends the held review entry and dispatches the exact minted bytes with the
// entry's token. The entry is deleted on ANY spend attempt (unknown id, stale, token mismatch,
// dispatch result) so nothing here is replayable.
func (s *Server) ui2TriageRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	fail := func(msg string) {
		model := map[string]any{"error": msg}
		ui2Fragment(w, r, "burpsy /ui2/ — Settings", "settings", ui2Exec("settings_triage_confirm.html", model))
	}
	id := r.PostFormValue("review_id")
	token := r.PostFormValue("token")
	v, ok := s.ui2TriageReviews.LoadAndDelete(id)
	entry, isReview := v.(ui2TriageReview)
	if !ok || !isReview {
		fail("that review is unknown or was already used - review the change again")
		return
	}
	if time.Now().After(entry.expires) {
		fail("that review expired with the confirmation window - review the change again")
		return
	}
	// Both sides are 128-bit random values; compare in constant time anyway so the check never
	// becomes an oracle if the id scheme ever changes.
	if subtle.ConstantTimeCompare([]byte(entry.token), []byte(token)) != 1 {
		fail("that review does not match this confirmation - review the change again")
		return
	}
	// Dispatch the held bytes verbatim. Re-marshaling a decoded map here could produce bytes
	// the gate did not bind, which the gate would (rightly) refuse with a 428.
	req := newReq(http.MethodPut, "/api/settings/triage")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ConfirmHeader, token)
	req.Body = ioNopCloser(strings.NewReader(string(entry.body)))
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "http://127.0.0.1")
	rec := newRecorder()
	s.guarded.ServeHTTP(rec, req)
	if rec.Code == http.StatusPreconditionRequired {
		fail("confirmation required (428) - the review and the dispatch disagree; review again")
		return
	}
	if rec.Code != http.StatusOK {
		// API validation errors are static strings that never echo the key; trim anyway so a
		// future message cannot smear a body across the page.
		fail("the settings API refused the change: " + truncateForDisplay(strings.TrimSpace(rec.Body.String()), 200))
		return
	}
	s.handleUI2Settings(w, r)
}
