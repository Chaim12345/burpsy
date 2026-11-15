package web

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- Access control (authz) ------------------------------------------------------------------
//
// Identities carry credentials (a cookie, an Authorization header), so the page never renders a
// stored value: rows show whether a cookie is stored and which header NAMES are set. A blank
// cookie/headers field keeps the stored value, so the editor never needs the secret to round-trip
// through the browser. Saving is a server-held review (the full PUT body lives in
// ui2AuthzReviews, the sheet shows it redacted, the run step dispatches the held bytes). The test
// run sends traffic (riskAttack): the gate token binds the full body and the run rebuilds it.

const ui2AuthzReviewCap = 8

type ui2AuthzReview struct {
	nonce     string
	body      []byte
	base      string // digest of the stored identities at review time
	gateToken string // minted only when the PUT route's risk class needs the gate
	expires   time.Time
}

// ui2AuthzDigest is the drift check for the identities editor: a save reviewed against one stored
// set must not overwrite a set changed since.
func ui2AuthzDigest(ids []authzIdentity) string {
	b, _ := json.Marshal(ids)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type ui2AuthzRuleOpt struct {
	ID       string
	Name     string
	Selected bool
}

type ui2AuthzRow struct {
	Index       int
	Orig        string // stored index, "" for a new row
	Label       string
	Baseline    bool
	StripCookie bool
	CookieLen   int
	HeaderNames []string
	Rules       []ui2AuthzRuleOpt
	RuleMissing string // a stored rule id that the rule list no longer serves
}

type ui2AuthzVerdictRow struct {
	authzVerdict
	Why  string
	Diff string // /ui2/authz/diff/{baseline}/{this} when both responses are stored
}

func (s *Server) ui2AuthzRuleOpts(selected *int64) ([]ui2AuthzRuleOpt, string) {
	var resp struct {
		Rules []struct {
			ID   *int64 `json:"id"`
			Name string `json:"name"`
		} `json:"rules"`
	}
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/session/rules"))
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	var opts []ui2AuthzRuleOpt
	found := false
	for _, r := range resp.Rules {
		if r.ID == nil {
			continue
		}
		sel := selected != nil && *selected == *r.ID
		found = found || sel
		name := r.Name
		if name == "" {
			name = "rule " + strconv.FormatInt(*r.ID, 10)
		}
		opts = append(opts, ui2AuthzRuleOpt{ID: strconv.FormatInt(*r.ID, 10), Name: name, Selected: sel})
	}
	missing := ""
	if selected != nil && !found {
		missing = strconv.FormatInt(*selected, 10)
	}
	return opts, missing
}

// ui2AuthzStored reads the identities through the JSON API, the page's only source for them.
func (s *Server) ui2AuthzStored() []authzIdentity {
	var resp authzIdentitiesReq
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/authz/identities"))
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp.Identities
}

// ui2AuthzView builds the page model. Cookie and header values never enter it.
func (s *Server) ui2AuthzView(extra int, note string) map[string]any {
	stored := s.ui2AuthzStored()
	rows := make([]ui2AuthzRow, 0, len(stored)+1)
	for i, id := range stored {
		names := make([]string, 0, len(id.Headers))
		for n := range id.Headers {
			names = append(names, n)
		}
		sort.Strings(names)
		opts, missing := s.ui2AuthzRuleOpts(id.SessionRuleID)
		rows = append(rows, ui2AuthzRow{
			Index: i, Orig: strconv.Itoa(i), Label: id.Label, Baseline: id.Baseline,
			StripCookie: id.StripCookie, CookieLen: len(id.Cookie), HeaderNames: names,
			Rules: opts, RuleMissing: missing,
		})
	}
	if extra < 1 {
		extra = 1
	}
	for n := 0; n < extra && len(rows) < maxAuthzIdentities; n++ {
		opts, _ := s.ui2AuthzRuleOpts(nil)
		rows = append(rows, ui2AuthzRow{Index: len(rows), Baseline: len(stored) == 0 && n == 0, Rules: opts})
	}
	return map[string]any{
		"rows":    rows,
		"stored":  len(stored),
		"base":    ui2AuthzDigest(stored),
		"note":    note,
		"more":    len(rows) - len(stored) + 1,
		"canMore": len(rows) < maxAuthzIdentities,
	}
}

func (s *Server) ui2AuthzRender(w http.ResponseWriter, r *http.Request, model map[string]any) {
	ui2Fragment(w, r, "burpsy /ui2/ — Access control", "authz", ui2Exec("authz.html", model))
}

// handleUI2Authz serves GET /ui2/authz: identities editor, test form. ?add=N renders N blank rows.
func (s *Server) handleUI2Authz(w http.ResponseWriter, r *http.Request) {
	extra, _ := strconv.Atoi(r.URL.Query().Get("add"))
	s.ui2AuthzRender(w, r, s.ui2AuthzView(extra, ""))
}

// ui2AuthzHeaders parses "Name: value" lines. A line splits on LF only after CR is trimmed, so no
// value can carry a line break into the re-sent request's head.
func ui2AuthzHeaders(text string) (map[string]string, error) {
	out := map[string]string{}
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" || strings.ContainsAny(name, " \t\r") || strings.ContainsAny(value, "\r") {
			return nil, fmt.Errorf("extra headers line %d is not \"Name: value\"", n+1)
		}
		out[name] = strings.TrimSpace(value)
	}
	return out, nil
}

// ui2AuthzBuild turns the editor form into the full identities list, keeping stored secrets for
// rows whose cookie/headers fields were left blank. The summary names what changes without values.
func ui2AuthzBuild(r *http.Request, stored []authzIdentity) ([]authzIdentity, []string, error) {
	out := []authzIdentity{}
	var lines []string
	baseline := r.PostFormValue("baseline")
	keptOrig := map[int]bool{}
	for _, idx := range r.PostForm["row"] {
		if _, err := strconv.Atoi(idx); err != nil {
			return nil, nil, fmt.Errorf("row %q is not a row index", idx)
		}
		f := func(k string) string { return r.PostFormValue(k + "_" + idx) }
		var prev *authzIdentity
		if o := f("orig"); o != "" {
			n, err := strconv.Atoi(o)
			if err != nil || n < 0 || n >= len(stored) || keptOrig[n] {
				return nil, nil, fmt.Errorf("row %s names a stored identity this page did not list - reload", idx)
			}
			keptOrig[n] = true
			prev = &stored[n]
		}
		label := strings.TrimSpace(f("label"))
		cookie := f("cookie")
		headersText := f("headers")
		if f("remove") != "" {
			if prev != nil {
				lines = append(lines, fmt.Sprintf("remove %q", prev.Label))
			}
			continue
		}
		if prev == nil && label == "" && cookie == "" && strings.TrimSpace(headersText) == "" && f("rule") == "" {
			continue // an untouched blank row
		}
		if strings.ContainsAny(cookie, "\r\n") {
			return nil, nil, fmt.Errorf("the cookie for %q contains a line break", label)
		}
		id := authzIdentity{Label: label, Baseline: baseline == idx, StripCookie: f("strip") != "", Headers: map[string]string{}}
		cookieNote := "captured cookie unchanged"
		switch {
		case cookie != "":
			id.Cookie = cookie
			cookieNote = fmt.Sprintf("new cookie (%d chars)", len(cookie))
		case prev != nil && f("cookie_clear") == "" && prev.Cookie != "":
			id.Cookie = prev.Cookie
			cookieNote = fmt.Sprintf("stored cookie kept (%d chars)", len(prev.Cookie))
		}
		switch {
		case strings.TrimSpace(headersText) != "":
			h, err := ui2AuthzHeaders(headersText)
			if err != nil {
				return nil, nil, err
			}
			id.Headers = h
		case prev != nil && f("headers_clear") == "":
			for k, v := range prev.Headers {
				id.Headers[k] = v
			}
		}
		if raw := f("rule"); raw != "" {
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("session rule %q is not a rule id", raw)
			}
			id.SessionRuleID = &n
			cookieNote = fmt.Sprintf("cookie from session rule %d's jar (logged in before the test)", n)
		}
		if id.StripCookie && id.SessionRuleID == nil {
			cookieNote = "Cookie header stripped (no auth)"
		}
		names := make([]string, 0, len(id.Headers))
		for n := range id.Headers {
			names = append(names, n)
		}
		sort.Strings(names)
		role := ""
		if id.Baseline {
			role = " [baseline]"
		}
		verb := "keep"
		if prev == nil {
			verb = "add"
		}
		lines = append(lines, fmt.Sprintf("%s %q%s: %s; headers: %s", verb, id.Label, role, cookieNote, ui2AuthzNames(names)))
		out = append(out, id)
	}
	return out, lines, nil
}

func ui2AuthzNames(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// ui2AuthzProjection renders the held PUT body for review with every cookie and header value
// withheld; the run step dispatches the unredacted held bytes.
func ui2AuthzProjection(body []byte) string {
	var req authzIdentitiesReq
	if err := json.Unmarshal(body, &req); err != nil {
		return "PUT /api/authz/identities\n(unreadable body)"
	}
	for i := range req.Identities {
		id := &req.Identities[i]
		if id.Cookie != "" {
			id.Cookie = redactedValue
		}
		red := map[string]string{}
		for k := range id.Headers {
			red[k] = redactedValue
		}
		id.Headers = red
	}
	pretty, _ := json.MarshalIndent(req, "", "  ")
	return "PUT /api/authz/identities\n" + string(pretty)
}

func (s *Server) ui2AuthzConfirmPage(w http.ResponseWriter, r *http.Request, model map[string]any) {
	ui2Fragment(w, r, "burpsy /ui2/ — Access control", "authz", ui2Exec("authz_confirm.html", model))
}

// handleUI2AuthzIdentities serves POST /ui2/authz/identities/{confirm|run}.
func (s *Server) handleUI2AuthzIdentities(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	switch r.PathValue("action") {
	case "confirm":
		s.ui2AuthzIdentitiesConfirm(w, r)
	case "run":
		s.ui2AuthzIdentitiesRun(w, r)
	default:
		http.Error(w, "unknown identities action", http.StatusBadRequest)
	}
}

func (s *Server) ui2AuthzIdentitiesConfirm(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) { s.ui2AuthzConfirmPage(w, r, map[string]any{"error": msg}) }
	stored := s.ui2AuthzStored()
	base := ui2AuthzDigest(stored)
	if r.PostFormValue("base") != base {
		fail("the saved identities changed since this form opened - reload before saving")
		return
	}
	ids, lines, err := ui2AuthzBuild(r, stored)
	if err != nil {
		fail(err.Error())
		return
	}
	body, _ := json.Marshal(authzIdentitiesReq{Identities: ids})
	var gateToken string
	if _, risk, _ := routeRiskFor("/api/authz/identities"); needsConfirmation(risk) {
		tok, _, errText := s.ui2MintConfirm("/api/authz/identities", http.MethodPut, "/api/authz/identities", body)
		if errText != "" {
			fail(errText)
			return
		}
		gateToken = tok
	}
	reviewID, err1 := randomHex(16)
	nonce, err2 := randomHex(16)
	if err1 != nil || err2 != nil {
		fail("could not mint a review id")
		return
	}
	now := time.Now()
	count := 0
	s.ui2AuthzReviews.Range(func(k, v any) bool {
		if e, ok := v.(ui2AuthzReview); ok && now.After(e.expires) {
			s.ui2AuthzReviews.Delete(k)
		} else {
			count++
		}
		return true
	})
	if count >= ui2AuthzReviewCap {
		fail("too many reviews are open at once - confirm or let some expire, then try again")
		return
	}
	s.ui2AuthzReviews.Store(reviewID, ui2AuthzReview{nonce: nonce, body: body, base: base, gateToken: gateToken, expires: now.Add(ConfirmTTL)})
	s.ui2AuthzConfirmPage(w, r, map[string]any{
		"kind":      "identities",
		"summary":   lines,
		"preview":   ui2AuthzProjection(body),
		"review_id": reviewID,
		"token":     nonce,
	})
}

func (s *Server) ui2AuthzIdentitiesRun(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) { s.ui2AuthzRender(w, r, s.ui2AuthzView(0, "Not saved: "+msg)) }
	v, ok := s.ui2AuthzReviews.LoadAndDelete(r.PostFormValue("review_id"))
	entry, isEntry := v.(ui2AuthzReview)
	if !ok || !isEntry {
		fail("that review is unknown or was already used - review again")
		return
	}
	if time.Now().After(entry.expires) {
		fail("that review expired - review again")
		return
	}
	if subtle.ConstantTimeCompare([]byte(entry.nonce), []byte(r.PostFormValue("token"))) != 1 {
		fail("that review does not match this confirmation - review again")
		return
	}
	if ui2AuthzDigest(s.ui2AuthzStored()) != entry.base {
		fail("the saved identities changed since the review - nothing was written; review again")
		return
	}
	req := newReq(http.MethodPut, "/api/authz/identities")
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(strings.NewReader(string(entry.body)))
	if entry.gateToken != "" {
		req.Header.Set(ConfirmHeader, entry.gateToken)
	}
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "http://127.0.0.1")
	rec := newRecorder()
	s.guarded.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		fail(truncateForDisplay(ui2APIErrorText(strings.TrimSpace(rec.Body.String())), 300))
		return
	}
	s.ui2AuthzRender(w, r, s.ui2AuthzView(0, "identities saved"))
}

// ui2AuthzTestBody builds the /api/authz/test body from the form; confirm and run both call it,
// so the run dispatches exactly the bytes the token was minted for.
func ui2AuthzTestBody(r *http.Request) (authzTestReq, error) {
	id, err := strconv.ParseUint(strings.TrimSpace(r.PostFormValue("exchange_id")), 10, 64)
	if err != nil {
		return authzTestReq{}, fmt.Errorf("enter the exchange id to test (a whole number from HTTP history)")
	}
	samples := 0
	if raw := strings.TrimSpace(r.PostFormValue("samples")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 20 {
			return authzTestReq{}, fmt.Errorf("baseline samples must be 1-20")
		}
		samples = n
	}
	return authzTestReq{ExchangeID: core.ExchangeID(id), Samples: samples}, nil
}

// handleUI2AuthzTest serves POST /ui2/authz/test/{confirm|run}.
func (s *Server) handleUI2AuthzTest(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	action := r.PathValue("action")
	if action != "confirm" && action != "run" {
		http.Error(w, "unknown test action", http.StatusBadRequest)
		return
	}
	body, err := ui2AuthzTestBody(r)
	if err != nil {
		s.ui2AuthzConfirmPage(w, r, map[string]any{"error": err.Error()})
		return
	}
	if action == "run" {
		res, errText := s.ui2DispatchConfirmed(http.MethodPost, "/api/authz/test", body, r.PostFormValue("token"))
		model := s.ui2AuthzView(0, "")
		model["exchange_id"] = uint64(body.ExchangeID)
		if errText != "" {
			model["test_error"] = ui2APIErrorText(errText)
		} else {
			model["verdicts"] = ui2AuthzVerdictRows(res)
		}
		s.ui2AuthzRender(w, r, model)
		return
	}
	payload, _ := json.Marshal(body)
	ex, exErr := s.store.GetExchange(body.ExchangeID)
	if exErr != nil {
		s.ui2AuthzConfirmPage(w, r, map[string]any{"error": fmt.Sprintf("no exchange %d", body.ExchangeID)})
		return
	}
	token, _, errText := s.ui2MintConfirm("/api/authz/test", http.MethodPost, "/api/authz/test", payload)
	if errText != "" {
		s.ui2AuthzConfirmPage(w, r, map[string]any{"error": errText})
		return
	}
	stored := s.ui2AuthzStored()
	samples := body.Samples
	if samples == 0 {
		samples = 5
	}
	lines := []string{fmt.Sprintf("Re-send exchange %d (%s %s%s) to its target under each saved identity: the baseline %d times for calibration, every other identity once - about %d requests.",
		body.ExchangeID, ex.Method, ex.Host, ex.Path, samples, samples+max(len(stored)-1, 0))}
	for _, id := range stored {
		names := make([]string, 0, len(id.Headers))
		for n := range id.Headers {
			names = append(names, n)
		}
		sort.Strings(names)
		cookie := "captured cookie"
		switch {
		case id.SessionRuleID != nil:
			cookie = fmt.Sprintf("cookie from session rule %d", *id.SessionRuleID)
		case id.StripCookie:
			cookie = "no cookie"
		case id.Cookie != "":
			cookie = fmt.Sprintf("stored cookie (%d chars, withheld)", len(id.Cookie))
		}
		role := ""
		if id.Baseline {
			role = " [baseline]"
		}
		lines = append(lines, fmt.Sprintf("%q%s: %s; headers: %s", id.Label, role, cookie, ui2AuthzNames(names)))
	}
	s.ui2AuthzConfirmPage(w, r, map[string]any{
		"kind":        "test",
		"summary":     lines,
		"preview":     "POST /api/authz/test\n" + string(payload),
		"token":       token,
		"exchange_id": uint64(body.ExchangeID),
		"samples":     r.PostFormValue("samples"),
	})
}

// ui2AuthzVerdictRows decodes the test result and links each non-baseline row to a Comparer diff
// of its stored response against the baseline's.
func ui2AuthzVerdictRows(res any) []ui2AuthzVerdictRow {
	raw, _ := json.Marshal(res)
	var out struct {
		Verdicts []authzVerdict `json:"verdicts"`
	}
	_ = json.NewDecoder(bytes.NewReader(raw)).Decode(&out)
	var base *uint64
	for _, v := range out.Verdicts {
		if v.Verdict == "Baseline" && v.ResponseID != nil {
			base = v.ResponseID
		}
	}
	rows := make([]ui2AuthzVerdictRow, 0, len(out.Verdicts))
	for _, v := range out.Verdicts {
		row := ui2AuthzVerdictRow{authzVerdict: v, Why: v.Error}
		if row.Why == "" {
			row.Why = strings.Join(v.Reasons, "; ")
		}
		if v.Verdict != "Baseline" && base != nil && v.ResponseID != nil {
			row.Diff = fmt.Sprintf("/ui2/authz/diff/%d/%d", *base, *v.ResponseID)
		}
		rows = append(rows, row)
	}
	return rows
}

// handleUI2AuthzDiff serves GET /ui2/authz/diff/{a}/{b}: the Comparer seeded with two stored
// messages (baseline response vs one identity's), diffed through /api/tools/compare.
func (s *Server) handleUI2AuthzDiff(w http.ResponseWriter, r *http.Request) {
	a, errA := strconv.ParseUint(r.PathValue("a"), 10, 64)
	b, errB := strconv.ParseUint(r.PathValue("b"), 10, 64)
	if errA != nil || errB != nil {
		http.Error(w, "message ids must be whole numbers", http.StatusBadRequest)
		return
	}
	ma, errA := s.store.Get(core.MsgId(a))
	mb, errB := s.store.Get(core.MsgId(b))
	if errA != nil || errB != nil {
		http.Error(w, "message not found", http.StatusNotFound)
		return
	}
	ra := strings.ToValidUTF8(string(ma.Raw()), "�")
	rb := strings.ToValidUTF8(string(mb.Raw()), "�")
	s.ui2CmpRenderTexts(w, r, "", "response", fmt.Sprintf("message %d", a), ra, fmt.Sprintf("message %d", b), rb)
}
