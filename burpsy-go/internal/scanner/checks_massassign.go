package scanner

// Mass assignment (burpsy-react-ui-0vzb.46 slice 3): a create/update request is replayed with a
// privileged field added - one the object's own READ answer names but the request never carried -
// and a finding stands only when a fresh re-read of the object shows the field persisted with the
// injected canary value. The write is a state change, so the pass runs only under BOTH
// CheckMassAssignment and the explicit writes opt-in CheckAPIWrites.
//
// Field discovery from the audited response is this slice; the OpenAPI schema source the bead
// also names is follow-up work. String-valued fields only: a canary must survive the round trip
// typed, and injecting a string into a numeric or boolean field would test the binder's error
// handling, not its allow-list.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// maPrivilegedFields are the lower-cased JSON field names a binder must never accept from a
// client. Tight on purpose: names that merely SOUND administrative ("owner", "type") false-fire
// on ordinary domain fields.
var maPrivilegedFields = map[string]bool{
	"role": true, "roles": true, "admin": true, "isadmin": true, "is_admin": true,
	"permissions": true, "permission": true, "scope": true, "scopes": true,
	"usertype": true, "user_type": true, "verified": true,
}

// maCanary mints an unpredictable marker value for one injection attempt.
func maCanary() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "burpsy-ma-fixed"
	}
	return "burpsy-ma-" + hex.EncodeToString(b[:])
}

// maEnabled gates the pass on its switch AND the writes opt-in, either alone is not enough.
func maEnabled(c *ScanConfig) bool { return c != nil && c.CheckMassAssignment && c.CheckAPIWrites }

// maSwitchOn reports only the switch, for the descriptor predicate: the descriptor must admit the
// exchange so the writes gate's silence is the check's own decision, visible in its doc comment.
func maSwitchOn(c *ScanConfig) bool { return c != nil && c.CheckMassAssignment }

// maCandidates names the privileged string fields the response carries and the request does not.
func maCandidates(respBody, reqBody string) []string {
	var resp, req map[string]any
	if json.Unmarshal([]byte(respBody), &resp) != nil || json.Unmarshal([]byte(reqBody), &req) != nil {
		return nil
	}
	var out []string
	for k, v := range resp {
		if _, isString := v.(string); !isString {
			continue
		}
		if !maPrivilegedFields[strings.ToLower(k)] {
			continue
		}
		if _, carried := req[k]; carried {
			continue
		}
		out = append(out, k)
	}
	return out
}

// maRebuiltRequest returns raw with its JSON body replaced by body and Content-Length adjusted.
func maRebuiltRequest(raw string, body []byte) string {
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	out := []string{lines[0]}
	for _, line := range lines[1:] {
		name, _, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "content-length") {
			continue
		}
		out = append(out, line)
	}
	out = append(out, "Content-Length: "+strconv.Itoa(len(body)))
	return strings.Join(out, "\r\n") + "\r\n\r\n" + string(body)
}

// maReadRequest rewrites raw as a GET of the same path with no body, for the re-read.
func maReadRequest(raw string) string {
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) != 3 {
		return ""
	}
	out := []string{"GET " + parts[1] + " " + parts[2]}
	for _, line := range lines[1:] {
		name, _, ok := strings.Cut(line, ":")
		if ok && (strings.EqualFold(strings.TrimSpace(name), "content-length") ||
			strings.EqualFold(strings.TrimSpace(name), "content-type")) {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\r\n") + "\r\n\r\n"
}

// maFieldReads reports what a JSON body carries at field, and whether it parses as an object.
func maFieldReads(body, field string) (string, bool) {
	var m map[string]any
	if json.Unmarshal([]byte(body), &m) != nil {
		return "", false
	}
	v, ok := m[field].(string)
	return v, ok
}

func checkMassAssignment(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	if !maEnabled(cc.Config) {
		return nil, nil
	}
	m := strings.ToUpper(cc.Exchange.Method)
	if m != "POST" && m != "PUT" && m != "PATCH" {
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" || !idorHasCredentials(raw) {
		return nil, nil
	}
	_, reqBody, hasBody := strings.Cut(raw, "\r\n\r\n")
	if !hasBody || !strings.Contains(strings.ToLower(raw), "content-type: application/json") {
		return nil, nil
	}
	h, err := NewProbeHarness(ctx, cc, []string{"body"})
	if err != nil {
		return nil, fmt.Errorf("mass-assignment: %w", err)
	}
	base := h.Baseline()
	if base.Status < 200 || base.Status > 299 {
		return nil, nil
	}
	cands := maCandidates(base.Body, reqBody)
	if len(cands) == 0 {
		return nil, nil
	}
	field := cands[0]
	readRaw := maReadRequest(raw)
	if readRaw == "" {
		return nil, nil
	}
	// Pre-read: the object before any injection, so persistence is measured against something.
	pre, err := h.send(ctx, []byte(readRaw))
	if err != nil {
		return nil, err
	}
	if pre.Status < 200 || pre.Status > 299 {
		return nil, nil
	}
	// The anonymous write control: a create/update anyone can run is not a binder failure.
	nr, err := h.send(ctx, []byte(maRebuiltRequest(idorAnonymous(raw, nil), []byte(reqBody))))
	if err != nil {
		return nil, err
	}
	if nr.Status >= 200 && nr.Status <= 299 {
		return nil, nil
	}
	var req map[string]any
	if json.Unmarshal([]byte(reqBody), &req) != nil {
		return nil, nil
	}
	var firstCanary, secondCanary string
	var wr, reread ProbeResponse
	for attempt := 0; attempt < 2; attempt++ {
		canary := maCanary()
		req[field] = canary
		body, err := json.Marshal(req)
		if err != nil {
			return nil, nil
		}
		wr, err = h.send(ctx, []byte(maRebuiltRequest(raw, body)))
		if err != nil {
			return nil, err
		}
		if wr.Status < 200 || wr.Status > 299 {
			return nil, nil
		}
		re, err := h.send(ctx, []byte(readRaw))
		if err != nil {
			return nil, err
		}
		got, ok := maFieldReads(re.Body, field)
		if !ok || got != canary {
			if attempt == 0 {
				return nil, nil // the first write did not persist: no point repeating
			}
			return nil, nil // the repeat disagreed: unstable, nothing claimed
		}
		if attempt == 0 {
			firstCanary = canary
		} else {
			secondCanary, reread = canary, re
		}
	}
	detail := fmt.Sprintf("The update request's answer names %q, a field the request itself never "+
		"carries. Replaying the request with %q added and set to a canary returned HTTP %d, and a "+
		"fresh GET of the same object then showed %q holding the canary: the server binds a "+
		"client-supplied value into a field it manages itself. The injection was repeated with a "+
		"second canary (%q, then %q) and persisted both times. Controls: the pre-injection read "+
		"carried no canary, and the same write with every credential removed returned HTTP %d.",
		field, field, wr.Status, field, firstCanary, secondCanary, nr.Status)
	f := buildHeaderFinding(cc, "Broken access control", "high", "firm",
		fmt.Sprintf("injected %q persisted and re-read, %s", field, maCanaryExcerpt(reread.Body, secondCanary)), detail)
	f.Param = field
	f.Solution = "Bind incoming data to an explicit allow-list of client-writable fields on the " +
		"server, or map the body onto a request type that has no privileged members. Never persist " +
		"fields the request was not meant to carry, and keep server-managed fields such as roles " +
		"out of the deserialised model's settable surface."
	return []*Finding{f}, nil
}

// maCanaryExcerpt quotes the re-read body around the canary it holds, so the evidence shows the
// persisted value rather than the start of the document.
func maCanaryExcerpt(body, canary string) string {
	if i := strings.Index(body, canary); i >= 0 {
		return excerpt(body, i, len(canary))
	}
	return excerpt(body, 0, 160)
}
