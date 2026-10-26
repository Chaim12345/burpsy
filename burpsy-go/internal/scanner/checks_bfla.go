package scanner

// Broken function-level authorization (burpsy-react-ui-0vzb.46 slice 2): the audited request is
// the administrator's own call to a privileged operation; the check replays it under the
// configured second, low-privilege identity. Being served the operation proves the function is
// not role-enforced, with no object-reference ambiguity: B asked for exactly what A asked for.
//
// GET/HEAD exchanges are replayed under CheckBFLA alone. A state-changing admin operation (POST, PUT
// or PATCH) is replayed too, but that is a WRITE on the target, so it needs the explicit writes
// opt-in CheckAPIWrites on top. DELETE is never replayed: a destructive probe is not worth the
// damage a role check could do. The second identity's write is sent once, not repeated for
// stability: a second write would apply the change twice. The captured write still reaches the
// target up to three times in all - the harness baseline (as the audited identity), the second
// identity's replay, and the anonymous control - so a create with a uniqueness rule can answer the
// baseline with a conflict, and the pass then has nothing to compare. A write is reported only when
// the second identity's answer matches the audited identity's VALUE for value, not just in shape:
// a 200 refusal envelope ({"success":false,...}) has the success answer's shape.

import (
	"context"
	"fmt"
	"strings"
)

// bflaAdminWords mark a path segment as a privileged operation's. Tight on purpose: a loose list
// turns the pass into a wordlist spray.
var bflaAdminWords = map[string]bool{
	"admin": true, "administrator": true, "backoffice": true,
}

// bflaAdminPath reports whether any segment of path names a privileged operation.
func bflaAdminPath(path string) bool {
	for _, seg := range strings.Split(strings.ToLower(path), "/") {
		if bflaAdminWords[seg] {
			return true
		}
	}
	return false
}

// bflaWriteMethod reports the state-changing methods the pass may replay under the writes opt-in.
func bflaWriteMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
}

// bflaEnabled admits the descriptor when the switch is on.
func bflaEnabled(c *ScanConfig) bool { return c != nil && c.CheckBFLA }

// bflaIdentity returns the configured second identity when the BFLA switch admitted it, else nil.
func bflaIdentity(c *ScanConfig) *SecondIdentity {
	if c == nil || !c.CheckBFLA {
		return nil
	}
	sec := &c.SecondIdentity
	if sec.CookieHeader == "" && sec.AuthorizationHeader == "" && (sec.APIKeyHeader == "" || sec.APIKeyValue == "") {
		return nil
	}
	return sec
}

func checkBFLA(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	sec := bflaIdentity(cc.Config)
	if sec == nil {
		return nil, nil
	}
	write := bflaWriteMethod(cc.Exchange.Method)
	if !write && !strings.EqualFold(cc.Exchange.Method, "GET") && !strings.EqualFold(cc.Exchange.Method, "HEAD") {
		return nil, nil
	}
	if write && !cc.Config.CheckAPIWrites {
		return nil, nil // a write probe needs the explicit writes opt-in; without it, send nothing
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" || !idorHasCredentials(raw) {
		return nil, nil
	}
	if !bflaAdminPath(cc.Exchange.Path) {
		return nil, nil
	}
	h, err := NewProbeHarness(ctx, cc, []string{"header"})
	if err != nil {
		return nil, fmt.Errorf("bfla: %w", err)
	}
	base := h.Baseline()
	if base.Status < 200 || base.Status > 299 {
		return nil, nil // the audited identity itself is refused: nothing about B to learn
	}
	ashape := idorShapeOf(base.Body)
	if ashape == nil {
		return nil, nil
	}
	braw, covered := idorReidentity(raw, sec)
	if !covered {
		return nil, nil
	}
	br, err := h.send(ctx, []byte(braw))
	if err != nil {
		return nil, err
	}
	if br.Status < 200 || br.Status > 299 || !ashape.same(idorShapeOf(br.Body)) {
		return nil, nil // B was refused, or answered with a different shape (an error body)
	}
	if write && !bflaSameValues(ashape, idorShapeOf(br.Body)) {
		return nil, nil // same shape, different answer: a refusal dressed as the success envelope
	}
	// The anonymous control: a privileged operation anyone can invoke is a finding of another
	// kind, already the session-comparison row's business - and not a ROLE failure.
	nr, err := h.send(ctx, []byte(idorAnonymous(raw, nil)))
	if err != nil {
		return nil, err
	}
	if nr.Status >= 200 && nr.Status <= 299 && ashape.same(idorShapeOf(nr.Body)) {
		return nil, nil
	}
	// Stability: the cross-read repeated must answer the same way. Never for a write: repeating it
	// would apply the change a second time.
	againStatus := br.Status
	if !write {
		again, err := h.send(ctx, []byte(braw))
		if err != nil {
			return nil, err
		}
		if again.Status != br.Status || !ashape.same(idorShapeOf(again.Body)) {
			return nil, nil
		}
		againStatus = again.Status
	}
	detail := fmt.Sprintf("The request as captured invokes a privileged operation (%s %s) as the "+
		"audited identity. Replayed under a second configured identity - a low-privilege account on "+
		"the same application - it returned HTTP %d with the same response structure: the operation "+
		"is served regardless of role. Controls: the same request with every credential removed "+
		"returned HTTP %d, and the second-identity replay repeated returned HTTP %d again.",
		cc.Exchange.Method, cc.Exchange.Path, br.Status, nr.Status, againStatus)
	if write {
		detail = fmt.Sprintf("The request as captured is a state-changing call to a privileged operation "+
			"(%s %s) made as the audited identity. Replayed once under a second configured identity - a "+
			"low-privilege account on the same application - it returned HTTP %d with the same response "+
			"structure and the same values as the audited identity's own write: the operation accepted the "+
			"write regardless of role. Control: the same request with every credential removed returned HTTP %d. "+
			"Not repeated for stability, because a second write would change state again.",
			cc.Exchange.Method, cc.Exchange.Path, br.Status, nr.Status)
	}
	f := buildHeaderFinding(cc, "Broken access control", "high", "firm",
		fmt.Sprintf("second identity replay of %s -> HTTP %d, %s", cc.Exchange.Path, br.Status,
			excerpt(br.Body, 0, 160)), detail)
	f.Solution = "Enforce the required role for every privileged operation on the server, at the " +
		"operation itself rather than by hiding it in the interface: deny any session whose account " +
		"lacks the role, whatever path or method the request uses."
	return []*Finding{f}, nil
}

// bflaSameValues reports whether two answers match value for value: every JSON leaf equal, or the
// same document for any other body. A write's answer is usually a small status envelope, where the
// shape alone cannot tell "saved" from "denied".
func bflaSameValues(a, b *idorShape) bool {
	if a == nil || b == nil || a.kind != b.kind {
		return false
	}
	if a.kind != "json" {
		return strings.TrimSpace(a.body) == strings.TrimSpace(b.body)
	}
	if len(a.leaves) != len(b.leaves) {
		return false
	}
	for k, v := range a.leaves {
		if w, ok := b.leaves[k]; !ok || w != v {
			return false
		}
	}
	return true
}
