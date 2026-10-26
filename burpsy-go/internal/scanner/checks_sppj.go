package scanner

// Server-side prototype pollution, non-destructive JSON techniques (burpsy-react-ui-0vzb.3).
//
// A JSON API whose settings merge keeps a posted "__proto__" member pollutes the server-side
// object prototype every later serialisation reads. The probes are the two benign properties
// PortSwigger's research demonstrates (portswigger.net/research/server-side-prototype-pollution):
//
//   - {"__proto__":{"json spaces":10}} — the response to a later request is re-serialised with
//     ten-space indentation where the baseline was compact;
//   - {"__proto__":{"status":510}} — the endpoint's ERROR answer afterwards carries 510.
//
// Both are pollution of behaviour, not of data, and both REVERT: after the technique answers, the
// check posts the null form ({"__proto__":{"json spaces":null}} / {"status":null}) and confirms
// the default is back, so the finding can say the target was left as it was found.
//
// The evidence bar mirrors the rest of this package: a fresh baseline must differ from the
// polluted response in the named way, the polluted response must reproduce once, and the revert
// must restore the baseline. Anything less is silence, not a weaker finding.
//
// Only captured JSON-object bodies are probed, and only behind CheckServerSidePrototypePollution
// (off by default): the probe replays the application's own POST once per technique, and on a
// state-changing endpoint that replay is the operator's to authorise.

import (
	"context"
	"fmt"
	"strings"
)

// IssueServerSidePrototypePollution is burpsy's own row; see BurpsyNativeRows.
const IssueServerSidePrototypePollution = "Server-side prototype pollution"

// sppjEnabled is the check's own switch.
func sppjEnabled(c *ScanConfig) bool { return c != nil && c.CheckServerSidePrototypePollution }

// sppjWithProto returns the captured JSON object body with the given __proto__ member merged in,
// or "" when the body is not a JSON object.
func sppjWithProto(body, protoMember string) string {
	t := strings.TrimSpace(body)
	if len(t) < 2 || t[0] != '{' || t[len(t)-1] != '}' {
		return ""
	}
	inner := strings.TrimSpace(t[1 : len(t)-1])
	if inner == "" {
		return `{"__proto__":` + protoMember + `}`
	}
	return t[:len(t)-1] + `,"__proto__":` + protoMember + `}`
}

// sppjRawWithBody rewrites the captured request with a new JSON body, fixing Content-Length.
func sppjRawWithBody(raw, body string) string {
	head, _, ok := strings.Cut(raw, "\r\n\r\n")
	if !ok {
		return ""
	}
	out := rawSetHeader(head+"\r\n\r\n", "Content-Length", fmt.Sprintf("%d", len(body)))
	return out + body
}

// sppjIndented reports whether the body is JSON serialised with ten-space indentation.
func sppjIndented(body string) bool {
	return strings.Contains(body, "\n          \"")
}

// checkServerSidePrototypePollution runs the two techniques against one captured JSON request.
func checkServerSidePrototypePollution(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" {
		return nil, nil
	}
	head, body, ok := strings.Cut(raw, "\r\n\r\n")
	if !ok || !strings.Contains(strings.ToLower(head), "application/json") {
		return nil, nil
	}
	if sppjWithProto(body, `{"json spaces":10}`) == "" {
		return nil, nil
	}
	h, err := NewProbeHarness(ctx, cc, []string{"body"})
	if err != nil {
		return nil, fmt.Errorf("server-side prototype pollution: %w", err)
	}
	send := func(rawBody string) (ProbeResponse, error) {
		return h.send(ctx, []byte(sppjRawWithBody(raw, rawBody)))
	}
	base := h.Baseline()

	// Technique 1: json spaces. The polluted response — or the plain request right after the
	// polluting one — comes back re-serialised with the ten-space indent.
	finding, err := func() (*Finding, error) {
		probe, err := send(sppjWithProto(body, `{"json spaces":10}`))
		if err != nil {
			return nil, err
		}
		wasIndented := sppjIndented(probe.Body)
		if !wasIndented {
			after, err := h.send(ctx, []byte(raw))
			if err != nil {
				return nil, err
			}
			wasIndented = sppjIndented(after.Body)
		}
		_, rerr := send(sppjWithProto(body, `{"json spaces":null}`))
		if !wasIndented {
			// The pollution never showed; a revert that moved the shape anyway is noise, not evidence.
			return nil, nil
		}
		if rerr != nil {
			return nil, rerr
		}
		confirm, err := h.send(ctx, []byte(raw))
		if err != nil {
			return nil, err
		}
		if sppjIndented(confirm.Body) {
			// The indent survived the revert: either the revert failed (still polluted — say so)
			// or the shape was never the pollution's doing. Neither is a clean finding.
			return nil, nil
		}
		evidence := "baseline: compact JSON\nPOST with __proto__ json spaces=10: indented with 10 spaces\nPOST with __proto__ json spaces=null: compact again"
		detail := "The endpoint merges a posted JSON body into server-side settings without dropping " +
			"__proto__: a {\"__proto__\":{\"json spaces\":10}} member re-serialised this endpoint's JSON " +
			"responses with ten-space indentation, and a null member reverted it. The property reached " +
			"the server-side object prototype every object inherits, which is server-side prototype " +
			"pollution; an attacker who finds a readable behaviour of the prototype can turn it into " +
			"full control of response shape or status."
		f := buildHeaderFinding(cc, IssueServerSidePrototypePollution, "high", "firm", evidence, detail)
		f.Param = "__proto__.json spaces"
		return f, nil
	}()
	if err != nil {
		return nil, fmt.Errorf("server-side prototype pollution: %w", err)
	}
	if finding != nil {
		return []*Finding{finding}, nil
	}

	// Technique 2: status override. Pollute, then answer the error path (a body that is not JSON);
	// a 510 where the baseline error was 400 is the proof. Revert with null.
	pollute, err := send(sppjWithProto(body, `{"status":510}`))
	if err != nil {
		return nil, fmt.Errorf("server-side prototype pollution: %w", err)
	}
	_ = pollute
	errResp, err := send("not json")
	if err != nil {
		return nil, fmt.Errorf("server-side prototype pollution: %w", err)
	}
	reverted, rerr := send(sppjWithProto(body, `{"status":null}`))
	errAfter, aerr := send("not json")
	if errResp.Status == 510 && (rerr == nil && aerr == nil && errAfter.Status != 510 && reverted.Status != 510) {
		evidence := fmt.Sprintf("baseline error: HTTP %d\nPOST with __proto__ status=510, then bad body: HTTP 510\nPOST with __proto__ status=null, then bad body: HTTP %d",
			base.Status, errAfter.Status)
		detail := "The endpoint merges a posted JSON body into server-side settings without dropping " +
			"__proto__: a {\"__proto__\":{\"status\":510}} member made the endpoint's error answers carry " +
			"HTTP 510, and a null member reverted it. The property reached the server-side object " +
			"prototype, which is server-side prototype pollution."
		f := buildHeaderFinding(cc, IssueServerSidePrototypePollution, "high", "firm", evidence, detail)
		f.Param = "__proto__.status"
		return []*Finding{f}, nil
	}
	return nil, nil
}

// withServerSidePrototypePollution adds this check to the runner of the descriptor it rides
// ("Client-side prototype pollution", the DOM row whose server-side counterpart this is).
func withServerSidePrototypePollution(inner CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil {
			return nil, nil
		}
		innerF, innerErr := inner(ctx, cc)
		var spF []*Finding
		var spErr error
		if sppjEnabled(cc.Config) {
			spF, spErr = checkServerSidePrototypePollution(ctx, cc)
		}
		out := append(innerF, spF...)
		switch {
		case len(spF) > 0:
			return out, nil
		case innerErr != nil:
			return innerF, innerErr
		case spErr != nil:
			return innerF, spErr
		}
		return out, nil
	}
}
