package session

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// MacroStepFromRequest renders a stored request's bytes as a macro step, which is what Burp's Macro
// Recorder does when the operator picks items out of the Proxy history
// (settings/sessions/macros.html: "Macros are made up of requests taken from the Proxy history […]
// Select the items you need from the Proxy history list", burpsy-react-ui-escl).
//
// # Why this lives in this package
//
// A macro step is this package's type, and its shape is this package's contract: the URL has to be
// absolute (validate.go refuses a hostless step), the headers have to be the ones the runner will
// send verbatim, and the body has to be the bytes after the head rather than anything re-encoded.
// Rendering that from raw bytes somewhere else — in the web layer, say, or in TypeScript — would put
// a second copy of the contract next to the one that validates it, and the copy is what drifts. The
// CLI's session login and the console's macro recorder therefore both call this.
//
// # What it keeps, and the one thing it deliberately does not
//
// The method and target come from the request line, the headers from the head, the body from
// everything after the blank line. The request-target is stored origin-form (`GET /path HTTP/1.1`)
// because that is what a proxy forwards — see toOriginForm's note — so the authority has to be
// supplied, and it comes from the exchange rather than being re-derived: the exchange's host, port
// and TLS are the addressing the request actually used, whereas parsing a Host header back out
// would answer a question about what the client claimed instead.
//
// The port is written into the URL only when it is not the scheme's default. That is a cosmetic
// choice with a real consequence: Burp's editor shows `https://host/path` for a 443 request, and an
// operator comparing this step against Burp's would otherwise see `:443` that Burp does not add.
// Both spellings address the same origin, so nothing about the step's behaviour depends on it.
//
// A request that is not HTTP — a WebSocket frame, a truncated capture — is refused rather than
// produced with a guessed method. Refuse-by-default on unparseable input is this project's rule
// everywhere else, and a macro step with an empty method would be a step that fails at login time
// with nothing to point at.
func MacroStepFromRequest(raw []byte, host string, port uint16, tls bool) (MacroStep, error) {
	if strings.TrimSpace(host) == "" {
		// The URL would have no authority, and validate.go refuses a hostless step anyway — but it
		// refuses it at save time, after an operator has typed a name and a scope. Naming it here
		// means the refusal arrives while they are looking at the history row that caused it.
		return MacroStep{}, fmt.Errorf("a macro step needs the exchange's host, and none was supplied")
	}
	head, body := splitRequestHeadBody(raw)
	if len(head) == 0 {
		return MacroStep{}, fmt.Errorf("the request has no request line, so there is no method or target to build a step from")
	}
	lines := strings.Split(string(head), "\r\n")
	if len(lines) == 1 {
		// Tolerate a bare-LF capture, but not a head that is one long string: without a separator
		// there is nothing to split headers on and a "header" would be invented out of the middle.
		lines = strings.Split(string(head), "\n")
	}
	parts := strings.Fields(strings.TrimSpace(lines[0]))
	if len(parts) < 2 {
		return MacroStep{}, fmt.Errorf("the request line %q names no method and target", strings.TrimSpace(lines[0]))
	}
	method, target := parts[0], parts[1]
	if target == "" || (target[0] != '/' && target[0] != '*') {
		// A stored request is origin-form or asterisk-form (an OPTIONS probe). Anything else means
		// these are not the bytes this function thinks they are, and concatenating them onto a
		// scheme and host would produce a URL pointing somewhere unintended.
		return MacroStep{}, fmt.Errorf("the request target %q is not origin-form, so it cannot be addressed against the exchange's host", target)
	}

	scheme := "http"
	if tls {
		scheme = "https"
	}
	url := scheme + "://" + hostForURL(host)
	if !isDefaultPort(scheme, port) {
		url += ":" + strconv.Itoa(int(port))
	}
	url += target

	headers := make(map[string]string, len(lines)-1)
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			// A continuation line or junk. Skipped rather than folded into the previous header:
			// obs-fold is deprecated, and guessing which header it belonged to would put a value in
			// a header the operator cannot see the origin of.
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, exists := headers[name]; exists {
			// A repeated header the map cannot hold both of. Kept first-wins rather than
			// last-wins because that is what a single-value field means, and the operator can see
			// from the history row that there were two — the step is a copy of one reading of the
			// request, not a claim that it had one header.
			continue
		}
		headers[name] = strings.TrimSpace(value)
	}

	return MacroStep{Method: strings.ToUpper(method), URL: url, Headers: headers, Body: string(body)}, nil
}

// splitRequestHeadBody splits a raw message at the blank line, returning the head without its
// terminator and the body as it stands. Both separators are accepted: every capture in this tree is
// CRLF-framed, but a request assembled by a test or a hand-written file may not be, and refusing it
// would be pedantry rather than safety.
func splitRequestHeadBody(raw []byte) (head, body []byte) {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[:i], raw[i+4:]
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return raw[:i], raw[i+2:]
	}
	// No blank line: a request with no body, or a truncated one. The whole message is head, which is
	// the honest reading — there is no body to claim.
	return raw, nil
}

// hostForURL brackets an IPv6 literal, which is the one authority a naive concatenation gets wrong:
// `http://::1:8080/path` parses as host "::1:8080", so the port is lost and the URL addresses a
// differently-named host. A scoped zone suffix (fe80::1%eth0) is preserved as captured, because
// dropping it would address a different interface's address.
func hostForURL(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

// isDefaultPort reports whether a port is the one the scheme implies, so the URL can omit it.
func isDefaultPort(scheme string, port uint16) bool {
	return (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
}
