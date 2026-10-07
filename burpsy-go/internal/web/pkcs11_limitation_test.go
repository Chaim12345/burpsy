package web

// The PKCS#11 limitation must stay VISIBLE (burpsy-react-ui-m7ld).
//
// # Why this test exists at all
//
// The bead's acceptance criterion is "either a PKCS#11 source behind an optional build tag, or a
// declined row in the client-certificate UI naming the cgo and signing-operation constraints — and a
// test that the UI names the limitation, so the silent half cannot return."
//
// Both halves of the second option already exist, and that is exactly why they need a test: a
// limitation that is DECLARED everywhere is the state that is easy to lose. Someone tidying the wire
// shape drops `pkcs11_supported` as a field that "is always false", the panel's `data && !data.
// pkcs11_supported` condition then never fires, and the operator is left with a certificate panel that
// silently lacks the option — indistinguishable from a build that never considered it. The field
// vanishing is not a failure anything else detects, because nothing else reads it.
//
// # What is asserted, and what is deliberately not
//
// Three things, each about a different way the limitation can go missing:
//
//  1. The API still carries the field, and it is FALSE. Not omitted: `false` and absent are different
//     on the wire, and only the present-false one can drive a panel that says so.
//  2. The panel's source still renders the notice — asserted by READING THE TSX SOURCE, because the
//     condition is a JSX boolean that no Go test can evaluate.
//  3. The notice names WHY, so it is a limitation an operator can act on rather than a bare "not
//     supported".
//
// Not asserted: that PKCS#11 works. It does not, deliberately (internal/netauth/clientcert.go:19-34:
// cgo to a vendor .so, and signing that has to happen inside the token, which cannot reuse the
// tls.Certificate path at all). A test asserting support would be asserting the opposite of the
// decision the bead records, and the bead is explicitly decision-needed.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The field is present and false — not omitted, because a panel that finds it absent cannot say so.
func Test_the_client_cert_api_states_that_pkcs11_is_unsupported_rather_than_omitting_it(t *testing.T) {
	recorder := call(t, networkServer(), http.MethodGet, "/api/network/client-certs", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET answered %d: %s", recorder.Code, recorder.Body)
	}

	// Decoded as a map rather than into the response struct, because unmarshalling into the struct
	// would synthesise a false for an absent field and this test cannot tell the two apart — which is
	// the entire thing being checked.
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("the response is not a JSON object: %v", err)
	}
	raw, present := body["pkcs11_supported"]
	if !present {
		t.Fatal("the response has no pkcs11_supported field at all; a panel cannot state a " +
			"limitation it is not told about, and omitting it is how a declared gap becomes a silent one")
	}
	supported, isBool := raw.(bool)
	if !isBool {
		t.Fatalf("pkcs11_supported is %T, want a boolean", raw)
	}
	if supported {
		t.Error("the API claims PKCS#11 support, which this build does not implement — see " +
			"internal/netauth/clientcert.go for why it is out of scope rather than stubbed")
	}
}

// The panel still renders the notice, and names why.
//
// Read out of the source because the condition is a JSX boolean: `data && !data.pkcs11_supported` is
// true exactly when the API above says false, and there is no Go-side evaluation of it. Reading the
// source is the only way to catch the row being deleted, which is the failure this bead is about — and
// it is worth being explicit that this asserts PRESENCE OF THE DECLARATION, not that the panel renders
// it for a given response. The end-to-end rendering is covered by the UI pass.
func Test_the_client_certificate_panel_states_the_pkcs11_limitation_and_its_reason(t *testing.T) {
	raw := readUIFile(t, "src/pages/settings.network.tsx")

	if !strings.Contains(raw, "pkcs11_supported") {
		t.Error("the client-certificate panel no longer reads pkcs11_supported; the declined row " +
			"cannot render without it, and this is the silent half the bead says must not return")
	}

	// The NOTICE, not the whole file. This file also carries a // header comment that mentions
	// PKCS#11, and a substring search over the whole source finds THAT first — so a test that passes
	// against the deleted row. The text is therefore taken from the JSX element that renders it and
	// only that is asserted on.
	notice := jsxNotice(raw, "notice", "PKCS#11")
	if notice == "" {
		t.Fatal("the panel has no .notice element carrying the PKCS#11 declined row; the row is gone")
	}
	if !strings.Contains(notice, "PKCS#11 hardware tokens are not supported") {
		t.Error("the panel no longer states that PKCS#11 is unsupported in words the operator reads; " +
			"the notice now says: " + notice)
	}
	// The reason, not just the verdict. An operator deciding whether to file this as a gap wants to
	// know it is a vendor driver and in-token signing rather than an omission.
	for _, reason := range []string{"vendor driver", "signing has to happen inside the token"} {
		if !strings.Contains(notice, reason) {
			t.Errorf("the panel's declined row no longer names %q, so it states a limitation without "+
				"saying why — which is the part an operator acts on. Notice: %s", reason, notice)
		}
	}
	// And it must not offer the option at all: a token control that cannot open a token is worse than
	// no control, which is the reason netauth/clientcert.go gives for declaring rather than stubbing.
	if strings.Contains(raw, `value="pkcs11"`) {
		t.Error("the panel offers PKCS#11 as a selectable source value; this build cannot open a token, " +
			"and an option that always fails at the handshake is the failure the declined row exists to avoid")
	}
}

// jsxNotice returns the prose of the first element carrying a class that includes cls AND whose text
// contains mustContain, with comment markers and whitespace collapsed.
//
// Scoped to ONE element and one phrase on purpose, and both scopings were found the hard way:
//
//   - A whole-file substring search finds this project's own file-header COMMENT, which also mentions
//     PKCS#11 — so a test over the raw source passes against a row that has been deleted.
//   - This panel has SEVERAL .notice elements (the platform-auth one is the first), so matching on the
//     class alone finds the wrong one and reports a healthy row as missing.
//
// Together those mean the assertion names the element by what it SAYS, which is the only thing
// distinguishes the PKCS#11 declined row from every other notice on the page.
func jsxNotice(source, cls, mustContain string) string {
	for offset := 0; offset < len(source); {
		i := strings.Index(source[offset:], `className="`+cls)
		if i < 0 {
			return ""
		}
		i += offset
		rest := source[i:]
		var text string
		if end := strings.Index(rest, "</span>"); end >= 0 {
			text = prose(rest[:end])
		} else if end := strings.Index(rest, "</div>"); end >= 0 {
			text = prose(rest[:end])
		} else {
			text = prose(rest)
		}
		if strings.Contains(text, mustContain) {
			return text
		}
		offset = i + 1
	}
	return ""
}

// The Go side documents the same limitation in the place a reader of the package will find it, so the
// absence is a DECISION on the record rather than something only the panel knows.
func Test_the_netauth_package_documents_why_pkcs11_is_out_of_scope(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "netauth", "clientcert.go"))
	if err != nil {
		t.Fatalf("reading internal/netauth/clientcert.go: %v", err)
	}
	// Whitespace-normalised before matching, because the sentence wraps across comment lines and a
	// raw substring would fail on the wrap rather than on the fact. Asserting on prose is a choice
	// worth naming: it is why these checks name SUBSTRINGS THAT SURVIVE REWRAPPING ("cgo", "vendor
	// driver") rather than whole sentences that a harmless re-wrap would break.
	text := prose(string(source))
	for _, fact := range []string{"PKCS#11", "cgo", "signing operation has to happen inside the token"} {
		if !strings.Contains(text, fact) {
			t.Errorf("internal/netauth/clientcert.go no longer states %q; the limitation belongs in "+
				"the package that owns it, not only on a panel", fact)
		}
	}
}

// prose collapses a source file's comment markers and whitespace so a phrase can be asserted on.
//
// Both steps matter and the second is the one that surprises: collapsing whitespace alone leaves the
// "//" that Go puts at the start of every comment line interleaved with the words, so "the signing
// operation" never matches "the signing // operation". Asserting on prose needs the markers gone.
func prose(source string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(source, "//", " ")), " ")
}

// readUIFile reads one file under internal/web/ui, failing the test rather than the assertion if it
// is not where the UI tree says it is.
func readUIFile(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join("ui", rel)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(data)
}
