package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Custom data and location exclusion on a minted Collaborator payload (burpsy-react-ui-80tc).
//
// Burp's generatePayload takes a custom-data string — up to 16 alphanumeric characters carried
// by the payload and recoverable from any interaction it causes — and a PayloadOption that drops
// the server location. Without the first, an operator minting five payloads for five parameters
// cannot tell which one fired: every interaction reads the same, and the finding cannot name the
// injectable parameter even though the payload proved it.
//
// These tests use the fake provider the rest of this package's collaborator tests use, so they run
// everywhere; the live-pool registration chain is covered by api_collaborator_batch_test.go.

// collaboratorWithFakeChannel wires a domain that is available immediately.
func collaboratorWithFakeChannel(t *testing.T) *Server {
	t.Helper()
	s := newTestServerWithScanner(t)
	s.wiredScanner().WithOOBProvider(&mintableOOB{domain: "oobtest.oast.example"})
	return s
}

// The claim: custom data rides the payload and comes back with it, so an interaction can be
// attributed to the parameter that carried it.
func TestCustomDataRidesTheMintedPayload(t *testing.T) {
	s := collaboratorWithFakeChannel(t)
	rec := postJSONRaw(t, s, "/api/collaborator/payload", `{"count":2,"custom_data":"userid"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint with custom data = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var out struct {
		Payloads []struct {
			Address    string `json:"address"`
			CustomData string `json:"custom_data"`
		} `json:"payloads"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}
	if len(out.Payloads) != 2 {
		t.Fatalf("mint of 2 returned %d payload rows; each payload must carry its own custom data "+
			"or a batch cannot be attributed", len(out.Payloads))
	}
	for i, p := range out.Payloads {
		if p.CustomData != "userid" {
			t.Errorf("payload %d carries custom_data %q, want %q; the value is what makes an "+
				"interaction name the parameter that caused it", i, p.CustomData, "userid")
		}
		if p.Address == "" {
			t.Errorf("payload %d has no address", i)
		}
	}
	// And it reaches the STATUS view, which is what the page actually renders. A value the mint
	// returns but the payload list cannot show is not usable for attribution.
	rows := hubPayloads(t, s)
	found := false
	for _, row := range rows {
		if row["custom_data"] == "userid" {
			found = true
		}
	}
	if !found {
		t.Errorf("no hub payload carries the custom data; the page cannot show it (rows: %v)", rows)
	}
}

// A mint with no custom data is unchanged: the field is optional and existing clients send only a
// count.
func TestAMintWithoutCustomDataIsUnchanged(t *testing.T) {
	s := collaboratorWithFakeChannel(t)
	rec := postJSONRaw(t, s, "/api/collaborator/payload", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("plain mint = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var out struct {
		Address string `json:"address"`
		Marker  string `json:"marker"`
		Domain  string `json:"domain"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Address == "" || out.Marker == "" || out.Domain == "" {
		t.Errorf("the historical mint response changed shape: address=%q marker=%q domain=%q",
			out.Address, out.Marker, out.Domain)
	}
}

// A non-alphanumeric custom data is REFUSED rather than sanitised: the value is carried inside the
// payload's own address, so a character the address grammar disallows would either be dropped
// (silently mislabelling the operator's payload) or change the address's shape.
func TestNonAlphanumericCustomDataIsRefused(t *testing.T) {
	s := collaboratorWithFakeChannel(t)
	for _, bad := range []string{"user-id", "user id", "user.id", "user_id", "üserid", "a/b"} {
		rec := postJSONRaw(t, s, "/api/collaborator/payload", `{"custom_data":"`+bad+`"}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("custom_data %q was accepted (%d); a separator or a non-ASCII character "+
				"cannot be carried inside a DNS label, and sanitising it silently would hand back "+
				"a payload labelled with something other than what was asked for", bad, rec.Code)
		}
	}
}

// The bound is Burp's 16 characters. Past it, refusal rather than truncation; at it, acceptance.
func TestOverlongCustomDataIsRefusedWithTheBoundNamed(t *testing.T) {
	s := collaboratorWithFakeChannel(t)
	rec := postJSONRaw(t, s, "/api/collaborator/payload", `{"custom_data":"`+strings.Repeat("a", 17)+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("17 characters of custom data was accepted (%d); the bound is what fits a label", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "16") {
		t.Errorf("the refusal does not name the bound: %s", strings.TrimSpace(rec.Body.String()))
	}
	ok := postJSONRaw(t, s, "/api/collaborator/payload", `{"custom_data":"`+strings.Repeat("a", 16)+`"}`)
	if ok.Code != http.StatusOK {
		t.Errorf("16 characters was refused (%d); the bound is inclusive: %s",
			ok.Code, strings.TrimSpace(ok.Body.String()))
	}
}

// WITHOUT_SERVER_LOCATION omits the domain — and the STATUS view must omit it too, because that is
// what the page renders. Mutation-checked: asserting only on the mint response left the status
// branch undefended, and a domain re-added there would disclose exactly what the option withholds.
func TestWithoutServerLocationOmitsTheDomain(t *testing.T) {
	s := collaboratorWithFakeChannel(t)

	// The without-location mint, then a plain mint. Both are read from the status list in ONE
	// read afterwards: the list is newest-first, so reading before the second mint would see only
	// one kind of row and the pair assertion below would silently pass on half its evidence.
	rec := postJSONRaw(t, s, "/api/collaborator/payload", `{"without_server_location":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint without location = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var out struct {
		Payloads []map[string]any `json:"payloads"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Payloads) == 0 {
		t.Fatal("no payload rows returned")
	}
	if _, present := out.Payloads[0]["domain"]; present {
		t.Errorf("the mint response still carries a domain under without_server_location (row: %v)",
			out.Payloads[0])
	}
	if out.Payloads[0]["address"] == "" {
		t.Error("the address was dropped along with the domain; the address IS the payload")
	}

	plain := postJSONRaw(t, s, "/api/collaborator/payload", `{}`)
	if plain.Code != http.StatusOK {
		t.Fatalf("plain mint = %d: %s", plain.Code, strings.TrimSpace(plain.Body.String()))
	}
	var def struct {
		Payloads []map[string]any `json:"payloads"`
	}
	if err := json.Unmarshal(plain.Body.Bytes(), &def); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, present := def.Payloads[0]["domain"]; !present {
		t.Error("a plain mint no longer reports its domain; the option must be a branch, not a " +
			"change to the default")
	}

	withoutOrigin, withOrigin := 0, 0
	for _, row := range hubPayloads(t, s) {
		_, hasDomain := row["domain"]
		flag, _ := row["without_server_location"].(bool)
		switch {
		case flag && hasDomain:
			t.Errorf("a payload minted without a server location still reports a domain in the "+
				"status view (%v); that is the one fact the option exists to withhold", row)
		case flag:
			withoutOrigin++
		case hasDomain:
			withOrigin++
		}
	}
	if withoutOrigin == 0 {
		t.Error("no status row was marked without_server_location; the page cannot explain the " +
			"missing domain without the flag")
	}
	if withOrigin == 0 {
		t.Error("no status row carried a domain although a payload was minted with one; the " +
			"default path lost its domain in the status view")
	}
}
