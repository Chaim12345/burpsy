package web

// The token rules' CRUD surface (xe82): create/list/replace/delete over the mux, with the
// validation and not-found answers distinct, and the id and order stable across an edit.

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/session"
)

func tokenRuleBody(name, header string) map[string]any {
	return map[string]any{
		"name": name, "enabled": true,
		"extract": map[string]any{
			"name": "csrf", "from": "body", "pattern": `name="csrf" value="([^"]+)"`, "group": 1,
		},
		"inject_header": header, "inject_value": "Bearer {{csrf}}",
	}
}

func TestSessionTokenRulesCRUD(t *testing.T) {
	s := newTestServer()

	// Create two: ids minted, list in insertion order.
	rec := postJSON(t, s, "/api/session/token-rules", tokenRuleBody("first", "X-First"))
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created struct {
		Rule session.TokenRule `json:"rule"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	firstID := created.Rule.ID
	if firstID == "" {
		t.Fatal("the create answer carried no minted id")
	}
	if rec2 := postJSON(t, s, "/api/session/token-rules", tokenRuleBody("second", "X-Second")); rec2.Code != http.StatusOK {
		t.Fatalf("second create: %d %s", rec2.Code, rec2.Body)
	}

	rec = get(t, s, "/api/session/token-rules")
	var list struct {
		Wired bool                `json:"wired"`
		Rules []session.TokenRule `json:"rules"`
		Tools []string            `json:"tools"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if !list.Wired || len(list.Rules) != 2 || list.Rules[0].ID != firstID {
		t.Fatalf("list = %+v", list)
	}

	// Replace the first: same id, same place in the order.
	rec = putJSON(t, s, "/api/session/token-rules/"+firstID, tokenRuleBody("first edited", "X-Edited"))
	if rec.Code != http.StatusOK {
		t.Fatalf("replace: %d %s", rec.Code, rec.Body)
	}
	rec = get(t, s, "/api/session/token-rules")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list after edit: %v", err)
	}
	if list.Rules[0].ID != firstID || list.Rules[0].Name != "first edited" || list.Rules[0].InjectHeader != "X-Edited" {
		t.Fatalf("the edit did not keep id and order: %+v", list.Rules[0])
	}

	// Delete the first: gone from the list, the second keeps its place.
	rec = deleteReq(t, s, "/api/session/token-rules/"+firstID)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	rec = get(t, s, "/api/session/token-rules")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list after delete: %v", err)
	}
	if len(list.Rules) != 1 || list.Rules[0].Name != "second" {
		t.Fatalf("the delete left %d rules: %+v", len(list.Rules), list.Rules)
	}
}

func TestSessionTokenRuleValidationAndNotFound(t *testing.T) {
	s := newTestServer()

	// An invalid rule is refused with the coordinator's reason, not created.
	bad := tokenRuleBody("", "X-Empty") // no name
	rec := postJSON(t, s, "/api/session/token-rules", bad)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a nameless rule was not refused: %d %s", rec.Code, rec.Body)
	}
	// An extraction that can never resolve is refused too, rather than carried inert.
	inert := tokenRuleBody("inert", "X-Inert")
	inert["extract"].(map[string]any)["from"] = "nowhere"
	rec = postJSON(t, s, "/api/session/token-rules", inert)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an extraction with no readable source was not refused: %d %s", rec.Code, rec.Body)
	}

	// Editing or deleting a rule that is not there is a 404, distinct from a bad edit.
	rec = putJSON(t, s, "/api/session/token-rules/token-404", tokenRuleBody("ghost", "X-Ghost"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("editing an absent rule: %d, want 404", rec.Code)
	}
	rec = deleteReq(t, s, "/api/session/token-rules/token-404")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("deleting an absent rule: %d, want 404", rec.Code)
	}
}
