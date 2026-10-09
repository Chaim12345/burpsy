package web

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"testing"
)

// The per-position FIPS battery reaches the browser through the real analyse route
// (burpsy-react-ui-c0k3). A pinned first hex digit fails at exactly bits 0-3, and a switched-off test is
// marked with its arrays as [], not null.
func Test_analyse_route_carries_fips_at_each_bit_position(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	tokens := make([]string, 400)
	for i := range tokens {
		tokens[i] = "0" + fmt.Sprintf("%015x", rng.Uint64()&(1<<60-1))
	}
	s := newTestServer()
	rec := postJSON(t, s, "/api/sequencer/analyse", map[string]any{"tokens": tokens, "disabled_tests": []string{"poker"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		FipsPositions struct {
			Computed          bool `json:"computed"`
			Tokens            int  `json:"tokens"`
			PositionsExamined int  `json:"positions_examined"`
			AffectsGrade      bool `json:"affects_grade"`
			Tests             []struct {
				ID               string          `json:"id"`
				Disabled         bool            `json:"disabled"`
				FailingPositions []int           `json:"failing_positions"`
				Significance     json.RawMessage `json:"significance"`
			} `json:"tests"`
		} `json:"fips_positions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	fp := out.FipsPositions
	if !fp.Computed || fp.Tokens != 400 || fp.PositionsExamined != 64 || fp.AffectsGrade {
		t.Fatalf("fips_positions: %+v", fp)
	}
	seen := map[string]bool{}
	for _, test := range fp.Tests {
		seen[test.ID] = true
		switch test.ID {
		case "monobit":
			if fmt.Sprint(test.FailingPositions) != "[0 1 2 3]" {
				t.Errorf("monobit failing positions %v, want [0 1 2 3]", test.FailingPositions)
			}
		case "poker":
			if !test.Disabled || string(test.Significance) != "[]" {
				t.Errorf("poker disabled=%v significance=%s, want true and []", test.Disabled, test.Significance)
			}
		}
	}
	if len(seen) != 4 {
		t.Errorf("tests on the wire: %v", seen)
	}
	if !strings.Contains(rec.Body.String(), `"fips_positions":{`) {
		t.Error("fips_positions missing from the marshalled report")
	}
}
