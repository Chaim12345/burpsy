package web

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

// "Define extract grep from response" (burpsy-react-ui-df8r) builds its rule in the browser, which also
// previews it with a JS RegExp; the attack runs it with Go's regexp. The golden cases are the rules the
// browser builds (intruder-extract.test.ts asserts each regex is what buildExtractRule produces and that
// the preview extracts value). Here each regex goes through the real POST /api/intruder/run as
// grep_extract, against a target answering with the case's response, and the engine must extract the
// same value — so a rule the preview approved is a rule the attack honours.
func TestExtractRulesBuiltInTheBrowserExtractTheSameValueInTheEngine(t *testing.T) {
	raw, err := os.ReadFile("ui/src/lib/intruder-extract.golden.json")
	if err != nil {
		t.Fatalf("read golden cases: %v", err)
	}
	var golden struct {
		Cases []struct {
			Name     string `json:"name"`
			Response string `json:"response"`
			Regex    string `json:"regex"`
			Value    string `json:"value"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatalf("decode golden cases: %v", err)
	}
	if len(golden.Cases) == 0 {
		t.Fatal("no golden cases: the cross-engine check would pass vacuously")
	}
	for _, c := range golden.Cases {
		t.Run(c.Name, func(t *testing.T) {
			target := startCaptureTarget(t, func(string) string { return c.Response })
			srv, id, points := intruderSendFixture(t, "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n")
			var view struct {
				Report struct {
					Attempts []struct {
						GrepExtract *string `json:"grep_extract"`
					} `json:"attempts"`
				} `json:"report"`
			}
			if code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
				"msg_id": id, "target": "http://" + target.addr, "mode": "sniper",
				"manual_points": points, "payload_sets": [][]string{{"x"}},
				"grep_extract": c.Regex, "rps": 1000, "retries": 0,
			}, &view); code != http.StatusOK {
				t.Fatalf("run = %d", code)
			}
			if len(view.Report.Attempts) != 1 || view.Report.Attempts[0].GrepExtract == nil {
				t.Fatalf("attempts = %+v, want one row with an extracted value", view.Report.Attempts)
			}
			if got := *view.Report.Attempts[0].GrepExtract; got != c.Value {
				t.Fatalf("the engine extracted %q with %q, the browser previewed %q", got, c.Regex, c.Value)
			}
		})
	}
}
