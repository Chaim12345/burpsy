package crawler

import (
	"encoding/json"
	"strings"
	"testing"
)

// burpsy-react-ui-j5j7: every stop has a name, an explanation and a place in the legend, and goes on
// the wire as its name — a stop that serialised as a bare integer, or named itself "unknown", turned a
// crawl that paused itself into one the console reported as done.
func TestEveryCrawlStopIsNamedExplainedAndRoundTripsByName(t *testing.T) {
	seen := map[string]bool{}
	for _, stop := range CrawlStopAll {
		name := stop.String()
		if name == "unknown" || seen[name] {
			t.Errorf("stop %d has name %q (unknown or duplicate)", int(stop), name)
		}
		seen[name] = true
		if stop.Explanation() == "unknown stop" {
			t.Errorf("stop %s has no explanation", name)
		}
	}
	// The legend must be the whole enum: the last stop's value + 1 is the count.
	if want := int(StopFollowUpCancelled) + 1; len(CrawlStopAll) != want {
		t.Errorf("CrawlStopAll has %d stops, the enum has %d", len(CrawlStopAll), want)
	}

	raw, err := json.Marshal(LimitReport{Stops: []CrawlStop{StopPausedTimeouts, StopFollowUpBudget}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"stops":["paused-timeouts","follow-up-budget"]`) {
		t.Errorf("stops on the wire: %s, want names", raw)
	}
	var back LimitReport
	if err := json.Unmarshal(raw, &back); err != nil || len(back.Stops) != 2 || back.Stops[0] != StopPausedTimeouts {
		t.Errorf("round trip = %+v %v", back.Stops, err)
	}
	if err := json.Unmarshal([]byte(`{"stops":["no-such-stop"]}`), &back); err == nil {
		t.Error("an unknown stop name was accepted")
	}
}
