package scanner

// A skipped insertion point names its kind, and the XML/multipart parameter kinds exist
// (burpsy-react-ui-75jm).
//
// "Skipped" with no kind is unactionable: an operator cannot tell a skip they chose from a point
// the enumerator refused, and cannot tell WHICH of a request's places was passed over. Burp's own
// status vocabulary names the kind a status refers to (Zq5.java:48-85).

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// The row an operator reads names the kind that was skipped.
func TestASkippedPointRowNamesTheKindThatWasSkipped(t *testing.T) {
	row := AuditItemPoint{
		Kind:   string(bcheck.IpCookie),
		Name:   "session",
		Status: AuditItemPointSkippedDeclined,
	}
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got struct {
		Status string `json:"status"`
		Kind   string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Status == "Skipped" {
		t.Error("the row still reports a bare \"Skipped\"; an operator cannot tell which of the " +
			"request's places was passed over, which is the whole defect")
	}
	if !strings.Contains(got.Status, "cookie") {
		t.Errorf("status = %q, want it to name the cookie kind", got.Status)
	}
	// The kind field itself is untouched — the label is additional, not a replacement.
	if got.Kind != string(bcheck.IpCookie) {
		t.Errorf("kind = %q, want it preserved alongside the label", got.Kind)
	}
}

// Only the bare status is elaborated. Statuses that already name their own cause must not grow a
// second clause — a queue column that repeats itself is longer without saying more.
func TestOnlyTheBareSkippedStatusGrowsAKind(t *testing.T) {
	for _, s := range []AuditItemPointStatus{
		AuditItemPointSkippedNested,
		AuditItemPointSkippedOperator,
		AuditItemPointSkippedIneffective,
		AuditItemPointCovered,
		AuditItemPointFailed,
	} {
		if got := s.LabelFor(string(bcheck.IpQuery)); got != s.Label() {
			t.Errorf("%q grew a kind clause (%q); it already names its own cause", s.Label(), got)
		}
	}
}

// A point with no kind — a declined PLACE, which by construction has none — must not render an
// empty parenthesis.
func TestAPlaceWithNoKindRendersNoEmptyClause(t *testing.T) {
	got := AuditItemPointSkippedDeclined.LabelFor("")
	if got != AuditItemPointSkippedDeclined.Label() {
		t.Errorf("label = %q for a place with no kind, want the bare status", got)
	}
	if strings.Contains(got, "()") {
		t.Errorf("label = %q carries an empty clause", got)
	}
}

// Every kind the enumerator can emit has a label. A kind added without one would render its raw
// identifier at an operator — readable, but not what the column is for.
func TestEveryEnumeratedKindHasAnOperatorLabel(t *testing.T) {
	for _, kind := range []bcheck.IpKind{
		bcheck.IpQuery, bcheck.IpBody, bcheck.IpCookie, bcheck.IpHeader,
		bcheck.IpParamNameURL, bcheck.IpParamNameBody, bcheck.IpEntireBody,
		bcheck.IpURLPathFilename, bcheck.IpURLPathFolder, bcheck.IpSyntheticHeader,
		bcheck.IpXML, bcheck.IpMultipartAttr,
	} {
		label, known := insertionKindLabel(string(kind))
		if !known {
			t.Errorf("kind %q has no operator label, so the queue shows its raw identifier", kind)
		}
		if label == "" {
			t.Errorf("kind %q labels as the empty string", kind)
		}
	}
	// An unknown kind passes through rather than becoming "unknown": more information than nothing,
	// and it makes an unlisted kind visible instead of hidden.
	label, known := insertionKindLabel("a_kind_added_later")
	if known {
		t.Error("an unlisted kind reported itself as recognised")
	}
	if label != "a_kind_added_later" {
		t.Errorf("an unlisted kind rendered as %q; passing it through is what makes the omission "+
			"visible rather than silently relabelled", label)
	}
}
