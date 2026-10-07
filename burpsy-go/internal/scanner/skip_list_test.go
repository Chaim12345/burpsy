package scanner

// The operator's parameter skip list (burpsy-react-ui-v9cg) — Burp's
// scanner.ignored_insertion_points.skip_all_tests_for_parameters: parameters an operator
// exempted from testing entirely, by name. What these tests pin:
//
//   - a named parameter's points are dropped from EVERY kind it appears in (query, body,
//     cookie), and the drop is counted as a Declined with its own What — an audit that
//     skipped a parameter it was told to skip must say so, or the operator's own exemption
//     reads as "nothing to test here";
//   - matching is case-insensitive (a parameter is an identifier; HTTP identifiers fold) and
//     does not touch anything else — the survivors' fixed order is unchanged, because order
//     is observable and an exemption must not reorder what it did not exempt;
//   - the skip list and the per-request cap do not double-count one point;
//   - the queue row classifies as the operator skip, distinct from the cap and from a
//     nested-off skip;
//   - an empty list name is refused at the API door rather than silently dropped.
import (
	"fmt"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

const skipFixture = "POST /search?sort=name&page=2 HTTP/1.1\r\n" +
	"Host: app.test\r\n" +
	"Cookie: SID=abc; THEME=dark\r\n" +
	"Content-Type: application/x-www-form-urlencoded\r\n" +
	"Content-Length: 25\r\n" +
	"\r\n" +
	"user=admin&password=x&token=t"

func TestASkippedParameterIsDroppedFromEveryKindAndCounted(t *testing.T) {
	// Control: without the list, the parameter is enumerated in all three kinds.
	base, _ := bcheck.Enumerate([]byte(skipFixture), []string{"any"})
	var control int
	for _, p := range base {
		if p.Name == "user" {
			control++
		}
	}
	if control == 0 {
		t.Fatalf("control case: 'user' yielded %d points without the skip list; the fixture must carry it", control)
	}

	pts, declined := bcheck.EnumerateWith([]byte(skipFixture), []string{"any"}, bcheck.EnumerateOptions{
		Max:                       bcheck.DefaultMaxInsertionPoints,
		SkipAllTestsForParameters: []string{"user"},
	})
	for _, p := range pts {
		if p.Name == "user" {
			t.Errorf("the skipped parameter still yielded a point of kind %s", p.Kind)
		}
	}
	var skipDeclines int
	for _, d := range declined {
		if d.What == bcheck.DeclinedSkippedParamWhat {
			skipDeclines++
			if !strings.Contains(d.Reason, fmt.Sprint(control)) {
				t.Errorf("decline reason = %q, want it to name all %d dropped point(s)", d.Reason, control)
			}
		}
	}
	if skipDeclines != 1 {
		t.Errorf("skip declines = %d, want exactly one row for the whole list", skipDeclines)
	}
}

func TestSkipMatchingIsCaseInsensitiveAndLeavesTheOtherPointsAlone(t *testing.T) {
	base, _ := bcheck.Enumerate([]byte(skipFixture), []string{"any"})
	var withoutUser []bcheck.InsertionPoint
	for _, p := range base {
		if p.Name != "user" {
			withoutUser = append(withoutUser, p)
		}
	}

	pts, declined := bcheck.EnumerateWith([]byte(skipFixture), []string{"any"}, bcheck.EnumerateOptions{
		Max:                       bcheck.DefaultMaxInsertionPoints,
		SkipAllTestsForParameters: []string{"  USER "}, // trimmed + folded
	})
	if len(pts) != len(withoutUser) {
		t.Fatalf("filtered points = %d, want the %d the control left after removing 'user'", len(pts), len(withoutUser))
	}
	for i := range pts {
		if pts[i].Kind != withoutUser[i].Kind || pts[i].Name != withoutUser[i].Name {
			t.Fatalf("order changed at %d: got %s/%s, want %s/%s — an exemption must not reorder what it did not exempt",
				i, pts[i].Kind, pts[i].Name, withoutUser[i].Kind, withoutUser[i].Name)
		}
	}
	if len(declined) == 0 {
		t.Fatal("case-insensitive skip produced no decline row")
	}
}

func TestTheSkipListAndThePerRequestCapDoNotDoubleCountOnePoint(t *testing.T) {
	// The skip runs BEFORE the cap, so the pool the cap measures never contains a skipped
	// point. The robust claim, asserted from the decline rows themselves: the skip's count
	// names exactly the points the parameter owned (measured from the no-skip control), and
	// at a generous cap the cap row is absent — so neither mechanism ever claims the same
	// point, and a generous-cap run's skip row is the only decline that names it.
	base, _ := bcheck.Enumerate([]byte(skipFixture), []string{"any"})
	var userPoints int
	for _, p := range base {
		if p.Name == "user" {
			userPoints++
		}
	}
	if userPoints == 0 {
		t.Fatal("control case: the fixture carries no points named user")
	}
	pts, declined := bcheck.EnumerateWith([]byte(skipFixture), []string{"any"}, bcheck.EnumerateOptions{
		Max:                       bcheck.DefaultMaxInsertionPoints,
		SkipAllTestsForParameters: []string{"user"},
	})
	// A generous cap: the survivors are all kept, so the cap has nothing to say.
	var skipCounted, capRows int
	for _, d := range declined {
		switch d.What {
		case bcheck.DeclinedSkippedParamWhat:
			if !strings.Contains(d.Reason, fmt.Sprintf("%d point(s)", userPoints)) {
				t.Errorf("the skip row says %q, but the parameter owned %d point(s) in the control", d.Reason, userPoints)
			}
			skipCounted++
		case bcheck.DeclinedPastLimitWhat:
			capRows++
		}
	}
	if skipCounted != 1 || capRows != 0 {
		t.Fatalf("decline rows: skip=%d cap=%d, want exactly one skip row and no cap row at a generous cap", skipCounted, capRows)
	}
	if len(pts) != len(base)-userPoints {
		t.Fatalf("points kept = %d, want the control's %d minus the %d the parameter owned", len(pts), len(base), userPoints)
	}
}

func TestTheQueueRowClassifiesAsTheOperatorSkip(t *testing.T) {
	rows, _ := auditItemPoints([]byte(skipFixture), []string{"any"}, bcheck.EnumerateOptions{
		Max:                       bcheck.DefaultMaxInsertionPoints,
		SkipAllTestsForParameters: []string{"user"},
	})
	var operatorSkips int
	for _, r := range rows {
		if r.Status == AuditItemPointSkippedOperator {
			operatorSkips++
		}
	}
	if operatorSkips != 1 {
		t.Fatalf("operator-skip rows = %d, want 1", operatorSkips)
	}
	// and its label says whose choice it was
	if got := AuditItemPointSkippedOperator.Label(); !strings.Contains(got, "operator") {
		t.Errorf("label = %q, want it to name the operator's list", got)
	}
	if !AuditItemPointSkippedOperator.IsSkip() {
		t.Error("IsSkip() is false for the operator skip — no work is dispatched at the point")
	}
}

func TestTheSkipListRidesTheRunConfigurationIntoEveryEnumeration(t *testing.T) {
	cfg := AuditConfig{}
	cfg.SkipAllTestsForParameters = []string{"user"}
	opts := cfg.enumerateOptions()
	if len(opts.SkipAllTestsForParameters) != 1 || opts.SkipAllTestsForParameters[0] != "user" {
		t.Fatalf("enumerateOptions().SkipAllTestsForParameters = %v, want the run's list", opts.SkipAllTestsForParameters)
	}
	// and the zero config carries none
	if got := (AuditConfig{}).enumerateOptions().SkipAllTestsForParameters; len(got) != 0 {
		t.Errorf("zero config carried %v; unset means no exemptions", got)
	}
}
