package intruder

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- gaps in the live payload path's coverage ----------------------------------------------
//
// These four tests exist because `PayloadGenerator` was deleted: a type with zero production
// callers whose three methods were exercised only by tests, sitting beside the real implementation
// (`PayloadSource.Resolve`) that the API actually reaches. Deleting dead code must not delete
// behavioural coverage, so anything those tests demonstrated is asserted here against the live path
// instead — but only where it was not already covered.
//
// It mostly was. payload_test.go already pins inclusive ranges, counting down with a negative step,
// a zero step, a step pointing away from the end of the range, and list/generator equivalence. I
// filed an issue claiming the live path's inverted-range handling was "currently unasserted"; that
// was an overstatement. `TestAStepPointingAwayFromTheEndOfTheRangeIsRefused` covers From < To with a
// negative step. What it does not cover is the other direction, From > To with a *positive* step,
// which is the exact shape of the deleted `GenerateNumbers(5, 1)` test — so one of the four below is
// the real gap and the rest of that issue was wrong.
//
// The file source, added when payload types were wired to the UI, had no test at all.
//
// One behavioural note worth recording: the live path is *stricter* than the code that was deleted.
// An inverted range is a named error here, where `GenerateNumbers` returned an empty slice. That is
// the better behaviour and is pinned as such rather than softened to match — an operator who typed 5
// to 1 made a mistake, and an empty payload set presents as "the attack ran and found nothing".

func numbersSource(n *Numbers) *PayloadSource {
	return &PayloadSource{Type: "numbers", Numbers: n}
}

// The real gap. From > To with a positive step: the deleted GenerateNumbers(5, 1) case, and the one
// direction payload_test.go does not exercise.
func TestAnInvertedSequentialRangeIsRefusedRatherThanSilentlyEmpty(t *testing.T) {
	_, err := numbersSource(&Numbers{From: 5, To: 1, Step: 1}).Resolve(1000)
	if err == nil {
		t.Fatal("From=5 To=1 Step=1 was accepted; an inverted range must not produce a payload set, " +
			"and an empty one would read to the operator as \"the attack ran and found nothing\"")
	}
	var perr *PayloadError
	if !errors.As(err, &perr) {
		t.Fatalf("error is %T, want *PayloadError so callers can branch on the kind", err)
	}
	if perr.Kind != PayloadErrBackwardsRange {
		t.Errorf("kind = %v, want PayloadErrBackwardsRange", perr.Kind)
	}
	msg := err.Error()
	for _, want := range []string{"5", "1"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name the bound %q the operator typed", msg, want)
		}
	}
}

// From == To is one payload, not zero and not two — the off-by-one most likely to hide in an
// inclusive range, and not covered elsewhere.
func TestASingleValueRangeYieldsOnePayload(t *testing.T) {
	set, err := numbersSource(&Numbers{From: 7, To: 7, Step: 1}).Resolve(1000)
	if err != nil {
		t.Fatalf("From=To=7: %v", err)
	}
	if len(set.Items) != 1 || set.Items[0] != "7" {
		t.Errorf("items = %v, want exactly [7]", set.Items)
	}
}

// ---- the file source, which had no coverage at all -----------------------------------------

func TestAFileSourceReadsOnePayloadPerLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payloads.txt")
	if err := os.WriteFile(path, []byte("alpha\nbeta\ngamma\n"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	set, err := (&PayloadSource{Type: "file", File: &FileSource{Filename: path}}).Resolve(1000)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := []string{"alpha", "beta", "gamma"}
	if strings.Join(set.Items, ",") != strings.Join(want, ",") {
		t.Errorf("items = %v, want %v", set.Items, want)
	}
}

// A missing file must be an error, not an empty set. The distinction matters more here than it did
// on the dead generator: an empty payload set makes an attack report zero findings as though it had
// run, which is indistinguishable from a target that survived it.
func TestAMissingPayloadFileIsAnErrorNotAnEmptySet(t *testing.T) {
	set, err := (&PayloadSource{
		Type: "file",
		File: &FileSource{Filename: filepath.Join(t.TempDir(), "does-not-exist.txt")},
	}).Resolve(1000)
	if err == nil {
		t.Fatalf("a missing payload file was accepted, yielding %d items — an attack would report "+
			"zero findings as though it had run", len(set.Items))
	}
}
