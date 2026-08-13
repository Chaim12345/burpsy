package scanner

import "testing"

func TestNativeCheckCoverageSeparatesRunnableAndDeclined(t *testing.T) {
	rows := NativeCheckCoverage()
	if len(rows) != 183 {
		t.Fatalf("got %d coverage rows, want 183", len(rows))
	}
	runnable, declined := 0, 0
	for _, row := range rows {
		if row.Runnable {
			runnable++
		}
		if row.Implementation == ImplementationDeclined {
			declined++
			if row.DeclineReason == "" {
				t.Errorf("declined row %q has no reason", row.Name)
			}
		}
	}
	if runnable != 183 || declined != 0 {
		t.Fatalf("coverage has runnable=%d declined=%d, want 183 and 0", runnable, declined)
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1].TypeIndex >= rows[i].TypeIndex {
			t.Fatalf("coverage rows are not strictly sorted at %d", i)
		}
	}
}
