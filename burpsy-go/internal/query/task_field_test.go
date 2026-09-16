// The task field (burpsy-react-ui-k3a7): run attribution in the filter grammar.
//
// The field exists because "show me the path set of crawl A" is half of the access-control
// site-map comparison, and before it the grammar could not ask the question. The tests pin the
// three behaviours that make it honest rather than merely present:
//
//   - task = N matches the rows that run produced, and only those;
//   - task != 0 is "rows some run owns", and task = 0 is the operator's own proxied traffic —
//     0 is a real answer here, not a placeholder, which is exactly why TaskID carries a bool;
//   - a consumer that cannot answer attribution (the frontier, a match/replace candidate) fails
//     every task comparison, negations included, rather than sweeping up untracked rows.
package query

import "testing"

// taskRow answers attribution and nothing else, so a failure names the field under test.
type taskRow struct {
	task uint64
}

func (r taskRow) Host() string                   { return "" }
func (r taskRow) Method() string                 { return "" }
func (r taskRow) Path() string                   { return "" }
func (r taskRow) Status() int                    { return 0 }
func (r taskRow) Mime() string                   { return "" }
func (r taskRow) Body() []byte                   { return nil }
func (r taskRow) ResponseLen() (int64, bool)     { return 0, false }
func (r taskRow) DurationUs() (int64, bool)      { return 0, false }
func (r taskRow) Header(string) ([]string, bool) { return nil, false }
func (r taskRow) Annotation() (string, string, bool) {
	return "", "", false
}

// noAttributionRow is the consumer that cannot answer: the Queryable contract's (0, false).
type noAttributionRow struct {
	taskRow
}

func (r noAttributionRow) TaskID() (uint64, bool) { return 0, false }

func (r taskRow) TaskID() (uint64, bool) { return r.task, true }

func TestTaskFieldMatchesTheRunThatProducedTheRow(t *testing.T) {
	e := mustParse(t, `task = 3`)
	if !e.Match(taskRow{task: 3}) {
		t.Error("task = 3 did not match a row task 3 produced")
	}
	if e.Match(taskRow{task: 4}) {
		t.Error("task = 3 matched a row task 4 produced — attribution that lies is worse than none")
	}
}

func TestTaskZeroIsTheUntrackedRowNotTheUnknownOne(t *testing.T) {
	// task = 0: everything the operator's own client proxied.
	if e := mustParse(t, `task = 0`); !e.Match(taskRow{task: 0}) {
		t.Error("task = 0 did not match an untracked row — 0 is a real answer, the whole reason TaskID carries a bool")
	}
	// task != 0: everything some run owns.
	e := mustParse(t, `task != 0`)
	if e.Match(taskRow{task: 0}) {
		t.Error("task != 0 matched an untracked row")
	}
	if !e.Match(taskRow{task: 7}) {
		t.Error("task != 0 did not match a row task 7 owns")
	}
}

func TestTaskComparisonsFailForAConsumerThatCannotAnswerAttribution(t *testing.T) {
	for _, q := range []string{`task = 0`, `task != 0`, `task = 3`} {
		e := mustParse(t, q)
		if e.Match(noAttributionRow{}) {
			t.Errorf("%q matched a row the consumer cannot answer attribution for — the contract is fail-every-comparison, not assume-untracked", q)
		}
	}
}

func TestTaskFieldIsNamedByFieldOrderSoErrorMessagesAndFieldsStayHonest(t *testing.T) {
	// Fields() must report the field a query used; an operator debugging a filter reads this
	// list, and a field silently absent from it is a field the grammar's own tooling denies.
	e := mustParse(t, `task = 3`)
	got := e.Fields()
	if len(got) != 1 || got[0] != "task" {
		t.Errorf("Fields() = %v, want [task]", got)
	}
}
