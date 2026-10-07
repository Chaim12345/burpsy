package core

import (
	"testing"
	"time"
)

func TestFindingStoreAddAssignsTimestamp(t *testing.T) {
	fs := NewFindingStore()
	before := uint64(time.Now().UnixMilli())
	id := fs.Add(NewFinding{Name: "test"})
	after := uint64(time.Now().UnixMilli())

	f, err := fs.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if f.Timestamp == 0 {
		t.Error("timestamp is 0, want real Unix milliseconds")
	}
	if f.Timestamp < before || f.Timestamp > after {
		t.Errorf("timestamp %d outside [%d, %d]", f.Timestamp, before, after)
	}
}

func TestFindingStoreCRUD(t *testing.T) {
	fs := NewFindingStore()
	id1 := fs.Add(NewFinding{Name: "a", Severity: SeverityHigh})
	id2 := fs.Add(NewFinding{Name: "b", Severity: SeverityLow})

	if fs.Count() != 2 {
		t.Errorf("count = %d, want 2", fs.Count())
	}
	if id1 == id2 {
		t.Errorf("ids collide: %d", id1)
	}

	f, err := fs.Get(id1)
	if err != nil {
		t.Fatalf("Get(%d): %v", id1, err)
	}
	if f.Name != "a" || f.Severity != SeverityHigh {
		t.Errorf("finding = %+v, want name=a high", f)
	}

	if !fs.Delete(id1) {
		t.Error("Delete(id1) = false, want true")
	}
	if fs.Delete(id1) {
		t.Error("second Delete(id1) = true, want false")
	}
	if _, err := fs.Get(id1); err == nil {
		t.Error("Get after delete should error")
	}
	if fs.Count() != 1 {
		t.Errorf("count after delete = %d, want 1", fs.Count())
	}

	fs.Clear()
	if fs.Count() != 0 {
		t.Errorf("count after clear = %d, want 0", fs.Count())
	}
}

// ---- Deduplication ------------------------------------------------------------------------------

func xssAt(param string, ex ExchangeID, target FindingTarget) NewFinding {
	return NewFinding{
		Name:       "Cross-site scripting (reflected)",
		Severity:   SeverityHigh,
		Confidence: ConfidenceFirm,
		Param:      param,
		Target:     target,
		Occurrences: []Occurrence{{
			ExchangeID: ex,
			Request:    MsgPtr(MsgId(uint64(ex) * 2)),
		}},
	}
}

func searchTarget() FindingTarget {
	return FindingTarget{Host: "app.test", Port: 443, TLS: true, Path: "/search"}
}

// The headline case: one endpoint, one issue class, five vulnerable parameters. Burp reports one
// issue with five occurrences; this pins that burpsy-go now does too, and — the part that makes the
// merge worth doing rather than lossy — that the five parameter names survive it.
func TestFindingStoreMergesSameTypeSameTargetAcrossParams(t *testing.T) {
	fs := NewFindingStore()
	params := []string{"q", "sort", "page", "lang", "ref"}
	var ids []uint64
	for i, p := range params {
		ids = append(ids, fs.Add(xssAt(p, ExchangeID(i+1), searchTarget())))
	}

	if got := fs.Count(); got != 1 {
		t.Fatalf("Count = %d, want 1 merged finding", got)
	}
	for i, id := range ids {
		if id != ids[0] {
			t.Errorf("Add #%d returned id %d, want the merged-into id %d", i, id, ids[0])
		}
	}
	f, err := fs.Get(ids[0])
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(f.Occurrences) != len(params) {
		t.Errorf("Occurrences = %d, want %d", len(f.Occurrences), len(params))
	}
	if len(f.Params) != len(params) {
		t.Fatalf("Params = %v, want all %d", f.Params, len(params))
	}
	for i, p := range params {
		if f.Params[i] != p {
			t.Errorf("Params[%d] = %q, want %q (first-seen order)", i, f.Params[i], p)
		}
	}
	if f.Param != "q" {
		t.Errorf("Param = %q, want the first observed parameter %q", f.Param, "q")
	}
}

// The same parameter twice is still two observations of the same issue: both occurrences are kept
// (they are different requests) but the parameter is not listed twice.
func TestFindingStoreMergeDoesNotDuplicateParams(t *testing.T) {
	fs := NewFindingStore()
	fs.Add(xssAt("q", 1, searchTarget()))
	fs.Add(xssAt("q", 2, searchTarget()))

	f := fs.All()[0]
	if len(f.Occurrences) != 2 {
		t.Errorf("Occurrences = %d, want 2", len(f.Occurrences))
	}
	if len(f.Params) != 1 || f.Params[0] != "q" {
		t.Errorf("Params = %v, want [q]", f.Params)
	}
}

func TestFindingStoreDoesNotMergeDifferentTargets(t *testing.T) {
	fs := NewFindingStore()
	other := searchTarget()
	other.Path = "/login"
	fs.Add(xssAt("q", 1, searchTarget()))
	fs.Add(xssAt("q", 2, other))

	if got := fs.Count(); got != 2 {
		t.Fatalf("Count = %d, want 2 — different paths are different targets", got)
	}

	// Same path, different port: the origin is part of the key, so these stay apart too.
	fs2 := NewFindingStore()
	altPort := searchTarget()
	altPort.Port = 8443
	fs2.Add(xssAt("q", 1, searchTarget()))
	fs2.Add(xssAt("q", 2, altPort))
	if got := fs2.Count(); got != 2 {
		t.Fatalf("Count = %d, want 2 — different ports are different targets", got)
	}
}

func TestFindingStoreDoesNotMergeDifferentTypes(t *testing.T) {
	fs := NewFindingStore()
	a := xssAt("q", 1, searchTarget())
	b := xssAt("q", 2, searchTarget())
	b.Name = "SQL injection"
	fs.Add(a)
	fs.Add(b)

	if got := fs.Count(); got != 2 {
		t.Fatalf("Count = %d, want 2 — different issue types never merge", got)
	}
}

// Burp's burp.Zbvp.Zd exempts two issue types from the intake gate entirely. Both exist verbatim as
// burpsy-go catalog rows, and both describe one specific message rather than an endpoint, so
// collapsing them would hide distinct facts behind a count.
func TestFindingStoreExemptRowsNeverMerge(t *testing.T) {
	for _, name := range []string{"Cross-domain POST", "Serialized object in HTTP message"} {
		fs := NewFindingStore()
		for i := 0; i < 3; i++ {
			f := xssAt("", ExchangeID(i+1), searchTarget())
			f.Name = name
			fs.Add(f)
		}
		if got := fs.Count(); got != 3 {
			t.Errorf("%s: Count = %d, want 3 — this row is exempt from deduplication", name, got)
		}
	}
}

// A finding whose producer could not resolve a target is never merged: merging on name alone across
// unknown locations would collapse genuinely distinct issues.
func TestFindingStoreUnknownTargetNeverMerges(t *testing.T) {
	fs := NewFindingStore()
	fs.Add(NewFinding{Name: "Cross-site scripting (reflected)", Param: "q"})
	fs.Add(NewFinding{Name: "Cross-site scripting (reflected)", Param: "sort"})

	if got := fs.Count(); got != 2 {
		t.Fatalf("Count = %d, want 2 — a finding with no target has nothing to merge on", got)
	}
}

// Host granularity is opt-in per catalog row, because it is only right for rows that describe an
// origin rather than an endpoint.
func TestFindingStoreHostScopedPolicyMergesAcrossPaths(t *testing.T) {
	fs := NewFindingStore()
	fs.SetDedupPolicy(&DedupPolicy{HostScoped: map[string]bool{"Strict transport security not enforced": true}})

	for i, path := range []string{"/", "/login", "/account"} {
		f := xssAt("", ExchangeID(i+1), FindingTarget{Host: "app.test", Port: 443, TLS: true, Path: path})
		f.Name = "Strict transport security not enforced"
		fs.Add(f)
	}
	if got := fs.Count(); got != 1 {
		t.Fatalf("Count = %d, want 1 — a host-scoped row ignores the path", got)
	}

	// A different origin is still a different target even for a host-scoped row.
	f := xssAt("", 9, FindingTarget{Host: "other.test", Port: 443, TLS: true, Path: "/"})
	f.Name = "Strict transport security not enforced"
	fs.Add(f)
	if got := fs.Count(); got != 2 {
		t.Fatalf("Count = %d, want 2 — a host-scoped row still separates origins", got)
	}
}

// A policy installed after findings were restored must re-key them, or a restored session quietly
// stops merging exactly the rows the policy exists for.
func TestFindingStoreSetDedupPolicyRebuildsIndex(t *testing.T) {
	fs := NewFindingStore()
	fs.Restore([]*Finding{{
		ID:     7,
		Name:   "Strict transport security not enforced",
		Target: FindingTarget{Host: "app.test", Port: 443, TLS: true, Path: "/"},
	}})
	fs.SetDedupPolicy(&DedupPolicy{HostScoped: map[string]bool{"Strict transport security not enforced": true}})

	f := xssAt("", 3, FindingTarget{Host: "app.test", Port: 443, TLS: true, Path: "/account"})
	f.Name = "Strict transport security not enforced"
	if got := fs.Add(f); got != 7 {
		t.Fatalf("Add returned %d, want the restored finding's id 7", got)
	}
	if got := fs.Count(); got != 1 {
		t.Errorf("Count = %d, want 1", got)
	}
}

// Severity takes the maximum and confidence the best across a merge, so triage by either never
// hides a worse or more certain observation behind whichever one happened to arrive first.
func TestFindingStoreMergeEscalatesSeverityAndConfidence(t *testing.T) {
	fs := NewFindingStore()
	low := xssAt("q", 1, searchTarget())
	low.Severity = SeverityLow
	low.Confidence = ConfidenceTentative
	id := fs.Add(low)

	high := xssAt("sort", 2, searchTarget())
	high.Severity = SeverityCritical
	high.Confidence = ConfidenceCertain
	fs.Add(high)

	f, err := fs.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %v, want Critical", f.Severity)
	}
	if f.Confidence != ConfidenceCertain {
		t.Errorf("Confidence = %v, want Certain", f.Confidence)
	}

	// And it does not de-escalate: a weaker later observation leaves the finding where it was.
	weak := xssAt("page", 3, searchTarget())
	weak.Severity = SeverityInformational
	weak.Confidence = ConfidenceTentative
	fs.Add(weak)
	f, _ = fs.Get(id)
	if f.Severity != SeverityCritical || f.Confidence != ConfidenceCertain {
		t.Errorf("after a weaker observation: %v/%v, want Critical/Certain", f.Severity, f.Confidence)
	}
}

// The live-update stream and the durable mirror both have to hear about a merge: the set of findings
// did not grow, but one of them changed, and the UI's list is stale either way.
func TestFindingStoreMergeFiresChangeAndPersistenceHooks(t *testing.T) {
	fs := NewFindingStore()
	var changes int
	var saved []uint64
	fs.OnChange(func() { changes++ })
	fs.SetPersistenceSink(func(f *Finding) { saved = append(saved, f.ID) })

	id := fs.Add(xssAt("q", 1, searchTarget()))
	fs.Add(xssAt("sort", 2, searchTarget()))

	if changes != 2 {
		t.Errorf("onChange fired %d times, want 2 (the add and the merge)", changes)
	}
	if len(saved) != 2 || saved[0] != id || saved[1] != id {
		t.Errorf("persistence sink saw %v, want the same id %d twice — a merge rewrites the row", saved, id)
	}
}

// Deleting the finding an index entry points at must clear the entry, or the next matching finding
// would merge into a finding that is no longer in the store and vanish.
func TestFindingStoreDeleteClearsDedupIndex(t *testing.T) {
	fs := NewFindingStore()
	id := fs.Add(xssAt("q", 1, searchTarget()))
	if !fs.Delete(id) {
		t.Fatal("Delete returned false")
	}
	newID := fs.Add(xssAt("sort", 2, searchTarget()))
	if newID == id {
		t.Errorf("Add returned the deleted id %d", id)
	}
	if got := fs.Count(); got != 1 {
		t.Fatalf("Count = %d, want 1", got)
	}
	if _, err := fs.Get(newID); err != nil {
		t.Errorf("the finding added after the delete is not in the store: %v", err)
	}
}

func TestFindingStoreClearResetsDedupIndex(t *testing.T) {
	fs := NewFindingStore()
	fs.Add(xssAt("q", 1, searchTarget()))
	fs.Clear()
	fs.Add(xssAt("sort", 2, searchTarget()))
	if got := fs.Count(); got != 1 {
		t.Fatalf("Count = %d, want 1", got)
	}
	if len(fs.All()[0].Occurrences) != 1 {
		t.Error("the finding added after Clear inherited occurrences from a cleared one")
	}
}
