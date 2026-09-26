package core

import "testing"

// burpsy-react-ui-7tc1: Burp's issue merger has a per-issue-type rule, and JWT weak-HMAC uses a
// fingerprint comparison (Zbvp.java:53-56, Zu / Zxi().ZZ()). burpsy had exactly one keying rule for
// every row — (name, target) — so a weak key proven on three endpoints was filed as three High
// findings for one fact. The reverse error is just as bad: a check whose identity is a secret rather
// than a place would over-merge under a shared target if the fingerprint were folded INTO the key
// instead of replacing the target.
//
// These pin both directions, because a fix that only stops the duplicates is not a fix.

// One weak key, seen on two endpoints, is ONE finding.
func TestTheSameWeakKeyOnTwoEndpointsIsOneFinding(t *testing.T) {
	fs := NewFindingStore()
	fs.SetDedupPolicy(&DedupPolicy{})

	target := func(path string) FindingTarget {
		return FindingTarget{Host: "app.test", Port: 443, TLS: true, Path: path}
	}

	first := fs.Add(NewFinding{
		Name: "JWT weak HMAC secret", Severity: SeverityHigh, Confidence: ConfidenceCertain,
		Description: "signed with the secret \"secret\"",
		Target:      target("/login"),
		MergeKey:    "secret",
		Occurrences: []Occurrence{{ExchangeID: ExchangeID(1)}},
	})
	second := fs.Add(NewFinding{
		Name: "JWT weak HMAC secret", Severity: SeverityHigh, Confidence: ConfidenceCertain,
		Description: "signed with the secret \"secret\"",
		Target:      target("/api/session"),
		MergeKey:    "secret",
		Occurrences: []Occurrence{{ExchangeID: ExchangeID(2)}},
	})

	if first != second {
		t.Errorf("the same recovered secret on two endpoints produced findings %d and %d; one weak key "+
			"is one weakness, and filing it per endpoint is the duplicate Burp's fingerprint rule "+
			"exists to prevent (Zbvp.java:53-56)", first, second)
	}
	f, err := fs.Get(first)
	if err != nil {
		t.Fatalf("finding %d is not in the store after the merge: %v", first, err)
	}
	if len(f.Occurrences) != 2 {
		t.Errorf("the merged finding carries %d occurrences, want both endpoints' — a merge that "+
			"silently dropped the second observation is the same defect as not merging", len(f.Occurrences))
	}
}

// Two DIFFERENT secrets on the same endpoint are two findings. Without this the merge key would be
// swallowing distinct weaknesses, which is the direction the fingerprint rule also has to avoid.
func TestTwoDifferentWeakKeysAreTwoFindings(t *testing.T) {
	fs := NewFindingStore()
	fs.SetDedupPolicy(&DedupPolicy{})
	target := FindingTarget{Host: "app.test", Port: 443, TLS: true, Path: "/login"}

	first := fs.Add(NewFinding{
		Name: "JWT weak HMAC secret", Severity: SeverityHigh, Confidence: ConfidenceCertain,
		Target: target, MergeKey: "hunter2",
	})
	second := fs.Add(NewFinding{
		Name: "JWT weak HMAC secret", Severity: SeverityHigh, Confidence: ConfidenceCertain,
		Target: target, MergeKey: "password",
	})

	if first == second {
		t.Error("two different recovered secrets on one endpoint collapsed into one finding; the " +
			"merge key identifies WHICH weakness was proven, and merging across secrets hides one of them")
	}
}

// The same secret on two HOSTS is two findings: the weakness is only actionable on the application
// that issued the token, and one host's weak key is not another host's issue.
func TestTheSameSecretOnTwoHostsIsTwoFindings(t *testing.T) {
	fs := NewFindingStore()
	fs.SetDedupPolicy(&DedupPolicy{})

	first := fs.Add(NewFinding{
		Name: "JWT weak HMAC secret", Severity: SeverityHigh, Confidence: ConfidenceCertain,
		Target: FindingTarget{Host: "a.test", Port: 443, TLS: true, Path: "/login"}, MergeKey: "secret",
	})
	second := fs.Add(NewFinding{
		Name: "JWT weak HMAC secret", Severity: SeverityHigh, Confidence: ConfidenceCertain,
		Target: FindingTarget{Host: "b.test", Port: 443, TLS: true, Path: "/login"}, MergeKey: "secret",
	})

	if first == second {
		t.Error("the same secret on two hosts was reported as one finding; the weakness belongs to the " +
			"application that issued the token, so a.test's weak key is not a claim about b.test")
	}
}

// An EMPTY merge key is every row's behaviour before the field existed, and the path-scoped default
// must be untouched by a field that only some rows set.
func TestAnEmptyMergeKeyLeavesTargetKeyingExactlyAsItWas(t *testing.T) {
	fs := NewFindingStore()
	fs.SetDedupPolicy(&DedupPolicy{})
	target := func(path string) FindingTarget {
		return FindingTarget{Host: "app.test", Port: 443, TLS: true, Path: path}
	}

	// Same path -> merges (the pre-existing behaviour).
	same := fs.Add(NewFinding{
		Name: "Reflected XSS", Severity: SeverityHigh, Confidence: ConfidenceCertain, Target: target("/search"),
	})
	if got := fs.Add(NewFinding{
		Name: "Reflected XSS", Severity: SeverityHigh, Confidence: ConfidenceCertain, Target: target("/search"),
	}); got != same {
		t.Errorf("two findings at the same target did not merge (%d vs %d); an empty merge key must "+
			"leave path-scoped keying exactly as it was", same, got)
	}
	// Different path -> does not merge.
	other := fs.Add(NewFinding{
		Name: "Reflected XSS", Severity: SeverityHigh, Confidence: ConfidenceCertain, Target: target("/login"),
	})
	if other == same {
		t.Error("findings at two paths merged; the empty merge key fell back to host granularity " +
			"rather than to the path-scoped default")
	}
}

// The exemptions still apply to a finding that carries a merge key. A row that can never merge is a
// correctness rule, and a new keying input must not become a way around it.
func TestAMergeKeyCannotBypassAnExemption(t *testing.T) {
	fs := NewFindingStore()
	fs.SetDedupPolicy(&DedupPolicy{})

	first := fs.Add(NewFinding{
		Name: "Cross-domain POST", Severity: SeverityMedium, Confidence: ConfidenceFirm,
		Target:   FindingTarget{Host: "app.test", Port: 443, TLS: true, Path: "/a"},
		MergeKey: "anything",
	})
	second := fs.Add(NewFinding{
		Name: "Cross-domain POST", Severity: SeverityMedium, Confidence: ConfidenceFirm,
		Target:   FindingTarget{Host: "app.test", Port: 443, TLS: true, Path: "/b"},
		MergeKey: "anything",
	})
	if first == second {
		t.Error("two Cross-domain POST findings merged on a shared merge key; that row is exempt from " +
			"merging entirely (Zbvp.java:62-64) and a new keying input must not become a way around it")
	}
}

// A merge key still needs a resolved target. A producer that set one and forgot the other would
// otherwise file a hostless finding that merges with every hostless finding of the same row.
func TestAMergeKeyDoesNotSubstituteForAMissingTarget(t *testing.T) {
	fs := NewFindingStore()
	fs.SetDedupPolicy(&DedupPolicy{})

	first := fs.Add(NewFinding{
		Name: "JWT weak HMAC secret", Severity: SeverityHigh, Confidence: ConfidenceCertain,
		MergeKey: "secret",
	})
	second := fs.Add(NewFinding{
		Name: "JWT weak HMAC secret", Severity: SeverityHigh, Confidence: ConfidenceCertain,
		MergeKey: "secret",
	})
	if first == second {
		t.Error("two findings with no target merged on their merge key; the merge key replaces the " +
			"target as a key input, it does not make an unresolved target resolvable")
	}
}
