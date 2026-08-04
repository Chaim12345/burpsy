package crawler

import (
	"strings"
	"testing"
)

// TestCrawl04SignalTableCoversTheNamedClasses walks the classes CRAWL-04 names explicitly —
// logout/signout, delete/remove/destroy, purge/empty-trash, deactivate/close-account, admin
// plugin-install, and state-changing verbs — against both a URL spelling and a link-text spelling of
// each. Table-driven because the requirement is a list, and a list requirement wants a test that
// visibly covers every item on it.
func TestCrawl04SignalTableCoversTheNamedClasses(t *testing.T) {
	cases := []struct {
		name   string
		target string
		text   string
		want   Skip
	}{
		// logout / signout, in URL and in text, with every separator spelling.
		{"logout path", "http://h/logout", "", SkipDestructiveLogout},
		{"log-out path", "http://h/log-out", "", SkipDestructiveLogout},
		{"log_out path", "http://h/log_out", "", SkipDestructiveLogout},
		{"logOut camel path", "http://h/user/logOut", "", SkipDestructiveLogout},
		{"signout path", "http://h/signout", "", SkipDestructiveLogout},
		{"sign out text", "http://h/x/9", "Sign out", SkipDestructiveLogout},
		{"log out text", "http://h/x/9", "Log Out", SkipDestructiveLogout},
		{"logoff path", "http://h/logoff", "", SkipDestructiveLogout},
		{"sessions destroy", "http://h/sessions/destroy", "", SkipDestructiveLogout},
		{"logout in query", "http://h/go?next=/logout", "", SkipDestructiveLogout},

		// delete / remove / destroy.
		{"delete path", "http://h/items/8/delete", "", SkipDestructiveDelete},
		{"deleteItem camel", "http://h/api/deleteItem", "", SkipDestructiveDelete},
		{"remove path", "http://h/cart/remove/3", "", SkipDestructiveDelete},
		{"destroy path", "http://h/records/destroy", "", SkipDestructiveDelete},
		{"delete in query", "http://h/act?action=delete&id=3", "", SkipDestructiveDelete},
		{"delete text only", "http://h/items/8", "Delete", SkipDestructiveDelete},
		{"remove text only", "http://h/items/8", "Remove from list", SkipDestructiveDelete},
		{"percent-encoded delete", "http://h/items%2Fdelete", "", SkipDestructiveDelete},

		// purge / empty trash.
		{"purge path", "http://h/cache/purge", "", SkipDestructivePurge},
		{"empty-trash path", "http://h/mail/empty-trash", "", SkipDestructivePurge},
		{"emptyTrash camel", "http://h/mail/emptyTrash", "", SkipDestructivePurge},
		{"empty trash text", "http://h/mail/act/7", "Empty Trash", SkipDestructivePurge},
		{"truncate path", "http://h/db/truncate", "", SkipDestructivePurge},

		// deactivate / close account.
		{"deactivate path", "http://h/account/deactivate", "", SkipDestructiveDeactivate},
		{"close-account path", "http://h/close-account", "", SkipDestructiveDeactivate},
		{"close account text", "http://h/a/1", "Close account", SkipDestructiveDeactivate},
		{"disable path", "http://h/user/9/disable", "", SkipDestructiveDeactivate},
		{"unsubscribe path", "http://h/unsubscribe?t=9", "", SkipDestructiveDeactivate},

		// admin plugin install and friends.
		{"plugin-install path", "http://h/admin/plugin-install", "", SkipDestructiveAdminPlugin},
		{"install plugin query", "http://h/plugins.php?action=install&p=x", "", SkipDestructiveAdminPlugin},
		{"update-core path", "http://h/wp-admin/update-core.php", "", SkipDestructiveAdminPlugin},
		{"upgrade path", "http://h/admin/upgrade", "", SkipDestructiveAdminPlugin},
		{"setup path", "http://h/setup", "", SkipDestructiveAdminPlugin},
		{"shutdown text", "http://h/ops/9", "Shut down", SkipDestructiveAdminPlugin},

		// state-changing verbs, in text as well as target.
		{"reset path", "http://h/password/reset", "", SkipDestructiveStateChange},
		{"revoke path", "http://h/tokens/4/revoke", "", SkipDestructiveStateChange},
		{"approve text", "http://h/requests/4", "Approve", SkipDestructiveStateChange},
		{"publish text", "http://h/posts/4", "Publish now", SkipDestructiveStateChange},
		{"cancel path", "http://h/orders/4/cancel", "", SkipDestructiveStateChange},
		{"transfer text", "http://h/x", "Transfer ownership", SkipDestructiveStateChange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := classifyDestructive(tc.target, tc.text)
			if !v.Refused {
				t.Fatalf("classifyDestructive(%q, %q) did not refuse", tc.target, tc.text)
			}
			if v.Reason != tc.want {
				t.Errorf("classified as %s, want %s (signal %q)", v.Reason, tc.want, v.Signal)
			}
			if v.Signal == "" {
				t.Error("a refusal must name the signal that matched")
			}
			// The signal says where it matched, which is what makes the ledger reviewable.
			if !strings.HasSuffix(v.Signal, "(target)") && !strings.HasSuffix(v.Signal, "(text)") {
				t.Errorf("signal %q does not say whether the target or the text matched", v.Signal)
			}
		})
	}
}

// TestCrawl04TokenRunMatchingDoesNotRefuseOrdinaryPaths is the false-positive half. Every string here
// contains a signal as a substring and must not be refused, because a check that refuses `/presets`
// trains its operator to ignore it.
func TestCrawl04TokenRunMatchingDoesNotRefuseOrdinaryPaths(t *testing.T) {
	fine := []struct{ target, text string }{
		{"http://h/user/presets", ""},                    // "reset" inside "presets"
		{"http://h/cancellation-policy", ""},             // "cancel" inside "cancellation"
		{"http://h/undeleted-items", ""},                 // "delete" inside "undeleted"
		{"http://h/blog/removalists", ""},                // "remove" inside "removalists"
		{"http://h/catalogue", ""},                       // "logout"-adjacent noise
		{"http://h/products/banana", ""},                 // "ban" inside "banana"
		{"http://h/disabled-features-guide", ""},         // "disable" inside "disabled"
		{"http://h/articles/9", "Read about deletion"},   // "delete" is not "deletion"
		{"http://h/docs/installation-notes", ""},         // "install" inside "installation"
		{"http://h/help", "Confirmation email settings"}, // "confirm" is not "confirmation"
		{"http://h/", "Home"},
		{"http://h/about", "About us"},
		{"http://h/search?q=shoes", "Search"},
	}
	for _, tc := range fine {
		if v := classifyDestructive(tc.target, tc.text); v.Refused {
			t.Errorf("classifyDestructive(%q, %q) refused on signal %q; it should not have",
				tc.target, tc.text, v.Signal)
		}
	}
}

// TestCrawl04SpecificClassWinsOverTheGeneralVerb pins the table's ordering contract: a link that
// matches both a named class and the catch-all verb list reports as the named class, because that is
// the more actionable of the two facts.
func TestCrawl04SpecificClassWinsOverTheGeneralVerb(t *testing.T) {
	// "cancel account" is in the deactivate class and "cancel" alone is in the state-change class.
	if v := classifyDestructive("http://h/cancel-account", ""); v.Reason != SkipDestructiveDeactivate {
		t.Errorf("cancel-account classified as %s, want %s", v.Reason, SkipDestructiveDeactivate)
	}
	// "sessions destroy" is logout; "destroy" alone is delete.
	if v := classifyDestructive("http://h/sessions/destroy", ""); v.Reason != SkipDestructiveLogout {
		t.Errorf("sessions/destroy classified as %s, want %s", v.Reason, SkipDestructiveLogout)
	}
}

// TestCrawl04TargetMatchIsReportedOverTextMatch pins that a URL match wins the label, since the URL
// describes the request that would actually be sent.
func TestCrawl04TargetMatchIsReportedOverTextMatch(t *testing.T) {
	v := classifyDestructive("http://h/items/1/delete", "Log out")
	if v.Reason != SkipDestructiveDelete {
		t.Fatalf("classified as %s, want the target's %s", v.Reason, SkipDestructiveDelete)
	}
	if !strings.HasSuffix(v.Signal, "(target)") {
		t.Errorf("signal %q should attribute the match to the target", v.Signal)
	}
}

func TestTokeniseSplitsSeparatorsAndCamelHumps(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"logout", []string{"logout"}},
		{"log-out", []string{"log", "out"}},
		{"log_out", []string{"log", "out"}},
		{"logOut", []string{"log", "out"}},
		{"Log Out", []string{"log", "out"}},
		{"/api/v2/records/8814/delete", []string{"api", "v2", "records", "8814", "delete"}},
		{"HTTPDelete", []string{"http", "delete"}},
		{"http://h/a?b=c&d=e", []string{"http", "h", "a", "b", "c", "d", "e"}},
		{"", nil},
		{"---", nil},
	}
	for _, tc := range cases {
		got := tokenise(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("tokenise(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("tokenise(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}

// TestSkipLedgerAccountsForEveryReason is the honest-counting invariant, in the shape
// scanner.CoverageReport.Partition's test has: every reason has a slot, a name, an explanation and a
// category, the slots are distinct, and the per-category rollup sums to the per-reason total. A
// reason added to the enum without being wired into all four fails here rather than silently
// under-reporting.
func TestSkipLedgerAccountsForEveryReason(t *testing.T) {
	seen := map[int]Skip{}
	for _, s := range SkipAll {
		slot := s.slot()
		if prev, dup := seen[slot]; dup {
			t.Fatalf("%s and %s share slot %d", prev, s, slot)
		}
		seen[slot] = s
		if s.String() == "unknown" {
			t.Errorf("skip at slot %d has no name", slot)
		}
		if s.Explanation() == "unknown skip" {
			t.Errorf("%s has no explanation", s)
		}
		// Category panics on an unhandled reason, which is the point: it must be total.
		_ = s.Category()
	}
	if len(seen) != len(SkipAll) {
		t.Fatalf("%d reasons occupy %d slots", len(SkipAll), len(seen))
	}

	// One of each reason through the ledger, then check the two rollups agree.
	l := newSkipLedger(len(SkipAll))
	for _, s := range SkipAll {
		l.record(SkipRecord{Reason: s, URL: "http://h/" + s.String()})
	}
	rep := l.Snapshot()
	if rep.Total() != uint64(len(SkipAll)) {
		t.Fatalf("total is %d, want %d", rep.Total(), len(SkipAll))
	}
	var summed uint64
	for _, c := range rep.Categories {
		summed += c.Count
	}
	if summed != rep.Total() {
		t.Fatalf("the per-category rollup sums to %d but the per-reason total is %d", summed, rep.Total())
	}
	// Every reason is reported, including the zeroes — a reason that never fired must be a visible
	// zero and not an absent row.
	if len(rep.Counts) != len(SkipAll) {
		t.Fatalf("the report has %d rows for %d reasons", len(rep.Counts), len(SkipAll))
	}
	if got := rep.CategoryTotal(CategoryDestructive); got != 6 {
		t.Errorf("six destructive reasons should roll up to 6, got %d", got)
	}
}

// TestSkipLedgerCountsRecordsItDropped pins that the record cap is a cap on detail and never on the
// counts.
func TestSkipLedgerCountsRecordsItDropped(t *testing.T) {
	l := newSkipLedger(2)
	for i := 0; i < 10; i++ {
		l.record(SkipRecord{Reason: SkipAlreadyQueued, URL: "http://h/x"})
	}
	rep := l.Snapshot()
	if rep.Count(SkipAlreadyQueued) != 10 {
		t.Fatalf("count is %d, want the exact 10", rep.Count(SkipAlreadyQueued))
	}
	if len(rep.Records) != 2 {
		t.Fatalf("kept %d records, want the cap of 2", len(rep.Records))
	}
	if rep.RecordsDropped != 8 {
		t.Fatalf("dropped count is %d, want 8 — a dropped record is counted, never silently absent", rep.RecordsDropped)
	}
}

// TestCrawlStopsAllHaveNamesAndExplanations is the same totality check for the stop enum.
func TestCrawlStopsAllHaveNamesAndExplanations(t *testing.T) {
	for _, s := range CrawlStopAll {
		if s.String() == "unknown" {
			t.Errorf("stop %d has no name", int(s))
		}
		if s.Explanation() == "unknown stop" {
			t.Errorf("stop %s has no explanation", s)
		}
	}
	// Every stop must reach Caveat, or a bound could be hit without the caveat mentioning it.
	var r LimitReport
	for _, s := range CrawlStopAll {
		r.record(s)
	}
	caveat := r.Caveat()
	for _, s := range CrawlStopAll {
		if !strings.Contains(caveat, s.Explanation()) {
			t.Errorf("Caveat does not mention the %s stop", s)
		}
	}
	// record is idempotent per stop: a bound hit a hundred times is one entry.
	before := len(r.Stops)
	r.record(CrawlStopAll[0])
	if len(r.Stops) != before {
		t.Error("record must add each stop at most once")
	}
}
