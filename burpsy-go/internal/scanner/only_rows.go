package scanner

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Row selection by name (ScanConfig.OnlyRows): Burp's scan-configuration "Issues reported → select
// individual issues", keyed by the row name a finding reports rather than by a catalogue type index.
//
// It exists so measuring one check does not cost every family. An audit restricted to one row runs
// only the checks that can report that row; every other check sends nothing and is counted Skipped
// with the reason, so a narrowed audit's silence is never read as a clean bill for the rows it was
// not asked about. Findings the admitted checks — and the passive, JavaScript-analysis and deferred
// stored paths — produce for rows not listed are dropped and counted, because an admitted check that
// reports a second row was not asked to.
//
// Each check declares the rows it can produce (activeCheck.rows): the catalogue row it is registered
// under, plus every burpsy row that rides that descriptor (BurpsyNativeRows). A check that declares
// no row — a loaded corpus BCheck, whose finding names the corpus file chooses — cannot be selected by
// name and is never admitted under a selection; the outcome says so.

// KnownRowNames is every row name ScanConfig.OnlyRows accepts: Burp's catalogue plus burpsy's own rows.
func KnownRowNames() map[string]bool {
	out := make(map[string]bool, len(catalogData)+32)
	for _, d := range catalogData {
		out[d.Name] = true
	}
	for _, r := range BurpsyNativeRows() {
		out[r.Name] = true
	}
	return out
}

// UnknownRows returns the names in rows that are neither a catalogue row nor a burpsy row, sorted and
// de-duplicated. Empty means every name can be selected.
func UnknownRows(rows []string) []string {
	known := KnownRowNames()
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		if !known[r] && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// declaredRows is the row set a check registered under the catalogue row name can report: that row,
// the burpsy rows riding it (BurpsyNativeRows order), then the other catalogue rows it reports
// (alsoReports).
func declaredRows(name string) []string {
	out := []string{name}
	for _, r := range BurpsyNativeRows() {
		if r.Rides == name {
			out = append(out, r.Name)
		}
	}
	return append(out, alsoReports[name]...)
}

// alsoReports are the catalogue rows a check reports besides its own, because the registry admits one
// descriptor per Burp type and a second technique rides an existing one. Found by recording every
// (check, finding row) pair of the runtime corpus; AuditOutcome.undeclaredRows makes that corpus fail
// when a check reports a row missing here, so the table cannot silently fall behind.
var alsoReports = map[string][]string{
	// The active file-upload check (checks_file_upload.go) runs under the stored-XSS descriptor: an
	// uploaded file served back is a stored input. Its two other verdicts are their own Burp rows.
	"Cross-site scripting (stored)": {"File upload functionality", "File path traversal"},
	// The client-IP header check (checks_client_ip.go) reports Burp's informational row for a reflected
	// address, whose registered descriptor is the passive one, beside its own burpsy rows.
	"Broken access control": {"Spoofable client IP address"},
	// The reflected-XSS check files a decoded-before-encoding reflection under the transformation row
	// (checks_core_injection.go) rather than inventing a name for a lesser fact than a breakout.
	// It also files a payload that executes again when the unchanged request is replayed as stored XSS
	// (xss_fragment.go): the replay is what proves storage, and it is the reflected check that sent it.
	"Cross-site scripting (reflected)": {"Suspicious input transformation (reflected)", "Cross-site scripting (stored)"},
	// The password-reset check (checks_pwreset_account.go) files a reset form that answers existing and
	// unknown accounts differently under the login check's enumeration row: it is the same class.
	"SMTP header injection": {"Username enumeration"},
}

// rowSelection is OnlyRows as a set. A nil selection selects everything.
type rowSelection map[string]bool

func newRowSelection(rows []string) rowSelection {
	if len(rows) == 0 {
		return nil
	}
	s := make(rowSelection, len(rows))
	for _, r := range rows {
		s[r] = true
	}
	return s
}

// admits reports whether a finding of this row is reported under the selection.
func (s rowSelection) admits(row string) bool { return s == nil || s[row] }

// filterFindings drops the findings whose row the selection does not list, returning the kept ones
// and how many were dropped. The input slice is not modified.
func (s rowSelection) filterFindings(fs []*Finding) ([]*Finding, int) {
	if s == nil {
		return fs, 0
	}
	kept := make([]*Finding, 0, len(fs))
	dropped := 0
	for _, f := range fs {
		if f == nil {
			continue
		}
		if s[f.Name] {
			kept = append(kept, f)
		} else {
			dropped++
		}
	}
	return kept, dropped
}

// RowNotSelected is one check an audit did not dispatch because ScanConfig.OnlyRows lists none of
// the rows it can report.
type RowNotSelected struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

// RowsNotSelected marshals as [] rather than null, like the outcome's other lists.
type RowsNotSelected []RowNotSelected

// MarshalJSON keeps an empty list a list.
func (r RowsNotSelected) MarshalJSON() ([]byte, error) {
	type plain []RowNotSelected
	if r == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(plain(r))
}

// markRowSelection stamps every check the selection excludes with the reason it was not admitted. The
// checks stay in the set, so their ledger positions and the outcome's Considered() partition are the
// same as an unfiltered run's; plan() leaves them out and auditItem counts them Skipped. An empty
// selection returns the set unchanged.
func markRowSelection(checks []activeCheck, rows []string) []activeCheck {
	sel := newRowSelection(rows)
	if sel == nil {
		return checks
	}
	out := make([]activeCheck, len(checks))
	copy(out, checks)
	for i := range out {
		c := &out[i]
		if len(c.rows) == 0 {
			c.rowSkip = "declares no issue row it can report, so only_rows cannot select it"
			continue
		}
		hit := false
		for _, r := range c.rows {
			if sel[r] {
				hit = true
				break
			}
		}
		if !hit {
			c.rowSkip = fmt.Sprintf("only_rows lists none of the rows it can report (%s)", strings.Join(c.rows, "; "))
		}
	}
	return out
}

// declares reports whether row is one of the rows c can report. A check with no declaration (a corpus
// BCheck) declares every row, because there is nothing to hold it to.
func (c activeCheck) declares(row string) bool {
	if c.rows == nil {
		return true
	}
	for _, r := range c.rows {
		if r == row {
			return true
		}
	}
	return false
}
