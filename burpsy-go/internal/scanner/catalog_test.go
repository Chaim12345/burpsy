package scanner

import (
	"sort"
	"strings"
	"testing"
)

func Test_catalog_is_sorted_by_type_index_and_unique(t *testing.T) {
	if len(catalogData) != 183 {
		t.Fatalf("catalog has %d issues, want 183", len(catalogData))
	}
	for i := 1; i < len(catalogData); i++ {
		if catalogData[i].TypeIndex <= catalogData[i-1].TypeIndex {
			t.Fatalf("catalog not strictly ascending at index %d: %d then %d",
				i, catalogData[i-1].TypeIndex, catalogData[i].TypeIndex)
		}
	}
	if !sort.SliceIsSorted(catalogData, func(a, b int) bool {
		return catalogData[a].TypeIndex < catalogData[b].TypeIndex
	}) {
		t.Fatalf("catalog is not sorted (binary search would be unsound)")
	}
}

func Test_by_type_index_finds_a_known_shipped_issue(t *testing.T) {
	// 0x00100200_SqlInjection.json => 0x00100200
	d, ok := ByTypeIndex(0x00100200)
	if !ok {
		t.Fatalf("ByTypeIndex(0x00100200) found nothing, want SQL injection")
	}
	if d.Name != "SQL injection" {
		t.Errorf("name = %q, want the shipped name", d.Name)
	}
	if d.TypicalSeverity != "high" {
		t.Errorf("typical severity = %q, want the shipped HIGH", d.TypicalSeverity)
	}
	if !d.HasRemediation() {
		t.Errorf("SQL injection must ship remediation text")
	}
	if !strings.Contains(d.Remediation, "parameterized queries") {
		t.Errorf("remediation must be the shipped text, not a paraphrase: %.80s", d.Remediation)
	}
	if !strings.Contains(d.Description, "SQL injection") {
		t.Errorf("description must be the shipped text: %.80s", d.Description)
	}
}

func Test_by_type_index_returns_false_for_an_unknown_id(t *testing.T) {
	if _, ok := ByTypeIndex(0x00000001); ok {
		t.Fatalf("ByTypeIndex(1) reported an issue where none exists")
	}
}

func Test_by_name_finds_an_issue_by_its_catalogued_name(t *testing.T) {
	d, ok := ByName("OS command injection")
	if !ok {
		t.Fatalf("ByName('OS command injection') found nothing")
	}
	if d.TypeIndex != 0x00100100 {
		t.Errorf("type index = %d, want 0x00100100", d.TypeIndex)
	}
}

func Test_every_entry_round_trips_through_by_type_index(t *testing.T) {
	// The binary search must agree with the slice it searches: each entry's own ID resolves back
	// to that entry, and that entry is the only one the ID resolves to.
	for _, d := range catalogData {
		got, ok := ByTypeIndex(d.TypeIndex)
		if !ok {
			t.Fatalf("ByTypeIndex(%d) missed an entry that is present", d.TypeIndex)
		}
		if got.TypeIndex != d.TypeIndex || got.Name != d.Name {
			t.Fatalf("ByTypeIndex(%d) returned a different entry", d.TypeIndex)
		}
	}
}

func Test_the_two_stale_declared_type_indexes_are_kept_verbatim_not_reconciled(t *testing.T) {
	var disagree int
	for _, d := range catalogData {
		if d.TypeIndex != d.DeclaredTypeIndex {
			disagree++
		}
	}
	if disagree != 2 {
		t.Errorf("found %d issues where TypeIndex != DeclaredTypeIndex, want the shipped 2", disagree)
	}
}

func Test_provenance_meta_counts_match_the_generated_data(t *testing.T) {
	// The generated meta is written by the generator from the same pass as the data, so a
	// mismatching hand-edit of either side is caught here rather than reported as healthy.
	p := Provenance()
	if p.Issues != len(catalogData) {
		t.Errorf("Provenance.Issues = %d, data has %d", p.Issues, len(catalogData))
	}
	withRemed, withoutRemed := 0, 0
	for _, d := range catalogData {
		if d.HasRemediation() {
			withRemed++
		} else {
			withoutRemed++
		}
	}
	if p.Declared != withRemed || p.WithoutRemed != withoutRemed {
		t.Errorf("provenance remedy counts = declared:%d/without:%d, data is %d/%d",
			p.Declared, p.WithoutRemed, withRemed, withoutRemed)
	}
}

func Test_cwe_and_capec_ids_are_parsed_from_classification_titles(t *testing.T) {
	// SQL injection classifies as CWE-89 and CWE-20 plus CAPECs, in the shipped order.
	d, ok := ByTypeIndex(0x00100200)
	if !ok {
		t.Fatalf("SQL injection missing from catalog")
	}
	cwes := d.CWEs()
	if len(cwes) == 0 || cwes[0] != 89 {
		t.Errorf("first CWE id = %v, want 89 (CWE-89 must be parsed from its title)", cwes)
	}
	capecs := d.CAPECs()
	if len(capecs) == 0 {
		t.Errorf("expected at least one CAPEC id for SQL injection, got none")
	}
}

// Test_single_owasp_classification_has_no_cwe_or_capec covers the one non-CWE/CAPEC entry without
// coupling to which entry it is.
func Test_some_classification_is_not_a_cwe_or_capec_and_parses_to_nothing(t *testing.T) {
	sawNonCWE := false
	for _, d := range catalogData {
		for _, c := range d.Classifications {
			if !strings.Contains(c.Title, "CWE-") && !strings.Contains(c.Title, "CAPEC-") {
				sawNonCWE = true
				if len(c.CWEs()) != 0 || len(c.CAPECs()) != 0 {
					t.Errorf("non-CWE/CAPEC classification %q parsed ids: CWE=%v CAPEC=%v",
						c.Title, c.CWEs(), c.CAPECs())
				}
			}
		}
	}
	if !sawNonCWE {
		t.Errorf("expected the single OWASP-style classification to exist")
	}
}
