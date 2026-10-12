package scanner

// burpsy's own issue rows: classes a burpsy check reports that Burp's catalogue has no entry for.
//
// They are not catalogue rows. catalog_data.go is Burp's transcribed catalogue and stays exactly 183
// entries, and the registry admits one descriptor per Burp type, so a burpsy row is reported by a
// check that rides an existing Burp descriptor (Rides) behind its own switch. Each row's advisory —
// description, remediation, CWE — is a burpsy-authored definition in internal/advisory/native, which
// is what attaches the CWE to the finding; burpsy_rows_test.go keeps the two in step.

// BurpsyRow is one burpsy-only issue row.
type BurpsyRow struct {
	// Name is the finding name the check reports and the native advisory definition's name.
	Name string
	// TypeIndex is the native advisory definition's index (0xb5xxxxxx), never a Burp index.
	TypeIndex uint32
	// CWE is the row's primary classification.
	CWE uint32
	// Rides is the Burp catalogue descriptor the reporting check is dispatched under.
	Rides string
	// Why records why Burp's catalogue has no row for this class.
	Why string
}

// BurpsyNativeRows lists burpsy's own rows.
func BurpsyNativeRows() []BurpsyRow {
	return []BurpsyRow{{
		Name:      idorIssue,
		TypeIndex: 0xb5000100,
		CWE:       639,
		Rides:     "Broken access control",
		Why: "Burp's catalogue has no insecure-direct-object-reference row: Burp leaves object-level " +
			"authorization to the Autorize and AuthMatrix extensions, whose issues carry the generic " +
			"extension-generated type. Its 'Broken access control' row (CWE-284) is the ancestor class.",
	}}
}
