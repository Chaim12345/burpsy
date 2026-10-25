package scanner

// burpsy's ORM/driver bank (v0ei.9) under the two standing rules: a signature counts only when the
// probe introduced it (baseline-differs), and one a shell diagnostic owns is Foreign, never evidence.

import (
	"strings"
	"testing"
)

// Each ORM/driver family the bead names is in the bank, and each bank entry names its ORM and,
// where the driver names one, its DBMS.
func TestORMErrorBankCoversTheNamedFrameworks(t *testing.T) {
	bank := ORMErrorSignatures()
	byORM := map[string]bool{}
	for _, p := range bank {
		byORM[p.ORM] = true
	}
	for _, orm := range []string{
		"Hibernate (HQL)", "Sequelize", "SQLAlchemy", "EF Core", "ActiveRecord", "Django ORM",
	} {
		if !byORM[orm] {
			t.Errorf("bank has no %s signature", orm)
		}
	}
	var withDBMS int
	for _, p := range bank {
		if p.DBMS != "" {
			withDBMS++
		}
	}
	if withDBMS == 0 {
		t.Error("no bank entry names its DBMS")
	}
}

// An introduced ORM error is error-signature evidence, labelled with its ORM; a driver error that
// names its database lands in DBMS.
func TestORMErrorIntroducedIsEvidenceNamingItsORM(t *testing.T) {
	baseline := "<html><body>results for widget</body></html>"
	injected := `<html><body>org.hibernate.hql.internal.ast.QuerySyntaxException: unexpected token: ' near line 1, column 42</body></html>`
	ev := ClassifySQLError(baseline, injected)
	if !ev.Evidence.Confirms() {
		t.Fatalf("introduced Hibernate error did not confirm: %v", ev.Evidence)
	}
	joined := strings.Join(ev.Matched, "\n")
	if !strings.Contains(joined, "Hibernate") {
		t.Errorf("matched signatures do not name Hibernate: %s", joined)
	}
}

func TestORMErrorNamingItsDBMSAttributesTheEngine(t *testing.T) {
	baseline := "<html><body>ok</body></html>"
	injected := `<html><body>(psycopg2.errors.SyntaxError) syntax error at or near "'"
LINE 1: SELECT * FROM items WHERE id = '1''
</body></html>`
	ev := ClassifySQLError(baseline, injected)
	if !ev.Evidence.Confirms() {
		t.Fatalf("introduced psycopg2 error did not confirm: %v", ev.Evidence)
	}
	found := false
	for _, d := range ev.DBMS {
		if strings.Contains(d, "PostgreSQL") {
			found = true
		}
	}
	if !found {
		t.Errorf("DBMS attribution lacks PostgreSQL: %v", ev.DBMS)
	}
}

// A signature the baseline already carried decides nothing.
func TestORMErrorInBaselineIsInconclusive(t *testing.T) {
	body := "<html><body>django.db.utils.ProgrammingError: relation \"items\" does not exist</body></html>"
	ev := ClassifySQLError(body, body)
	if ev.Evidence.Confirms() {
		t.Errorf("a pre-existing Django error confirmed")
	}
	if len(ev.Preexisting) == 0 {
		t.Errorf("the pre-existing signature was not recorded: %+v", ev)
	}
}

// A shell's own diagnostic line that happens to carry an ORM class name is the shell's, not the
// ORM's: the attribution rule removes it from evidence.
func TestORMErrorOwnedByAShellLineIsForeign(t *testing.T) {
	baseline := "<html><body>ok</body></html>"
	injected := "sh: 1: SequelizeDatabaseError"
	ev := ClassifySQLError(baseline, injected)
	if ev.Evidence.Confirms() {
		t.Errorf("a shell-owned Sequelize mention confirmed: %+v", ev)
	}
	if len(ev.Foreign) == 0 {
		t.Errorf("the shell-owned mention was not recorded foreign: %+v", ev)
	}
}

// The offline (captured-body) read reports an ORM signature with its ORM named.
func TestORMOfflineSignatureNamesTheORM(t *testing.T) {
	label, ok := ormErrorInBody(`{"detail":"ActiveRecord::StatementInvalid: PG::SyntaxError: ERROR:  syntax error"}`)
	if !ok {
		t.Fatal("no ORM signature read from the captured body")
	}
	if !strings.Contains(label, "ActiveRecord") {
		t.Errorf("label %q does not name ActiveRecord", label)
	}
}
