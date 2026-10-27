package scanner

// burpsy's own ORM and driver error-signature bank (burpsy-react-ui-v0ei.9).
//
// Burp's recovered substring bank (SQLErrorSignatures) and sqlmap's per-DBMS regexes
// (sqlmap_errors.go) both name DATABASES. An application behind an ORM often relays the ORM's or
// the driver's error instead — Hibernate's QuerySyntaxException, SequelizeDatabaseError,
// sqlalchemy.exc.ProgrammingError, EF Core's DbUpdateException, ActiveRecord::StatementInvalid,
// django.db.utils.* — and a quote probe that provokes exactly that matched NEITHER bank. These are
// burpsy's own entries (v0ei's licence decision covers sqlmap's data, not these frameworks'
// wording): each is the class name or message shape the framework itself emits, matched as a plain
// substring, and each names its ORM; where the driver names the database (psycopg2, Npgsql, the
// SqlClients, PG::, Mysql2) the DBMS is attributed too.
//
// # The evidence rules are the other banks', unchanged
//
//   - a signature counts only when the injected response carries it and the baseline does not
//     (baseline-differs; ClassifyErrorEvidence's rule);
//   - matching runs over the body as received and HTML-unescaped (matchableForms);
//   - a signature every occurrence of which sits on a shell's own diagnostic line is the shell's,
//     recorded Foreign (signatureOwnedByShell, the shell-attribution rule).
//
// The bank adds signatures; it never relaxes the rule.

import "strings"

// ORMErrorSignature is one framework/driver signature: the substring it matches, the ORM or driver
// it names, and the DBMS where the signature names one ("" when it does not).
type ORMErrorSignature struct {
	Substring string
	ORM       string
	DBMS      string
}

// Label names the signature in a probe's detail: the ORM and the matched wording, attributed.
func (s ORMErrorSignature) Label() string {
	if s.DBMS != "" {
		return s.ORM + " (" + s.DBMS + ") error '" + s.Substring + "' (burpsy ORM bank)"
	}
	return s.ORM + " error '" + s.Substring + "' (burpsy ORM bank)"
}

// ormErrorSignatures is the bank. Additions must name the framework's own class or message shape;
// a signature one vendor's sample app happens to print does not belong here.
var ormErrorSignatures = []ORMErrorSignature{
	// Hibernate / HQL (Java). The HQL parser's own exceptions; the 3.x and 5+/6 package spellings.
	{Substring: "org.hibernate.exception.SQLGrammarException", ORM: "Hibernate (HQL)"},
	{Substring: "org.hibernate.QueryException", ORM: "Hibernate (HQL)"},
	{Substring: "org.hibernate.hql.internal.ast.QuerySyntaxException", ORM: "Hibernate (HQL)"},
	{Substring: "org.hibernate.hql.ast.QuerySyntaxException", ORM: "Hibernate (HQL)"},
	{Substring: "QuerySyntaxException: unexpected token", ORM: "Hibernate (HQL)"},
	{Substring: "java.sql.SQLSyntaxErrorException", ORM: "JDBC"},

	// Sequelize (Node). Its wrapped-database error class and dialect stack frames.
	{Substring: "SequelizeDatabaseError", ORM: "Sequelize"},
	{Substring: "sequelize/lib/dialects", ORM: "Sequelize"},

	// SQLAlchemy and the Python drivers it relays.
	{Substring: "sqlalchemy.exc.ProgrammingError", ORM: "SQLAlchemy"},
	{Substring: "sqlalchemy.exc.OperationalError", ORM: "SQLAlchemy"},
	{Substring: "sqlalchemy.exc.DatabaseError", ORM: "SQLAlchemy"},
	{Substring: "(psycopg2.errors.SyntaxError)", ORM: "SQLAlchemy (psycopg2)", DBMS: "PostgreSQL"},
	{Substring: "psycopg2.errors.", ORM: "psycopg2", DBMS: "PostgreSQL"},
	{Substring: "MySQLdb._exceptions.", ORM: "mysqlclient", DBMS: "MySQL"},
	{Substring: "pymysql.err.", ORM: "PyMySQL", DBMS: "MySQL"},

	// EF Core and the .NET drivers.
	{Substring: "Microsoft.EntityFrameworkCore.DbUpdateException", ORM: "EF Core"},
	{Substring: "System.Data.SqlClient.SqlException", ORM: "System.Data.SqlClient", DBMS: "Microsoft SQL Server"},
	{Substring: "Microsoft.Data.SqlClient.SqlException", ORM: "Microsoft.Data.SqlClient", DBMS: "Microsoft SQL Server"},
	{Substring: "Npgsql.NpgsqlException", ORM: "Npgsql", DBMS: "PostgreSQL"},
	{Substring: "Npgsql.PostgresException", ORM: "Npgsql", DBMS: "PostgreSQL"},
	{Substring: "MySql.Data.MySqlClient.MySqlException", ORM: "MySql.Data", DBMS: "MySQL"},

	// ActiveRecord (Rails) and the Ruby drivers it relays.
	{Substring: "ActiveRecord::StatementInvalid", ORM: "ActiveRecord"},
	{Substring: "PG::SyntaxError", ORM: "ActiveRecord (pg)", DBMS: "PostgreSQL"},
	{Substring: "Mysql2::Error", ORM: "ActiveRecord (mysql2)", DBMS: "MySQL"},
	{Substring: "SQLite3::SQLException", ORM: "ActiveRecord (sqlite3)", DBMS: "SQLite"},

	// Django ORM (its database errors all live under django.db.utils).
	{Substring: "django.db.utils.ProgrammingError", ORM: "Django ORM"},
	{Substring: "django.db.utils.OperationalError", ORM: "Django ORM"},
	{Substring: "django.db.utils.DatabaseError", ORM: "Django ORM"},
}

// ORMErrorSignatures returns the bank, for the coverage test and for nothing else: the classifier
// reads the package-level slice directly.
func ORMErrorSignatures() []ORMErrorSignature {
	return ormErrorSignatures
}

// addORMErrorEvidence folds the ORM bank into ev under the substring bank's rules and recomputes
// the verdict. ev is the earlier banks' result for the same pair of bodies.
func addORMErrorEvidence(ev ErrorEvidence, baselineBody, injectedBody string) ErrorEvidence {
	baseForms := matchableForms(baselineBody)
	injForms := matchableForms(injectedBody)
	for _, s := range ormErrorSignatures {
		needle := strings.ToLower(s.Substring)
		if !containsAny(injForms, needle) {
			continue
		}
		switch {
		case containsAny(baseForms, needle):
			ev.Preexisting = append(ev.Preexisting, s.Label())
		case signatureOwnedByShell(injectedBody, s.Substring):
			ev.Foreign = append(ev.Foreign, s.Label())
		default:
			ev.Matched = append(ev.Matched, s.Label())
			if s.DBMS != "" {
				ev.DBMS = appendUnique(ev.DBMS, s.ORM+" ("+s.DBMS+")")
			}
		}
	}
	switch {
	case len(ev.Matched) > 0:
		ev.Evidence = InjectionEvidenceErrorSignature
	case len(ev.Preexisting) > 0:
		ev.Evidence = InjectionEvidenceInconclusive
	default:
		ev.Evidence = InjectionEvidenceNone
	}
	return ev
}

// ormErrorInBody is the no-sender read of the bank: the first signature the captured body carries
// outside a shell diagnostic, as its label.
func ormErrorInBody(body string) (string, bool) {
	forms := matchableForms(body)
	for _, s := range ormErrorSignatures {
		needle := strings.ToLower(s.Substring)
		if containsAny(forms, needle) && !signatureOwnedByShell(body, s.Substring) {
			return s.Label(), true
		}
	}
	return "", false
}
