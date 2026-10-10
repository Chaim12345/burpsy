# sqlmap data (GPL — not covered by burpsy's own licence)

`errors.xml` is copied verbatim from sqlmap (`data/xml/errors.xml`,
https://github.com/sqlmapproject/sqlmap), (C) 2006-2026 Bernardo Damele Assumpcao Guimaraes and
Miroslav Stampar, distributed under the GNU GPL version 2 or later with the clarifications in
`LICENSE` (sqlmap's own licence file, also copied verbatim).

sqlmap's licence treats a program that "reads or includes sqlmap copyrighted data files" as a
derived work. burpsy embeds this file (`sqlmap_errors.go`), so **a burpsy binary built from this
tree is a derived work of sqlmap**. It was added for private, non-commercial research while the
project's licence is undecided (2026-10-10). Before burpsy is distributed in any form, either
license burpsy under GPL-3.0-or-later (compatible with sqlmap's "or later" grant and with the
Apache-2.0 ZAP strings in `../infra_injection_payloads.go`) or delete this directory and
`../sqlmap_errors.go`; nothing else depends on it.

To update: replace `errors.xml` with the upstream file. `TestSqlmapErrorPatternsLoad` fails if a
pattern stops compiling under Go's RE2 syntax.
