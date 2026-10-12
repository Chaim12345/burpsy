# sqlmap data

`errors.xml` and `LICENSE` are copied verbatim from sqlmap
(https://github.com/sqlmapproject/sqlmap, `data/xml/errors.xml` and `LICENSE`, fetched
2026-10-12, sha256 of errors.xml
`7a2ca9768bde1e6b23d44c015e5694d5c3e5931f376657c96bfc84040ff1a6d6`).

sqlmap is (C) 2006-2026 Bernardo Damele Assumpcao Guimaraes and Miroslav Stampar, distributed
under the GNU General Public License version 2 or later with the clarifications in `LICENSE`.
That licence treats a program that reads sqlmap's data files as a derived work. burpsy embeds
`errors.xml` (`../sqlmap_errors.go`) and is itself licensed GPL-3.0-or-later (the repository's
`LICENSE`), which sqlmap's "version 2 or later" grant permits. Keep both files and this notice
with any copy of the bank.

The file is used as data only: each `<error regexp=... fork=...>` row under a `<dbms value=...>`
is compiled case-insensitively and matched against a probe's response under burpsy's own
evidence rules (a match the baseline already carried is not evidence; a match on a command
shell's own diagnostic line is not evidence). See `../sqlmap_errors.go`.

To update: replace `errors.xml` with the upstream file and update the hash above.
`TestSqlmapErrorPatternsLoad` fails if a pattern stops compiling under Go's RE2 syntax or the
bank shrinks.
