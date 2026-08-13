# Java SQL Injection Port Evidence

Sources:

- `/root/burp-re/out/clean/root/Zegp.java` — SQLi strategy base.
- `/root/burp-re/out/clean/root/Zegy.java` — MySQL strategy wiring.
- `/root/burp-re/out/clean/root/Zegc.java` — Oracle strategy wiring.
- `/root/burp-re/out/clean/root/Zegg.java` — MSSQL strategy wiring.
- `/root/burp-re/out/clean/root/Zeoh.java` — MySQL payload construction and speed gates.
- `/root/burp-re/out/clean/root/Zpl5.java` — Oracle payload construction.
- `/root/burp-re/out/clean/root/Zwk6.java` — MSSQL payload suffix families.
- `/root/burp-re/out/clean/root/Zh6.java` — result/evidence classification.

## Java coverage recovered

The Java implementation is not a seven-payload error scanner. It has strategy families:

- MySQL: numeric/string SQLi and numeric/string ORDER BY payloads.
- Oracle: numeric/string SQLi and comma/ORDER BY-oriented payloads.
- MSSQL: raw, one-column, two-column, three-column, four-column, and nested-function numeric/string payloads.
- Collaborator-backed OOB variants for Oracle, MSSQL, and MySQL. These use XML external entity, `xp_dirtree`, `load_file`, and file-write primitives.

Java's result evaluator (`Zh6`) recognizes these evidence classes:

| Bit | Evidence |
|---:|---|
| 16 | database error returned for a payload |
| 32 | single quote caused a database error, escaped quote removed it |
| 64 | single quote caused a general error, escaped quote removed it |
| 128 | true/false subqueries produced different responses |
| 256 | ORDER BY subqueries produced different responses |
| 512 | Oracle OOB interaction |
| 1024 | MSSQL `xp_dirtree` OOB interaction |
| 2048 | MySQL `load_file` OOB interaction |
| 4096 | database write-to-file OOB interaction |

The strategy is enabled only when the DB-specific and Collaborator-based SQLi capabilities are selected, and it also has a second-order variant for `SQL_INJECTION_2ND_ORDER`.

## Go port decision

BurpSy keeps the Java evidence model but uses Go-native boundaries:

1. Payload families are immutable package data, not per-exchange allocations.
2. Probe execution remains behind the existing sender/scope/meter chokepoint.
3. Error, quote-pair, boolean-difference, and ORDER BY-difference evidence are implemented locally.
4. OOB evidence is explicit unsupported until a safe Collaborator/OAST transport exists; it is never counted as a clean miss.
5. Finding text is enriched from the shipped Go catalog rather than copied from decompiled Java prose.
6. Second-order SQLi remains a separate phase/registry row until a stored-exchange producer and follow-up task are wired.

This ports the observable coverage classes without copying Java's obfuscated class structure or unsafe OOB behavior.
