# xui: templ + Datastar MVP (read-only)

Server-driven console at `/x` (Map) and `/x/prove` (Prove). GET routes only, so no confirm-gate surface is added.
Not migrated: Probe, Scope, Search, Tools (stay in the existing altui).

- Map streams the newest 300 non-tool exchanges over SSE (morph patches, max 1 push per 250ms). Filter is a substring match on host, path, method, status (not the query DSL). Row click loads `/x/detail?id`, truncated to 64KB with a link to /api/message/{id}.
- Prove streams severity chips and the top 300 findings (false positives and isolated excluded).
- Edit `views.templ`, then run `templ generate` (v0.3.1100) and commit `views_templ.go`.
- Datastar v1.0.4 vendored (MIT, see DATASTAR-LICENSE.txt).

Decision gate still open: godom Spike B and the editor spike are NOT done. This branch is a templ+Datastar MVP per the research report, not a final architecture choice.
Not merged, not deployed.
