# apidoc

<!-- Parent: ../AGENTS.md -->

## Purpose

Reads an API *definition* and turns it into the concrete requests an API-only scan sends. Burp's
fourth scan kind (Zhw0 in the 2026.7.1 teardown) is the one whose seed is a document rather than a URL;
this is the reading half. The launch surface is `internal/web/api_apiscan.go`, which hands a document
here and passes the resulting `[]crawler.SeedRequest` to the crawl engine in seeds-only mode.

Reads OpenAPI 3.x and Swagger 2.0, in JSON or YAML, including local `$ref`s into the document's own
schema section. Sends nothing, stores nothing, and knows nothing about burpsy's stores or scope.

## Key files

| File | Description |
|------|-------------|
| `apidoc.go` | The whole package: `Parse`, the flavour detection and refusals, `Document`/`Operation`/`Parameter`, value selection with provenance, placeholder invention, and the bounded local-`$ref` resolver. |
| `apidoc_test.go` | Provenance ordering (example > default > enum > placeholder), placeholder recognisability, parse determinism, the Swagger 2 shape, `$ref` resolution and cycle bounding, and every refusal. |

## For AI Agents

- **Every value carries where it came from, and that is the point of the package.** `Parameter.Source`
  is what lets a scan report "9 of 31 parameter values were invented" instead of presenting a sweep
  driven by guesses as one driven by the document. A new value-selection branch that does not set a
  `ValueSource` is a defect even when the request it builds is byte-identical.
- **A placeholder must read as invented, not as plausible.** An integer parameter becomes `1`, a string
  one becomes its own name, a boolean becomes `true`. A placeholder that looked like real data would
  make it impossible to tell, when reading captured traffic, which values the API's authors chose.
- **The counts cover path, query and header parameters — not bodies.** `DeclaredValues` and
  `PlaceholderValues` are derived from `Operation.Parameters`, so a body synthesised from a schema is
  counted by neither. Every message built from the two therefore says "path, query and header value(s)"
  rather than "values". A caller that shortened that to "values" would be over-claiming.
- **Order is fixed, and it is not cosmetic.** Paths and methods are sorted before the walk, because Go's
  map iteration order is random: two scans of one document that sent the same endpoints in different
  orders would produce two different-looking reports of identical work. The same rule applies inside
  `Operation`: query pairs and per-request headers are written in a stable order.
- **Unreadable is refused by name, never read as empty.** A loader that treated an AsyncAPI file or a
  Postman collection as an empty definition would report "0 endpoints", which reads as an empty API
  rather than as a document nobody could read — and sends the operator to their API instead of their
  file. RAML is detected from the document's *text* (`#%RAML 1.0` is a comment, so the parsed tree is
  empty); everything else is detected from the tree.
- **Nothing further is fetched.** Only in-document `$ref`s are resolved. A `$ref` naming another file or
  a URL would be a request to a host the operator did not name, and that decision belongs to a caller
  with a scope gate — not to a parser.
