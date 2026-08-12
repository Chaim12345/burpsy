# burpsy design source

`burpsy-roundtrip.fig` is the OpenPencil source for the burpsy UI design system.

## Open it with the `.fig` extension, not `.pen`

The file is a zip archive (`canvas.fig` + `meta.json` + `thumbnail.png`).
OpenPencil 0.14.0 has an asymmetry in its file handling:

- `save_file` **writes** this zip format regardless of whether you name the
  output `.pen` or `.fig`.
- `open_file` **reads** `.pen` as JSON, so it rejects the very file it just
  wrote with `JSON Parse error: Unexpected identifier "PK"`.

`.fig` is read as a zip and opens correctly, so the `.fig` is the only source
kept here. A `.pen` written by this version cannot be reopened by it.

## Contents

17 tool boards (Dashboard, Target x3, Proxy x4, Intruder, Repeater, Sequencer,
Decoder, Comparer, Logger, Organizer, Session, Settings), each instancing a
single `00 Components / frame / app-shell` component for menubar + tool-tab
strip + statusbar, with the active tab overridden per board.

18 components total, including five built for the UX backlog: `highlight-picker`,
`comment-indicator`, `reorder-handle`, `filter-toggle` (off/on), and
`menu / column-visibility`.

## Active tab state is real nodes, not instance overrides

OpenPencil does not serialise instance overrides. The first retrofit set each
board's active tab by overriding the shell instance's children; that rendered
correctly in-session but came back from disk with `overrideCount: 0` on all 16
instances and every board highlighting "Dashboard".

So the shell component now carries no active state, and each board owns a real
`active-tab-marker` frame (pill + label) drawn over the shell. Rebuild it with
`scripts/fix-active-tabs.py --verify`, which re-opens the saved file and fails
if any board lost its marker.

**Verify design changes by reopening the saved file, never from live memory.**

## Tokens

`scripts/bind-design-tokens.py` creates a `semantic` variable collection with
dark and light modes from `src/tokens/penpot-export.json` and binds it across
the file: 24 variables, 1,120 bound fills and strokes. 67 colour usages remain
unbound because they are genuinely off-token (`#1a1a1a`, `#3c1414`, ...); the
script lists them so they can be reconciled rather than silently matched.

## Tooling

`openpencil-cli` exposes all 110 tools over one persistent connection, which is
far faster than a process per call. It is generated, not committed:

    mcporter generate-cli --server openpencil --name openpencil --output ./openpencil-cli

It needs `commander` and `mcporter` resolvable from the ui package.
`openpencil-client.ts` / `.d.ts` are the typed client for the same server.
