# burpsy design source

`burpsy-roundtrip.fig` is the OpenPencil source for the burpsy UI design system.

## Open it with the `.fig` extension, not `.pen`

Both files here are byte-identical zip archives (`canvas.fig` + `meta.json` +
`thumbnail.png`). OpenPencil 0.14.0 has an asymmetry in its file handling:

- `save_file` **writes** this zip format regardless of whether you name the
  output `.pen` or `.fig`.
- `open_file` **reads** `.pen` as JSON, so it rejects the very file it just
  wrote with `JSON Parse error: Unexpected identifier "PK"`.

`.fig` is read as a zip and opens correctly. `burpsy-roundtrip.pen` is kept only
so the older filename stays resolvable; treat the `.fig` as canonical.

## Contents

17 tool boards (Dashboard, Target x3, Proxy x4, Intruder, Repeater, Sequencer,
Decoder, Comparer, Logger, Organizer, Session, Settings), each instancing a
single `00 Components / frame / app-shell` component for menubar + tool-tab
strip + statusbar, with the active tab overridden per board.

18 components total, including five built for the UX backlog: `highlight-picker`,
`comment-indicator`, `reorder-handle`, `filter-toggle` (off/on), and
`menu / column-visibility`.
