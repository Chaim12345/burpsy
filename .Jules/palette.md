# Palette's Journal - Critical UX/a11y Learnings

## 2026-08-05 - Symmetric Grid Columns with Stacks
**Learning:** In a two-column grid (`.two`), having different layouts (e.g. input using a `.stack` and output using a plain `div`) results in asymmetrical alignment of the header labels. Wrapping both columns in `.stack` containers with identical label/metadata rows allows perfect alignment and symmetrical aesthetics.
**Action:** When creating side-by-side comparison or transform views, wrap both sides in `.stack` and use matching placeholder heights and labels.

## 2026-08-05 - Text Transform Clipboard Copy Delight
**Learning:** For utility screens where the primary user flow is input-transform-output (like Decoder/Encoder/Hasher), having a dedicated "Copy to Clipboard" button provides massive user delight. It removes the fiddly requirement to select wrapped/overflowing text inside `<pre>` blocks, especially for hex dumps.
**Action:** Always provide a dedicated, accessible Copy button for output panels on transform-centric pages.
