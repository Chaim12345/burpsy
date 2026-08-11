# Pending token changes

Token values that are *proposed* but not yet applied, and why — plus a record of
what this file used to call blocked and no longer is.

Nothing in this file changes the app on its own. That is deliberate, and this
document exists to explain the state rather than to stage a workaround.

## Status, as of the first successful live fetch

Both routes this file originally called blocked now work:

- **REST (`fetch:penpot`)** — runs end to end against the live file. It needed
  one real fix: `design.penpot.app` sits behind Cloudflare's JS challenge, so a
  plain `fetch()` gets HTTP 403 regardless of headers. The script now proxies
  the request through headless Chromium (borrowing the copy `e2e/` already
  installs) to clear the challenge first. See the comment on `loadBrowserRunner`
  in `scripts/fetch-penpot-file.mjs`.
- **Penpot MCP plugin** — connected, and used directly for the token additions
  below. It has since dropped mid-session at least once; treat it as available
  but not durably so, and re-check with a trivial call before relying on it.

The first live fetch also found a real, previously untested bug: Penpot returns
a fontFamilies token's single reference wrapped in a one-element array
(`["{font.family.sans}"]`), not the bare string
(`"{font.family.sans}"`) the export format expects — exactly the failure mode
`tokenToExportShape`'s own comment predicted but did not actually guard against,
because the guard was string-only. Fixed in `isFontFamilyReference` /
`tokenToExportShape` (`scripts/lib/penpot-file.mjs`); `font.family.body` and
`font.family.code` now round-trip correctly in both semantic sets.

## Applied

Three token types that did not exist in Penpot at all — confirmed by reading
`penpot.library.local.tokens` before adding anything: 0 `borderRadius`, 0
`borderWidth`, 0 `fontWeights` tokens. Added directly in Penpot via the MCP
plugin, then pulled in with `fetch:penpot --overwrite` and regenerated:

| Token | Value | Source |
| --- | --- | --- |
| `radius.none` | 0 | the surfaces that already have no radius |
| `radius.sm` | 2px | `tab / active-bg`, unanimous at 17 of 17 boards |
| `radius.md` | 3px | `panel / *` and `card / metric-*` |
| `border.hairline` | 1px | the existing 1px-hairline convention, now nameable |
| `border.focus` | 2px | the focus-ring convention, now nameable |
| `font.weight.regular` | 400 | |
| `font.weight.bold` | 700 | |

`primitives` is now 82 tokens (75 + 7); `EXPECTED_COUNTS` was updated in both
`gen-tokens.mjs` and `fetch-penpot-file.mjs` in the commit that adopted them,
per both files' own instructions on that count.

The `4/6/8/10/12` radius values seen on 17 shapes, all named the generic
`Rectangle`, were **not** tokenised — they are noise on individual shapes, not a
role-level decision, and creating a token per stray value would document the
noise rather than the design.

## Chrome sizing — derived, and still gated

`height.menubar`, `height.toolbar`, `height.subtab`, `height.statusbar` were
originally going to be adopted from four numbers hand-typed into
`docs/ui-map/07-design-analysis.md`. **That document was the wrong source and
contradicted two of the claims** — see the git history of this file for the
detailed comparison, since the source problem no longer applies: the real
numbers below come from reading every board in the live file directly, not from
that document.

| Role | Current token | Boards actually draw | Agreement |
| --- | --- | --- | --- |
| `chrome / menubar` | `height.menubar` = 21px | 24px | 17 of 17 |
| `chrome / toolbar` | `height.toolbar` = 29px | 38px | 17 of 17 |
| `chrome / subtabs` | `height.subtab` = 24px | 28px | 7 of 7 (only 7 tools have a subtab strip) |
| `chrome / statusbar` | `height.statusbar` = 19px | 22px | 17 of 17 |

Every role is unanimous — this is a decision the mockups have made, not drift
inside them. It is **still not applied**, on a gate that has nothing to do with
provenance: the change adds roughly 30px of fixed chrome, which is real vertical
loss at 390×844 and worse in short-landscape. That responsive baseline was being
built by a separate workstream (Playwright, `e2e/`) and had not landed as of
this writing. Apply these four values in Penpot only after that evidence exists,
even though the boards are unanimous.

## Chrome colours — corrected: no change needed

The original plan was to change `color.chrome` to `#414547`. **That was wrong.**
Resolving each board's actual fill against the semantic token set:

| Role | Drawn | Resolves to | Verdict |
| --- | --- | --- | --- |
| `chrome / menubar` | `#313335` (17/17) | `color.chrome` | already correct — no change |
| `chrome / statusbar` | `#313335` (17/17) | `color.chrome` | already correct — no change |
| `chrome / toolbar` | `#414547` (17/17) | `color.paper-raised` | a different *role* reads this colour, not a value to change |
| `chrome / subtabs` | `#323232` (7/7) | `color.paper-deep` | already correct — no change |

Every chrome fill in the boards already resolves to an existing semantic token.
There is no colour value to add or change here; the earlier framing ("adopt
`#414547` as `color.chrome`") mistook a role assignment for a value change.

## WCAG AA contrast failures — two Penpot fixes pending, three already fixed directly

The e2e a11y suite's first real run (axe-core, in `e2e/specs/a11y.spec.ts`)
found five contrast failures across several passes, none invented. Two are
Penpot-token problems; the other three turned out to be plain bugs in this
repo's own hand-authored CSS and are already fixed, no sign-off needed. Full
detail is in `penpot-export.json`'s `_provenance.pendingPenpotEdits`.

**Pending Penpot changes:**

| Token | Role | Current | Needs | Fix |
| --- | --- | --- | --- | --- |
| `color.muted` (`grey.10`) | nav tab labels + statusbar text, on `color.chrome`, light theme | 4.01:1 | 4.5:1 | darken to `#646464` (4.65:1) |
| `color.accent` (`orange.deep`) | white text on `--accent` (buttons, brand mark), light theme | 4.49:1 | 4.5:1 | darken to `#ce480f` (4.61:1) |

Both are real token-value bugs — the token itself fails in normal use, at 61
call sites for `--muted` and at least two independent components for
`--accent` (`.brand-symbol`, `.button-primary`) — so a token's exact shade is a
design decision the MCP plugin should not make unattended. Applied as scoped,
`token-exempt` CSS stopgaps for now; apply both values in Penpot, re-fetch,
then delete the two stopgaps in `styles.css` and confirm `e2e-ui.sh`'s axe
checks still pass on the token values alone.

The `--accent` finding is a correction of an earlier, wrong fix: it was first
found on `.brand-symbol` alone and patched there on the reasoning that
`--accent` "has no other consumer in this file" — that reasoning came from a
grep that silently failed to match (a `\b` word boundary right after a `)`
does not work the way it looks like it should), and the same failure later
turned up on `.button-primary` on a different route. Two independent consumers
hitting the identical rounding boundary is the token failing, not either
component, so the fix moved to token scope rather than staying a
`.brand-symbol`-only patch.

**Already fixed, no Penpot involvement:**

- **The four badge-tone rules** (`good`/`warn`/`bad`/`info`) shared an 11%
  `color-mix()` for their backgrounds — a hand-authored constant in
  `styles.css`, not a Penpot token, so this was a plain formula bug rather than
  a design decision. At 11%, every dark-theme tone and light theme's `good`
  failed (4.0–4.44:1). The mix is now 3% for all four, which clears all 8
  tone/theme combinations with real margin (4.54–5.50:1) using the
  **original, unmodified** semantic colours — no token needed to change at all.
- **`.notice`/`.notice-warn`** (7%/8% mix; dark theme's fixed `--text-soft`
  text failed at 4.19/4.09:1) and **`.crash-panel`** (7% mix; `--bad` as its
  own text failed dark theme at 4.26:1) — the same hand-authored-formula bug as
  the badges, fixed by lowering `.notice`'s mix to 1% and `.crash-panel`'s to
  3%, both with real margin in both themes.
- **Every `HttpEditor` (CodeMirror) instance had no accessible name at all** —
  `role="textbox"` with no `aria-label`, because `@uiw/react-codemirror` does
  not forward an `aria-label` prop to CM6's own content DOM node. Not a colour
  bug and not a token bug: fixed in `ui/editor.tsx` by adding
  `EditorView.contentAttributes.of({"aria-label": label})` to the extensions
  list, using the `label` prop every call site already supplies.
- **`--editor-active-line`** (a hand-authored `rgba(255,102,51,/alpha)` tint,
  10% dark / 7% light) composited over `--editor-bg` and pushed
  `.cm-placeholder`'s fixed grey below 4.5:1 — 4.09:1 in dark theme and a
  catastrophic 2.81:1 in light theme, because `.cm-placeholder` used **one**
  grey for both themes and `#949494` was only ever tuned against the dark
  background. Fixed by lowering the tint to 2% in both themes and splitting
  `.cm-placeholder` per theme: dark keeps `#949494`, light reuses `#646464` —
  the same value already settled on for `--muted`'s identical role.

## Still open

- **File rename** (`New File 1` → `burpsy design system`): attempted via the MCP
  plugin and refused — `penpot.currentFile.name` has only a getter in the plugin
  API (`Cannot set property name ... which has only a getter`). Needs to be
  renamed from Penpot's own UI (the file name in the dashboard or workspace
  header), not through a script.
- **Empty `Page 1`, the stray `positions-panel` shape, the connected `Locofy
  Lightning` library** — not yet resolved. An attempt was interrupted mid-call
  when the MCP connection dropped; re-run once the plugin is confirmed
  reachable again. `Page 1` is confirmed empty (`root.children.length === 0`)
  and safe to delete once reachable.

## Why there is no override layer

The obvious way to land a value ahead of a Penpot edit would be an override
block that `gen-tokens.mjs` applies on top of the export. Rejected, because it
inverts the one property the whole pipeline exists to provide: Penpot holds a
value, the export mirrors it, the generator emits it, `--check` proves the
emitted CSS still matches. An override is a second source of truth for the same
token, and — unlike `pending.css`, where the repo is canonical for tokens Penpot
does not have, so there is nothing to disagree with — an override would assert a
value Penpot actively contradicts. That is not a gap being filled, it is a fork,
and it would be a self-inflicted version of the exact bug this workstream exists
to fix: `fetch-penpot-file.mjs` refuses to write when the export and the live
file differ, so an override would make that refusal permanent and routinely
ignored, which is a disabled guard.

The clean order is the one the fetch script assumes: **change the value in
Penpot, fetch, regenerate.**

## How to reproduce the audit

```sh
export PENPOT_ACCESS_TOKEN=<token from Penpot profile settings -> Access tokens>
bun run fetch:penpot -- --save-raw /tmp/penpot-file.json
bun run audit:penpot /tmp/penpot-file.json
```

`penpot-audit.mjs`'s output has two halves: a lint (raw hex fills matching no
token, off-scale font sizes, shapes with a tokenisable property and no binding)
and a proposed token diff, reported per role with an agreement/disagreement
count so a unanimous board decision is never conflated with drift inside the
mockups themselves.

## Already recorded elsewhere

Token-level debts with their own homes, so they are not duplicated here:

- `font.size.2xs` and `font.size.xs` are both 11px, making them indistinguishable
  in Penpot. See `ACKNOWLEDGED_DUPLICATE_FLOORS` in `scripts/gen-tokens.mjs` and
  `_provenance.pendingPenpotEdits` in `penpot-export.json`.
- The token types Penpot supports that the design does not yet use (beyond the
  seven applied above) live in `penpot-export.json`'s `_pendingPenpot` block and
  generate `pending.css`.

## Near-duplicate greys, found via a second tool (OpenPencil, on a Figma
## round-trip of the same file), worth folding in when Phase C rebinds tokens

A structural `.fig`/`.pen` export of the live file (`/root/burpsy.fig`,
`/root/burpsy-roundtrip.pen`) round-tripped all 970 shapes with full geometry
fidelity — confirmed against this repo's own direct Penpot measurements
(chrome/menubar 24px, toolbar 38px, statusbar 22px, panel radius 3px, all
matched exactly). It carries zero token bindings and zero auto-layout, for the
same reason the live Penpot file does: there was never anything to round-trip.
So this is not a second source of truth, only a second read of the same one —
but its colour-clustering pass caught three near-duplicate greys worth folding
into one token each, rather than three, when Phase C rebinds the library:

| Cluster | Colours in use | Total uses | Canonical |
| --- | --- | --- | --- |
| dark surfaces | `#323232`, `#313335`, `#2b2b2b` | 98 | `#323232` |
| raised panels | `#414547`, `#3c3f41` | 107 | `#414547` |
| chrome-hover | `#4e5254`, `#4b5052` | 45 | `#4e5254` |

Not applied here — like the rest of this file, a colour merge is a design
decision for Phase C, not a value to patch unattended. Recorded so it isn't
rediscovered from scratch.
