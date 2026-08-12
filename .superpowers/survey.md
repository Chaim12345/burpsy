# React UI survey — facts implementers need

Measured from `burpsy-go/internal/web/ui/src`. File:line references are exact.

## ui/table.tsx — the shared virtual table

```ts
export type Column<T> = ColumnDef<T, any>;          // table.tsx:17-20 — TanStack column defs

export interface VirtualTableProps<T> {            // table.tsx:56-73
  data: T[];
  columns: Column<T>[];
  getRowId: (row: T) => string;
  ariaLabel: string;
  selectedId?: string | null;
  onSelect?: (row: T) => void;
  onActivate?: (row: T) => void;
  menuGroups?: (row: T) => MenuGroup[];
  rowClassName?: (row: T) => string | undefined;
  loading?: boolean;
  empty?: ReactNode;
  density?: "comfortable" | "compact";
  height?: string;
  initialSort?: SortingState;
}
```

- **TanStack Table** (`useReactTable`, table.tsx:91-103) with
  `getSortedRowModel()` and `columnResizeMode: "onChange"`.
- **Column visibility: supported by TanStack, never used.** `row.getVisibleCells()`
  is called (table.tsx:305) but nothing ever sets visibility state. There is no
  `columnVisibility` state and no UI. This is a wiring job, not a rewrite.
- **Sort state is per-instance** `useState<SortingState>(initialSort)` — not
  lifted to the page.
- **Selection is single-row only** (`selectedId`/`onSelect`); no multi-select.
- **Virtualised** with `@tanstack/react-virtual`, `overscan: 14`. Row height is
  measured from a CSS custom property by an off-screen probe
  (`useFluidRowHeight`, table.tsx:31-54), fallback `{comfortable: 30, compact: 24}`.
- **Row colour:** `rowClassName?(row)` adds a CSS class (table.tsx:278-314). It
  is a class hook only — there is no per-row inline style. Existing flags
  `row-flag-bad` / `row-flag-warn` render as a 2px left inset box-shadow
  (styles.css:1093-1098), not a full-row fill. **An arbitrary per-row highlight
  colour needs a new mechanism** — either one class per colour, or a new prop
  that can set an inline background.
- `SimpleTable` (table.tsx:317-334) is a separate non-virtualised static table
  (`headers: string[]` + children) used by Organizer, Match&Replace, Intercept,
  Session.

## ui/primitives.tsx — what already exists

`Button` (variants primary/outline/danger/quiet/ghost), `LinkButton`,
`IconButton({label})` (label is required and becomes `aria-label`), `Input`,
`Textarea`, `Select`, `Card`, `Badge({tone})`, `Field`, `Toolbar`,
**`Empty({title, detail, action})` (203-211)**, **`ErrorNotice({error, onRetry})`
(213-228)**, `Metric`, `Kbd`, **`Spinner({label})` (256-258)**, `Tooltip`,
`Switch`, `Checkbox({checked, onCheckedChange, label})`, Radix `Tabs*`, `Modal`.

`Tone = "neutral" | "good" | "warn" | "bad" | "info" | "accent"`.

**`Field` is the accessibility guard** (primitives.tsx:148-197). It is the only
place that mints a `LabelledId` (a branded string, 44-45) via `useId()`.
`Input`/`Textarea`/`Select` **will not typecheck** unless given an `id` from
`Field`, an `aria-label`, or an `aria-labelledby`. Render-prop form:

```tsx
<Field label="Host pattern">{(id) => <Input id={id} … />}</Field>
```

`htmlFor` form is used for Radix widgets that render their own focusable node.

## pages/history.tsx

- 9 columns via `useMemo<Column<Exchange>[]>` (123-180): `id` (#, size 62),
  `method` (Badge), synthetic `authority` (`accessorFn` host:port, "Host"),
  `path` (`<code>`), `status` (Badge, `statusTone()`), `mime`, `response_len`
  (`formatBytes`), `duration_ms`, `started_ms` (`relativeTime`). All sized in px.
- `<VirtualTable ariaLabel="Captured HTTP exchanges" …>` inside a `SplitPane`.
- **Filtering today:** one free-text DSL `Input` (260ms debounce) sent to
  `GET /api/history?limit=&q=`; a `QueryHelp` modal documenting the grammar
  (fields: host, status, method, path, mime, body); plus **client-side**
  `Select`s for status bucket and method, and a row-limit `Select`.
- **No toggle/checkbox filter UI exists.**

## pages/organizer.tsx — the highlight vocabulary

```ts
const HIGHLIGHTS = ["none","red","orange","yellow","green","cyan","blue","pink","magenta","gray"];  // :12
const HIGHLIGHT_TONE: Record<string, Tone> = {                                    // :14-23
  red:"bad", orange:"warn", yellow:"warn", green:"good",
  cyan:"info", blue:"info", pink:"accent", magenta:"accent" };                    // gray/none unmapped
```

Edit is a `Field` + `Select` of the vocabulary (289-303); list rendering is a
tone-coloured `Badge` (201-206). Saving normalises `"none"` → `""` (93-101).
There is **no swatch picker** — the "colour" is just the Badge's tone.

## lib/types.ts

```ts
export interface Exchange {            // :22-42
  id; request; response; host; port; method; path; status;
  response_len; started_ms; duration_ms; tls; protocol;
  mime?; source?;
  notes?: string | null;               // :40 — present on the wire, NEVER read or written by the frontend
  related?;
}
export interface OrganizerItem { id; exchange; title; note; highlight }  // :270-276
```

No `highlight` on `Exchange`.

## Ordered lists — what already has reorder

| Page | List | Reorder today |
|---|---|---|
| `matchreplace.tsx` | `draft.rules` (index is identity) | **YES** — up/down `IconButton`s (322-340), `move()` (102-110), labels `Move rule N up` |
| `session.tsx` | macro `steps` | **YES** — `StepCard onMove` (372-382), `moveStep()` (462-472) |
| `intercept.tsx` | request rules + response rules in `RuleEditor` | **NO** — add (137-143) and remove (237-245) only |
| `session.tsx` | header pairs, extraction rows, scope hosts | no (not order-semantic) |

So the reorder gap is **`intercept.tsx` only**, and the established pattern to
copy lives in `matchreplace.tsx:102-110,322-340`.

## API surface

- Reads: `useHistory(q, limit)` → `GET /api/history?limit=&q=`;
  `useExchange` → `GET /api/exchange/:id`; `useMessage(id)`.
- Organizer mutations (`useOrganizerMutations`, data.ts:293-309):
  `POST /api/tools/organizer`, `POST /api/tools/organizer/:id`,
  `DELETE /api/tools/organizer/:id`; all invalidate `keys.organizer`.
- `useExchangeActions()` (actions.ts:70-185): `sendToRepeater`, `sendToIntruder`,
  `sendToComparer`, `addToOrganizer`, `copyUrl`, `copyCurl`, `filterByHost`,
  `menu()`.
- **There is no write route for an exchange's notes or highlight.** Go defines
  `Notes *string \`json:"notes"\`` (api_types.go:46) but nothing sets it.

## Tests

`e2e/specs/{routes,behaviour,screenshots,a11y}.spec.ts`. Helpers from
`../harness/fixtures` (`test`, `expect`, `gotoApp`, `gotoRoute`, `pinTheme`,
`activePane`) and `../harness/routes` (`ROUTES`).

behaviour.spec.ts's header states the rule: *"Behaviour, not smoke — each of
these asserts an observable consequence rather than a mechanism."*

```ts
test("Escape closes the palette without navigating", async ({ page }) => {   // :81-89
  await gotoApp(page);
  const before = page.url();
  await page.keyboard.press("ControlOrMeta+k");
  await expect(page.getByLabel("Search commands")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByLabel("Search commands")).toHaveCount(0);
  expect(page.url()).toBe(before);
});
```

Locators are role/label based, assertions are on rendered effects
(`getComputedStyle`, URL hash, DOM attributes), and many tests also assert
`consoleErrors` is empty.
