## e2e-ui result: 212 passed, 7 failed (14.8m)

All 7 failures are in `behaviour.spec.ts`. Three distinct defect classes:

### Class 1: React key warning pollutes console (4 failures)
`console.error: Each child in a list should have a unique "key" prop` — `Check the render method of `div`. It was passed a child from xi.`

Tests affected:
- `menu bar opens a Repeater tab and navigates to it`
- `adding a header in the Inspector puts it on the wire`
- `a Repeater response is inspectable but says why it is not editable`
- `the Inspector's decoder decodes a value and writes it back`

**Root cause:** A `div` component renders children without keys. The test asserts `consoleErrors === []`.

### Class 2: Functional gaps (3 failures)
1. **`the in-scope-only toggle filters the rows`** — `getByText('No exchange matches this filter')` not visible. The toggle doesn't produce the expected empty-state message.

2. **`the Inspector dock preference survives a reload`** — `.editor-grid-inspected > .editor` not found. The editor grid layout is missing or uses different selectors.

3. **`an Inspector edit in Intercept changes the bytes actually forwarded`** — `ReferenceError: proxyGet is not defined`. Test helper function missing.

### Class 3: Timeout (1 failure)
- **`the Inspector's decoder decodes a value`** — 40s timeout waiting for `.inspector-section` "Query parameters" → `getByRole('button', { name: 'Add' })`. The Inspector section structure doesn't match.

### Summary
- 4 failures = React key warning (console error assertion)
- 2 failures = Inspector/editor DOM structure mismatch
- 1 failure = missing test helper (`proxyGet`)
- 1 failure = in-scope filter empty-state message wrong

**Not flaky** — deterministic failures on a clean tree at HEAD `a7f458a`.
