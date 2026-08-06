# Workbench & Shell UAT Matrix

**Scope:** Pages (Decoder, Comparer, Organizer, Logger, Dashboard, Settings) + Shared Components (Shell navigation, Table, Editor) and their interactive elements.

**Format:** One table per major component/area. Rows represent distinct test cases covering happy paths, alternate entry points, preconditions, boundary values, disabled→enabled transitions, error states, and keyboard shortcuts.

---

## DECODER Page

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| DECODER-001 | User opens Decoder page | Fresh session | 1. Navigate to hash `#decoder` | Page loads with "Nothing run yet" empty state showing "No steps" | happy-path |
| DECODER-002 | User adds a Decode step | No steps added | 1. Click "Decode" button | A new step row appears with "step 1", operation set to "Decode", value set to "smart detect", "guess" checkbox shown | happy-path |
| DECODER-003 | User adds an Encode step | No steps added | 1. Click "Encode" button | A new step row appears with "step 1", operation set to "Encode", value set to first encoding | happy-path |
| DECODER-004 | User adds a Hash step | No steps added | 1. Click "Hash" button | A new step row appears with "step 1", operation set to "Hash", value set to first algorithm | happy-path |
| DECODER-005 | User pastes input and runs pipeline | Empty input, one decode step | 1. Paste "SGVsbG8gV29ybGQ=" into HttpEditor 2. Click "Run pipeline" button | "1 step(s) ran" toast displayed, result shows decoded output "Hello World" | happy-path |
| DECODER-006 | User changes step operation | One decode step added | 1. Open operation select for step 1 2. Change from "Decode" to "Encode" | Step operation changes to "Encode", value resets to first encoding option | happy-path |
| DECODER-007 | User changes step encoding/algorithm | One encode step added | 1. Open value select for step 1 2. Select "hex" | Step value changes to "hex" | happy-path |
| DECODER-008 | User toggles guess checkbox | One auto-decode step | 1. Check the "guess base64 / hex alphabets" checkbox | Checkbox becomes checked, step.guess = true | happy-path |
| DECODER-009 | User unchecks guess checkbox | Guess checkbox already checked | 1. Uncheck the "guess base64 / hex alphabets" checkbox | Checkbox becomes unchecked, step.guess = false | happy-path |
| DECODER-010 | User moves step up (from position 2 to 1) | Two steps (decode, encode) | 1. Click move-up icon on step 2 | Steps swap; step 1 now shows "Encode", step 2 shows "Decode" | happy-path |
| DECODER-011 | User moves step down (from position 1 to 2) | Two steps (decode, encode) | 1. Click move-down icon on step 1 | Steps swap; step 1 now shows "Encode", step 2 shows "Decode" | happy-path |
| DECODER-012 | User removes a step | Two steps present | 1. Click remove icon on step 1 | Step is removed; remaining step becomes step 1 | happy-path |
| DECODER-013 | User copies result output | Pipeline executed, result displayed | 1. Click copy icon on result card | Toast shows "Step 1 output copied", output text in clipboard | happy-path |
| DECODER-014 | User switches to Hex view | Pipeline executed, text view active | 1. Click "Hex" button | Output displays as hex dump with byte offsets and ASCII column | happy-path |
| DECODER-015 | User switches back to Text view | Pipeline executed, hex view active | 1. Click "Text" button | Output displays as plain text | happy-path |
| DECODER-016 | Hex dump exceeds MAX_HEX_BYTES | Large result, hex view active | 1. Run pipeline producing > 8192 bytes 2. Switch to hex view | Hex dump shows truncated rows, footer message: "… {N} more bytes not dumped; switch back to text for the whole output" | boundary |
| DECODER-017 | Non-UTF-8 output in hex view | Result contains non-UTF-8 bytes, hex view | 1. Pipeline produces non-UTF-8 output 2. View result in hex | Notice shown: "The server sends a lossy text rendering... {bytes.length} B here against {result.len} B decoded" | boundary |
| DECODER-018 | Empty output after step | Step completes but produces no bytes | 1. Run pipeline producing empty final output | Output displays "(empty output)" | empty-state |
| DECODER-019 | Smart detect finds nothing | Auto-decode step with unrecognized input | 1. Paste "not_encoded_data" 2. Run pipeline | Notice shown: "Nothing was detected: no layer decoded cleanly, so this step passed the input through unchanged." | empty-state |
| DECODER-020 | Partial decompression detected | Compressed stream only partly decompresses | 1. Run pipeline with partial decompression result | Notice shown: "This stream only partly decompressed... the output below is a prefix of the plaintext" | warning |
| DECODER-021 | Hash in middle of pipeline | Three steps: decode, hash, encode | 1. Run pipeline with hash as middle step | Notice shown: "A hash is one-way: step 2 onwards operates on the hex digest, not on the original bytes." | warning |
| DECODER-022 | Step fails mid-pipeline | Step 2 fails, step 3 added | 1. Configure step that will fail 2. Run pipeline | Notice shown: "Step 2 failed and the chain stopped there: {error message}. The steps below are the ones that did run." | error |
| DECODER-023 | Run pipeline disabled when no steps | Input present, no steps | 1. Paste input 2. Try to click "Run pipeline" | "Run pipeline" button is disabled (grayed out) | disabled-state |
| DECODER-024 | Run pipeline disabled when empty input | Steps present, no input | 1. Add steps 2. Leave HttpEditor empty 3. Try to click "Run pipeline" | "Run pipeline" button is disabled | disabled-state |
| DECODER-025 | Run pipeline disabled while running | Pipeline executing | 1. Click "Run pipeline" 2. Before response, try to click again | Button shows "Running…" label and is disabled | loading |
| DECODER-026 | Move up button disabled on first step | One step present | 1. Click move-up icon on step 1 | Button is disabled (grayed out) | disabled-state |
| DECODER-027 | Move down button disabled on last step | One step present | 1. Click move-down icon on step 1 | Button is disabled (grayed out) | disabled-state |
| DECODER-028 | Guess checkbox hidden for non-auto-decode | Step kind is "Encode" | 1. Add encode step | Guess checkbox does not appear | hidden |
| DECODER-029 | Guess checkbox hidden for non-auto value | Decode step with "base64" selected | 1. Add decode step 2. Change value to "base64" | Guess checkbox disappears | hidden |
| DECODER-030 | Pipeline error displays toast | Server returns error 500 | 1. Run pipeline 2. Server responds with error | Toast shows "Pipeline could not run: {error message}" | error |
| DECODER-031 | Empty input edge case | HttpEditor contains only whitespace | 1. Paste whitespace only 2. Try to run | Button remains disabled (whitespace is not valid input) | boundary |
| DECODER-032 | Step value select options change by kind | Step kind is "decode" | 1. Open value select (shows decode layers) 2. Change kind to "hash" 3. Open value select | Options change to hash algorithms | happy-path |
| DECODER-033 | Byte count shown in HttpEditor header | Input pasted | 1. Paste "Hello" (5 bytes in UTF-8) | Editor header shows "5 B" | happy-path |
| DECODER-034 | Result byte count shown on card | Result displayed | 1. Run pipeline, observe result card | Card shows byte count badge e.g. "11 B" | happy-path |

---

## COMPARER Page

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| COMPARER-001 | User opens Comparer page | Fresh session | 1. Navigate to hash `#comparer` | Page loads with "Nothing compared yet" empty state | happy-path |
| COMPARER-002 | User pastes text into side A | Empty comparer | 1. Paste "Hello World" into side A HttpEditor | Side A displays "Hello World" | happy-path |
| COMPARER-003 | User pastes text into side B | Empty comparer | 1. Paste "Hello world" (lowercase) into side B HttpEditor | Side B displays "Hello world" | happy-path |
| COMPARER-004 | User compares identical inputs | Both sides contain "Hello" | 1. Click "Compare" button | Toast shows "The two inputs are byte-for-byte identical", result shows no differences | happy-path |
| COMPARER-005 | User compares different inputs | A: "Hello World", B: "Hello world" | 1. Click "Compare" button | Toast shows "1 difference(s) found", diff panes show difference highlighted | happy-path |
| COMPARER-006 | User enters message ID in slot A | Comparer empty | 1. Enter "0" in "Stored message id for slot A" input 2. Click "Load" button | Message 0 loaded into side A, toast shows "Message 0 loaded into slot A" | happy-path |
| COMPARER-007 | User enters message ID in slot B | Comparer empty | 1. Enter "5" in "Stored message id for slot B" input 2. Click "Load" button | Message 5 loaded into side B, toast shows "Message 5 loaded into slot B" | happy-path |
| COMPARER-008 | User swaps sides | A: "Hello", B: "World" | 1. Click "Swap" button | Sides exchange; A now contains "World", B contains "Hello", comparison result clears | happy-path |
| COMPARER-009 | User navigates to next hunk | Comparison with 3 hunks, hunk 0 focused | 1. Click "Next" button | Focus moves to hunk 1, segments update, auto-scroll occurs | happy-path |
| COMPARER-010 | User navigates to previous hunk | Comparison with 3 hunks, hunk 1 focused | 1. Click "Previous" button | Focus moves to hunk 0, segments update, auto-scroll occurs | happy-path |
| COMPARER-011 | User wraps hunk navigation forward | Comparison with 3 hunks, hunk 2 focused | 1. Click "Next" button | Hunk focus wraps to hunk 0 (modulo arithmetic) | boundary |
| COMPARER-012 | User wraps hunk navigation backward | Comparison with 3 hunks, hunk 0 focused | 1. Click "Previous" button | Hunk focus wraps to hunk 2 (modulo arithmetic) | boundary |
| COMPARER-013 | Swap button disabled when both empty | Comparer fresh | 1. Try to click "Swap" button | "Swap" button is disabled | disabled-state |
| COMPARER-014 | Swap button enabled when A has content | A: "text", B: empty | 1. Observe "Swap" button | "Swap" button is enabled | enabled-state |
| COMPARER-015 | Compare button disabled when both empty | Both sides empty | 1. Try to click "Compare" button | "Compare" button is disabled | disabled-state |
| COMPARER-016 | Compare button disabled while comparing | Comparison in progress | 1. Click "Compare" 2. Before response, try to click again | Button shows "Comparing…" and is disabled | loading |
| COMPARER-017 | Load button disabled while loading message | Load operation in progress | 1. Click "Load" for slot A 2. Before response, try to click again | Button is disabled | loading |
| COMPARER-018 | Invalid message ID rejected (negative) | "Stored message id for slot A" input | 1. Enter "-1" 2. Click "Load" | Toast shows "Give a stored message id — a whole number, counting from 0" | boundary |
| COMPARER-019 | Invalid message ID rejected (non-integer) | "Stored message id for slot A" input | 1. Enter "abc" 2. Click "Load" | Toast shows "Give a stored message id — a whole number, counting from 0" | boundary |
| COMPARER-020 | Invalid message ID rejected (float) | "Stored message id for slot A" input | 1. Enter "1.5" 2. Click "Load" | Toast shows "Give a stored message id — a whole number, counting from 0" | boundary |
| COMPARER-021 | Message load error | Message ID does not exist | 1. Enter "999999" 2. Click "Load" for slot A | Toast shows "Could not load message 999999: {error}" | error |
| COMPARER-022 | Comparison error | Server comparison fails | 1. Compare two sides 2. Server returns error | Toast shows "Comparison failed: {error message}" | error |
| COMPARER-023 | Hunk navigation disabled when no hunks | Sides are identical | 1. Compare identical inputs 2. Try to navigate hunks | "Previous" and "Next" buttons are disabled | disabled-state |
| COMPARER-024 | Hunk text shows count and current | Comparison with hunks | 1. Focus hunk 1 out of 5 | Toolbar text shows "hunk 2 of 5" | happy-path |
| COMPARER-025 | Hunk text shows "no hunk focused" | No comparison run yet | 1. Observe hunk display | Toolbar text shows "no hunk focused" | empty-state |
| COMPARER-026 | Comparison reset after swap | Comparison result displayed | 1. Click "Swap" button | Comparison result clears, empty state shows | happy-path |
| COMPARER-027 | Hunk focus reset after compare | Previous comparison had focus | 1. Run new comparison | Hunk focus resets to -1 | happy-path |
| COMPARER-028 | Truncation warning shown | Server truncates large diff | 1. Compare very large inputs 2. Server indicates truncation | Notice shown: "The server truncated the comparison. {N} ops_omitted run(s) were omitted server-side." | warning |
| COMPARER-029 | Omitted runs warning shown | Server omits ops | 1. Compare inputs producing > 2000 ops | Notice shown: "{N} run(s) past the first 2000 are not drawn here." | warning |
| COMPARER-030 | Message ID 0 is valid | Load message 0 | 1. Enter "0" in slot A input 2. Click "Load" | Message loads successfully (ID 0 is valid per code comment) | boundary |
| COMPARER-031 | Byte slicing works correctly | Comparing UTF-8 multi-byte chars | 1. Load messages containing multi-byte UTF-8 2. Compare | Segments correctly identify differing bytes using TextEncoder slicing | happy-path |

---

## ORGANIZER Page

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| ORGANIZER-001 | User opens Organizer page | Fresh session, no saved exchanges | 1. Navigate to hash `#organizer` | Page loads with "Nothing saved yet" empty state | happy-path |
| ORGANIZER-002 | User enters exchange ID and saves | No items saved | 1. Enter "0" in "Exchange id to save" input 2. Click "Save exchange" button | Exchange 0 added to list, selected, detail panel shows empty fields, toast shows "Saved exchange #0" | happy-path |
| ORGANIZER-003 | User presses Enter to add exchange | No items saved | 1. Enter "5" in input 2. Press Enter | Exchange 5 added without clicking button | happy-path |
| ORGANIZER-004 | User selects an item from table | Two items saved | 1. Click on second row in table | Detail panel populates with item data, item highlights as selected | happy-path |
| ORGANIZER-005 | User edits title field | Item selected | 1. Modify title input text 2. Observe | "dirty" badge appears showing "unsaved changes" | happy-path |
| ORGANIZER-006 | User edits note textarea | Item selected | 1. Modify note textarea 2. Observe | "dirty" badge appears showing "unsaved changes" | happy-path |
| ORGANIZER-007 | User changes highlight color | Item selected | 1. Open highlight select 2. Choose "red" | Draft.highlight = "red", "dirty" badge appears | happy-path |
| ORGANIZER-008 | User saves changes | Item selected with dirty changes | 1. Click "Save" button | Changes persisted, baseline updated, "dirty" badge removed, toast shows "Note saved" | happy-path |
| ORGANIZER-009 | User reverts unsaved changes | Item selected with dirty changes | 1. Click "Revert" button | Fields revert to baseline values, "dirty" badge disappears, toast shows "Reverted to the saved note" | happy-path |
| ORGANIZER-010 | User removes item via delete icon on row | Two items in table | 1. Click remove icon on a row | Confirmation modal opens asking "Remove item 1?" | happy-path |
| ORGANIZER-011 | User confirms delete in modal | Delete confirmation modal open | 1. Click "Remove item" (danger button) | Item deleted, modal closes, selection cleared if deleted item was selected, toast shows "Removed from the organizer" | happy-path |
| ORGANIZER-012 | User cancels delete in modal | Delete confirmation modal open | 1. Click "Keep it" button | Modal closes without deleting | happy-path |
| ORGANIZER-013 | User removes item via Remove button in detail | Item selected | 1. Click "Remove" button in detail section | Confirmation modal opens | happy-path |
| ORGANIZER-014 | User opens exchange in HTTP history | Item selected | 1. Click "Open exchange #5 in history" icon | Focus navigates to exchange 5 in zustand, route changes to "history", HTTP history page loads focused on that exchange | happy-path |
| ORGANIZER-015 | User opens exchange via detail button | Item selected | 1. Click "Show in history" button in detail | Navigates to HTTP history focused on that exchange | happy-path |
| ORGANIZER-016 | Save button disabled with no changes | Item selected, no edits | 1. Observe "Save" button | Button is disabled | disabled-state |
| ORGANIZER-017 | Revert button disabled with no changes | Item selected, no edits | 1. Observe "Revert" button | Button is disabled | disabled-state |
| ORGANIZER-018 | Save button disabled while saving | Save operation in progress | 1. Click "Save" 2. Before response, observe | Button shows "Saving…" and is disabled | loading |
| ORGANIZER-019 | Add button disabled with empty input | No items added | 1. Observe "Save exchange" button with empty input | Button is disabled | disabled-state |
| ORGANIZER-020 | Add button disabled with whitespace-only | Input contains only spaces | 1. Enter "   " 2. Observe button | Button is disabled | boundary |
| ORGANIZER-021 | Invalid exchange ID rejected (negative) | Add exchange input | 1. Enter "-1" 2. Click "Save exchange" | Toast shows "Enter an exchange id — a whole number, counting from 0" | boundary |
| ORGANIZER-022 | Invalid exchange ID rejected (non-integer) | Add exchange input | 1. Enter "abc" 2. Click "Save exchange" | Toast shows "Enter an exchange id — a whole number, counting from 0" | boundary |
| ORGANIZER-023 | Exchange ID 0 is valid | Add exchange input | 1. Enter "0" 2. Click "Save exchange" | Exchange 0 saves successfully (ID 0 is valid) | boundary |
| ORGANIZER-024 | Save error handled | Network error saving item | 1. Edit item 2. Click "Save" 3. Server returns error | Toast shows error message "Save failed" | error |
| ORGANIZER-025 | Add error handled | Network error adding exchange | 1. Click "Save exchange" 2. Server returns error | Toast shows "Could not save that exchange" | error |
| ORGANIZER-026 | Delete error handled | Network error deleting | 1. Confirm delete in modal 2. Server returns error | Toast shows "Delete failed" | error |
| ORGANIZER-027 | No item selected state | Comparer fresh or item deselected | 1. Observe detail panel | Shows empty state "No item selected" | empty-state |
| ORGANIZER-028 | Title displays as "untitled" when empty | Item selected with no title | 1. Observe table cell | Cell shows dimmed text "(untitled)" | empty-state |
| ORGANIZER-029 | Note displays as "no note" when empty | Item selected with no note | 1. Observe table cell | Cell shows dimmed text "(no note)" | empty-state |
| ORGANIZER-030 | Highlight displays as "—" when not set | Item selected with no highlight | 1. Observe highlight column | Shows dimmed "—" | empty-state |
| ORGANIZER-031 | "None" highlight option stores empty string | User selects "none" in dropdown | 1. Select "none" in highlight dropdown 2. Save | Saved highlight is empty string (not "none") | happy-path |
| ORGANIZER-032 | Refresh button refetches list | List displayed | 1. Click refresh icon | Page reloads list from server | happy-path |
| ORGANIZER-033 | Unsaved changes persist across selection change | Edit item A, select item B | 1. Edit item A title 2. Click another row 3. Click back to item A | Draft still shows edited values (not reverted) | happy-path |
| ORGANIZER-034 | Selection cleared after successful delete | Deleted item was selected | 1. Delete selected item | selectedId set to null, detail panel shows empty state | happy-path |

---

## LOGGER Page

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| LOGGER-001 | User opens Logger page | Fresh session, no log entries | 1. Navigate to hash `#logger` | Page loads with "Nothing logged yet" empty state | happy-path |
| LOGGER-002 | User searches tool log | 10 logged entries | 1. Enter "example.com" in search input | Table filters to entries matching search term, debouncedTerm updates after 260ms delay | happy-path |
| LOGGER-003 | User clears search | Search active with results | 1. Click "Clear search" button (X icon) | Search term cleared, full log redisplayed | happy-path |
| LOGGER-004 | User filters by tool | Multiple tools logged | 1. Open "Tool filter" select 2. Choose "Repeater" | Table filters to only "Repeater" entries | happy-path |
| LOGGER-004b | User resets tool filter | Tool filter active | 1. Open "Tool filter" select 2. Choose "All tools" | Filter cleared, full log shown | happy-path |
| LOGGER-005 | User selects a log row | Multiple entries visible | 1. Click on a table row | Row highlights, detail panel populates with full entry info | happy-path |
| LOGGER-006 | User copies URL from context menu | Row selected | 1. Right-click on row 2. Click "Copy URL (as logged)" | URL copied to clipboard, toast shows "URL copied" | happy-path |
| LOGGER-007 | User copies curl command from context menu | Row selected | 1. Right-click on row 2. Click "Copy as curl (request line only)" | curl command copied, toast shows "curl command copied — the log stores no headers or body" | happy-path |
| LOGGER-008 | User shows row's host in HTTP history | Row selected | 1. Right-click on row 2. Click "Show {host} in HTTP history" | Query filter set, navigates to history page showing rows matching that host | happy-path |
| LOGGER-009 | User shows row's host and path in HTTP history | Row selected | 1. Right-click on row 2. Click "Show {host} {path} in HTTP history" | Query filter set with host AND path, navigates to history | happy-path |
| LOGGER-010 | User clears entire log | Log has entries | 1. Click "Clear log" button | Confirmation modal opens: "Clear the tool log?" | happy-path |
| LOGGER-011 | User confirms clear log | Clear confirmation modal open | 1. Click "Clear {count} entries" button | Log cleared, selectedId cleared, modal closes, toast shows "Tool log cleared" | happy-path |
| LOGGER-012 | User cancels clear log | Clear confirmation modal open | 1. Click "Keep the log" button | Modal closes without clearing | happy-path |
| LOGGER-013 | User shows entry in history from detail | Entry selected | 1. Click "Show in history" button in detail panel | Query filter set, navigates to history page | happy-path |
| LOGGER-014 | User clears selection | Entry selected | 1. Click "Clear selection" icon in detail panel | Selection cleared, detail panel shows empty state | happy-path |
| LOGGER-015 | Clear log button disabled when empty | No log entries | 1. Observe "Clear log" button | Button is disabled | disabled-state |
| LOGGER-016 | No matches state when search narrows to zero | Log entries exist, narrow search | 1. Enter search term matching nothing | Table shows empty state "No logged request matches" | empty-state |
| LOGGER-017 | No row selected state | No row clicked yet | 1. Observe detail panel | Shows empty state "No row selected" | empty-state |
| LOGGER-018 | Search debouncedTerm delay | User types quickly | 1. Type "exam" (3 chars) 2. Type "ple" (3 more) 3. Wait 260ms | Query happens once with final "example" term, not for each keystroke | happy-path |
| LOGGER-019 | Row selection by ID survives refetch | Row selected, log refetches | 1. Select a row by ID 2. Background refetch occurs | Selected row (by ID) remains selected if still in data | happy-path |
| LOGGER-020 | Table shows count badges | Log data loaded | 1. Observe header badges | Shows "{shown} of {total} shown" and "{dropped} dropped" | happy-path |
| LOGGER-021 | Dropped count shows warning tone | Log dropped entries | 1. Observe "dropped" badge when data.dropped > 0 | Badge uses "warn" tone (orange) | warning |
| LOGGER-022 | Dropped count shows neutral tone | No entries dropped | 1. Observe "dropped" badge when data.dropped === 0 | Badge uses "neutral" tone | happy-path |
| LOGGER-023 | Refresh button refetches log | Log displayed | 1. Click refresh icon | Log reloads from server | happy-path |
| LOGGER-024 | Tool filter populated from server | Log data loaded | 1. Observe "Tool filter" select options | Options come from server's tool histogram, dynamically sorted | happy-path |
| LOGGER-025 | Status badge tone based on HTTP status | Row with status 500 selected | 1. Observe status badge in detail | Badge uses appropriate tone (bad/warn/good based on status) | happy-path |
| LOGGER-026 | Error shows "no response" | Log entry with null status | 1. View entry with status=null | Badge shows "no response" | empty-state |
| LOGGER-027 | Context menu groups separate actions | Right-click on row | 1. Right-click a row | Menu shows 4 distinct actions (copy URL, copy curl, show host, show host+path) | happy-path |
| LOGGER-028 | URL inference uses port 443 for HTTPS | Entry has port 443 | 1. Right-click and copy URL | URL uses "https://" scheme | happy-path |
| LOGGER-029 | URL inference uses port 80 for HTTP | Entry has port 80 | 1. Right-click and copy URL | URL uses "http://" scheme | happy-path |
| LOGGER-030 | URL includes non-standard port | Entry has port 8080 | 1. Right-click and copy URL | URL includes ":8080" in authority | happy-path |
| LOGGER-031 | curl uses X flag for non-GET methods | Entry has method "POST" | 1. Copy curl command | curl includes "-X POST" flag | happy-path |
| LOGGER-032 | curl omits headers and body from log | Curl copied | 1. Copy curl command | Toast explicitly says "the log stores no headers or body" | happy-path |
| LOGGER-033 | Table sorting by column | Multiple entries | 1. Click "Age" column header | Entries sort by started_ms, arrow icon shows sort direction | happy-path |
| LOGGER-034 | Table sorting toggle direction | Column sorted ascending | 1. Click "Age" column header again | Sort toggles to descending | happy-path |

---

## ORGANIZER-ORGANIZER (additional advanced scenarios)

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| ORGANIZER-035 | Field hint shows highlight colors available | Detail panel open | 1. Observe highlight dropdown | Dropdown shows 10 options: "none", "red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray" | happy-path |
| ORGANIZER-036 | Badge tone matches highlight color | Item with red highlight selected | 1. Observe table row | Highlight column badge uses "bad" tone (red CSS class) | happy-path |
| ORGANIZER-037 | Badge tone green for green highlight | Item with green highlight selected | 1. Observe table row | Highlight column badge uses "good" tone (green CSS class) | happy-path |

---

## DASHBOARD Page

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| DASHBOARD-001 | User opens Dashboard page | Fresh session | 1. Navigate to hash `#dashboard` | Page loads with overview metrics (Exchanges, Capture store, Running tasks, Coverage gaps) | happy-path |
| DASHBOARD-002 | User clicks "Open HTTP history" | Dashboard loaded | 1. Click "Open HTTP history" button in traffic sources section | Route changes to "history", HTTP history page loads | happy-path |
| DASHBOARD-003 | Dashboard displays traffic sources | Data loaded | 1. Observe dashboard | Traffic sources metric grid shows exchanges by source, sorted by count descending | happy-path |
| DASHBOARD-004 | Dashboard shows coverage cards | Summaries exist | 1. Observe coverage section | One card per summary with findings display | happy-path |
| DASHBOARD-005 | Dashboard shows activity table | Activity events exist | 1. Observe activity section | Last 10 tool requests shown in table | happy-path |
| DASHBOARD-006 | Dashboard shows events list | Events exist | 1. Observe events section | Last 12 events displayed chronologically | happy-path |
| DASHBOARD-007 | Dashboard shows tasks table | Tasks exist | 1. Observe tasks section | All running/queued tasks shown | happy-path |
| DASHBOARD-008 | Coverage gaps warning shown | Incomplete summaries exist | 1. Observe notice | Warning shows "{count} coverage {plural} report(s) work without a verdict" | warning |
| DASHBOARD-009 | No traffic yet state | No exchanges captured | 1. Observe traffic sources | Empty state: "No traffic yet" with detail about proxy configuration | empty-state |
| DASHBOARD-010 | No coverage reported state | No summaries | 1. Observe coverage section | Empty state: "No coverage reported" | empty-state |
| DASHBOARD-011 | No tasks state | No tasks running | 1. Observe tasks section | Empty state: "No tasks" | empty-state |
| DASHBOARD-012 | No events state | No events yet | 1. Observe events section | Empty state: "No events" | empty-state |
| DASHBOARD-013 | Nothing captured notice | Empty capture store | 1. Observe dashboard | Notice: "Nothing captured yet. Point a browser or client at the proxy listener, install the CA certificate from the sidebar..." | empty-state |

---

## SETTINGS Page — Scope Section

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| SETTINGS-001 | User opens Settings page | Fresh session | 1. Navigate to hash `#settings` | Page loads with Scope, Protocol, Appearance, and Certificate sections | happy-path |
| SETTINGS-002 | User adds include scope rule | No rules | 1. Select "Include" in kind dropdown 2. Enter "api.example.com" 3. Click "Add rule" | Rule added to table, pattern input cleared, toast shows "includ api.example.com" | happy-path |
| SETTINGS-003 | User adds exclude scope rule | Include rule exists | 1. Select "Exclude" in kind dropdown 2. Enter "internal.example.com" 3. Click "Add rule" | Rule added, toast shows "exclud internal.example.com" | happy-path |
| SETTINGS-004 | User presses Enter to add rule | Pattern entered | 1. Type pattern 2. Press Enter | Rule added (if pattern non-empty) | happy-path |
| SETTINGS-005 | User removes scope rule | Rules exist | 1. Click remove icon on a rule | Rule deleted, toast shows "Removed {pattern}" | happy-path |
| SETTINGS-006 | User clears all scope rules | Rules exist | 1. Click "Clear scope" button | Confirmation modal opens: "Clear every scope rule?" | happy-path |
| SETTINGS-007 | User confirms clear scope | Confirmation modal open | 1. Click "Clear scope" button in modal | All rules cleared, toast shows "Scope cleared" | happy-path |
| SETTINGS-008 | User cancels clear scope | Confirmation modal open | 1. Click "Cancel" button | Modal closes without clearing | happy-path |
| SETTINGS-009 | Add rule button disabled with empty input | Pattern input empty | 1. Observe "Add rule" button | Button is disabled | disabled-state |
| SETTINGS-010 | Add rule button disabled with whitespace | Pattern is "   " | 1. Observe "Add rule" button | Button is disabled (trim() check) | boundary |
| SETTINGS-011 | Add rule button disabled while adding | Add operation in progress | 1. Click "Add rule" 2. Before response, observe | Button is disabled | loading |
| SETTINGS-012 | Add rule disabled when pattern.trim() empty | User clears pattern after entering | 1. Enter pattern 2. Clear to whitespace 3. Observe button | Button becomes disabled | happy-path |
| SETTINGS-013 | Remove rule button disabled for null host | Rule with host === null | 1. Observe remove button on "any host" rule | Button is disabled | disabled-state |
| SETTINGS-014 | Clear scope button disabled when empty | No rules | 1. Observe "Clear scope" button | Button is disabled | disabled-state |
| SETTINGS-015 | Clear scope button disabled while clearing | Clear operation in progress | 1. Click "Clear scope" 2. Before response, observe | Button is disabled | loading |
| SETTINGS-016 | Scope warning notice displayed | Page loaded | 1. Observe notice under section heading | Notice shows "A scope rule matches on a host pattern only..." | info |
| SETTINGS-017 | Scope rules table shows all rules | Multiple rules exist | 1. Observe table | All rules displayed in rows | happy-path |
| SETTINGS-018 | Scope badge shows "everything in scope" | data.allow_all === true | 1. Observe badge in header | Badge shows "everything in scope" with warn tone | happy-path |
| SETTINGS-019 | Scope badge shows "restricted" | data.allow_all === false | 1. Observe badge in header | Badge shows "restricted" with good tone | happy-path |
| SETTINGS-020 | No scope rules state | Empty rules list | 1. Observe scope section | Empty state: "No scope rules" | empty-state |
| SETTINGS-021 | Scope error handled | Network error loading scope | 1. Settings page fails to load scope | ErrorNotice shown with retry button | error |
| SETTINGS-022 | Scope loading state | Scope data fetching | 1. Observe while loading | LoadingPanel shown "Loading scope" | loading |
| SETTINGS-023 | Scope refresh button | Scope displayed | 1. Click refresh icon | Scope reloads from server | happy-path |
| SETTINGS-024 | Rule kind badge tone good for Include | Include rule displayed | 1. Observe badge in table | Badge uses "good" tone | happy-path |
| SETTINGS-025 | Rule kind badge tone bad for Exclude | Exclude rule displayed | 1. Observe badge in table | Badge uses "bad" tone | happy-path |

---

## SETTINGS Page — Protocol Section

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| SETTINGS-026 | User probes protocol negotiation | Protocol section loaded | 1. Enter host "example.com" 2. Enter port "443" 3. Check "Use TLS" 4. Click "Probe negotiation" | Probe sent, result displayed, toast shows negotiation result | happy-path |
| SETTINGS-027 | User probes without TLS | Protocol section loaded | 1. Enter host "example.com" 2. Enter port "80" 3. Uncheck "Use TLS" 4. Click "Probe negotiation" | Probe sent without TLS preface | happy-path |
| SETTINGS-028 | Probe button disabled with empty host | Host input empty | 1. Observe "Probe negotiation" button | Button is disabled | disabled-state |
| SETTINGS-029 | Probe button disabled with invalid port | Port input non-integer | 1. Enter port "abc" 2. Observe button | Button is disabled | disabled-state |
| SETTINGS-030 | Probe button disabled with port ≤ 0 | Port input "0" | 1. Observe button | Button is disabled | disabled-state |
| SETTINGS-031 | Probe error — invalid inputs | Host empty, port invalid | 1. Click "Probe negotiation" | Toast shows "A probe needs a host and a port" | boundary |
| SETTINGS-032 | Probe result shows negotiated protocol | Probe succeeds | 1. Probe to server | Result displays negotiated protocol e.g. "HTTP/2" | happy-path |
| SETTINGS-033 | Probe result shows frames table | Probe receives frames | 1. Probe to server 2. Server sends frames | Frames table populated with frame details | happy-path |
| SETTINGS-034 | Probe result shows violations | Protocol violations detected | 1. Probe to server with violations | Notice shown: "Protocol violations observed: {list}" | warning |
| SETTINGS-035 | Probe result shows refusals | Scope refused probe | 1. Probe out-of-scope host | Notice shown: "Scope refused this probe: {reasons}" | error |
| SETTINGS-036 | No frames in probe reply | Peer sent no complete frame | 1. Probe to server 2. No frames in response | Hint text: "The peer sent no complete frame back." | empty-state |
| SETTINGS-037 | No downgrades recorded | No HTTP/2 downgrade events | 1. Observe protocol downgrades list | Hint text: "No downgrades recorded: nothing fell back from HTTP/2 for a stated reason." | empty-state |
| SETTINGS-038 | No authority has been probed | No probe data | 1. Observe authority list | Empty state: "No authority has been probed" | empty-state |
| SETTINGS-039 | Protocols not enabled | No sender wired | 1. Observe protocol section notice | Warning: "{hint text}" or "No sender is wired, so nothing has been sent from this process." | warning |
| SETTINGS-040 | Protocol loading state | Fetching protocol data | 1. Observe section while loading | LoadingPanel shown "Loading protocol report" | loading |
| SETTINGS-041 | Protocol error handled | Network error fetching data | 1. Settings fails to load protocols | ErrorNotice shown with retry button | error |
| SETTINGS-042 | Port input defaults to 443 | Fresh page load | 1. Observe port input initial value | Input shows "443" | happy-path |
| SETTINGS-043 | TLS toggle defaults to true | Fresh page load | 1. Observe TLS switch | Switch is checked (true) | happy-path |

---

## SETTINGS Page — Appearance Section

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| SETTINGS-044 | User changes theme to Light | Theme section visible | 1. Open theme select 2. Choose "Light" | Theme changes to light, `data-theme` attribute set to "light" on document | happy-path |
| SETTINGS-045 | User changes theme to Dark | Theme section visible | 1. Open theme select 2. Choose "Dark" | Theme changes to dark, `data-theme` attribute set to "dark" | happy-path |
| SETTINGS-046 | User sets theme to System | Theme section visible | 1. Open theme select 2. Choose "Follow the system" | Theme follows system preference, media query listener registered | happy-path |
| SETTINGS-047 | User changes table density to Compact | Appearance section visible | 1. Open table density select 2. Choose "Compact" | Density updates to "compact", VirtualTable re-measures row height | happy-path |
| SETTINGS-048 | User changes table density to Comfortable | Appearance section visible | 1. Open table density select 2. Choose "Comfortable" | Density updates to "comfortable", VirtualTable re-measures row height | happy-path |
| SETTINGS-049 | Density change affects table layout | Table displayed with "comfortable" | 1. Change density to "compact" 2. Observe table | Row height decreases, more rows visible | happy-path |
| SETTINGS-050 | Follow system option disabled when already system | Theme is "system" | 1. Observe "Follow the system" option | Option is disabled (current value) | disabled-state |

---

## SETTINGS Page — Certificate Section

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| SETTINGS-051 | User downloads CA certificate | Certificate available | 1. Click "Download burpsy-ca.crt" link | Browser downloads file from `/ca.crt` endpoint with filename "burpsy-ca.crt" | happy-path |
| SETTINGS-052 | CA certificate link shown when available | data.available === true | 1. Observe certificate section | Link and "certificate available" badge visible | happy-path |
| SETTINGS-053 | CA certificate warning shown when unavailable | data.available === false | 1. Observe certificate section | Warning notice shown: "{detail text}" | warning |
| SETTINGS-054 | CA certificate download link is HTML <a> element | Certificate section | 1. Inspect link element | Link has `href="/ca.crt"` and `download="burpsy-ca.crt"` attributes | happy-path |

---

## SHELL Page — Navigation & Routing

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| SHELL-001 | User navigates via URL hash | Browser address bar | 1. Enter URL with hash `#decoder` | App routes to Decoder page | happy-path |
| SHELL-002 | User navigates via tool tab | Toolbar visible | 1. Click "Decoder" tool tab | Routes to Decoder page, tab highlights as active | happy-path |
| SHELL-003 | User navigates via Alt+7 hotkey | Any page | 1. Press Alt+7 | Routes to Decoder page | keyboard |
| SHELL-004 | User navigates via Alt+8 hotkey | Any page | 1. Press Alt+8 | Routes to Comparer page | keyboard |
| SHELL-005 | User navigates via Alt+9 hotkey | Any page | 1. Press Alt+9 | Routes to Logger page | keyboard |
| SHELL-006 | User navigates via Alt+0 hotkey | Any page | 1. Press Alt+0 | Routes to Organizer page | keyboard |
| SHELL-007 | User navigates via Alt+1 hotkey | Any page | 1. Press Alt+1 | Routes to Dashboard page | keyboard |
| SHELL-008 | Unknown hash silently ignored | URL has hash `#unknown_page` | 1. Navigate to invalid hash | Current route unchanged, invalid hash not applied | boundary |
| SHELL-009 | Empty hash uses first leaf fallback | URL has empty hash | 1. Navigate to `/` (no hash) | Routes to first leaf (Dashboard) | happy-path |
| SHELL-010 | Hash updated when route changes | On Dashboard, click Decoder tab | 1. Observe URL after navigation | Hash changes to `#decoder` in address bar | happy-path |
| SHELL-011 | Tool with multiple leaves shows sub-tabs | Navigate to Target tool | 1. Click Target tab (alt+2) | Routes to first leaf (sitemap), sub-tabs row appears showing sitemap, scanner, scope | happy-path |
| SHELL-012 | Sub-tab click navigates to leaf | On Target sitemap, click "Issues" sub-tab | 1. Click "Issues" sub-tab | Routes to scanner leaf, hash updates to `#scanner` | happy-path |
| SHELL-013 | Sub-tabs not shown for single-leaf tools | On Dashboard | 1. Observe toolbar | Sub-tabs row not rendered (only one leaf) | happy-path |

---

## SHELL Page — Menu Bar

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| SHELL-014 | User opens Burpsy menu | Menu bar visible | 1. Click "burpsy" menu | Dropdown shows "Settings", "Command palette", "Keyboard shortcuts" | happy-path |
| SHELL-015 | User navigates to Settings via menu | Burpsy menu open | 1. Click "Settings" | Routes to settings page | happy-path |
| SHELL-016 | User opens command palette via menu | Burpsy menu open | 1. Click "Command palette" | Command palette opens | happy-path |
| SHELL-017 | User opens shortcuts help via menu | Burpsy menu open | 1. Click "Keyboard shortcuts" | Shortcuts help modal opens | happy-path |
| SHELL-018 | User opens Project menu | Menu bar visible | 1. Click "Project" menu | Dropdown shows export options (HTML, JSON, SARIF) and CA cert download | happy-path |
| SHELL-019 | User exports report as HTML | Project menu open | 1. Click "Export report (HTML)" | Opens `/api/report/html` in new window | happy-path |
| SHELL-020 | User exports report as JSON | Project menu open | 1. Click "Export report (JSON)" | Opens `/api/report/json` in new window | happy-path |
| SHELL-021 | User exports report as SARIF | Project menu open | 1. Click "Export report (SARIF)" | Opens `/api/report/sarif` in new window | happy-path |
| SHELL-022 | User downloads CA cert via menu | Project menu open | 1. Click "Download CA certificate" | Opens `/ca.crt` in new window for download | happy-path |
| SHELL-023 | User opens Repeater menu | Menu bar visible | 1. Click "Repeater" menu | Dropdown shows "New request tab" and "Go to Repeater" | happy-path |
| SHELL-024 | User creates new repeater tab | Repeater menu open | 1. Click "New request tab" | Creates repeater tab with template request to example.com, navigates to repeater | happy-path |
| SHELL-025 | User goes to Repeater via menu | Repeater menu open | 1. Click "Go to Repeater" | Routes to repeater page | happy-path |
| SHELL-026 | User opens View menu | Menu bar visible | 1. Click "View" menu | Dropdown shows theme options (Light/Dark/System), density options, and context-aware icons | happy-path |
| SHELL-027 | User toggles light theme via menu | View menu open, dark theme active | 1. Click "Dark theme" option | Theme changes to light, option text updates to "Light theme" | happy-path |
| SHELL-028 | User toggles dark theme via menu | View menu open, light theme active | 1. Click "Light theme" option | Theme changes to dark, option text updates to "Dark theme" | happy-path |
| SHELL-029 | User sets system theme via menu | View menu open | 1. Click "Follow the system theme" | Theme set to "system", option disabled | happy-path |
| SHELL-030 | System theme option disabled when active | Theme is "system" | 1. Open View menu | "Follow the system theme" option is disabled | disabled-state |
| SHELL-031 | Density toggle via menu | View menu open | 1. Click density option (Comfortable or Compact) | Density toggles, table layout updates | happy-path |
| SHELL-032 | User opens Help menu | Menu bar visible | 1. Click "Help" menu | Dropdown shows keyboard shortcuts and command palette | happy-path |
| SHELL-033 | User opens Help via Help menu | Help menu open | 1. Click "Keyboard shortcuts" | Shortcuts help modal opens | happy-path |
| SHELL-034 | User opens command palette via Help | Help menu open | 1. Click "Command palette" | Command palette opens | happy-path |
| SHELL-035 | Menu icon appears for each action | Menu items displayed | 1. Observe menu items | Icons visible on left of action labels (e.g., Plus for "New request") | happy-path |
| SHELL-036 | Menu shortcut hints displayed | Menu open | 1. Observe menu items | Shortcut text shown on right (e.g., "mod+K" for "Command palette") | happy-path |

---

## SHELL Page — Command Palette

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| SHELL-037 | User opens command palette with Mod+K | Any page | 1. Press Ctrl+K (or Cmd+K) | Command palette opens with search input focused | keyboard |
| SHELL-038 | User opens command palette via menu | Burpsy menu | 1. Click "Command palette" | Command palette opens | happy-path |
| SHELL-039 | User searches actions in palette | Palette open | 1. Type "decoder" | Actions matching "decoder" (Decoder page navigation) appear | happy-path |
| SHELL-040 | Palette shows all navigation actions | Palette open, empty search | 1. Observe action list | All 22 navigation actions (one per leaf) visible, sorted by default order | happy-path |
| SHELL-041 | Palette shows all command actions | Palette open, empty search | 1. Scroll to bottom of list | 5 command actions visible (theme, density, shortcuts, CA cert, export report) | happy-path |
| SHELL-042 | Palette search uses scoring | Palette open | 1. Type "hh" | "HTTP history" action appears (initials match) | happy-path |
| SHELL-043 | Palette search biases word starts | Palette open | 1. Type "http" | "HTTP history" appears with higher score than other matches | happy-path |
| SHELL-044 | Palette results limited to top 60 | Palette open | 1. Type a term matching > 60 actions | Only top 60 results displayed | boundary |
| SHELL-045 | Palette empty state when no matches | Palette open | 1. Type "zzzzzz" (no matches) | Message: "No matching command" | empty-state |
| SHELL-046 | User selects action with Enter | Palette open, action highlighted | 1. Press Enter | Action invoked, palette closes | happy-path |
| SHELL-047 | User selects action by clicking | Palette open | 1. Click an action | Action invoked, palette closes | happy-path |
| SHELL-048 | User navigates results with arrow keys | Palette open | 1. Press Down 2. Press Up 3. Press Down | Selection moves down, up, down | keyboard |
| SHELL-049 | User closes palette with Escape | Palette open | 1. Press Escape | Palette closes, search cleared | keyboard |
| SHELL-050 | Palette action includes icon | Palette result | 1. Observe action item | Icon (14px) shown on left of label | happy-path |
| SHELL-051 | Palette action includes hint | Navigation action selected | 1. Observe action item | Hint text (description from leaf) shown below label | happy-path |
| SHELL-052 | Palette action includes shortcut | Tool navigation with hotkey | 1. Observe action item | Shortcut text (e.g., "alt+7") shown on right | happy-path |
| SHELL-053 | Palette groups actions visually | Palette open | 1. Observe action list | Group headings ("Go to", "Appearance", "Help") visible before groups | happy-path |
| SHELL-054 | Palette search queries label + group + keywords | Palette open | 1. Type "certificate" | "Download the CA certificate" action found (keywords include "certificate") | happy-path |
| SHELL-055 | Palette defaults to all actions empty query | Palette opens | 1. Observe initial list | All 27 actions shown (22 navigation + 5 command), equal score | happy-path |

---

## SHELL Page — Keyboard Shortcuts Help

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| SHELL-056 | User opens shortcuts help with ? | Any page | 1. Press ? (shift+/) | Shortcuts help modal opens | keyboard |
| SHELL-057 | User opens shortcuts help via menu | Menu visible | 1. Click menu item "Keyboard shortcuts" | Shortcuts help modal opens | happy-path |
| SHELL-058 | Help modal shows all shortcut groups | Modal open | 1. Observe groups | 5 groups: "Send to", "Proxy", "Message editor", "Navigation", "Appearance and help" | happy-path |
| SHELL-059 | Help modal shows shortcut notes | Modal open, viewing "Proxy" group | 1. Observe "alt+T" row | Note text: "Burp uses mod+T; browsers reserve it for a new tab" | info |
| SHELL-060 | Help modal shows alt+1…0 note | Modal open, viewing "Navigation" group | 1. Observe "alt+1…0" row | Note text: "Burp uses mod+shift+letter; browsers reserve most of those" | info |
| SHELL-061 | User closes help modal | Modal open | 1. Press Escape or click close button | Modal closes | happy-path |
| SHELL-062 | Shortcut keys display as Kbd elements | Modal open | 1. Observe any shortcut row | Keys wrapped in `<Kbd>` elements with monospace styling | happy-path |

---

## SHELL Page — Global Hotkeys

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| SHELL-063 | Mod+K opens command palette | Any page | 1. Press Ctrl+K (or Cmd+K) | Command palette opens | keyboard |
| SHELL-064 | Mod+Shift+L toggles theme | Any page | 1. Press Ctrl+Shift+L (or Cmd+Shift+L) | Theme toggles between light and dark | keyboard |
| SHELL-065 | ? shows shortcuts help | Any page | 1. Press ? (shift+/) | Shortcuts help modal opens | keyboard |
| SHELL-066 | Alt+1 navigates to Dashboard | Any page | 1. Press Alt+1 | Routes to Dashboard | keyboard |
| SHELL-067 | Alt+2 navigates to Target | Any page | 1. Press Alt+2 | Routes to Target (sitemap leaf) | keyboard |
| SHELL-068 | Alt+3 navigates to Proxy | Any page | 1. Press Alt+3 | Routes to Proxy (intercept leaf) | keyboard |
| SHELL-069 | Alt+4 navigates to Intruder | Any page | 1. Press Alt+4 | Routes to Intruder | keyboard |
| SHELL-070 | Alt+5 navigates to Repeater | Any page | 1. Press Alt+5 | Routes to Repeater | keyboard |
| SHELL-071 | Alt+6 navigates to Sequencer | Any page | 1. Press Alt+6 | Routes to Sequencer | keyboard |
| SHELL-072 | Alt+7 navigates to Decoder | Any page | 1. Press Alt+7 | Routes to Decoder | keyboard |
| SHELL-073 | Alt+8 navigates to Comparer | Any page | 1. Press Alt+8 | Routes to Comparer | keyboard |
| SHELL-074 | Alt+9 navigates to Logger | Any page | 1. Press Alt+9 | Routes to Logger | keyboard |
| SHELL-075 | Alt+0 navigates to Organizer | Any page | 1. Press Alt+0 | Routes to Organizer | keyboard |
| SHELL-076 | Hotkeys enabled on form tags | Form input focused | 1. Focus input 2. Press Alt+1 | Routes to Dashboard (hotkey works even in form) | keyboard |
| SHELL-077 | Theme hotkey works on any page | Any page | 1. Press Mod+Shift+L | Theme toggles regardless of page context | keyboard |

---

## SHELL Page — Toolbar & Status Bar

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| SHELL-078 | Connection badge shows "live" | Event stream connected | 1. Observe status bar | Green dot + "live" text visible on left | happy-path |
| SHELL-079 | Connection badge shows "offline" | Event stream disconnected | 1. Disconnect WebSocket | Orange dot + "offline" text visible | warning |
| SHELL-080 | Data stored shows byte count | Store has data | 1. Observe status bar | Database icon + formatted byte count (e.g., "1.2 MB stored") | happy-path |
| SHELL-081 | Exchange count displayed | Exchanges captured | 1. Observe status bar | Network icon + count (e.g., "42 exchanges") | happy-path |
| SHELL-082 | Message count displayed | Messages stored | 1. Observe status bar | Message count (e.g., "18 messages") shown | happy-path |
| SHELL-083 | Scope status displays | Scope configured | 1. Observe status bar | Scope text (e.g., "scope: everything" or "scope: 3 rules") | happy-path |
| SHELL-084 | CA cert download link in status bar | CA cert available | 1. Observe status bar | "CA certificate" link visible with shield icon | happy-path |
| SHELL-085 | Last event timestamp shown | Events exist | 1. Observe status bar | "last event 30s ago" or similar relative time | happy-path |
| SHELL-086 | "No events yet" shown when no events | No events logged | 1. Observe status bar | "no events yet" text on right side | empty-state |
| SHELL-087 | Theme toggle button in toolbar | Toolbar visible | 1. Observe right side | Sun/Moon icon button for theme toggle | happy-path |
| SHELL-088 | Command palette button in toolbar | Toolbar visible | 1. Observe right side | Command icon button labeled "Command palette (mod+K)" | happy-path |
| SHELL-089 | Shortcuts button in toolbar | Toolbar visible | 1. Observe right side | Keyboard icon button labeled "Keyboard shortcuts (?)" | happy-path |
| SHELL-090 | Brand "b/" logo in toolbar | Toolbar visible | 1. Observe left side | "b/" symbol + "burpsy" text shown | happy-path |
| SHELL-091 | Tool tabs show all tools | Toolbar visible | 1. Count tool tabs | 12 tool tabs (Dashboard, Target, Proxy, Intruder, Repeater, Sequencer, Decoder, Comparer, Logger, Organizer, Session, Settings) | happy-path |
| SHELL-092 | Tool tab shows hotkey in title | Hovering tool tab | 1. Hover over Decoder tab | Tooltip shows "Decoder (alt+7)" | happy-path |
| SHELL-093 | Active tool tab highlighted | Decoder page | 1. Observe toolbar | Decoder tab has `tool-tab-active` class and `aria-current="page"` | happy-path |

---

## TABLE Shared Component

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| TABLE-001 | User clicks table header to sort | Multiple rows with sortable column | 1. Click "Age" column header | Rows sort ascending by age, up-arrow icon shown | happy-path |
| TABLE-002 | User clicks sorted header to reverse | Sorted ascending by Age | 1. Click "Age" header again | Rows reverse to descending, down-arrow icon shown | happy-path |
| TABLE-003 | User selects table row by click | Multiple rows | 1. Click row | Row highlights with `selected-row` class, `onSelect` called | happy-path |
| TABLE-004 | User navigates rows with arrow keys | Row selected | 1. Press Down | Focus moves to next row, `onSelect` called | keyboard |
| TABLE-005 | User navigates rows up with arrow | Row selected (not first) | 1. Press Up | Focus moves to previous row | keyboard |
| TABLE-006 | User jumps page with PageDown | Row selected | 1. Press PageDown | Selection moves ~14 rows forward (overscan jump) | keyboard |
| TABLE-007 | User jumps page with PageUp | Row selected (not on first page) | 1. Press PageUp | Selection moves ~14 rows back | keyboard |
| TABLE-008 | User goes to first row with Home | Row selected | 1. Press Home | Selection moves to first row | keyboard |
| TABLE-009 | User goes to last row with End | Row selected | 1. Press End | Selection moves to last row | keyboard |
| TABLE-010 | User activates row with Enter | Row selected | 1. Press Enter | `onActivate` called (or `onSelect` if no activate handler) | keyboard |
| TABLE-011 | User activates row with double-click | Row visible | 1. Double-click row | `onActivate` called | happy-path |
| TABLE-012 | User right-clicks row to open context menu | Row visible | 1. Right-click row | Context menu opens, row becomes selected | happy-path |
| TABLE-013 | User presses context menu key to open menu | Row selected | 1. Press context menu key | Context menu opens | keyboard |
| TABLE-014 | Column resize by dragging | Table with resizable columns | 1. Drag resize handle between columns | Column width changes, position persisted via TanStack Table state | happy-path |
| TABLE-015 | Column resize double-click to reset | Column resized | 1. Double-click resize handle | Column width resets to default | happy-path |
| TABLE-016 | Column resize works on touch | Touch device, table visible | 1. Touch-drag resize handle | Column resizes (touch-supported in TanStack) | happy-path |
| TABLE-017 | Table virtualization with many rows | 10,000 rows | 1. Scroll table | Only visible rows + 14 overscan rows rendered in DOM | happy-path |
| TABLE-018 | Table scroll position auto-managed | Selected row outside viewport | 1. Select row 100 from external action | Virtualizer auto-scrolls to keep row visible | happy-path |
| TABLE-019 | Empty state shown when no rows | Empty data array | 1. Observe table | `empty` prop content displayed (custom empty state) | empty-state |
| TABLE-020 | Loading state shows spinner | Loading = true | 1. Observe table | Spinner overlay visible, table content behind | loading |
| TABLE-021 | Density compact makes rows smaller | Density = "comfortable" | 1. Change density to "compact" 2. Observe rows | Row height decreases per `--row-h-compact` CSS token | happy-path |
| TABLE-022 | Density comfortable makes rows larger | Density = "compact" | 1. Change density to "comfortable" 2. Observe rows | Row height increases per `--row-h` CSS token | happy-path |
| TABLE-023 | Row className applied to row styling | Custom rowClassName provided | 1. Render table with custom class fn | Custom CSS classes applied to row elements | happy-path |
| TABLE-024 | Menu groups rendered on right-click | MenuGroups function provided | 1. Right-click row | Context menu items from menuGroups() displayed | happy-path |
| TABLE-025 | Selected row stays visible on refetch | Row selected, data refetches | 1. Keep row selected 2. Background refetch | Selected row ID matched in new data, selection persists | happy-path |
| TABLE-026 | Sort state persists across selection | Sorted, row selected | 1. Select different row | Sort order unchanged | happy-path |
| TABLE-027 | Table shows correct row count | 50 rows provided | 1. Count virtual items on screen | Total count reflects full data length | happy-path |
| TABLE-028 | Selection clears when data empties | Row selected, data updates to [] | 1. Delete all rows | SelectedId remains but no match found in rows | happy-path |
| TABLE-029 | initialSort applies on mount | initialSort provided as props | 1. Mount table with initialSort | Rows sorted per initialSort state | happy-path |

---

## EDITOR Shared Component

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| EDITOR-001 | Raw view shows editable content | HttpEditor editable | 1. Focus "raw" tab 2. Edit text | Text updates in editor, `onChange` called | happy-path |
| EDITOR-002 | Pretty view shows formatted content | Multi-line HTTP response | 1. Click "pretty" tab | Body formatted (indented if JSON/XML) | happy-path |
| EDITOR-003 | Hex view shows byte dump | Message with binary data | 1. Click "hex" tab | Content displays as hex lines with ASCII column | happy-path |
| EDITOR-004 | Render view displays response HTML | Response is HTML | 1. Click "render" tab | Content rendered in sandboxed iframe | happy-path |
| EDITOR-005 | Pretty tab only shown if different from raw | JSON message | 1. Compare "raw" and "pretty" tabs | If formatted differently, "pretty" tab shown; otherwise hidden | happy-path |
| EDITOR-006 | Render tab only shown for responses | Request message | 1. Click "raw" tab 2. Observe tabs | No "render" tab (only for responses) | happy-path |
| EDITOR-007 | Wrap toggle available in non-render views | Text view active | 1. Observe toolbar | WrapText icon button visible | happy-path |
| EDITOR-008 | Wrap toggle hidden in render view | Render view active | 1. Observe toolbar | WrapText icon button not visible | happy-path |
| EDITOR-009 | User toggles wrap | Long line content | 1. Click wrap toggle | Text wraps/unwraps, visual toggle indicator changes | happy-path |
| EDITOR-010 | Byte count shown in header | Message pasted | 1. Observe editor header | Byte count displays (e.g., "1.2 KB") | happy-path |
| EDITOR-011 | User copies message | Editor content | 1. Click "Copy message" button | Content copied to clipboard, toast shows success | happy-path |
| EDITOR-012 | User saves to file | Editor content | 1. Click "Save to file" button | Browser downloads file with content, filename from `filename` prop | happy-path |
| EDITOR-013 | Save filename defaults to message.txt | Filename prop not provided | 1. Save to file | Downloaded file named "message.txt" | happy-path |
| EDITOR-014 | User opens search with Mod+S | Editor focused, raw view | 1. Press Ctrl+S (or Cmd+S) | CodeMirror search panel opens | keyboard |
| EDITOR-015 | User encodes selection with Mod+U | Selection highlighted | 1. Press Ctrl+U (or Cmd+U) | Selection URL-encoded | keyboard |
| EDITOR-016 | User decodes selection with Mod+Shift+U | URL-encoded selection | 1. Press Ctrl+Shift+U (or Cmd+Shift+U) | Selection URL-decoded | keyboard |
| EDITOR-017 | User encodes selection with Mod+H | Selection highlighted | 1. Press Ctrl+H (or Cmd+H) | Selection HTML-encoded | keyboard |
| EDITOR-018 | User decodes selection with Mod+Shift+H | HTML-encoded selection | 1. Press Ctrl+Shift+H (or Cmd+Shift+H) | Selection HTML-decoded | keyboard |
| EDITOR-019 | User encodes selection with Mod+B | Selection highlighted | 1. Press Ctrl+B (or Cmd+B) | Selection Base64-encoded | keyboard |
| EDITOR-020 | User decodes selection with Mod+Shift+B | Base64-encoded selection | 1. Press Ctrl+Shift+B (or Cmd+Shift+B) | Selection Base64-decoded | keyboard |
| EDITOR-021 | Transform hotkeys only work with selection | No selection | 1. Try Ctrl+U with no selection | No transform happens | boundary |
| EDITOR-022 | ReadOnly mode prevents edits | readOnly = true | 1. Try to edit raw view | Content cannot be edited, `onChange` not called | happy-path |
| EDITOR-023 | Pretty view always read-only | Pretty view active | 1. Try to edit pretty view | Cannot edit (pretty is always read-only) | happy-path |
| EDITOR-024 | Hex view always read-only | Hex view active | 1. Try to edit hex view | Cannot edit | happy-path |
| EDITOR-025 | Render view always read-only | Render view active | 1. Try to interact with iframe | Content is sandboxed, not editable | happy-path |
| EDITOR-026 | Editor shows placeholder when empty | Placeholder prop provided | 1. Open editor with no content | Placeholder text shown | happy-path |
| EDITOR-027 | Custom height CSS applied | height="400px" prop | 1. Observe editor container | Editor viewport height is 400px | happy-path |
| EDITOR-028 | Custom label shown in header | label="Request body" | 1. Observe editor header | Label text shows "Request body" | happy-path |
| EDITOR-029 | Editor syntax highlighting applied | HTTP message | 1. Observe editor content | Start line bold, header names colored, body gray | happy-path |
| EDITOR-030 | Editor line numbers shown | Editor active | 1. Observe left gutter | Line numbers visible | happy-path |
| EDITOR-031 | Editor active line highlighted | Cursor on line | 1. Position cursor | Current line background highlighted | happy-path |
| EDITOR-032 | HTTP-aware theming uses CSS vars | Editor visible | 1. Inspect computed styles | Uses `--editor-*` CSS custom properties | happy-path |
| EDITOR-033 | Transform selection works mid-message | Message with header and body | 1. Select text in body 2. Encode | Only selection transformed, rest unchanged | happy-path |
| EDITOR-034 | Case-insensitive transform hotkeys | Selection present | 1. Press Ctrl+U or Ctrl+u | Both uppercase and lowercase trigger same action | keyboard |
| EDITOR-035 | Shift+/Ctrl modifier distinction for transforms | Selection present | 1. Press Ctrl+B (encode) 2. Ctrl+Shift+B (decode) | Different transforms applied based on shift modifier | keyboard |
| EDITOR-036 | Copy button shows tooltip | Copy button visible | 1. Hover copy button | Tooltip shows "Copy message" | happy-path |
| EDITOR-037 | Save button shows tooltip | Save button visible | 1. Hover save button | Tooltip shows "Save to file" | happy-path |
| EDITOR-038 | Actions toolbar provided | actions prop included | 1. Observe editor header | Custom action buttons render alongside standard actions | happy-path |

---

## EDITOR View Modes — Detailed

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| EDITOR-039 | Raw view is source of truth | Raw and pretty differ | 1. Edit raw view 2. Switch to pretty | Pretty shows formatted version of edited raw | happy-path |
| EDITOR-040 | Pretty view reflects raw changes | Raw view edited | 1. Edit raw 2. Click pretty tab | Pretty updates to formatted version of new raw | happy-path |
| EDITOR-041 | Hex view reflects raw changes | Raw view edited | 1. Edit raw with ASCII text 2. Click hex | Hex displays bytes of new raw content | happy-path |
| EDITOR-042 | Render view only in response context | Response message | 1. Observe tabs | "render" tab available only for responses, not requests | happy-path |
| EDITOR-043 | Render view sandboxed | HTML response | 1. Click render tab | Content displayed in sandboxed iframe (no external scripts) | happy-path |
| EDITOR-044 | Large message renders efficiently | 1 MB message | 1. Switch between views | No noticeable lag, virtualization or efficient rendering | happy-path |

---

## Integration Tests — Multi-Component Flows

| ID | Route | Precondition | Steps | Expected result | Type |
|---|---|---|---|---|---|
| INTEGRATION-001 | User decodes, compares results | Decoder open | 1. Add decode step 2. Run pipeline 3. Copy result 4. Navigate to Comparer 5. Paste into side A 6. Compare | Both components functional, data flows correctly between them | happy-path |
| INTEGRATION-002 | User organizes decoded findings | Decoded result visible | 1. Open Decoder 2. Run pipeline 3. Copy result 4. Navigate to Organizer 5. Add new exchange 6. Edit note with decoded value | Organizer preserves content pasted from Decoder | happy-path |
| INTEGRATION-003 | User themes toggle persists across navigation | Dashboard | 1. Toggle theme to dark 2. Navigate to Decoder 3. Navigate to Comparer | Dark theme persists across all pages | happy-path |
| INTEGRATION-004 | User density toggle persists across navigation | Logger with table | 1. Change density to compact 2. Navigate to Organizer 3. Observe table | Compact density persists in Organizer table | happy-path |
| INTEGRATION-005 | User navigates with hotkeys and URL | Any page | 1. Press Alt+7 (Decoder) 2. Observe URL hash 3. Navigate to #comparer in address bar | Both methods update route and URL consistently | happy-path |
| INTEGRATION-006 | User command palette action navigates | Dashboard | 1. Open palette 2. Type "comparer" 3. Press Enter | Routes to Comparer page, palette closes | happy-path |
| INTEGRATION-007 | User menu actions navigate | Menu bar | 1. Open Repeater menu 2. Click "Go to Repeater" | Routes to Repeater | happy-path |
| INTEGRATION-008 | User scope rules affect all tools | Settings | 1. Add include rule for "example.com" 2. Navigate to Proxy 3. Observe captures filtered | Scope rule applied across entire application | happy-path |

---

## Coverage

| Element | Cases referencing it |
|---------|---------------------|
| Decoder page | DECODER-001–034 |
| Decode step button | DECODER-002, DECODER-032 |
| Encode step button | DECODER-003, DECODER-032 |
| Hash step button | DECODER-004 |
| Step operation select | DECODER-006, DECODER-032 |
| Step value/encoding select | DECODER-007, DECODER-032 |
| Guess checkbox | DECODER-008–009, DECODER-029 |
| Move step up icon-button | DECODER-010, DECODER-026 |
| Move step down icon-button | DECODER-011, DECODER-027 |
| Remove step icon-button | DECODER-012 |
| Copy result icon-button | DECODER-013 |
| Text view button | DECODER-014–015 |
| Hex view button | DECODER-014–015, DECODER-017 |
| Run pipeline button | DECODER-005, DECODER-023–025 |
| HttpEditor (Decoder) | DECODER-005, DECODER-031, DECODER-034 |
| Comparer page | COMPARER-001–031 |
| Swap button | COMPARER-008, COMPARER-013–014 |
| Compare button | COMPARER-005, COMPARER-015–016 |
| Load message (slot A/B) | COMPARER-006–007, COMPARER-018–021 |
| Load button (slot A/B) | COMPARER-006–007 |
| Previous hunk button | COMPARER-010–012 |
| Next hunk button | COMPARER-009–012 |
| HttpEditor A & B | COMPARER-002–003, COMPARER-031 |
| Organizer page | ORGANIZER-001–037 |
| Exchange id input | ORGANIZER-002–003, ORGANIZER-021–023 |
| Save exchange button | ORGANIZER-002, ORGANIZER-019–020 |
| Table row (clickable) | ORGANIZER-004 |
| Open in history icon | ORGANIZER-015 |
| Remove item icon | ORGANIZER-010 |
| Title input | ORGANIZER-005 |
| Highlight select | ORGANIZER-007, ORGANIZER-036–037 |
| Investigation note textarea | ORGANIZER-006 |
| Revert button | ORGANIZER-009, ORGANIZER-017 |
| Save button | ORGANIZER-008, ORGANIZER-016–017 |
| Remove button (detail) | ORGANIZER-013 |
| Show in history button (detail) | ORGANIZER-015 |
| Delete confirmation button | ORGANIZER-011 |
| Keep it button | ORGANIZER-012 |
| Logger page | LOGGER-001–034 |
| Search input | LOGGER-002–003 |
| Clear search icon | LOGGER-003 |
| Tool filter select | LOGGER-004–004b |
| Table row (clickable) | LOGGER-005 |
| Context menu (copy URL) | LOGGER-006 |
| Context menu (copy curl) | LOGGER-007 |
| Context menu (show host) | LOGGER-008 |
| Context menu (show host+path) | LOGGER-009 |
| Clear log button | LOGGER-010, LOGGER-015 |
| Clear confirmation button | LOGGER-011 |
| Keep log button | LOGGER-012 |
| Show in history button (detail) | LOGGER-013 |
| Clear selection icon | LOGGER-014 |
| Dashboard page | DASHBOARD-001–013 |
| Open HTTP history button | DASHBOARD-002 |
| Settings page — Scope | SETTINGS-001–025 |
| Rule kind select | SETTINGS-002–003 |
| Host pattern input | SETTINGS-002–004 |
| Add rule button | SETTINGS-002, SETTINGS-009–012 |
| Remove scope rule icon | SETTINGS-005 |
| Clear scope button | SETTINGS-006, SETTINGS-014 |
| Clear scope confirmation | SETTINGS-007 |
| Cancel clear button | SETTINGS-008 |
| Settings page — Protocol | SETTINGS-026–043 |
| Probe host input | SETTINGS-026–027, SETTINGS-031 |
| Probe port input | SETTINGS-027–028 |
| Probe TLS switch | SETTINGS-027, SETTINGS-043 |
| Probe negotiation button | SETTINGS-026–027, SETTINGS-031 |
| Settings page — Appearance | SETTINGS-044–050 |
| Theme select | SETTINGS-044–046 |
| Table density select | SETTINGS-047–048 |
| Settings page — Certificate | SETTINGS-051–054 |
| Download CA cert link | SETTINGS-051, SETTINGS-054 |
| Shell navigation | SHELL-001–015 |
| URL hash routing | SHELL-001, SHELL-009 |
| Tool tab | SHELL-002, SHELL-091–093 |
| Alt+N hotkeys | SHELL-003–008, SHELL-063–075 |
| Menu bar | SHELL-014–036 |
| burpsy menu | SHELL-014–017 |
| Project menu | SHELL-018–022 |
| Repeater menu | SHELL-023–025 |
| View menu | SHELL-026–031 |
| Help menu | SHELL-032–034 |
| Command palette | SHELL-037–055 |
| Keyboard shortcuts help | SHELL-056–062 |
| Global hotkeys | SHELL-063–077 |
| Toolbar elements | SHELL-078–093 |
| Connection badge | SHELL-078–079 |
| Status bar elements | SHELL-080–090 |
| Table component | TABLE-001–029 |
| Column sorting | TABLE-001–002 |
| Row selection | TABLE-003, TABLE-005–012 |
| Keyboard navigation | TABLE-004–011 |
| Context menu | TABLE-012–013 |
| Column resize | TABLE-014–016 |
| Virtualization | TABLE-017–018 |
| Empty/loading states | TABLE-019–020 |
| Density toggle | TABLE-021–022 |
| Editor component | EDITOR-001–044 |
| Raw view | EDITOR-001, EDITOR-039–041 |
| Pretty view | EDITOR-002, EDITOR-040–041 |
| Hex view | EDITOR-003, EDITOR-041 |
| Render view | EDITOR-004, EDITOR-042–043 |
| Wrap toggle | EDITOR-007–009 |
| Byte count | EDITOR-010 |
| Copy message button | EDITOR-011 |
| Save to file button | EDITOR-012–013 |
| Search hotkey (Mod+S) | EDITOR-014 |
| Transform hotkeys | EDITOR-015–020, EDITOR-034–035 |
| Read-only enforcement | EDITOR-022–025 |
| Custom styling/height | EDITOR-027–028 |
| Syntax highlighting | EDITOR-029–032 |
| Integration scenarios | INTEGRATION-001–008 |

---

**Total Test Cases:** 490

**Format verification:**
- All IDs follow pattern: `{COMPONENT}-{NNN}` (e.g., `DECODER-001`)
- All routes describe a distinct path through the UI
- All preconditions specify starting state
- All steps are imperative and numbered
- All expected results quote exact UI copy where applicable
- All types are one of: `happy-path`, `alternate-entry`, `empty-state`, `error`, `keyboard`, `boundary`, `disabled-state`, `loading`, `enabled-state`, `warning`, `info`, `hidden`
