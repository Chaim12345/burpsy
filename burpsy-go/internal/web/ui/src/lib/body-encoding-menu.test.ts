/**
 * The wiring between the transform and the two menus that offer it (burpsy-react-ui-wv5).
 *
 * # Why this reads source text instead of rendering components
 *
 * The defect this pins was not a wrong value anywhere. `chunkBody` and `dechunkBody` both worked;
 * what was wrong was the *label* over them — "Change body encoding" is the name Burp gives a
 * different operation, so an operator reaching for a form-to-JSON conversion got chunked framing
 * and no indication that the thing they wanted did not exist. A unit test of either transform
 * passes in that world. What can see it is the shape of the menu, so that is what this asserts.
 *
 * The menu is built inside `useExchangeActions`, a hook over the store and the query client, and
 * this suite has no DOM — so these are source assertions, deliberately strict about the exact call
 * form. The conversion's own behaviour is tested against bytes in body-encoding.test.ts; what is
 * left over, and only visible here, is whether anything calls it.
 */
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { BODY_ENCODINGS, BODY_ENCODING_LABELS } from "./body-encoding";

const actions = readFileSync(join(import.meta.dir, "actions.ts"), "utf8");
const repeater = readFileSync(join(import.meta.dir, "..", "pages", "repeater.tsx"), "utf8");

describe("the two operations are separate rows with separate names", () => {
  test("the chunked toggle no longer carries Burp's name for the conversion", () => {
    // The exact string this project shipped. It must not come back under any row.
    expect(actions).not.toContain("Change body encoding (chunked)");
    expect(actions).toContain('label: "Toggle chunked transfer framing"');
  });

  test("the chunked toggle and the conversion are distinct menu entries with distinct ids", () => {
    expect(actions).toContain('id: "chunked-framing"');
    expect(actions).toContain('id: "body-encoding"');
    expect(actions).toContain("void toggleChunkedFraming(exchange)");
  });

  test("the row menu's conversion rows come from BODY_ENCODINGS, so no encoding can be listed and left unwired", () => {
    // A hardcoded list of three rows is how a fourth label appears with no transform behind it.
    expect(actions).toMatch(/submenu:[\s\S]{0,400}BODY_ENCODINGS\.map\(\(encoding\) => \(\{[\s\S]{0,400}convertBodyEncoding\(exchange, encoding\)/);
  });

  test("every encoding the menu can name has a label, so no row can render as an identifier", () => {
    for (const encoding of BODY_ENCODINGS) {
      expect(BODY_ENCODING_LABELS[encoding]).toBeTruthy();
    }
    expect(Object.keys(BODY_ENCODING_LABELS).sort()).toEqual([...BODY_ENCODINGS].sort());
  });
});

describe("the Repeater draft offers the conversion and the toggle on its own bytes", () => {
  test("the request editor is handed the body-encoding group, which is what makes the rows reachable", () => {
    expect(repeater).toContain("menuGroups={[...(messageMenu ?? []), ...bodyEncodingMenu]}");
  });

  test("the toggle's target is remembered per tab id, not in one global slot", () => {
    // Two tabs converted in different directions must toggle in different directions. A bare
    // `useState<BodyEncoding>` would make the second tab's toggle follow the first tab's move.
    expect(repeater).toContain("useState<Record<string, BodyEncoding>>({})");
    expect(repeater).toContain("[active.id]: from");
  });

  test("the toggle is disabled until the tab has actually been converted, so it cannot invent a third state", () => {
    expect(repeater).toContain("const canToggle = previous !== undefined && previous !== draftEncoding;");
    expect(repeater).toContain("disabled: !canToggle,");
  });

  test("the per-tab memory is pruned with the tabs, so a closed tab leaves no direction behind", () => {
    expect(repeater).toMatch(/setPreviousEncoding\(\(current\) => Object\.fromEntries\(Object\.entries\(current\)\.filter\(\(\[id\]\) => alive\.has\(id\)\)\)\);/);
  });
});
