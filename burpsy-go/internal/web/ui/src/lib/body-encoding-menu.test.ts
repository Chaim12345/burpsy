/**
 * Labels for the body-encoding conversion (burpsy-react-ui-wv5). The row menu's wiring (separate chunked
 * and conversion rows, the submenu built from BODY_ENCODINGS) is pinned by rendering History:
 * pages/history.menu.test.tsx; the Repeater half by pages/repeater.encoding.test.tsx (vln1).
 */
import { describe, expect, test } from "bun:test";
import { BODY_ENCODINGS, BODY_ENCODING_LABELS } from "./body-encoding";

describe("body encoding labels", () => {
 test("every encoding the menu can name has a label, so no row can render as an identifier", () => {
  for (const encoding of BODY_ENCODINGS) {
   expect(BODY_ENCODING_LABELS[encoding]).toBeTruthy();
  }
  expect(Object.keys(BODY_ENCODING_LABELS).sort()).toEqual([...BODY_ENCODINGS].sort());
 });
});
