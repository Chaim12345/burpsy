// HTTP/2 connection reuse (burpsy-react-ui-adkx): the wire half — one connection per tab, "new" then
// "reused" — is pinned in Go (web/repeater_h2_reuse_test.go, sender/h2sessions_test.go). This pins
// the page's half: the single send names its tab, and the Config panel offers both adkx switches.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const page = readFileSync(join(import.meta.dir, "..", "pages", "repeater.tsx"), "utf8");

describe("the Repeater page wires the adkx overrides", () => {
  test("the single send carries the tab id that keys its reused connection", () => {
    expect(page).toMatch(/tab_id: tab\.id,/);
  });
  test("the Config panel offers HTTP/2 connection reuse and cross-domain protocol enforcement", () => {
    expect(page).toMatch(/onChange\(\{ h2_connection_reuse: checked \}\)/);
    expect(page).toMatch(/onChange\(\{ enforce_protocol_cross_domain: checked \}\)/);
  });
});
