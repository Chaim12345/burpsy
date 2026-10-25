// Override SNI (burpsy-react-ui-k011): the wire half is pinned in Go (sender/sni_override_test.go,
// web/repeater_sni_test.go). The single send's behaviour (carried for TLS only, never blank) is now
// pinned by rendering the page: pages/repeater.sni.test.tsx (vln1).
//
// What remains here is a source-text pin, kept only for the two paths that test does not drive yet:
// the group send and the hand-off's own send. Replace it when those are rendered too.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const page = readFileSync(join(import.meta.dir, "..", "pages", "repeater.tsx"), "utf8");

describe("the Repeater page carries a tab's Override SNI", () => {
 test("on the single send, the group send and the hand-off's own send", () => {
  expect(page.match(/\.\.\.sniFor\(tab\)/g)?.length).toBe(3);
 });
});
