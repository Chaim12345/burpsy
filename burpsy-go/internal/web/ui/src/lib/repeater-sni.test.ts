// Override SNI (burpsy-react-ui-k011): the wire half — the ClientHello carries the override, Host and
// redirect hops do not — is pinned in Go (sender/sni_override_test.go, web/repeater_sni_test.go).
// This pins the page's half: every send path carries the tab's SNI, and only for a TLS target.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const page = readFileSync(join(import.meta.dir, "..", "pages", "repeater.tsx"), "utf8");

describe("the Repeater page carries a tab's Override SNI", () => {
  test("on the single send, the group send and the hand-off's own send", () => {
    expect(page.match(/\.\.\.sniFor\(tab\)/g)?.length).toBe(3);
  });

  test("only for an https target, and never a blank one", () => {
    expect(page).toMatch(/sni !== "" && schemeOf\(tab\.target\) === "https"/);
  });
});
