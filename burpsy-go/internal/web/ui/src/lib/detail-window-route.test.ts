// Burp's "Show details in new window" (burpsy-react-ui-wvcl). The page is mostly rendering; what
// can be wrong without a browser is the routing decision and the id resolution, and both have a
// failure mode that looks fine until an operator loses the window: a leaf that is routable but
// listed in the sub-tab row, and an id read from the wrong place in the URL.
import { describe, expect, test } from "bun:test";
import { NAV_LEAVES, findLeaf, toolOf } from "../nav";

describe("the detached exchange window's route", () => {
  const detail = NAV_LEAVES.find((leaf) => leaf.id === "exchange-detail");

  test("exists and is routable, because the window has to land on something", () => {
    expect(detail, "no leaf for the detail window: window.open would land on whatever route the opener had").toBeDefined();
    expect(findLeaf("exchange-detail").id).toBe("exchange-detail");
  });

  test("is not listed in the sub-tab row, because a window is not a destination to navigate to", () => {
    // The failure this guards: a leaf in Proxy's sub-tabs offering "go to another detached window",
    // which is not navigation anyone wants and looks like a bug in the strip.
    expect(
      detail?.hidden,
      "the detail leaf is listed in Proxy's sub-tab row, so the strip now offers to navigate to a window",
    ).toBe(true);
  });

  test("belongs to Proxy, which owns the HTTP history it is opened from", () => {
    expect(toolOf("exchange-detail").id).toBe("proxy");
  });

  test("every leaf id is unique, because the URL hash is the routing key", () => {
    const ids = NAV_LEAVES.map((leaf) => leaf.id);
    const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
    expect(duplicates, "two leaves with one id means one of them is unreachable").toEqual([]);
  });
});
