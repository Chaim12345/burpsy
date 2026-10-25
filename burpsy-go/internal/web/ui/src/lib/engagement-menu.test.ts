import { describe, expect, test } from "bun:test";
import {
 engagementSearchFor,
 engagementToolsGroup,
 referenceTerm,
 seedUrl,
 type EngagementHandlers,
 type EngagementSearch,
 type EngagementSeed,
} from "./engagement-menu";
import type { MenuAction } from "../ui/menu";

// ---- Burp's Engagement tools submenu (burpsy-react-ui-gupj) -------------------------------------
//
// What can go wrong here without anything throwing: a row that looks live and does nothing, a
// greyed row with no explanation, and — the one that actually reads as success — a seeded search
// whose term cannot match what the server looks in, so the operator gets an empty table and
// believes the site is clean.

const HOST_NODE: EngagementSeed = { host: "shop.test", path: "" };
const BRANCH_NODE: EngagementSeed = { host: "shop.test", path: "/checkout" };

function noopHandlers(): EngagementHandlers {
 return { runSearch: () => undefined, discoverContent: () => undefined, scheduleTask: () => undefined, analyzeTarget: () => undefined };
}

/** The submenu's rows, which is where every disposition under test lives. */
function items(seed: EngagementSeed, handlers: EngagementHandlers = noopHandlers()): MenuAction[] {
 const group = engagementToolsGroup(seed, handlers);
 const trigger = group.actions[0];
 if (!trigger?.submenu) throw new Error("the group's single action must be the submenu trigger");
 return trigger.submenu.flatMap((sub) => sub.actions);
}

describe("every row either acts or says why it cannot", () => {
 test("no row is a no-op: each is either enabled, or disabled carrying its reason", () => {
  for (const item of items(BRANCH_NODE)) {
   if (item.disabled) {
    expect(
     item.hint,
     `"${item.label}" is greyed with no hint — a disabled row with no explanation is a dead end ` +
      `the operator has to guess at, which is worse than an absent one`,
    ).toBeTruthy();
   }
  }
 });

 test("Target analyzer is live and analyses the right-clicked branch", () => {
  const analyzer = items(BRANCH_NODE).find((item) => item.id === "target-analyzer");
  expect(analyzer?.disabled, "the analyzer exists now (dnvi), so the row must act").toBeFalsy();
  expect(analyzer?.hint ?? "").toContain(BRANCH_NODE.path);
 });

 test("Manual simulator is absent, not greyed", () => {
  // Greying it would advertise a synthetic-traffic generator as pending work. It is not being
  // built, so the row must not be on the menu at all.
  const labels = items(BRANCH_NODE).map((item) => item.label);
  expect(labels, `Manual simulator must not appear at all; rows were ${labels.join(", ")}`).not.toContain("Manual simulator");
 });

 test("Generate CSRF PoC is not repeated here — the row menu already carries it flat", () => {
  const labels = items(BRANCH_NODE).map((item) => item.label);
  expect(labels, "two rows with one label on one menu").not.toContain("Generate CSRF PoC");
 });
});

describe("Find references searches for something the server can actually match", () => {
 test("a branch seeds its path, not its absolute URL", () => {
  // /api/engagement/references keeps a hit only when q is a substring of the href/src attribute
  // it found. Pages write relative links, so seeding "https://shop.test/checkout" would match
  // nothing on a page whose markup reads href="/checkout" — and an empty result table reads as
  // "nothing links here" rather than as "the wrong term was searched".
  expect(referenceTerm(BRANCH_NODE)).toBe("/checkout");
  expect(referenceTerm(BRANCH_NODE)).not.toContain("https://");
 });

 test("a host node seeds the host, which is what Burp does with a host selection", () => {
  expect(referenceTerm(HOST_NODE)).toBe("shop.test");
 });

 test("references are searched across every captured host, not just the seed's", () => {
  // Burp searches "all of Burp's tools for HTTP responses that link to a particular item". The
  // interesting answer to "who links here" is often another host, and a host filter would hide it.
  const search: EngagementSearch = engagementSearchFor("references", BRANCH_NODE);
  expect(search.host, "a host filter here would hide the cross-host reference that matters").toBe("");
  expect(search.q).toBe("/checkout");
 });

 test("comments and scripts are scoped to the seed's host and carry no term", () => {
  for (const kind of ["comments", "scripts"] as const) {
   const search = engagementSearchFor(kind, BRANCH_NODE);
   expect(search.host).toBe("shop.test");
   expect(search.q, `${kind} takes no search term — the server matches a fixed construct`).toBe("");
  }
 });
});

describe("the scope burpsy can honour is stated, not implied", () => {
 test("a branch seed says the search covers the whole host", () => {
  // The endpoint filters by host and has no path filter. Results from a sibling branch would
  // otherwise be read as hits inside the branch that was right-clicked.
  const comments = items(BRANCH_NODE).find((item) => item.id === "find-comments");
  expect(comments?.hint ?? "").toContain("not by branch");
 });

 test("a host seed does not carry the branch caveat, which would not be true of it", () => {
  const comments = items(HOST_NODE).find((item) => item.id === "find-comments");
  expect(comments?.hint ?? "").not.toContain("not by branch");
 });
});

describe("the rows that hand a target to another page hand it a usable one", () => {
 test("an exchange row's real URL wins over one rebuilt from host and path", () => {
  expect(seedUrl(BRANCH_NODE, "http://shop.test:8080/checkout")).toBe("http://shop.test:8080/checkout");
 });

 test("a plain-HTTP node on a non-default port keeps both, rather than being promoted to https", () => {
  // Caught live, not in review: the first version assumed https and dropped the port, so a node
  // captured on http://127.0.0.1:19222 offered to sweep https://127.0.0.1 — an origin the
  // operator had never visited, named confidently in the row's own hint.
  expect(seedUrl({ host: "127.0.0.1", path: "/checkout", port: 19222, tls: false })).toBe("http://127.0.0.1:19222/checkout");
 });

 test("default ports are left off, so the URL reads the way an operator would type it", () => {
  expect(seedUrl({ host: "shop.test", path: "/checkout", port: 443, tls: true })).toBe("https://shop.test/checkout");
  expect(seedUrl({ host: "shop.test", path: "/checkout", port: 80, tls: false })).toBe("http://shop.test/checkout");
 });

 test("Discover content and Schedule task pass the seed's URL to their handler", () => {
  const seen: string[] = [];
  const handlers: EngagementHandlers = {
   runSearch: () => undefined,
   discoverContent: (target) => seen.push(`discover:${target}`),
   scheduleTask: (target) => seen.push(`schedule:${target}`),
   analyzeTarget: (seed) => seen.push(`analyze:${seed.host}${seed.path}`),
  };
  for (const id of ["discover-content", "schedule-task", "target-analyzer"]) {
   items(BRANCH_NODE, handlers)
    .find((item) => item.id === id)
    ?.onSelect();
  }
  expect(seen).toEqual(["discover:https://shop.test/checkout", "schedule:https://shop.test/checkout", "analyze:shop.test/checkout"]);
 });

 test("Schedule task's hint admits the form is not seeded", () => {
  // It opens the right surface and copies the URL; claiming more than that would leave an
  // operator waiting for a schedule that was never created.
  const schedule = items(BRANCH_NODE).find((item) => item.id === "schedule-task");
  expect(schedule?.disabled, "burpsy can schedule a crawl against this URL, so greying it would be a lie").toBeFalsy();
  expect(schedule?.hint ?? "").toContain("not seeded");
 });
});

describe("the group is shaped for splicing into an existing menu", () => {
 test("it is one group holding one submenu trigger", () => {
  const group = engagementToolsGroup(BRANCH_NODE, noopHandlers());
  expect(group.actions).toHaveLength(1);
  expect(group.actions[0]?.submenu, "the row must open a submenu, not act").toBeTruthy();
 });

 test("the submenu is titled, so the group reads as Burp's named section", () => {
  const group = engagementToolsGroup(BRANCH_NODE, noopHandlers());
  expect(group.actions[0]?.submenu?.[0]?.title).toBe("Engagement tools");
 });
});
