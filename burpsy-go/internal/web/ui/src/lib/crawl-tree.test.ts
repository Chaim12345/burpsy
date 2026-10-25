// The crawl-paths forest (burpsy-react-ui-tix).
//
// Tested as a function because the three cases that matter are structural, and every one of them has
// a plausible wrong implementation that looks fine on screen:
//
//   - a seed rendered as a child of nothing,
//   - an orphan silently dropped, which understates coverage,
//   - an orphan re-parented to a seed, which asserts a path that was never walked.
import { expect, test, describe } from "bun:test";
import { buildCrawlTree } from "../ui/crawlpaths";
import type { CrawlFetch } from "./types.observe";

function fetchOf(url: string, depth: number, foundAt?: string, extra: Partial<CrawlFetch> = {}): CrawlFetch {
 return { url, method: "GET", status: 200, exchange_id: 1, depth, found_at: foundAt, ...extra };
}

describe("buildCrawlTree", () => {
 test("a seed has no parent and is a root", () => {
  const tree = buildCrawlTree([fetchOf("http://t/", 0)]);
  expect(tree.seeds.length).toBe(1);
  expect(tree.orphans.length).toBe(0);
  expect(tree.seeds[0]?.fetch.url).toBe("http://t/");
 });

 test("children hang off the page they were found on", () => {
  const tree = buildCrawlTree([
   fetchOf("http://t/", 0),
   fetchOf("http://t/a", 1, "http://t/"),
   fetchOf("http://t/a/deep", 2, "http://t/a"),
  ]);
  expect(tree.seeds.length).toBe(1);
  const seed = tree.seeds[0]!;
  expect(seed.children.map((c) => c.fetch.url)).toEqual(["http://t/a"]);
  expect(seed.children[0]!.children.map((c) => c.fetch.url)).toEqual(["http://t/a/deep"]);
 });

 test("depth alone cannot produce this: two pages at the same depth keep different parents", () => {
  // The reason found_at was needed at all. Both children are depth 2 and neither belongs to the
  // other's parent, which a depth-only rendering would be unable to express.
  const tree = buildCrawlTree([
   fetchOf("http://t/", 0),
   fetchOf("http://t/x", 1, "http://t/"),
   fetchOf("http://t/y", 1, "http://t/"),
   fetchOf("http://t/x/one", 2, "http://t/x"),
   fetchOf("http://t/y/two", 2, "http://t/y"),
  ]);
  const seed = tree.seeds[0]!;
  const x = seed.children.find((c) => c.fetch.url === "http://t/x")!;
  const y = seed.children.find((c) => c.fetch.url === "http://t/y")!;
  expect(x.children.map((c) => c.fetch.url)).toEqual(["http://t/x/one"]);
  expect(y.children.map((c) => c.fetch.url)).toEqual(["http://t/y/two"]);
 });

 test("a fetch whose parent this run did not retain is kept as an orphan, not dropped", () => {
  // The parent was refused, dropped at a limit, or excluded by the retention query. The child's
  // request was still made, so hiding it would report less coverage than actually happened.
  const tree = buildCrawlTree([fetchOf("http://t/", 0), fetchOf("http://t/orphan", 3, "http://t/never-retained")]);
  expect(tree.placed).toBe(2);
  expect(tree.orphans.map((o) => o.fetch.url)).toEqual(["http://t/orphan"]);
  // And it must NOT be re-parented onto the seed, which would draw a path nobody walked.
  expect(tree.seeds[0]!.children.length).toBe(0);
 });

 test("an orphan is not counted as a seed", () => {
  // The distinction the UI renders under its own heading. Collapsing them would present a page
  // reached from a discarded parent as something the operator pointed the crawl at.
  const tree = buildCrawlTree([fetchOf("http://t/lost", 2, "http://t/gone")]);
  expect(tree.seeds.length).toBe(0);
  expect(tree.orphans.length).toBe(1);
 });

 test("a cycle terminates rather than hanging the render", () => {
  // The input describes a target's link structure, not ours. A page whose found_at chain loops
  // must not be able to spin the sort walk forever.
  const tree = buildCrawlTree([fetchOf("http://t/a", 1, "http://t/b"), fetchOf("http://t/b", 1, "http://t/a")]);
  // Neither is a seed and neither is an orphan by the parent-missing rule — both parents exist —
  // so the forest has no roots. The guarantee under test is that building it returns at all.
  expect(tree.placed).toBe(2);
 });

 test("a self-referencing fetch becomes an orphan rather than its own child", () => {
  const tree = buildCrawlTree([fetchOf("http://t/self", 1, "http://t/self")]);
  expect(tree.orphans.map((o) => o.fetch.url)).toEqual(["http://t/self"]);
 });

 test("a duplicate URL is placed once, keeping the first edge", () => {
  // A redirect and its target can both appear. The first is the one whose edge was followed.
  const tree = buildCrawlTree([
   fetchOf("http://t/", 0),
   fetchOf("http://t/dup", 1, "http://t/"),
   fetchOf("http://t/dup", 2, "http://t/somewhere-else"),
  ]);
  expect(tree.placed).toBe(2);
  expect(tree.seeds[0]!.children.map((c) => c.fetch.url)).toEqual(["http://t/dup"]);
  expect(tree.orphans.length).toBe(0);
 });

 test("children are ordered by depth then URL, so the same crawl renders the same way twice", () => {
  const tree = buildCrawlTree([
   fetchOf("http://t/", 0),
   fetchOf("http://t/zebra", 1, "http://t/"),
   fetchOf("http://t/apple", 1, "http://t/"),
  ]);
  expect(tree.seeds[0]!.children.map((c) => c.fetch.url)).toEqual(["http://t/apple", "http://t/zebra"]);
 });

 test("an empty fetch set produces an empty forest rather than throwing", () => {
  const tree = buildCrawlTree([]);
  expect(tree.seeds).toEqual([]);
  expect(tree.orphans).toEqual([]);
  expect(tree.placed).toBe(0);
 });
});
