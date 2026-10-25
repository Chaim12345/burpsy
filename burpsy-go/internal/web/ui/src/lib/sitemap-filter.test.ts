// The site-map filter predicate (burpsy-react-ui-36d).
//
// The property worth pinning is the one the browser suite caught live: set axes (status class,
// MIME) are "matches here or matches below", because a synthesised folder's own aggregation is
// EMPTY — the folder path was never requested, so it answered no request and served no body. A
// per-node set-axis check hides every branch the moment a bucket is checked; this file exists so
// that regression fails here first, not in a 12-second browser boot.
import { describe, expect, test } from "bun:test";
import { NO_SITEMAP_FILTER, subtreeMatches } from "../pages/sitemap";
import type { SiteNodeDetail } from "./types.observe";

function node(over: Partial<SiteNodeDetail>): SiteNodeDetail {
  return {
    key: "k",
    segment: "/",
    path: "/",
    exchanges: 0,
    subtree_exchanges: 0,
    methods: [],
    statuses: [],
    requested: false,
    issues: 0,
    subtree_issues: 0,
    in_scope: true,
    params: null,
    ...over,
  } as SiteNodeDetail;
}

describe("sitemap filter predicate", () => {
  test("a folder with empty statuses stays visible when a descendant matches the bucket", () => {
    // The regression: /api itself answered nothing, its leaf /api/data answered 200. With the old
    // per-node check the folder failed statuses.some(...) and vanished with the whole branch.
    const tree = node({
      key: "h\x00/api",
      path: "/api",
      segment: "api",
      children: [node({ key: "h\x00/api/data", path: "/api/data", segment: "data", statuses: [200], requested: true })],
    });
    expect(subtreeMatches(tree, "", { ...NO_SITEMAP_FILTER, statuses: ["2"] })).toBe(true);
  });

  test("a branch where nothing matches the bucket is pruned", () => {
    // The filter must be able to produce an empty result, or it is decoration: a bucket nothing in
    // the capture belongs to has to take the whole tree out.
    const tree = node({
      key: "h\x00/api",
      path: "/api",
      segment: "api",
      children: [node({ key: "h\x00/api/data", path: "/api/data", segment: "data", statuses: [200], requested: true })],
    });
    expect(subtreeMatches(tree, "", { ...NO_SITEMAP_FILTER, statuses: ["4"] })).toBe(false);
  });

  test("boolean axes bind every node including folders", () => {
    // "Requested only" hides a synthesised folder even when its leaf was requested: the folder is
    // not a requested path, and showing it would claim the operator asked for /api itself.
    const tree = node({
      key: "h\x00/api",
      path: "/api",
      segment: "api",
      requested: false,
      children: [node({ key: "h\x00/api/data", path: "/api/data", segment: "data", requested: true, statuses: [200] })],
    });
    expect(subtreeMatches(tree, "", { ...NO_SITEMAP_FILTER, requestedOnly: true })).toBe(false);
  });

  test("hide not-found drops a leaf that answered only 4xx but keeps mixed nodes", () => {
    const notFound = node({ key: "a", path: "/a", segment: "a", statuses: [404], requested: true });
    const mixed = node({ key: "b", path: "/b", segment: "b", statuses: [404, 200], requested: true });
    const f = { ...NO_SITEMAP_FILTER, hideNotFound: true };
    expect(subtreeMatches(notFound, "", f)).toBe(false);
    expect(subtreeMatches(mixed, "", f)).toBe(true);
  });

  test("the MIME axis reads the subtree union, so a folder serving HTML below stays in an HTML filter", () => {
    const tree = node({
      key: "h\x00/site",
      path: "/site",
      segment: "site",
      children: [node({ key: "h\x00/site/index", path: "/site/index", segment: "index", mimes: ["html"], requested: true, statuses: [200] })],
    });
    expect(subtreeMatches(tree, "", { ...NO_SITEMAP_FILTER, mimes: ["html"] })).toBe(true);
    expect(subtreeMatches(tree, "", { ...NO_SITEMAP_FILTER, mimes: ["json"] })).toBe(false);
  });

  test("the free-text term still composes with the buckets", () => {
    const tree = node({
      key: "h\x00/api",
      path: "/api",
      segment: "api",
      children: [
        node({ key: "h\x00/api/data", path: "/api/data", segment: "data", statuses: [200], requested: true }),
        node({ key: "h\x00/api/other", path: "/api/other", segment: "other", statuses: [200], requested: true }),
      ],
    });
    expect(subtreeMatches(tree, "data", { ...NO_SITEMAP_FILTER, statuses: ["2"] })).toBe(true);
    expect(subtreeMatches(tree, "nomatch", { ...NO_SITEMAP_FILTER, statuses: ["2"] })).toBe(false);
  });
});
