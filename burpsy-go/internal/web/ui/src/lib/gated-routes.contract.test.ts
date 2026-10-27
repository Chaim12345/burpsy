/**
 * The client half of the gated-route contract (burpsy-react-ui-gatecontract). Run with `bun run test:lib`.
 *
 * gated-routes.contract.json is the gate's own resolution (routeRiskFor in internal/web/confirm_gate.go)
 * of every manifest pattern filled with sample segments, plus its /extra, /extra/more and trailing-slash
 * variants. It is written by internal/web/gated_routes_contract_test.go, which fails when the server
 * drifts from it; this file fails when the client does. A disagreement here is the PR #363 bug: the
 * console mints for one pattern and the gate spends against another, or the console sends a gated call
 * unconfirmed.
 */
import { describe, expect, test } from "bun:test";
import { gatedPatternFor, manifestPatternFor } from "./api";
import contract from "./gated-routes.contract.json";
import { ROUTE_GATED } from "./gated-routes";

type Entry = { path: string; key: string | null; gated: boolean };
const paths = contract.paths as Entry[];

describe("the contract fixture describes the table the client resolves over", () => {
 test("it covers every manifest pattern the client table carries, and only those", () => {
  expect(contract.patterns).toEqual(Object.keys(ROUTE_GATED).sort());
 });

 test("it is not vacuous: many paths, some gated and some not", () => {
  expect(paths.length).toBeGreaterThanOrEqual(3 * contract.patterns.length);
  const gated = paths.filter((e) => e.gated).length;
  expect(gated).toBeGreaterThan(0);
  expect(gated).toBeLessThan(paths.length);
 });
});

describe("manifestPatternFor resolves every fixture path to the gate's key", () => {
 // The gate skips the mux fallthrough "/" and reports no match (key null); the client's table carries
 // "/" as an ordinary ungated pattern, so it answers "/" for the same path. Both mean "ungated".
 test("same key and same gated flag for every path", () => {
  expect(ROUTE_GATED["/"]).toBe(false);
  const mismatches: string[] = [];
  for (const e of paths) {
   const key = manifestPatternFor(e.path);
   const want = e.key ?? "/";
   const gated = key !== undefined && Boolean(ROUTE_GATED[key]);
   if (key !== want || gated !== e.gated) {
    mismatches.push(`${e.path}: server ${want} gated=${e.gated}, client ${key} gated=${gated}`);
   }
  }
  // Every mismatch at once, so one run names the whole drift rather than the first path of it.
  expect(mismatches).toEqual([]);
 });

 test("gatedPatternFor, which decides whether the console mints, agrees on the gated pattern", () => {
  const mismatches: string[] = [];
  for (const e of paths) {
   // A "/confirm" path is a mint request, which gatedPatternFor answers before resolving; the fixture
   // has none, and this filter keeps the comparison honest if a manifest pattern ever ends that way.
   if (e.path.endsWith("/confirm")) continue;
   const got = gatedPatternFor(e.path);
   const want = e.gated ? e.key : undefined;
   if (got !== (want ?? undefined)) mismatches.push(`${e.path}: server ${want}, client ${got}`);
  }
  expect(mismatches).toEqual([]);
 });
});
