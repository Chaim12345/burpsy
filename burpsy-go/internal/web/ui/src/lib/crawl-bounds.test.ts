import { expect, test } from "bun:test";
import { crawlBound } from "./crawl-bounds";

// burpsy-react-ui-qzzy: the engine had eleven bounds and twelve named stops, and the console could
// reach three of the bounds. The four stops nobody could reach were the four with no wire field.
//
// The second defect is the one this file exists for. Every bound is a count or a length, so 0 is a
// real answer — zero locations, zero links per page, zero re-logins — and the form's own shape
// (`Number(x) || undefined`) reads 0 as "not set". An operator who typed 0 to bound a crawl to
// nothing got the engine default, and the run reported a stop nobody chose.

// A blank field is omitted entirely, so the engine's documented default applies and the request says
// "I did not choose" rather than carrying a value the operator never typed.
test("a blank bound is omitted rather than sent as a number", () => {
  expect(crawlBound("max_locations", "")).toEqual({});
  expect(crawlBound("max_locations", "   ")).toEqual({});
});

// A typed 0 is the operator's answer. This is the case `|| undefined` cannot express, and the reason
// the server's fields are pointers.
test("a typed zero is sent as zero, not dropped as falsy", () => {
  expect(crawlBound("max_locations", "0")).toEqual({ max_locations: 0 });
  expect(crawlBound("max_links_per_page", "0")).toEqual({ max_links_per_page: 0 });
  expect(crawlBound("max_relogins", "0")).toEqual({ max_relogins: 0 });
});

// A normal value is sent, and under the key the server reads.
test("a typed value is sent under its own wire key", () => {
  expect(crawlBound("max_links_per_page", "250")).toEqual({ max_links_per_page: 250 });
  expect(crawlBound("max_capture_bytes", "1048576")).toEqual({ max_capture_bytes: 1048576 });
});

// A non-numeric or negative value is omitted, so the server's 400 — which names the field and says
// what a bound is — is not pre-empted by a client-side guess.
test("a value the server would refuse is not sent", () => {
  expect(crawlBound("max_locations", "-1")).toEqual({});
  expect(crawlBound("max_locations", "abc")).toEqual({});
  expect(crawlBound("max_locations", "Infinity")).toEqual({});
  expect(crawlBound("max_locations", "NaN")).toEqual({});
});

// Whitespace around a number is a number, not a blank field: " 0 " is an operator who typed zero.
test("whitespace around a number still reads as that number", () => {
  expect(crawlBound("max_frontier", " 0 ")).toEqual({ max_frontier: 0 });
  expect(crawlBound("max_frontier", " 42 ")).toEqual({ max_frontier: 42 });
});
