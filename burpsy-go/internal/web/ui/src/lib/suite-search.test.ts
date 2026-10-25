import { describe, expect, it } from "bun:test";
import type { Exchange } from "./types";
import {
  buildSearchQuery,
  describeSearch,
  EMPTY_SEARCH_OPTIONS,
  highlightSegments,
  matchCountLabel,
  matchWindow,
  type SearchResult,
} from "./suite-search";

function result(overrides: Partial<SearchResult>): SearchResult {
  return {
    ...({} as Exchange),
    organizer: false,
    match_count: 0,
    matches: [],
    matches_truncated: false,
    ...overrides,
  };
}

describe("buildSearchQuery", () => {
  it("omits a flag that is off, so the URL reads as the search that ran", () => {
    expect(buildSearchQuery({ ...EMPTY_SEARCH_OPTIONS, term: "needle" })).toBe("q=needle");
  });

  it("sends the term even when it is blank, because a blank term describes the facility rather than asking nothing", () => {
    // The endpoint answers an absent term with the tool vocabulary and no results. Dropping `q`
    // entirely would make the dialog's opening fetch indistinguishable from a malformed request.
    expect(buildSearchQuery(EMPTY_SEARCH_OPTIONS)).toBe("q=");
  });

  it("sends each modifier only when it is on", () => {
    const query = buildSearchQuery({
      ...EMPTY_SEARCH_OPTIONS,
      term: "a b",
      caseSensitive: true,
      regex: true,
      negate: true,
      inScope: true,
    });
    expect(query).toContain("q=a+b");
    expect(query).toContain("case=1");
    expect(query).toContain("regex=1");
    expect(query).toContain("negate=1");
    expect(query).toContain("in_scope=1");
  });

  it("omits both location axes at their default and sends them otherwise", () => {
    expect(buildSearchQuery({ ...EMPTY_SEARCH_OPTIONS, term: "x" })).not.toContain("location=");
    expect(buildSearchQuery({ ...EMPTY_SEARCH_OPTIONS, term: "x" })).not.toContain("area=");
    const narrowed = buildSearchQuery({ ...EMPTY_SEARCH_OPTIONS, term: "x", location: "response", area: "body" });
    expect(narrowed).toContain("location=response");
    expect(narrowed).toContain("area=body");
  });

  it("omits tools entirely when all are selected, because empty already means every tool", () => {
    expect(buildSearchQuery({ ...EMPTY_SEARCH_OPTIONS, term: "x", tools: [] })).not.toContain("tools=");
  });

  it("sorts the tool list so two identical selections produce one URL", () => {
    // The list is built by clicking checkboxes, so its order is a click history rather than a
    // decision. Leaving it as-is would make the same search look like two different requests in
    // devtools and to any cache in between.
    const a = buildSearchQuery({ ...EMPTY_SEARCH_OPTIONS, term: "x", tools: ["repeater", "proxy"] });
    const b = buildSearchQuery({ ...EMPTY_SEARCH_OPTIONS, term: "x", tools: ["proxy", "repeater"] });
    expect(a).toBe(b);
    expect(a).toContain("tools=proxy%2Crepeater");
  });
});

describe("describeSearch", () => {
  it("names the literal default so a short result list is not read as a short answer", () => {
    const text = describeSearch({ ...EMPTY_SEARCH_OPTIONS, term: "needle" });
    expect(text).toContain("literal text");
    expect(text).toContain("case insensitive");
    expect(text).toContain("requests and responses");
    expect(text).toContain("headers and bodies");
    expect(text).toContain("every tool");
  });

  it("names each modifier that is actually on, and no others", () => {
    const text = describeSearch({
      ...EMPTY_SEARCH_OPTIONS,
      term: "needle",
      regex: true,
      negate: true,
      location: "request",
      area: "headers",
      tools: ["proxy"],
    });
    expect(text).toContain("regular expression");
    expect(text).toContain("negative matches");
    expect(text).toContain("requests, headers");
    expect(text).toContain("across proxy");
    expect(text).not.toContain("case sensitive");
    expect(text).not.toContain("in scope only");
  });
});

describe("matchWindow", () => {
  it("returns the whole message when it fits, and says nothing was cut", () => {
    expect(matchWindow(10, 4, 500)).toEqual({ start: 0, end: 500, leading: false, trailing: false });
  });

  it("centres a bounded window on the match and states which ends were cut", () => {
    const window = matchWindow(5000, 4, 20000, 100);
    expect(window.end - window.start).toBe(204);
    expect(window.start).toBeLessThanOrEqual(5000);
    expect(window.end).toBeGreaterThanOrEqual(5004);
    expect(window.leading).toBe(true);
    expect(window.trailing).toBe(true);
  });

  it("keeps its size at the tail of a message instead of shrinking to nothing", () => {
    // Anchoring only on the match would run the window off the end and render a shorter pane that
    // still reported leading=false.
    const window = matchWindow(19990, 4, 20000, 100);
    expect(window.leading).toBe(true);
    expect(window.trailing).toBe(false);
    expect(window.end).toBe(20000);
  });

  it("does not claim a cut at either end when the message fits exactly", () => {
    const window = matchWindow(3, 4, 204, 100);
    expect(window).toEqual({ start: 0, end: 204, leading: false, trailing: false });
  });
});

describe("highlightSegments", () => {
  it("marks exactly the matched bytes and leaves the rest plain", () => {
    const segments = highlightSegments("hello needle world", 0, [
      { direction: "request", area: "body", message_id: 1, offset: 6, len: 6 },
    ]);
    expect(segments).toEqual([
      { text: "hello ", hit: false },
      { text: "needle", hit: true },
      { text: " world", hit: false },
    ]);
  });

  it("translates absolute offsets into a window that does not start at zero", () => {
    // The offsets index the whole message; the pane renders a slice of it. Slicing the text with an
    // untranslated offset is how a highlight lands on the wrong bytes — or on none.
    const segments = highlightSegments("needle here", 1000, [
      { direction: "response", area: "headers", message_id: 2, offset: 1000, len: 6 },
    ]);
    expect(segments[0]).toEqual({ text: "needle", hit: true });
    expect(segments[1]).toEqual({ text: " here", hit: false });
  });

  it("drops a match that lies outside the window rather than shifting it into view", () => {
    const segments = highlightSegments("body text", 50, [
      { direction: "request", area: "body", message_id: 3, offset: 4, len: 6 },
    ]);
    expect(segments).toEqual([{ text: "body text", hit: false }]);
  });

  it("clips a match that straddles the start of the window", () => {
    // The message is "needle tail" and the pane renders from byte 2, so the match starts before the
    // window. The visible part of it is still a match; the part that is not rendered is not a
    // highlight.
    const segments = highlightSegments("edle tail", 2, [
      { direction: "request", area: "body", message_id: 4, offset: 0, len: 6 },
    ]);
    expect(segments).toEqual([
      { text: "edle", hit: true },
      { text: " tail", hit: false },
    ]);
  });

  it("never highlights the same byte twice", () => {
    const segments = highlightSegments("aaa", 0, [
      { direction: "request", area: "body", message_id: 5, offset: 0, len: 2 },
      { direction: "request", area: "body", message_id: 5, offset: 1, len: 2 },
    ]);
    const highlighted = segments.filter((segment) => segment.hit).map((segment) => segment.text);
    expect(highlighted).toEqual(["aa"]);
    expect(segments.map((segment) => segment.text).join("")).toBe("aaa");
  });

  it("returns the text unchanged when there is nothing to highlight", () => {
    expect(highlightSegments("plain", 0, [])).toEqual([{ text: "plain", hit: false }]);
  });
});

describe("matchCountLabel", () => {
  it("states the cap when the recorded offsets stop short of the true count", () => {
    expect(matchCountLabel(result({ match_count: 437, matches: new Array(200).fill(null), matches_truncated: true }))).toBe(
      "200 of 437",
    );
  });

  it("states the plain count when nothing was dropped", () => {
    expect(matchCountLabel(result({ match_count: 3 }))).toBe("3");
  });

  it("reads zero for a negative match, which is a match of the absence", () => {
    expect(matchCountLabel(result({ match_count: 0 }))).toBe("0");
  });
});
