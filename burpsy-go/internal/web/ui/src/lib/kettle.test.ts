// Kettled requests (burpsy-react-ui-jae5): the seeded list, the normalised text kept beside it, and
// the store chokepoint that drops the list when the text is edited. The chokepoint tests drive the real
// store, so deleting or inverting the rule in updateRepeaterTab fails here.
import { beforeEach, describe, expect, test } from "bun:test";
import { kettleHeaderEdit, renderNormalised, requestBody, requestHeadChanged, seedH2Fields, type H2Field } from "./kettle";
import { useApp } from "./store";

const DRAFT = "POST /a?b=1 HTTP/2\r\nHost: t.example\r\nX-Up: 1\r\nCookie: a=1\r\n\r\nbody";

describe("seedH2Fields", () => {
  test("pseudo-headers first, then every header lowercased in order, with each row's list index", () => {
    const { fields, headerRowField } = seedH2Fields(DRAFT, true);
    expect(fields).toEqual([
      { name: ":method", value: "POST" },
      { name: ":scheme", value: "https" },
      { name: ":authority", value: "t.example" },
      { name: ":path", value: "/a?b=1" },
      { name: "x-up", value: "1" },
      { name: "cookie", value: "a=1" },
    ]);
    // Host (row 0) became :authority; the others follow the pseudo-headers.
    expect(headerRowField).toEqual([2, 4, 5]);
    expect(seedH2Fields(DRAFT, false).fields[1]).toEqual({ name: ":scheme", value: "http" });
  });

  test("an edit to a row's value lands on that row's field and keeps the seeded lowercase name", () => {
    const fields = kettleHeaderEdit(DRAFT, true, 1, "X-Up", "X-Up", "a\r\nb");
    expect(fields[4]).toEqual({ name: "x-up", value: "a\r\nb" });
    expect(fields.filter((field) => field.value.includes("\r\n"))).toHaveLength(1);
    // A rename is the operator's, kept exactly as typed.
    expect(kettleHeaderEdit(DRAFT, true, 1, "X-Up", "X-Inj\r\nected", "1")[4]).toEqual({ name: "X-Inj\r\nected", value: "1" });
    // The Host row edits :authority.
    expect(kettleHeaderEdit(DRAFT, true, 0, "Host", "Host", "x\ny")[2]).toEqual({ name: ":authority", value: "x\ny" });
  });
});

describe("renderNormalised", () => {
  test("a list HTTP/1 can carry comes back as the draft it was seeded from", () => {
    const { fields } = seedH2Fields(DRAFT, true);
    expect(renderNormalised(fields, requestBody(DRAFT))).toBe("POST /a?b=1 HTTP/2\r\nHost: t.example\r\nx-up: 1\r\ncookie: a=1\r\n\r\nbody");
  });

  test("what HTTP/1 cannot carry is discarded: CR/LF, extra pseudo-headers, colon names; crumbs are joined", () => {
    const fields: H2Field[] = [
      { name: ":method", value: "GET" },
      { name: ":path", value: "/x" },
      { name: ":path", value: "/second" },
      { name: ":authority", value: "h" },
      { name: "x-inject", value: "a\r\nb: c" },
      { name: "x:colon", value: "1" },
      { name: "cookie", value: "a=1" },
      { name: "cookie", value: "b=2" },
    ];
    expect(renderNormalised(fields, "")).toBe("GET /x HTTP/2\r\nHost: h\r\nx-inject: ab: c\r\ncookie: a=1; b=2\r\n\r\n");
  });
});

describe("requestHeadChanged", () => {
  test("a body edit is not a head edit; a header edit is", () => {
    expect(requestHeadChanged(DRAFT, DRAFT.replace("body", "other"))).toBe(false);
    expect(requestHeadChanged(DRAFT, DRAFT.replace("X-Up: 1", "X-Up: 2"))).toBe(true);
  });
});

describe("the store drops a kettled list the text no longer describes", () => {
  const LIST: H2Field[] = [
    { name: ":method", value: "POST" },
    { name: "x", value: "a\r\nb" },
  ];
  beforeEach(() => useApp.setState({ repeaterTabs: [], closedRepeaterTabs: [], activeRepeaterTab: null }));
  const open = () => {
    const id = useApp.getState().openRepeaterTab({ name: "k", target: "https://t.example", request: DRAFT });
    useApp.getState().updateRepeaterTab(id, { h2Headers: LIST });
    return id;
  };
  const listOf = (id: string) => useApp.getState().repeaterTabs.find((tab) => tab.id === id)?.h2Headers;

  test("a raw edit to the head clears it, so the send falls back to the text the operator edited", () => {
    const id = open();
    expect(listOf(id)).toEqual(LIST);
    useApp.getState().updateRepeaterTab(id, { request: DRAFT.replace("X-Up: 1", "X-Up: 2") });
    expect(listOf(id)).toBeUndefined();
  });

  test("a body-only edit keeps it", () => {
    const id = open();
    useApp.getState().updateRepeaterTab(id, { request: DRAFT.replace("body", "new body") });
    expect(listOf(id)).toEqual(LIST);
  });

  test("an Inspector write that sets both keeps the new list", () => {
    const id = open();
    const next: H2Field[] = [...LIST, { name: "y", value: "1" }];
    useApp.getState().updateRepeaterTab(id, { request: renderNormalised(next, "body"), h2Headers: next });
    expect(listOf(id)).toEqual(next);
  });
});
