// The message-editor tab preferences (burpsy-react-ui-t94i): what the store model does, and
// what the editor wire is. The DOM half (the strip rendering hidden-off and reordered, the
// settings popover's checkboxes) needs a mounted console; the model rules are worth pinning
// without one because they decide whether a control exists at all — the failure class this
// bead was filed on.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { defaultEditorTabPrefs, moveEditorTab, type EditorTabPrefs, type OptionalEditorTab } from "./store";
import { addBodyParamToRequest, extraEditorTabs } from "./editor-extra-tabs";
import { addCookie } from "./message";

const ALL_TABS: OptionalEditorTab[] = ["render", "graphql", "jwt", "params", "headers", "queryparams", "bodyparams", "cookies", "attributes"];

describe("moveEditorTab", () => {
  test("the first move materialises the default order once, then moves within it", () => {
    const first = moveEditorTab(defaultEditorTabPrefs, "headers", -1);
    // headers sits at index 5 by default (render, graphql, jwt, params, protobuf, headers, ...); up
    // one swaps it with protobuf, while params keeps its slot.
    expect(first.order.indexOf("headers"), "an operator's first reorder should not have to fight an empty array").toBe(4);
    expect(first.order.indexOf("protobuf")).toBe(5);
    expect(first.order.indexOf("params")).toBe(3);
  });

  test("a move at the edge is a no-op that returns the same order, not a wrap", () => {
    const base: EditorTabPrefs = { hidden: [], order: [...ALL_TABS] };
    const up = moveEditorTab(base, "render", -1);
    expect(up.order, "render cannot move above first place; wrapping it to the end would be the opposite of what the button says").toEqual(ALL_TABS);
    const down = moveEditorTab(base, "attributes", 1);
    expect(down.order).toEqual(ALL_TABS);
  });

  test("hidden state rides along unchanged, because a hidden tab's position is still worth keeping", () => {
    const base: EditorTabPrefs = { hidden: ["jwt"], order: [] };
    const moved = moveEditorTab(base, "params", -1);
    expect(moved.hidden, "a reorder must not silently re-show a tab the operator hid").toEqual(["jwt"]);
  });
});

// How the editor wires the prefs (the five tabs offered, Show hides, order reorders, prefs persist) is
// pinned by rendering it: ui/editor-strip.test.tsx (vln1).

describe("the five extra tab views reuse the Inspector's own parsers", () => {
  // The one rule that makes these tabs honest: they read through the same lib/message parsers
  // the Inspector does, so the tab and the Inspector can never disagree about the same bytes.
  const sections = readFileSync(join(import.meta.dir, "..", "ui", "message-sections.tsx"), "utf8");

  test("every view derives from lib/message, not a second parser", () => {
    expect(sections).toMatch(/headerSpans\(raw\)/);
    expect(sections).toMatch(/querySpans\(raw\)/);
    expect(sections).toMatch(/bodyParamSpans\(raw\)/);
    expect(sections).toMatch(/cookieSpans\(raw\)/);
    expect(sections).toMatch(/cookiesOf\(parsed\.headers, true\)/);
    // 11r8: the tabs may ADD an item in an editable context, but only through lib/message's own
    // writers — never a second writer, and never edit-in-place, which the Inspector owns.
    expect(sections.includes("setHeaderAt") || sections.includes("setCookieAt") || sections.includes("setQueryParamAt"),
      "existing rows are readings — editing them in place is the Inspector's write path",
    ).toBe(false);
    expect(sections).toMatch(/write=\{addCookie\}/);
    expect(sections).toMatch(/write=\{addQueryParam\}/);
  });
});

describe("editable contexts show every view (burpsy-react-ui-11r8)", () => {
  const bare = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
  const response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhi";

  test("an editable request with no cookies, query or body still offers Cookies, Query params and Body params", () => {
    const tabs = extraEditorTabs(bare, true);
    expect(tabs, "Burp: in editable contexts the editor displays all views, so items can be added").toEqual([
      "headers",
      "attributes",
      "queryparams",
      "bodyparams",
      "cookies",
    ]);
  });

  test("a read-only request with none of them keeps the strip to what the message can fill", () => {
    expect(extraEditorTabs(bare, false)).toEqual(["headers", "attributes"]);
  });

  test("a read-only request that HAS cookies and a query still gets those tabs", () => {
    const withBoth = "GET /?a=1 HTTP/1.1\r\nHost: x\r\nCookie: s=1\r\n\r\n";
    expect(extraEditorTabs(withBoth, false)).toEqual(["headers", "attributes", "queryparams", "cookies"]);
  });

  test("an editable RESPONSE is not offered the request-only views (Intercept edits responses)", () => {
    expect(extraEditorTabs(response, true)).toEqual(["headers", "attributes"]);
  });

  test("adding a cookie to a request with no Cookie header creates the header, byte-exact elsewhere", () => {
    const next = addCookie(bare, "session", "abc");
    expect(next).toBe("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\n\r\n");
  });

  test("adding a body parameter to a typeless GET makes it a urlencoded form with a true Content-Length", () => {
    const next = addBodyParamToRequest(bare, "q", "a b");
    expect(next).toBe(
      "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nq=a%20b",
    );
  });

  test("a body that already declares JSON keeps its type", () => {
    const json = "POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
    const next = addBodyParamToRequest(json, "k", "v");
    expect(next).toContain("Content-Type: application/json\r\n");
    expect(next).not.toContain("x-www-form-urlencoded");
    expect(next.endsWith('{"k": "v"}')).toBe(true);
  });
});
