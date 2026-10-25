/**
 * burpsy-react-ui-vln1 (replaces the message-sections.tsx source pin in lib/editor-tabs.test.ts): the
 * extra tab views (Headers, Query params, Body params, Cookies) read through the Inspector's parsers,
 * add items only through lib/message's writers, and never edit an existing row in place
 * (burpsy-react-ui-11r8). Rendered in the real HttpEditor.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { HttpEditor } from "./editor";

afterEach(cleanup);

const REQUEST =
 "POST /s?q=1&r=two HTTP/1.1\r\nHost: probe.test\r\nCookie: sid=abc; theme=dark\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nuser=al";
const RESPONSE = "HTTP/1.1 200 OK\r\nSet-Cookie: s=1; Path=/\r\nContent-Type: text/plain\r\n\r\nhi";

function mount(value: string, readOnly: boolean) {
 const seen: string[] = [];
 renderWithProviders(
  <HttpEditor value={value} onChange={(next) => seen.push(next)} label={readOnly ? "Response" : "Request"} readOnly={readOnly} />,
 );
 return seen;
}
const openTab = async (name: string) => fireEvent.click(await screen.findByRole("tab", { name }));
const rowsOf = () =>
 [...document.querySelectorAll(".typed-table tbody tr")].map((tr) => [...tr.querySelectorAll("td")].map((td) => td.textContent));

describe("the extra tab views are readings of the editor's bytes", () => {
 test("Headers, Query params, Body params and Cookies each list what the parsers find in the request", async () => {
  mount(REQUEST, false);
  await openTab("Headers");
  await waitFor(() => expect(rowsOf().map((r) => r[0])).toContain("Host"));
  expect(rowsOf()).toContainEqual(["Cookie", "sid=abc; theme=dark"]);
  await openTab("Query params");
  await waitFor(() =>
   expect(rowsOf()).toEqual([
    ["q", "1"],
    ["r", "two"],
   ]),
  );
  await openTab("Body params");
  await waitFor(() => expect(rowsOf()).toEqual([["user", "al"]]));
  await openTab("Cookies");
  await waitFor(() =>
   expect(rowsOf()).toEqual([
    ["sid", "abc"],
    ["theme", "dark"],
   ]),
  );
 });

 test("an editable response's Cookies tab reads its Set-Cookie pairs and offers no cookie Add (those are headers)", async () => {
  mount(RESPONSE, false);
  await openTab("Cookies");
  await waitFor(() => expect(rowsOf()).toEqual([["s", "1"]]));
  expect(screen.queryByRole("form", { name: /Add a/ })).toBeNull();
 });

 test("existing rows are readings: no input inside a table row, in any tab", async () => {
  mount(REQUEST, false);
  for (const tab of ["Headers", "Query params", "Body params", "Cookies"]) {
   await openTab(tab);
   await waitFor(() => expect(rowsOf().length).toBeGreaterThan(0));
   expect(document.querySelectorAll(".typed-table input, .typed-table textarea, .typed-table [contenteditable]")).toHaveLength(0);
  }
 });
});

describe("what a tab writes is an added item, through the message writers", () => {
 test("adding a cookie appends to the request's Cookie header", async () => {
  const seen = mount(REQUEST, false);
  await openTab("Cookies");
  const form = await screen.findByRole("form", { name: "Add a cookie" });
  fireEvent.change(within(form).getByLabelText("New cookie name"), { target: { value: "lang" } });
  fireEvent.change(within(form).getByLabelText("New cookie value"), { target: { value: "en" } });
  fireEvent.click(within(form).getByRole("button", { name: "Add" }));
  await waitFor(() => expect(seen.length).toBeGreaterThan(0));
  expect(seen.at(-1)).toMatch(/Cookie: sid=abc; theme=dark; lang=en/);
 });

 test("adding a query parameter extends the request line's query", async () => {
  const seen = mount(REQUEST, false);
  await openTab("Query params");
  const form = await screen.findByRole("form", { name: "Add a query parameter" });
  fireEvent.change(within(form).getByLabelText("New query parameter name"), { target: { value: "z" } });
  fireEvent.change(within(form).getByLabelText("New query parameter value"), { target: { value: "9" } });
  fireEvent.click(within(form).getByRole("button", { name: "Add" }));
  await waitFor(() => expect(seen.length).toBeGreaterThan(0));
  expect(seen.at(-1)).toMatch(/^POST \/s\?q=1&r=two&z=9 HTTP\/1\.1/);
 });

 test("the Add button stays disabled for an empty name", async () => {
  mount(REQUEST, false);
  await openTab("Cookies");
  const form = await screen.findByRole("form", { name: "Add a cookie" });
  expect((within(form).getByRole("button", { name: "Add" }) as HTMLButtonElement).disabled).toBe(true);
 });
});
