/**
 * burpsy-react-ui-vln1 (replaces the editor.tsx/store.ts source pins in lib/hide-headers.test.ts):
 * the editor's "Hide specified headers" eye (whr), in the real HttpEditor.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { useApp } from "../lib/store";
import { HttpEditor } from "./editor";

const JSON_BODY = '{"a":1}';
const HEADS = `X-A: 1\r\nX-B: 2\r\nContent-Type: application/json\r\nContent-Length: ${JSON_BODY.length}\r\n\r\n${JSON_BODY}`;
const REQUEST = `POST / HTTP/1.1\r\nHost: x\r\n${HEADS}`;
const RESPONSE = `HTTP/1.1 200 OK\r\n${HEADS}`;

beforeEach(() => {
 window.localStorage.clear();
 useApp.setState({ hideRequestHeaders: ["X-A"], hideResponseHeaders: ["X-B"], hideHeadersByDefault: false });
});
afterEach(cleanup);

const show = (value: string, props: { readOnly?: boolean } = {}) =>
 renderWithProviders(<HttpEditor value={value} onChange={() => {}} label="Message" {...props} />);
const text = (container: HTMLElement) => container.querySelector(".cm-content")?.textContent ?? "";
/** The editor opens on Raw; the eye belongs to Pretty. */
const openPretty = async () => fireEvent.click(await screen.findByRole("tab", { name: "Pretty" }));
const eye = () => screen.queryByRole("button", { name: /specified headers/ });

describe("the hide-specified-headers eye", () => {
 test("a request pane hides the request list and a response pane the response list", async () => {
  const request = show(REQUEST);
  await openPretty();
  await waitFor(() => expect(text(request.container)).toContain("X-A: 1"));
  fireEvent.click(eye() as HTMLElement);
  await waitFor(() => expect(text(request.container)).not.toContain("X-A: 1"));
  expect(text(request.container)).toContain("X-B: 2");
  cleanup();

  const response = show(RESPONSE);

  await openPretty();
  await waitFor(() => expect(text(response.container)).toContain("X-B: 2"));
  fireEvent.click(eye() as HTMLElement);
  await waitFor(() => expect(text(response.container)).not.toContain("X-B: 2"));
  expect(text(response.container)).toContain("X-A: 1");
 });

 test("it is offered only when the list has something to hide", async () => {
  useApp.setState({ hideRequestHeaders: [] });
  const view = show(REQUEST);
  await openPretty();
  await waitFor(() => expect(text(view.container)).toContain("POST /"));
  expect(eye()).toBeNull();
 });

 test("it is offered only in Pretty: leaving for Raw takes it away, and Raw always shows every header", async () => {
  const view = show(REQUEST);
  await openPretty();
  await waitFor(() => expect(eye()).not.toBeNull());
  fireEvent.click(screen.getByRole("tab", { name: "Raw" }));
  await waitFor(() => expect(eye()).toBeNull());
  expect(text(view.container)).toContain("X-A: 1");
 });

 test("while it is on the pane says why editing stopped; pressing it again restores the headers", async () => {
  const view = show(REQUEST);
  await openPretty();
  await waitFor(() => expect(eye()).not.toBeNull());
  fireEvent.click(eye() as HTMLElement);
  expect(await screen.findByText(/Press the eye again to edit/)).toBeTruthy();
  expect(eye()?.getAttribute("aria-pressed")).toBe("true");
  fireEvent.click(eye() as HTMLElement);
  await waitFor(() => expect(text(view.container)).toContain("X-A: 1"));
  expect(screen.queryByText(/Press the eye again to edit/)).toBeNull();
 });

 test("an unpressed eye follows the Settings default, and pressing it wins over the default", async () => {
  useApp.setState({ hideHeadersByDefault: true });
  const view = show(REQUEST);
  await openPretty();
  await waitFor(() => expect(text(view.container)).toContain("POST /"));
  expect(text(view.container)).not.toContain("X-A: 1");
  expect(eye()?.getAttribute("aria-pressed")).toBe("true");
  fireEvent.click(eye() as HTMLElement);
  await waitFor(() => expect(text(view.container)).toContain("X-A: 1"));
 });

 test("both lists and the default are persisted, so they survive a reload", () => {
  useApp.setState({ hideRequestHeaders: ["X-Q"], hideResponseHeaders: ["X-R"], hideHeadersByDefault: true });
  const saved = JSON.parse(window.localStorage.getItem("burpsy.workspace") ?? "{}") as { state?: Record<string, unknown> };
  expect(saved.state).toMatchObject({ hideRequestHeaders: ["X-Q"], hideResponseHeaders: ["X-R"], hideHeadersByDefault: true });
 });
});
