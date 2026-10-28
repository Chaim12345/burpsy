import { expect, test } from "bun:test";
import { afterEach } from "bun:test";
import { cleanup, fireEvent, render } from "@testing-library/react";
import { ContextMenu, type MenuGroup } from "./menu";

afterEach(() => cleanup());

const build = (calls: { n: number }) => (): MenuGroup[] => {
 calls.n++;
 return [{ id: "g", actions: [{ id: "a", label: "Do the thing", onSelect: () => {} }] }];
};

test("a menu given a builder does not build its actions until it is opened", async () => {
 const calls = { n: 0 };
 const view = render(
  <ContextMenu groups={build(calls)} docTopic={null}>
   <div data-testid="row">row</div>
  </ContextMenu>,
 );
 view.rerender(
  <ContextMenu groups={build(calls)} docTopic={null}>
   <div data-testid="row">row</div>
  </ContextMenu>,
 );
 expect(calls.n).toBe(0);
 fireEvent.contextMenu(view.getByTestId("row"));
 await new Promise((resolve) => setTimeout(resolve, 50));
 expect(calls.n).toBeGreaterThan(0);
 expect(document.body.textContent).toContain("Do the thing");
});

test("a plain array still builds and renders as before", () => {
 const view = render(
  <ContextMenu groups={[{ id: "g", actions: [{ id: "a", label: "Plain", onSelect: () => {} }] }]} docTopic={null}>
   <div data-testid="row">row</div>
  </ContextMenu>,
 );
 expect(view.getByTestId("row")).toBeTruthy();
});
