// Expand / collapse a branch (txnw): breadth-first, capped, cycle-safe, and honest about what the
// cap left closed.
import { describe, expect, test } from "bun:test";
import { collectBranch, setExpandedKeys } from "./tree-expand";

interface N {
 key: string;
 children?: N[];
}
const leaf = (key: string): N => ({ key });
const tree: N = {
 key: "host",
 children: [
  { key: "/a", children: [{ key: "/a/x", children: [leaf("/a/x/1")] }, leaf("/a/y")] },
  { key: "/b", children: [leaf("/b/1")] },
  leaf("/c"),
 ],
};
const walk = (root: N, cap?: number) =>
 collectBranch(
  root,
  (node) => node.children,
  (node) => node.key,
  cap,
 );

describe("collectBranch", () => {
 test("every node with children, root first, breadth-first; leaves are not listed", () => {
  expect(walk(tree)).toEqual({ keys: ["host", "/a", "/b", "/a/x"], total: 4, truncated: false });
 });

 test("the cap keeps the shallow levels and reports how many it left", () => {
  expect(walk(tree, 2)).toEqual({ keys: ["host", "/a"], total: 4, truncated: true });
 });

 test("a leaf has nothing to expand", () => {
  expect(walk(leaf("/c"))).toEqual({ keys: [], total: 0, truncated: false });
 });

 test("a cycle in the input terminates", () => {
  const a: N = { key: "a", children: [] };
  const b: N = { key: "b", children: [a] };
  a.children!.push(b);
  expect(walk(a).keys).toEqual(["a", "b"]);
 });
});

test("setExpandedKeys opens or closes exactly the keys given, leaving others", () => {
 expect(setExpandedKeys({ keep: false, "/a": false }, ["/a", "/b"], true)).toEqual({ keep: false, "/a": true, "/b": true });
});
