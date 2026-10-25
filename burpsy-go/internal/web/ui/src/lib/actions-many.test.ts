// The multi-row menu (burpsy-react-ui-fe16): which entries are offered, and enabled, for N rows,
// and that each hands its handler exactly the rows it names.
import { describe, expect, test } from "bun:test";
import { distinctHosts, manyMenuGroups, type ManyHandlers } from "./actions-many";
import type { Exchange } from "./types";

function exchange(id: number, host = "a.test"): Exchange {
  return { id, host, port: 443, tls: true, method: "GET", path: `/${id}`, request: id * 10, response: id * 10 + 1 } as Exchange;
}

function recorder() {
  const calls: { name: string; args: unknown[] }[] = [];
  const handlers: ManyHandlers = {
    compare: (...args) => calls.push({ name: "compare", args }),
    copyUrls: (...args) => calls.push({ name: "copyUrls", args }),
    addHostsToScope: (...args) => calls.push({ name: "addHostsToScope", args }),
    addAllToOrganizer: (...args) => calls.push({ name: "addAllToOrganizer", args }),
  };
  return { calls, handlers };
}

function action(groups: ReturnType<typeof manyMenuGroups>, id: string) {
  const found = groups.flatMap((group) => group.actions).find((entry) => entry.id === id);
  if (!found) throw new Error(`no ${id} in the menu`);
  return found;
}

describe("manyMenuGroups", () => {
  test("titles the menu with the selection size", () => {
    const groups = manyMenuGroups([exchange(1), exchange(2), exchange(3)], recorder().handlers);
    expect(groups[0]!.title).toBe("3 selected items");
  });

  test("N=2: Send to Comparer is enabled and puts the first row in A and the second in B", () => {
    const { calls, handlers } = recorder();
    const rows = [exchange(7), exchange(9)];
    const groups = manyMenuGroups(rows, handlers);
    const compare = action(groups, "compare");
    expect(compare.disabled).toBe(false);
    expect(compare.label).toBe("Send to Comparer (A and B)");
    compare.onSelect();
    expect(calls).toEqual([{ name: "compare", args: [rows[0], rows[1]] }]);
  });

  test("N>2: the Comparer entry says only the first two are sent, and names the rest", () => {
    const groups = manyMenuGroups([exchange(1), exchange(2), exchange(3), exchange(4)], recorder().handlers);
    const compare = action(groups, "compare");
    expect(compare.label).toBe("Send first two to Comparer (A and B)");
    expect(compare.hint).toContain("The other 2 are not sent");
  });

  test("N=1: Comparer is disabled with the reason; Copy URLs and Organizer still work", () => {
    const { calls, handlers } = recorder();
    const groups = manyMenuGroups([exchange(5)], handlers);
    const compare = action(groups, "compare");
    expect(compare.disabled).toBe(true);
    expect(compare.hint).toContain("at least two");
    compare.onSelect();
    expect(calls).toEqual([]);
    expect(action(groups, "copy-urls").disabled).toBe(false);
    expect(action(groups, "organizer").disabled).toBe(false);
  });

  test("Copy URLs and Add to Organizer receive every selected row, in order", () => {
    const { calls, handlers } = recorder();
    const rows = [exchange(3), exchange(1), exchange(2)];
    const groups = manyMenuGroups(rows, handlers);
    action(groups, "copy-urls").onSelect();
    action(groups, "organizer").onSelect();
    expect(calls).toEqual([
      { name: "copyUrls", args: [rows] },
      { name: "addAllToOrganizer", args: [rows] },
    ]);
    expect(action(groups, "copy-urls").label).toBe("Copy URLs (3)");
  });

  test("Add to scope dedupes hosts: one rule per host, not one per row", () => {
    const { calls, handlers } = recorder();
    const groups = manyMenuGroups([exchange(1, "a.test"), exchange(2, "b.test"), exchange(3, "a.test")], handlers);
    const scope = action(groups, "scope");
    expect(scope.label).toBe("Add 2 hosts to scope");
    expect(scope.hint).toBe("a.test, b.test");
    scope.onSelect();
    expect(calls).toEqual([{ name: "addHostsToScope", args: [["a.test", "b.test"]] }]);
    expect(action(manyMenuGroups([exchange(1, "x.test"), exchange(2, "x.test")], handlers), "scope").label).toBe("Add x.test to scope");
  });

  test("a page's own groups are appended after the shared ones", () => {
    const groups = manyMenuGroups([exchange(1), exchange(2)], recorder().handlers, [
      { id: "page", actions: [{ id: "delete", label: "Delete selected items", onSelect: () => undefined }] },
    ]);
    expect(groups.at(-1)!.id).toBe("page");
  });

  test("distinctHosts keeps first-seen order", () => {
    expect(distinctHosts([{ host: "b" }, { host: "a" }, { host: "b" }])).toEqual(["b", "a"]);
  });
});
