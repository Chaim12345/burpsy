/**
 * The context menu for a multi-row selection (burpsy-react-ui-fe16).
 *
 * Burp branches its table menus on the selection size. Zr2s.java (the WebSocket/Proxy history
 * menu) drops "Send to Repeater" when more than one row is selected, keeps "Send to Comparer",
 * and swaps "Delete item" / "Copy URL" for "Delete selected items" / "Copy URLs". This builds that
 * menu for an exchange table; the page adds what only it can do (History's Delete selected items,
 * Audit selected items) as `extra`.
 *
 * Pure apart from the handler calls: the rows and the handlers come in, groups come out, so which
 * entries are offered and enabled for a given N is testable without a mounted table.
 */
import { Combine, Link2, NotebookPen, ShieldCheck } from "lucide-react";
import type { MenuGroup } from "../ui/menu";
import type { Exchange } from "./types";

export interface ManyHandlers {
  /** Load `a` into Comparer's A side and `b` into its B side. */
  compare: (a: Exchange, b: Exchange) => void;
  copyUrls: (exchanges: Exchange[]) => void;
  /** Add each distinct host to scope. */
  addHostsToScope: (hosts: string[]) => void;
  addAllToOrganizer: (exchanges: Exchange[]) => void;
}

/** The distinct hosts in a selection, first-seen order. One scope rule per host, not per row. */
export function distinctHosts(exchanges: readonly Pick<Exchange, "host">[]): string[] {
  return [...new Set(exchanges.map((exchange) => exchange.host))];
}

export function manyMenuGroups(exchanges: Exchange[], handlers: ManyHandlers, extra: MenuGroup[] = []): MenuGroup[] {
  const n = exchanges.length;
  const [first, second] = exchanges;
  const hosts = distinctHosts(exchanges);
  const canCompare = n >= 2 && first !== undefined && second !== undefined;
  return [
    {
      id: "selection",
      // The size is the heading, so an operator about to act on 30 rows can see that it is 30.
      title: `${n.toLocaleString()} selected item${n === 1 ? "" : "s"}`,
      actions: [
        {
          id: "compare",
          label: n > 2 ? "Send first two to Comparer (A and B)" : "Send to Comparer (A and B)",
          icon: Combine,
          disabled: !canCompare,
          hint: !canCompare
            ? "Comparer compares two messages; select at least two rows."
            : n > 2
              ? `Comparer has two sides: #${first!.id} goes to A and #${second!.id} to B. The other ${n - 2} are not sent.`
              : `#${first!.id} goes to A and #${second!.id} to B.`,
          onSelect: () => {
            if (canCompare) handlers.compare(first!, second!);
          },
        },
      ],
    },
    {
      id: "copy",
      actions: [
        {
          id: "copy-urls",
          label: `Copy URLs (${n.toLocaleString()})`,
          icon: Link2,
          disabled: n === 0,
          onSelect: () => handlers.copyUrls(exchanges),
        },
      ],
    },
    {
      id: "organise",
      actions: [
        {
          id: "organizer",
          label: `Add ${n.toLocaleString()} to Organizer`,
          icon: NotebookPen,
          disabled: n === 0,
          onSelect: () => handlers.addAllToOrganizer(exchanges),
        },
        {
          id: "scope",
          label: hosts.length === 1 ? `Add ${hosts[0]} to scope` : `Add ${hosts.length} hosts to scope`,
          icon: ShieldCheck,
          disabled: hosts.length === 0,
          hint: hosts.length > 1 ? hosts.join(", ") : undefined,
          onSelect: () => handlers.addHostsToScope(hosts),
        },
      ],
    },
    ...extra,
  ];
}
