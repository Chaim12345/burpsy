import * as ContextMenuPrimitive from "@radix-ui/react-context-menu";
import * as DropdownPrimitive from "@radix-ui/react-dropdown-menu";
import { BookOpen, Check, ChevronRight } from "lucide-react";
import { docEntryLabel, openDocs, type DocTopic } from "../lib/docs";
import type { ComponentType, ReactNode } from "react";

export interface MenuAction {
  /** A stable key; also the visible label unless `label` is given. */
  id: string;
  label: string;
  icon?: ComponentType<{ size?: number }>;
  shortcut?: string;
  danger?: boolean;
  /**
   * Renders the row as a checkable item with this state, for menus whose entries are switches
   * rather than commands — Burp's View menu, whose entries hide and show top-level tabs. Omit it
   * and the row is an ordinary item. `onSelect` still fires on click; the caller owns the state.
   */
  checked?: boolean;
  disabled?: boolean;
  /**
   * Why this row is here, rendered as the item's `title`.
   *
   * It exists for the disabled rows. A greyed item with no explanation is a dead end an operator
   * has to guess at — worse than an absent one, because it implies the feature is somewhere nearby.
   * With a hint the row says what burpsy cannot do and why, which is the honest version of a control
   * that cannot be honoured. Enabled rows may carry one too, as a plain hover explanation.
   */
  hint?: string;
  /**
   * Nested groups. When present the row becomes a submenu trigger and `onSelect` is
   * never called — a row cannot both open a submenu and do something, because a click
   * on it would then be ambiguous. Burp's own colour and severity pickers are submenus,
   * which is what this exists for.
   */
  submenu?: MenuGroup[];
  onSelect: () => void;
}

export interface MenuGroup {
  id: string;
  /** Optional non-interactive section title rendered above the group's items — Burp's
   *  "Engagement tools" style heading. Groups without one keep the separator-only look. */
  title?: string;
  actions: MenuAction[];
}

/**
 * The one place a menu's primitives are named. Context menus and dropdowns are two
 * different Radix packages with the same part names, so the renderer takes the bundle
 * rather than branching per part — adding a part to one branch and forgetting the other
 * is how a submenu ends up rendering only inside dropdowns.
 */
interface MenuParts {
  Item: typeof ContextMenuPrimitive.Item | typeof DropdownPrimitive.Item;
  CheckboxItem: typeof ContextMenuPrimitive.CheckboxItem | typeof DropdownPrimitive.CheckboxItem;
  Indicator: typeof ContextMenuPrimitive.ItemIndicator | typeof DropdownPrimitive.ItemIndicator;
  Separator: typeof ContextMenuPrimitive.Separator | typeof DropdownPrimitive.Separator;
  Sub: typeof ContextMenuPrimitive.Sub | typeof DropdownPrimitive.Sub;
  SubTrigger: typeof ContextMenuPrimitive.SubTrigger | typeof DropdownPrimitive.SubTrigger;
  SubContent: typeof ContextMenuPrimitive.SubContent | typeof DropdownPrimitive.SubContent;
  Portal: typeof ContextMenuPrimitive.Portal | typeof DropdownPrimitive.Portal;
}

const CONTEXT_PARTS: MenuParts = {
  Item: ContextMenuPrimitive.Item,
  CheckboxItem: ContextMenuPrimitive.CheckboxItem,
  Indicator: ContextMenuPrimitive.ItemIndicator,
  Separator: ContextMenuPrimitive.Separator,
  Sub: ContextMenuPrimitive.Sub,
  SubTrigger: ContextMenuPrimitive.SubTrigger,
  SubContent: ContextMenuPrimitive.SubContent,
  Portal: ContextMenuPrimitive.Portal,
};

const DROPDOWN_PARTS: MenuParts = {
  Item: DropdownPrimitive.Item,
  CheckboxItem: DropdownPrimitive.CheckboxItem,
  Indicator: DropdownPrimitive.ItemIndicator,
  Separator: DropdownPrimitive.Separator,
  Sub: DropdownPrimitive.Sub,
  SubTrigger: DropdownPrimitive.SubTrigger,
  SubContent: DropdownPrimitive.SubContent,
  Portal: DropdownPrimitive.Portal,
};

/** Whether a set of groups would render anything at all. Used to skip empty menus. */
export function hasMenuActions(groups: MenuGroup[]): boolean {
  return groups.some((group) => group.actions.length > 0);
}

function renderItems(groups: MenuGroup[], parts: MenuParts): ReactNode {
  const { Item, CheckboxItem, Indicator, Separator, Sub, SubTrigger, SubContent, Portal } = parts;
  const visible = groups.filter((group) => group.actions.length > 0);
  return visible.map((group, index) => (
    <div key={group.id}>
      {index > 0 ? <Separator className="menu-separator" /> : null}
      {group.title ? <div className="menu-group-title">{group.title}</div> : null}
      {group.actions.map((action) => {
        const Icon = action.icon;
        const body = (
          <>
            <span className="menu-item-icon">{Icon ? <Icon size={14} /> : null}</span>
            <span className="menu-item-label">{action.label}</span>
            {action.shortcut ? <span className="menu-item-shortcut">{action.shortcut}</span> : null}
          </>
        );
        if (action.submenu && hasMenuActions(action.submenu)) {
          return (
            <Sub key={action.id}>
              <SubTrigger className="menu-item menu-item-sub" disabled={action.disabled} title={action.hint}>
                {body}
                <span className="menu-item-chevron" aria-hidden="true">
                  <ChevronRight size={13} />
                </span>
              </SubTrigger>
              <Portal>
                <SubContent className="menu-content" collisionPadding={8} sideOffset={2}>
                  {renderItems(action.submenu, parts)}
                </SubContent>
              </Portal>
            </Sub>
          );
        }
        if (action.checked !== undefined) {
          // The tick sits in the icon slot rather than beside the label, so a checkable menu's
          // labels stay aligned with an ordinary menu's (Burp's View list does the same thing).
          return (
            <CheckboxItem
              key={action.id}
              className="menu-item"
              checked={action.checked}
              disabled={action.disabled}
              onSelect={action.onSelect}
            >
              <span className="menu-item-icon">
                <Indicator>
                  <Check size={14} />
                </Indicator>
              </span>
              <span className="menu-item-label">{action.label}</span>
              {action.shortcut ? <span className="menu-item-shortcut">{action.shortcut}</span> : null}
            </CheckboxItem>
          );
        }
        return (
          <Item
            key={action.id}
            className={action.danger ? "menu-item menu-item-danger" : "menu-item"}
            disabled={action.disabled}
            title={action.hint}
            onSelect={action.onSelect}
          >
            {body}
          </Item>
        );
      })}
    </div>
  ));
}

/**
 * The menu's trailing "<Tool> documentation" entry (u9zz), after a separator, as Burp ends its
 * table and editor menus (Zr2s.java, Zs7j.java). Only added to a menu that has entries of its
 * own: a documentation link is not a reason to give a row a menu it did not have.
 */
export function withDocs(groups: MenuGroup[], topic: DocTopic | null): MenuGroup[] {
  if (topic === null || !hasMenuActions(groups)) return groups;
  return [
    ...groups,
    { id: "docs", actions: [{ id: "docs", label: docEntryLabel(topic), icon: BookOpen, onSelect: () => openDocs(topic) }] },
  ];
}

/**
 * Right-click menu wrapper. `groups` is rebuilt per open, so it can close over row data.
 *
 * `docTopic` is required so every call site decides: a table or editor menu names its tool's
 * documentation topic (lib/docs.ts), anything else passes null.
 */
export function ContextMenu({
  groups: own,
  docTopic,
  children,
}: {
  groups: MenuGroup[];
  docTopic: DocTopic | null;
  children: ReactNode;
}): JSX.Element {
  const groups = withDocs(own, docTopic);
  if (!hasMenuActions(groups)) return <>{children}</>;
  return (
    <ContextMenuPrimitive.Root>
      <ContextMenuPrimitive.Trigger asChild>{children}</ContextMenuPrimitive.Trigger>
      <ContextMenuPrimitive.Portal>
        <ContextMenuPrimitive.Content className="menu-content" collisionPadding={8}>
          {renderItems(groups, CONTEXT_PARTS)}
        </ContextMenuPrimitive.Content>
      </ContextMenuPrimitive.Portal>
    </ContextMenuPrimitive.Root>
  );
}

/** Click-to-open menu, used for row overflow buttons and toolbar "more" affordances. */
export function DropdownMenu({
  groups,
  trigger,
  align = "end",
}: {
  groups: MenuGroup[];
  trigger: ReactNode;
  align?: "start" | "center" | "end";
}): JSX.Element {
  return (
    <DropdownPrimitive.Root>
      <DropdownPrimitive.Trigger asChild>{trigger}</DropdownPrimitive.Trigger>
      <DropdownPrimitive.Portal>
        <DropdownPrimitive.Content className="menu-content" align={align} sideOffset={5} collisionPadding={8}>
          {renderItems(groups, DROPDOWN_PARTS)}
        </DropdownPrimitive.Content>
      </DropdownPrimitive.Portal>
    </DropdownPrimitive.Root>
  );
}
