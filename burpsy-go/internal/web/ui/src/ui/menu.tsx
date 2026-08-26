import * as ContextMenuPrimitive from "@radix-ui/react-context-menu";
import * as DropdownPrimitive from "@radix-ui/react-dropdown-menu";
import type { ComponentType, ReactNode } from "react";

export interface MenuAction {
  /** A stable key; also the visible label unless `label` is given. */
  id: string;
  label: string;
  icon?: ComponentType<{ size?: number }>;
  shortcut?: string;
  danger?: boolean;
  disabled?: boolean;
  onSelect: () => void;
}

export interface MenuGroup {
  id: string;
  /** Optional non-interactive section title rendered above the group's items — Burp's
   *  "Engagement tools" style heading. Groups without one keep the separator-only look. */
  title?: string;
  actions: MenuAction[];
}

function renderItems(
  groups: MenuGroup[],
  Item: typeof ContextMenuPrimitive.Item | typeof DropdownPrimitive.Item,
  Separator: typeof ContextMenuPrimitive.Separator | typeof DropdownPrimitive.Separator,
): ReactNode {
  const visible = groups.filter((group) => group.actions.length > 0);
  return visible.map((group, index) => (
    <div key={group.id}>
      {index > 0 ? <Separator className="menu-separator" /> : null}
      {group.title ? <div className="menu-group-title">{group.title}</div> : null}
      {group.actions.map((action) => {
        const Icon = action.icon;
        return (
          <Item
            key={action.id}
            className={action.danger ? "menu-item menu-item-danger" : "menu-item"}
            disabled={action.disabled}
            onSelect={action.onSelect}
          >
            <span className="menu-item-icon">{Icon ? <Icon size={14} /> : null}</span>
            <span className="menu-item-label">{action.label}</span>
            {action.shortcut ? <span className="menu-item-shortcut">{action.shortcut}</span> : null}
          </Item>
        );
      })}
    </div>
  ));
}

/** Right-click menu wrapper. `groups` is rebuilt per open, so it can close over row data. */
export function ContextMenu({ groups, children }: { groups: MenuGroup[]; children: ReactNode }): JSX.Element {
  if (groups.every((group) => group.actions.length === 0)) return <>{children}</>;
  return (
    <ContextMenuPrimitive.Root>
      <ContextMenuPrimitive.Trigger asChild>{children}</ContextMenuPrimitive.Trigger>
      <ContextMenuPrimitive.Portal>
        <ContextMenuPrimitive.Content className="menu-content" collisionPadding={8}>
          {renderItems(groups, ContextMenuPrimitive.Item, ContextMenuPrimitive.Separator)}
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
          {renderItems(groups, DropdownPrimitive.Item, DropdownPrimitive.Separator)}
        </DropdownPrimitive.Content>
      </DropdownPrimitive.Portal>
    </DropdownPrimitive.Root>
  );
}
