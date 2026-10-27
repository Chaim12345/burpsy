/**
 * The Help menu (burpsy-react-ui-n2un). Burp's carries Documentation, Getting started, Support Center,
 * Release notes, Report bug, Diagnostics, License and Check for updates. Most of those are links to
 * PortSwigger's site; burpsy has no such site, and lib/reference.ts explains why a page of outbound
 * links would be worthless here. What does have an honest equivalent is reachable from this menu:
 *
 *   - Documentation: the in-app reference (the Discover tab: query grammar, BCheck syntax, hotkeys and
 *     the deliberate gaps), where Getting started also lives.
 *   - Diagnostics: the Settings section that reports the store and the live event stream. It used to
 *     be reachable only by knowing it was under Settings.
 *
 * Not offered, on purpose: Support Center, Release notes, Report bug, License, Check for updates. Each
 * needs a vendor service burpsy does not have, and a menu row that goes nowhere is worse than none.
 */
import { BookOpen, Command, Keyboard, Stethoscope } from "lucide-react";
import type { MenuGroup } from "../ui/menu";

export interface HelpMenuHandlers {
 openShortcuts: () => void;
 openPalette: () => void;
 openDocumentation: () => void;
 openDiagnostics: () => void;
}

export function helpMenuGroups(handlers: HelpMenuHandlers): MenuGroup[] {
 return [
  {
   id: "reference",
   actions: [
    { id: "documentation", label: "Documentation", icon: BookOpen, onSelect: handlers.openDocumentation },
    { id: "diagnostics", label: "Diagnostics", icon: Stethoscope, onSelect: handlers.openDiagnostics },
   ],
  },
  {
   id: "help",
   actions: [
    { id: "keys", label: "Keyboard shortcuts", shortcut: "?", icon: Keyboard, onSelect: handlers.openShortcuts },
    { id: "palette", label: "Command palette", shortcut: "mod+K", icon: Command, onSelect: handlers.openPalette },
   ],
  },
 ];
}
