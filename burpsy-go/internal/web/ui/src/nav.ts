import {
  BookOpen,
  Braces,
  ChartNoAxesCombined,
  Combine,
  RadioTower,
  Crosshair,
  FileClock,
  Gauge,
  NotebookTabs,
  Radar,
  Repeat2,
  Settings,
  ShieldCheck,
  Split,
  type LucideIcon,
} from "lucide-react";
import type { ComponentType } from "react";
import { IssueDefinitionsPage } from "./pages/advisories";
import { AuditQueuePage } from "./pages/auditqueue";
import { ComparerPage } from "./pages/comparer";
import { CollaboratorPage } from "./pages/collaborator";
import { DashboardPage } from "./pages/dashboard";
import { DecoderPage } from "./pages/decoder";
import { DiscoverPage } from "./pages/discover";
import { HistoryPage } from "./pages/history";
import { InterceptPage } from "./pages/intercept";
import { IntruderPage } from "./pages/intruder";
import { LoggerPage } from "./pages/logger";
import { MatchReplacePage } from "./pages/matchreplace";
import { OrganizerPage } from "./pages/organizer";
import { RepeaterPage } from "./pages/repeater";
import { ScannerPage } from "./pages/scanner";
import { SequencerPage } from "./pages/sequencer";
import { SessionPage } from "./pages/session";
import { SettingsPage } from "./pages/settings";
import { ScopePage } from "./pages/scope";
import { SiteMapPage } from "./pages/sitemap";
import { WebSocketPage } from "./pages/wshistory";

/** One routable view. `id` is the URL hash and the routing key. */
export interface NavLeaf {
  id: string;
  label: string;
  description: string;
  page: ComponentType;
}

/**
 * A top-level tool, rendered as a tab in the primary row. Tools with more than
 * one leaf get a second row of sub-tabs, which is how Burp organises the same
 * material — Proxy owning intercept and history rather than listing both at the
 * top level.
 */
export interface NavTool {
  id: string;
  label: string;
  icon: LucideIcon;
  /** Bound as alt+<key>. */
  hotkey?: string;
  leaves: NavLeaf[];
}

export const TOOLS: NavTool[] = [
  {
    id: "dashboard",
    label: "Dashboard",
    icon: Gauge,
    hotkey: "1",
    leaves: [
      {
        id: "dashboard",
        label: "Dashboard",
        description: "Coverage, running work, and recent activity",
        page: DashboardPage,
      },
    ],
  },
  {
    id: "target",
    label: "Target",
    icon: Radar,
    hotkey: "2",
    leaves: [
      { id: "sitemap", label: "Site map", description: "Hosts, paths, and observed behaviour", page: SiteMapPage },
      { id: "scanner", label: "Issues", description: "Findings, coverage, and active audits", page: ScannerPage },
      { id: "auditqueue", label: "Audit queue", description: "What the active audit did with each exchange, and why any were skipped", page: AuditQueuePage },
      {
        id: "advisories",
        label: "Issue definitions",
        // Reads as the companion to Issues, and sits next to it: Issues is what was found, this is
        // what can be described. Burp keeps the same pair under Target for the same reason.
        description: "Every issue class the catalogue describes, found or not",
        page: IssueDefinitionsPage,
      },
      { id: "scope", label: "Scope", description: "What the tools are allowed to touch", page: ScopePage },
    ],
  },
  {
    id: "proxy",
    label: "Proxy",
    icon: Split,
    hotkey: "3",
    leaves: [
      { id: "intercept", label: "Intercept", description: "Hold, edit, and release traffic in flight", page: InterceptPage },
      { id: "history", label: "HTTP history", description: "Every captured request and response", page: HistoryPage },
      { id: "wshistory", label: "WebSockets history", description: "Upgrade connections and frame payloads", page: WebSocketPage },
      {
        id: "matchreplace",
        label: "Match & Replace",
        description: "Reviewable traffic transformations",
        page: MatchReplacePage,
      },
    ],
  },
  {
    id: "intruder",
    label: "Intruder",
    icon: Crosshair,
    hotkey: "4",
    leaves: [
      {
        id: "intruder",
        label: "Intruder",
        description: "Payload-driven attacks with bounded accounting",
        page: IntruderPage,
      },
    ],
  },
  {
    id: "repeater",
    label: "Repeater",
    icon: Repeat2,
    hotkey: "5",
    leaves: [{ id: "repeater", label: "Repeater", description: "Craft and resend requests", page: RepeaterPage }],
  },
  {
    id: "sequencer",
    label: "Sequencer",
    icon: ChartNoAxesCombined,
    hotkey: "6",
    leaves: [
      { id: "sequencer", label: "Sequencer", description: "Token randomness analysis", page: SequencerPage },
    ],
  },
  {
    id: "decoder",
    label: "Decoder",
    icon: Braces,
    hotkey: "7",
    leaves: [{ id: "decoder", label: "Decoder", description: "Transform and hash data", page: DecoderPage }],
  },
  {
    id: "comparer",
    label: "Comparer",
    icon: Combine,
    hotkey: "8",
    leaves: [{ id: "comparer", label: "Comparer", description: "Byte-level differences", page: ComparerPage }],
  },
  {
    id: "collaborator",
    label: "Collaborator",
    icon: RadioTower,
    hotkey: "9",
    leaves: [
      {
        id: "collaborator",
        label: "Collaborator",
        description: "Out-of-band interactions and blind-XSS callbacks",
        page: CollaboratorPage,
      },
    ],
  },
  {
    id: "logger",
    label: "Logger",
    icon: FileClock,
    leaves: [{ id: "logger", label: "Logger", description: "Requests burpsy itself sent", page: LoggerPage }],
  },
  {
    id: "organizer",
    label: "Organizer",
    icon: NotebookTabs,
    hotkey: "0",
    leaves: [
      { id: "organizer", label: "Organizer", description: "Curated investigation notes", page: OrganizerPage },
    ],
  },
  {
    id: "session",
    label: "Session",
    icon: ShieldCheck,
    leaves: [
      { id: "session", label: "Session", description: "Login macros and recovery behaviour", page: SessionPage },
    ],
  },
  {
    // Burp's DISCOVER constant, the tab that used to be called Learn, sits second
    // to last — right before Settings — and so does this. What it holds is not
    // Burp's link farm: see pages/discover.tsx for why an in-app reference is the
    // honest analogue and a list of outbound links is not.
    id: "discover",
    label: "Discover",
    icon: BookOpen,
    leaves: [
      {
        id: "discover",
        label: "Discover",
        description: "Query grammar, BCheck syntax, hotkeys, and the deliberate gaps",
        page: DiscoverPage,
      },
    ],
  },
  {
    id: "settings",
    label: "Settings",
    icon: Settings,
    leaves: [
      {
        id: "settings",
        label: "Settings",
        description: "Protocols, appearance, certificates, and diagnostics",
        page: SettingsPage,
      },
    ],
  },
];

export const NAV_LEAVES: NavLeaf[] = TOOLS.flatMap((tool) => tool.leaves);

export function findLeaf(id: string): NavLeaf {
  return NAV_LEAVES.find((leaf) => leaf.id === id) ?? NAV_LEAVES[0]!;
}

export function toolOf(leafId: string): NavTool {
  return TOOLS.find((tool) => tool.leaves.some((leaf) => leaf.id === leafId)) ?? TOOLS[0]!;
}

/** Where a tool tab navigates: its first leaf. */
export function entryLeaf(tool: NavTool): string {
  return tool.leaves[0]?.id ?? "dashboard";
}
