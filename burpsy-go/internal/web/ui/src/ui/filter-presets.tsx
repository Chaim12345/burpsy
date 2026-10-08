/**
 * The filter-settings menu for History, Logger and Organizer (mntt): Burp's "Restore defaults",
 * "Load settings" and "Save settings" (desktop/tools/filter.html), plus named presets kept in this
 * browser. The rules — versioning, the table check, per-key type checks — are lib/filter-presets.ts;
 * this is the menu and the file plumbing.
 */
import { FileDown, FileUp, RotateCcw, Save, SlidersHorizontal, Trash2 } from "lucide-react";
import { useRef, useState } from "react";
import { toast } from "sonner";
import { downloadText } from "../lib/api";
import { confirmDialog, promptDialog } from "../lib/dialogs";
import {
  differsFromDefaults,
  FILTER_DEFAULTS,
  FILTER_TABLE_LABEL,
  parsePreset,
  presetStorageKey,
  readPresets,
  removePreset,
  serializePreset,
  upsertPreset,
  type AllowedValues,
  type FilterSettings,
  type FilterTable,
  type NamedPreset,
} from "../lib/filter-presets";
import { DropdownMenu } from "./menu";
import { Button } from "./primitives";

function persist(table: FilterTable, list: NamedPreset[]): boolean {
  try {
    localStorage.setItem(presetStorageKey(table), JSON.stringify(list));
    return true;
  } catch {
    return false;
  }
}

export function FilterPresetsMenu({
  table,
  current,
  apply,
  allowed = {},
}: {
  table: FilterTable;
  /** Closed option sets for the page's selects, so a loaded preset cannot pick a value none offers. */
  allowed?: AllowedValues;
  /** The table's filter settings as they stand now. */
  current: FilterSettings;
  /** Put a complete, sanitised settings object into the page's filter state. */
  apply: (settings: FilterSettings) => void;
}): JSX.Element {
  const [presets, setPresets] = useState<NamedPreset[]>(() => readPresets(localStorage, table, allowed));
  const fileRef = useRef<HTMLInputElement>(null);
  const label = FILTER_TABLE_LABEL[table];

  const save = (list: NamedPreset[]) => {
    setPresets(list);
    if (!persist(table, list)) toast.warning("Kept for this session only — this browser refused to store it");
  };

  const saveNamed = async () => {
    const name = await promptDialog({
      title: `Save the ${label} filter`,
      description: "Kept in this browser. Saving under an existing name replaces that preset.",
      label: "Preset name",
      confirmLabel: "Save preset",
    });
    if (name === null || name.trim() === "") return;
    save(upsertPreset(presets, name.trim(), current, table));
    toast.success(`Filter saved as "${name.trim()}"`);
  };

  const deleteNamed = async (name: string) => {
    const ok = await confirmDialog({
      title: `Delete the preset "${name}"?`,
      description: "Only the saved preset goes; the filter on screen is not changed.",
      confirmLabel: "Delete preset",
      cancelLabel: "Keep it",
      danger: true,
    });
    if (!ok) return;
    save(removePreset(presets, name));
    toast.success(`Preset "${name}" deleted`);
  };

  const loadFile = async (file: File) => {
    const parsed = parsePreset(await file.text(), table, allowed);
    if (!parsed.ok) {
      toast.error(`Could not load ${file.name}: ${parsed.reason}`);
      return;
    }
    apply(parsed.settings);
    if (parsed.skipped.length > 0) {
      toast.warning(`Loaded "${parsed.name}" — ${parsed.skipped.join(", ")} had the wrong type and stayed at the default`);
    } else {
      toast.success(`Loaded the filter "${parsed.name}"`);
    }
  };

  const changed = differsFromDefaults(table, current);

  return (
    <>
      <DropdownMenu
        align="start"
        trigger={
          <Button variant="quiet" size="small" title={`${label} filter: restore defaults, save or load`}>
            <SlidersHorizontal size={13} />
            Saved filters
          </Button>
        }
        groups={[
          {
            id: "defaults",
            actions: [
              {
                id: "restore",
                label: "Restore defaults",
                icon: RotateCcw,
                disabled: !changed,
                hint: changed ? `Every ${label} filter back to its shipped value` : "The filter is already at its defaults",
                onSelect: () => {
                  apply(structuredClone(FILTER_DEFAULTS[table]));
                  toast.success(`${label} filter restored to defaults`);
                },
              },
            ],
          },
          {
            id: "named",
            title: "Saved in this browser",
            actions: [
              { id: "save", label: "Save as preset…", icon: Save, onSelect: () => void saveNamed() },
              {
                id: "load",
                label: presets.length ? "Load preset" : "Load preset (none saved)",
                disabled: presets.length === 0,
                submenu: [
                  {
                    id: "presets",
                    actions: presets.map((preset) => ({
                      id: `load-${preset.name}`,
                      label: preset.name,
                      hint: preset.saved_at ? `Saved ${new Date(preset.saved_at).toLocaleString()}` : undefined,
                      onSelect: () => {
                        apply(preset.settings);
                        toast.success(`Loaded the filter "${preset.name}"`);
                      },
                    })),
                  },
                ],
                onSelect: () => undefined,
              },
              {
                id: "delete",
                label: "Delete preset",
                icon: Trash2,
                disabled: presets.length === 0,
                submenu: [
                  {
                    id: "delete-presets",
                    actions: presets.map((preset) => ({
                      id: `delete-${preset.name}`,
                      label: preset.name,
                      danger: true,
                      onSelect: () => void deleteNamed(preset.name),
                    })),
                  },
                ],
                onSelect: () => undefined,
              },
            ],
          },
          {
            id: "file",
            title: "Settings file",
            actions: [
              {
                id: "save-file",
                label: "Save settings to file…",
                icon: FileDown,
                onSelect: () => {
                  downloadText(`burpsy-${table}-filter.json`, serializePreset(table, `${label} filter`, current), "application/json");
                  toast.success(`${label} filter saved to burpsy-${table}-filter.json`);
                },
              },
              { id: "load-file", label: "Load settings from file…", icon: FileUp, onSelect: () => fileRef.current?.click() },
            ],
          },
        ]}
      />
      <input
        ref={fileRef}
        type="file"
        accept="application/json,.json"
        className="sr-only"
        aria-hidden="true"
        tabIndex={-1}
        onChange={(event) => {
          const file = event.target.files?.[0];
          event.target.value = "";
          if (file) void loadFile(file);
        }}
      />
    </>
  );
}
