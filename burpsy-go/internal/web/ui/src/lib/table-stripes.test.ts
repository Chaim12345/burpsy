// Zebra striping (69p0): on by default like Burp's table_appearance.zebra_striping, persisted with
// the workspace, and drawn from the pending stripe tokens rather than a raw colour.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { persistedWorkspace, useApp } from "./store";

describe("table stripes", () => {
  test("ship on, as Burp's do", () => {
    expect(useApp.getState().tableStripes).toBe(true);
  });

  test("the choice persists with the workspace", () => {
    useApp.getState().setTableStripes(false);
    expect(persistedWorkspace(useApp.getState()).tableStripes).toBe(false);
    useApp.getState().setTableStripes(true);
  });

  test("the stripe is drawn from the generated tokens, per theme", () => {
    const pending = readFileSync(join(import.meta.dir, "../tokens/pending.css"), "utf8");
    const styles = readFileSync(join(import.meta.dir, "../styles.css"), "utf8");
    expect(pending).toContain("--opacity-stripe-dark:");
    expect(pending).toContain("--opacity-stripe-light:");
    expect(styles).toContain("--stripe-alpha: var(--opacity-stripe-dark);");
    expect(styles).toContain("--stripe-alpha: var(--opacity-stripe-light);");
    expect(styles).toMatch(/\.table-stripes \.row-stripe td[\s\S]*?color-mix\(in srgb, var\(--ink\) calc\(var\(--stripe-alpha\) \* 100%\), var\(--paper-raised\)\)/);
  });
});
