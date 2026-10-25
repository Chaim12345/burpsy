import { afterEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen } from "@testing-library/react";
import { useApp } from "../lib/store";
import { renderWithProviders } from "../../test/render";
import { IntruderTabStrip } from "./intruder-tab-strip";

afterEach(cleanup);

describe("IntruderTabStrip", () => {
  test("shows the open tab as pressed and switches on click", () => {
    useApp.getState().openIntruderTab();
    renderWithProviders(<IntruderTabStrip />);
    const group = screen.getByRole("group", { name: "Intruder attack tabs" });
    const tabs = group.querySelectorAll<HTMLButtonElement>("button[aria-pressed]");
    expect(tabs.length).toBeGreaterThanOrEqual(2);
    const first = tabs[0] as HTMLButtonElement;
    fireEvent.click(first);
    expect(useApp.getState().activeIntruderTabId).toBe(useApp.getState().intruderTabs[0]!.id);
    expect(first.getAttribute("aria-pressed")).toBe("true");
  });
});
