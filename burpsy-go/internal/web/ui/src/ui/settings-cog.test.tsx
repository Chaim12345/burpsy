/** burpsy-react-ui-zpka: a tool's page header carries a settings cog that opens that tool's settings in place. */
import { afterEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen } from "@testing-library/react";
import { takePendingSettingsSection } from "../lib/settings-sections";
import { useApp } from "../lib/store";
import { renderWithProviders } from "../../test/render";
import { PageHeader } from "./layout";

afterEach(cleanup);

describe("PageHeader settings cog", () => {
  test("opens the named Settings section", () => {
    takePendingSettingsSection();
    useApp.getState().setRoute("logger");
    renderWithProviders(<PageHeader title="Tool log" settingsSection="logging" />);
    fireEvent.click(screen.getByRole("button", { name: "Open Tool log settings" }));
    expect(useApp.getState().route).toBe("settings");
    expect(takePendingSettingsSection()).toBe("logging");
  });

  test("a header without a section has no cog", () => {
    renderWithProviders(<PageHeader title="Dashboard" />);
    expect(screen.queryByRole("button", { name: /settings/i })).toBeNull();
  });

  test("the cog sits beside the page's own actions", () => {
    renderWithProviders(<PageHeader title="Proxy" settingsSection="proxy" actions={<button type="button">Mine</button>} />);
    expect(screen.getByRole("button", { name: "Mine" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Open Proxy settings" })).toBeTruthy();
  });
});
