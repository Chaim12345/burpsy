import { afterEach, describe, expect, test } from "bun:test";
import { cleanup, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { ScopeSection, TlsPassthroughSection } from "./settings";

afterEach(cleanup);

describe("Settings sections", () => {
 test("Scope renders its controls against a failing API", async () => {
  const view = renderWithProviders(<ScopeSection />);
  await waitFor(() => expect(view.container.querySelectorAll("button, input").length).toBeGreaterThan(0));
 });

 test("TLS passthrough renders its controls against a failing API", async () => {
  const view = renderWithProviders(<TlsPassthroughSection />);
  await waitFor(() => expect(view.container.querySelectorAll("button, input, textarea").length).toBeGreaterThan(0));
 });
});
