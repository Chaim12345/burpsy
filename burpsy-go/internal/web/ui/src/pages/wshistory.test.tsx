import { afterEach, describe, expect, test } from "bun:test";
import { cleanup, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { WebSocketPage } from "./wshistory";

afterEach(cleanup);

describe("WebSocketPage", () => {
  test("renders against a failing API without throwing, and settles", async () => {
    const view = renderWithProviders(<WebSocketPage />);
    await waitFor(() => expect(view.container.textContent?.length ?? 0).toBeGreaterThan(0));
  });
});
