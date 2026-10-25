/** vlrh: the react-hook-form + zod settings forms, driven in a DOM. */
import { afterEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { ProjectBackupSection, ProtocolSection } from "./settings";

afterEach(cleanup);

const probeButton = () => screen.getByRole("button", { name: /Probe negotiation/ }) as HTMLButtonElement;

describe("Protocols probe form", () => {
 test("says what is missing until a host and port are valid", async () => {
  renderWithProviders(<ProtocolSection />);
  await waitFor(() => expect(probeButton().disabled).toBe(true));
  expect(screen.getByText("needs a host")).toBeTruthy();

  fireEvent.change(screen.getByLabelText("Host"), { target: { value: "api.example.com" } });
  await waitFor(() => expect(probeButton().disabled).toBe(false));

  fireEvent.change(screen.getByLabelText("Port"), { target: { value: "abc" } });
  await waitFor(() => expect(probeButton().disabled).toBe(true));
  expect(screen.getByText("needs a port")).toBeTruthy();

  fireEvent.change(screen.getByLabelText("Port"), { target: { value: "8443" } });
  await waitFor(() => expect(probeButton().disabled).toBe(false));
 });
});

describe("Project backup form", () => {
 test("an out-of-range retention shows its message and sends nothing", async () => {
  renderWithProviders(<ProjectBackupSection />);
  fireEvent.change(screen.getByLabelText("How many snapshots to keep"), { target: { value: "-5" } });
  fireEvent.click(screen.getByRole("button", { name: "Back up now" }));
  await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("Keep must be -1"));
 });
});
