/** burpsy-react-ui-vlrh.1: a numeric setting never turns a blank or half-typed field into 0. */
import { afterEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { WholeNumberInput } from "./whole-number-input";

afterEach(cleanup);

describe("WholeNumberInput", () => {
  test("commits a valid whole number", () => {
    const commits: number[] = [];
    render(<WholeNumberInput aria-label="Timeout" value={5} min={0} onCommit={(n) => commits.push(n)} />);
    fireEvent.change(screen.getByLabelText("Timeout"), { target: { value: "250" } });
    expect(commits).toEqual([250]);
  });
  test("a cleared field commits nothing and is flagged, instead of becoming 0", () => {
    const commits: number[] = [];
    render(<WholeNumberInput aria-label="Timeout" value={5} min={0} onCommit={(n) => commits.push(n)} />);
    const input = screen.getByLabelText("Timeout") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "" } });
    expect(commits).toEqual([]);
    expect(input.value).toBe("");
    expect(input.getAttribute("aria-invalid")).toBe("true");
  });
  test("a value below the minimum is not committed", () => {
    const commits: number[] = [];
    render(<WholeNumberInput aria-label="Hops" value={5} min={1} onCommit={(n) => commits.push(n)} />);
    fireEvent.change(screen.getByLabelText("Hops"), { target: { value: "0" } });
    expect(commits).toEqual([]);
  });
  test("a fractional value is not committed", () => {
    const commits: number[] = [];
    render(<WholeNumberInput aria-label="Hops" value={5} min={0} onCommit={(n) => commits.push(n)} />);
    fireEvent.change(screen.getByLabelText("Hops"), { target: { value: "4.5" } });
    expect(commits).toEqual([]);
  });
  test("follows the value when it changes from outside, as a revert does", () => {
    const view = render(<WholeNumberInput aria-label="Timeout" value={5} min={0} onCommit={() => {}} />);
    fireEvent.change(screen.getByLabelText("Timeout"), { target: { value: "" } });
    view.rerender(<WholeNumberInput aria-label="Timeout" value={7} min={0} onCommit={() => {}} />);
    expect((screen.getByLabelText("Timeout") as HTMLInputElement).value).toBe("7");
  });
});
