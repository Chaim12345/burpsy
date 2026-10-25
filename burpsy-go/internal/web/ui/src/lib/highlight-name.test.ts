import { describe, expect, test } from "bun:test";
import { highlightName } from "./types";
import { tabColour } from "./repeater-tabs";
import { highlightBorderStyle } from "../pages/collaborator";

// burpsy-react-ui-iqwb: a stored highlight of "none" (any case) is no highlight, exactly like "".
describe("highlightName", () => {
 test("empty, missing and every spelling of none are no highlight", () => {
  for (const value of ["", "  ", undefined, null, "none", "NONE", "None", " none "]) {
   expect(highlightName(value)).toBe("");
  }
 });

 test("a real colour is kept, trimmed and lower-cased to match the --highlight-<name> tokens", () => {
  expect(highlightName("red")).toBe("red");
  expect(highlightName(" Cyan ")).toBe("cyan");
 });

 test("Repeater tab colours treat none as no colour and fall through to the group", () => {
  const groups = [{ id: "g", color: "green" }];
  expect(tabColour({ color: "none", groupId: "g" }, groups)).toEqual({ color: "green", from: "group" });
  expect(tabColour({ color: "NONE" }, groups)).toEqual({ color: "", from: undefined });
  expect(tabColour({ groupId: "g" }, [{ id: "g", color: "None" }])).toEqual({ color: "", from: undefined });
 });

 test("Collaborator's annotation border is absent for any spelling of none", () => {
  expect(highlightBorderStyle("NONE")).toBeUndefined();
  expect(highlightBorderStyle("Red")).toEqual({ borderLeft: "3px solid var(--highlight-red, var(--accent))" });
 });
});
