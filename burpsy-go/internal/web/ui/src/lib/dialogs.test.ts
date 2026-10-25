// The dialog channel's settle rules (burpsy-react-ui-bea3). The host is a thin renderer; what a
// cancel resolves to, what a blank field blocks, and the order two requests are shown in all live
// here, and each is the difference between a working dialog and a silently wrong one.
import { beforeAll, describe, expect, test } from "bun:test";
import {
 confirmDialog,
 currentDialog,
 dismissDialog,
 formDialog,
 initialValues,
 promptDialog,
 setDialogScheduler,
 submitBlocker,
 type PromptRequest,
} from "./dialogs";

beforeAll(() => setDialogScheduler((fn) => fn()));

describe("settling", () => {
 test("a confirm resolves true on confirm and false on dismissal", async () => {
  const yes = confirmDialog({ title: "Delete?", confirmLabel: "Delete" });
  currentDialog()!.settle(true);
  expect(await yes).toBe(true);

  const no = confirmDialog({ title: "Delete?", confirmLabel: "Delete" });
  dismissDialog(currentDialog()!);
  expect(await no).toBe(false);
  expect(currentDialog()).toBeUndefined();
 });

 test("a dismissed prompt resolves null, never the empty string", async () => {
  // "" is a real answer (clear the comment); a cancel that looked like it would wipe the note.
  const answer = promptDialog({ title: "Comment", label: "Comment", confirmLabel: "Save", allowEmpty: true });
  dismissDialog(currentDialog()!);
  expect(await answer).toBeNull();
 });

 test("a prompt resolves the typed value", async () => {
  const answer = promptDialog({ title: "Rename", label: "Name", confirmLabel: "Rename", initial: "old" });
  currentDialog()!.settle("new name");
  expect(await answer).toBe("new name");
 });

 test("a form resolves its values, or null when dismissed", async () => {
  const answer = formDialog({
   title: "Record",
   confirmLabel: "Record",
   fields: [{ id: "name", label: "Name", kind: "text", required: true }],
  });
  currentDialog()!.settle({ name: "XSS" });
  expect(await answer).toEqual({ name: "XSS" });

  const cancelled = formDialog({ title: "Record", confirmLabel: "Record", fields: [] });
  dismissDialog(currentDialog()!);
  expect(await cancelled).toBeNull();
 });

 test("a second request waits behind the first and is shown after it settles", async () => {
  const first = confirmDialog({ title: "First", confirmLabel: "OK first" });
  const second = confirmDialog({ title: "Second", confirmLabel: "OK second" });
  expect(currentDialog()!.request.title).toBe("First");
  currentDialog()!.settle(true);
  expect(currentDialog()!.request.title).toBe("Second");
  currentDialog()!.settle(false);
  expect(await first).toBe(true);
  expect(await second).toBe(false);
 });

 test("settling twice resolves once and does not drop the next dialog", async () => {
  const first = confirmDialog({ title: "First", confirmLabel: "Go" });
  const pending = currentDialog()!;
  const second = confirmDialog({ title: "Second", confirmLabel: "Go" });
  pending.settle(true);
  pending.settle(false); // a double click on Confirm
  expect(currentDialog()!.request.title).toBe("Second");
  expect(await first).toBe(true);
  dismissDialog(currentDialog()!);
  expect(await second).toBe(false);
 });

 test("each dialog gets a fresh serial, so the host never carries a draft across", () => {
  void confirmDialog({ title: "A", confirmLabel: "A" });
  const a = currentDialog()!;
  a.settle(false);
  void confirmDialog({ title: "B", confirmLabel: "B" });
  const b = currentDialog()!;
  expect(b.serial).toBeGreaterThan(a.serial);
  b.settle(false);
 });
});

describe("what blocks a submit", () => {
 const prompt: PromptRequest = { kind: "prompt", title: "Rename", label: "Project name", confirmLabel: "Rename" };

 test("a blank prompt is blocked unless the caller allows empty", () => {
  expect(submitBlocker(prompt, { value: "   " })).toBe("Project name must not be blank");
  expect(submitBlocker({ ...prompt, allowEmpty: true }, { value: "" })).toBeNull();
  expect(submitBlocker(prompt, { value: "engagement" })).toBeNull();
 });

 test("a required form field is blocked when blank, and a select must hold a listed value", () => {
  const form = {
   kind: "form" as const,
   title: "Record an issue",
   confirmLabel: "Record",
   fields: [
    { id: "name", label: "Name", kind: "text" as const, required: true },
    { id: "severity", label: "Severity", kind: "select" as const, options: [{ value: "low", label: "Low" }] },
   ],
  };
  expect(submitBlocker(form, { name: "", severity: "low" })).toBe("Name is required");
  expect(submitBlocker(form, { name: "XSS", severity: "hihg" })).toBe("Severity must be one of the listed values");
  expect(submitBlocker(form, { name: "XSS", severity: "low" })).toBeNull();
 });

 test("initial values: a prompt seeds its value, a select defaults to its first option", () => {
  expect(initialValues({ ...prompt, initial: "x" })).toEqual({ value: "x" });
  expect(
   initialValues({
    kind: "form",
    title: "t",
    confirmLabel: "c",
    fields: [
     {
      id: "s",
      label: "S",
      kind: "select",
      options: [
       { value: "a", label: "A" },
       { value: "b", label: "B" },
      ],
     },
     { id: "t", label: "T", kind: "text" },
    ],
   }),
  ).toEqual({ s: "a", t: "" });
 });
});
