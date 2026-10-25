/** burpsy-react-ui-vlrh: settings forms validate through zod schemas instead of hand Number() calls. */
import { describe, expect, test } from "bun:test";
import { autoBackupSchema, backupNowSchema, probeSchema, wholeNumber } from "./form-schemas";

const messages = (result: { success: boolean; error?: { issues: { message: string }[] } }) => result.error?.issues.map((issue) => issue.message) ?? [];

describe("wholeNumber", () => {
  test("parses digits, with surrounding space", () => {
    expect(wholeNumber("a number").parse(" 42 ")).toBe(42);
    expect(wholeNumber("a number").parse("-1")).toBe(-1);
  });
  test.each(["", "  ", "4.5", "1e3", "abc", "0x10", "NaN"])("rejects %j", (text) => {
    expect(wholeNumber("a number").safeParse(text).success).toBe(false);
  });
});

describe("probeSchema", () => {
  test("a host and a port", () => {
    expect(probeSchema.parse({ host: " api.example.com ", port: "443", tls: true })).toEqual({ host: "api.example.com", port: 443, tls: true });
  });
  test("a missing host and a bad port each say what is missing", () => {
    const result = probeSchema.safeParse({ host: " ", port: "0", tls: true });
    expect(result.success).toBe(false);
    expect(messages(result)).toEqual(["Enter a host", "Enter a port between 1 and 65535"]);
  });
  test("a port above 65535 is refused", () => {
    expect(probeSchema.safeParse({ host: "a", port: "70000", tls: false }).success).toBe(false);
  });
});

describe("backupNowSchema", () => {
  test("blank directory and retention mean the server defaults", () => {
    expect(backupNowSchema.parse({ dir: "  ", retention: "" })).toEqual({ dir: undefined, retention: undefined });
  });
  test("retention -1 never prunes; below that is refused", () => {
    expect(backupNowSchema.parse({ dir: "/b", retention: "-1" })).toEqual({ dir: "/b", retention: -1 });
    expect(backupNowSchema.safeParse({ dir: "", retention: "-2" }).success).toBe(false);
  });
  test("retention 0 keeps the server default, as the old Number(x) || undefined did", () => {
    expect(backupNowSchema.parse({ dir: "", retention: "0" }).retention).toBeUndefined();
  });
});

describe("autoBackupSchema", () => {
  test("interval is whole minutes, 0 is off", () => {
    expect(autoBackupSchema.parse({ interval: "0", dir: "", retention: "7" })).toEqual({ interval_minutes: 0, dir: "", retention: 7 });
    expect(messages(autoBackupSchema.safeParse({ interval: "1.5", dir: "", retention: "7" }))).toEqual([
      "The backup interval must be a whole number of minutes (0 turns it off).",
    ]);
    expect(autoBackupSchema.safeParse({ interval: "-5", dir: "", retention: "7" }).success).toBe(false);
  });
  test("a blank or zero retention saves as 0, as before", () => {
    expect(autoBackupSchema.parse({ interval: "5", dir: " /x ", retention: "" })).toEqual({ interval_minutes: 5, dir: "/x", retention: 0 });
  });
});
