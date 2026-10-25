/** burpsy-react-ui-vlrh: settings forms validate through zod schemas instead of hand Number() calls. */
import { describe, expect, test } from "bun:test";
import { autoBackupSchema, backupNowSchema, intervalHoursSchema, poolSchema, probeSchema, wholeNumber } from "./form-schemas";

const messages = (result: { success: boolean; error?: { issues: { message: string }[] } }) =>
 result.error?.issues.map((issue) => issue.message) ?? [];

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
  expect(probeSchema.parse({ host: " api.example.com ", port: "443", tls: true })).toEqual({
   host: "api.example.com",
   port: 443,
   tls: true,
  });
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

describe("poolSchema (resource pools)", () => {
 const base = { name: " api ", maxConcurrent: "10", delay: "50", throttle: true, increment: "25" };
 test("converts text to the Pool the API takes", () => {
  expect(poolSchema.parse(base)).toEqual({ name: "api", max_concurrent: 10, delay_ms: 50, throttle: { increment_ms: 25 } });
 });
 test("throttle off sends null and ignores a blank increment", () => {
  expect(poolSchema.parse({ ...base, throttle: false, increment: "" }).throttle).toBeNull();
 });
 test("a blank or zero concurrency is refused, not quietly turned into 1", () => {
  expect(poolSchema.safeParse({ ...base, maxConcurrent: "" }).success).toBe(false);
  expect(messages(poolSchema.safeParse({ ...base, maxConcurrent: "0" }))).toEqual(["Max concurrent requests must be at least 1"]);
 });
 test("a negative delay and a blank name are refused", () => {
  expect(poolSchema.safeParse({ ...base, delay: "-5" }).success).toBe(false);
  expect(poolSchema.safeParse({ ...base, name: "  " }).success).toBe(false);
 });
 test("throttling with no delay is refused, as the server does", () => {
  expect(messages(poolSchema.safeParse({ ...base, delay: "0" }))).toEqual(["Automatic throttling needs a delay above 0"]);
 });
 test("an increment of 0 is refused only while throttling is on", () => {
  expect(poolSchema.safeParse({ ...base, increment: "0" }).success).toBe(false);
  expect(poolSchema.safeParse({ ...base, throttle: false, increment: "0" }).success).toBe(true);
 });
});

describe("intervalHoursSchema (scheduled tasks)", () => {
 test("hours become whole seconds", () => {
  expect(intervalHoursSchema.parse("24")).toBe(86400);
  expect(intervalHoursSchema.parse("0.5")).toBe(1800);
 });
 test.each(["", "0", "-1", "abc", "1e2"])("refuses %j", (text) => {
  expect(intervalHoursSchema.safeParse(text).success).toBe(false);
 });
});
