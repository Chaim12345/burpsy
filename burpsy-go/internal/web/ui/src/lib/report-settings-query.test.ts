import { describe, expect, test } from "bun:test";
import { DEFAULT_REPORT_SETTINGS, reportSettingsQuery } from "../ui/report-settings-dialog";

describe("reportSettingsQuery", () => {
 test("the XML export is told 'none' explicitly, because unstated means full for it", () => {
  const settings = { ...DEFAULT_REPORT_SETTINGS, messageMode: "none" as const };
  expect(new URLSearchParams(reportSettingsQuery(settings, "xml")).get("message_mode")).toBe("none");
 });
 test("the HTML export's default stays out of the query", () => {
  const settings = { ...DEFAULT_REPORT_SETTINGS, messageMode: "none" as const };
  expect(new URLSearchParams(reportSettingsQuery(settings, "html")).has("message_mode")).toBe(false);
 });
});
