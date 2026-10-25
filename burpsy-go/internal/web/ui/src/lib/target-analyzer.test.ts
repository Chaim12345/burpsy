import { describe, expect, test } from "bun:test";
import { analyzerQuery } from "./target-analyzer";

describe("analyzerQuery", () => {
  test("a branch seed carries its path and origin", () => {
    expect(analyzerQuery({ host: "shop.test", path: "/api", port: 8443, tls: true })).toBe(
      "/api/target/analyze?host=shop.test&path=%2Fapi&port=8443&tls=true",
    );
  });
  test("a host seed has no path, and the saved report asks for html", () => {
    expect(analyzerQuery({ host: "shop.test", path: "" }, "html")).toBe("/api/target/analyze?host=shop.test&format=html");
  });
});
