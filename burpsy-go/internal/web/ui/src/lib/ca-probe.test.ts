import { describe, expect, test } from "bun:test";
import { probeCaCert } from "./data.policy";

// burpsy-react-ui-bntf: no request reaches /ca.crt unless the server says a CA is configured.
describe("probeCaCert", () => {
 test("no CA configured: /ca.crt is never requested and the server's hint is the detail", async () => {
  let heads = 0;
  const state = await probeCaCert(
   async () => ({ configured: false, hint: "TLS interception is off, so there is no signing CA." }),
   async () => {
    heads++;
    return { ok: false, status: 404 };
   },
  );
  expect(heads).toBe(0);
  expect(state).toEqual({ available: false, detail: "TLS interception is off, so there is no signing CA." });
 });

 test("no CA and no hint still says why", async () => {
  const state = await probeCaCert(
   async () => ({ configured: false }),
   async () => ({ ok: true, status: 200 }),
  );
  expect(state.available).toBe(false);
  expect(state.detail).toContain("-intercept-tls");
 });

 test("configured CA: the route is confirmed before a download is offered", async () => {
  let heads = 0;
  const state = await probeCaCert(
   async () => ({ configured: true }),
   async () => {
    heads++;
    return { ok: true, status: 200 };
   },
  );
  expect(heads).toBe(1);
  expect(state).toEqual({ available: true, detail: "" });
 });

 test("configured CA but the route disagrees: reported, not offered", async () => {
  const state = await probeCaCert(
   async () => ({ configured: true }),
   async () => ({ ok: false, status: 500 }),
  );
  expect(state.available).toBe(false);
  expect(state.detail).toContain("500");
 });

 test("a failed status read is an error, not a silent 'no CA'", async () => {
  await expect(
   probeCaCert(
    async () => {
     throw new Error("status unavailable");
    },
    async () => ({ ok: true, status: 200 }),
   ),
  ).rejects.toThrow("status unavailable");
 });
});
