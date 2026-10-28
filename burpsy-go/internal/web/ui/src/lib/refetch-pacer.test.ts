import { describe, expect, test } from "bun:test";
import { createRefetchPacer } from "./refetch-pacer";

describe("createRefetchPacer", () => {
 test("a fast fetch is not delayed", async () => {
  let t = 0;
  const pace = createRefetchPacer({ now: () => t });
  await pace(async () => { t += 1; });
  const s = Date.now();
  await pace(async () => "x");
  expect(Date.now() - s).toBeLessThan(30);
 });
 test("a slow fetch makes the next one wait in proportion, from its completion", async () => {
  let t = 0;
  const pace = createRefetchPacer({ factor: 4, now: () => t });
  await pace(async () => { t += 10; });
  // cost 10 -> gap 40; 15 elapsed since completion -> waits 25ms
  t += 15;
  const s = Date.now();
  await pace(async () => "x");
  const waited = Date.now() - s;
  expect(waited).toBeGreaterThanOrEqual(20);
  expect(waited).toBeLessThan(80);
 });
 test("the wait is capped", async () => {
  let t = 0;
  const pace = createRefetchPacer({ factor: 1000, maxWaitMs: 30, now: () => t });
  await pace(async () => { t += 500; });
  const s = Date.now();
  await pace(async () => "x");
  expect(Date.now() - s).toBeLessThan(90);
 });
 test("abort during the wait rejects and does not run the fetch", async () => {
  let t = 0;
  const pace = createRefetchPacer({ factor: 100, maxWaitMs: 2000, now: () => t });
  await pace(async () => { t += 20; });
  const ac = new AbortController();
  let ran = false;
  const p = pace(async () => { ran = true; }, ac.signal);
  setTimeout(() => ac.abort(), 10);
  await expect(p).rejects.toBeDefined();
  expect(ran).toBe(false);
 });
});
