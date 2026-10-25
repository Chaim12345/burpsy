import { describe, expect, test } from "bun:test";
import { describeTarget, sameTarget, targetFromDraft, targetOf, targetScheme } from "./intercept-target";

describe("describeTarget", () => {
 test("spells the authority the way the held-message table does, so a row and the header bar name the same destination", () => {
  expect(describeTarget({ host: "example.test", port: 443, tls: true })).toBe("example.test:443 (tls)");
  expect(describeTarget({ host: "example.test", port: 80, tls: false })).toBe("example.test:80");
 });
});

describe("targetFromDraft", () => {
 test("accepts a host and a port and carries the scheme through unchanged", () => {
  expect(targetFromDraft("other.test", "8443", true)).toEqual({
   ok: true,
   target: { host: "other.test", port: 8443, tls: true },
  });
 });

 test("trims the host rather than dialling a name with a trailing space in it", () => {
  expect(targetFromDraft("  other.test  ", " 8080 ", false)).toEqual({
   ok: true,
   target: { host: "other.test", port: 8080, tls: false },
  });
 });

 test("keeps an IPv6 literal whole, because its colons are the address and not a port separator", () => {
  expect(targetFromDraft("[::1]", "8080", false)).toEqual({
   ok: true,
   target: { host: "[::1]", port: 8080, tls: false },
  });
 });

 test("refuses a blank host, naming the consequence instead of the field", () => {
  const result = targetFromDraft("   ", "80", false);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error("expected a refusal");
  expect(result.error).toMatch(/local machine/);
 });

 test("refuses a pasted URL rather than sending its path as part of the Host header", () => {
  for (const host of ["other.test/", "other.test /admin", "other.test /admin"]) {
   expect(targetFromDraft(host, "80", false).ok).toBe(false);
  }
 });

 test("refuses port 0 and port 65536, which the engine would refuse with its own sentence", () => {
  expect(targetFromDraft("other.test", "0", false).ok).toBe(false);
  expect(targetFromDraft("other.test", "65536", false).ok).toBe(false);
 });

 test("refuses a blank port rather than defaulting to one, because the default would be a guess", () => {
  const result = targetFromDraft("other.test", "", false);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error("expected a refusal");
  expect(result.error).toMatch(/443 for https/);
 });

 test("refuses a port that is not a whole number", () => {
  for (const port of ["8080.5", "http", "-1", "8 0 8 0"]) {
   expect(targetFromDraft("other.test", port, false).ok).toBe(false);
  }
 });

 test("accepts the boundary ports a socket can actually take", () => {
  expect(targetFromDraft("other.test", "1", false)).toEqual({
   ok: true,
   target: { host: "other.test", port: 1, tls: false },
  });
  expect(targetFromDraft("other.test", "65535", false)).toEqual({
   ok: true,
   target: { host: "other.test", port: 65535, tls: false },
  });
 });
});

describe("sameTarget", () => {
 test("treats a change to any one of the three parts as a different destination", () => {
  const base = { host: "example.test", port: 80, tls: false };
  expect(sameTarget(base, { ...base })).toBe(true);
  expect(sameTarget(base, { ...base, host: "other.test" })).toBe(false);
  expect(sameTarget(base, { ...base, port: 443 })).toBe(false);
  expect(sameTarget(base, { ...base, tls: true })).toBe(false);
 });
});

describe("targetOf", () => {
 test("carries the row's own scheme, so opening the editor and forwarding cannot silently downgrade https", () => {
  expect(targetOf({ host: "example.test", port: 443, tls: true })).toEqual({
   host: "example.test",
   port: 443,
   tls: true,
  });
 });
});

describe("targetScheme", () => {
 test("spells the scheme a retarget would use, so the page can say what (tls) means", () => {
  expect(targetScheme({ host: "a.test", port: 443, tls: true })).toBe("https");
  expect(targetScheme({ host: "a.test", port: 80, tls: false })).toBe("http");
 });
});
