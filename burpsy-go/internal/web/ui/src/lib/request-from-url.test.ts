import { describe, expect, test } from "bun:test";
import { requestFromUrl } from "./api";

/**
 * Burp's "Paste host / URL as request" (burpsy-react-ui-ce8): a URL from a ticket, a report or a
 * browser bar becomes a working Repeater tab instead of four hand-edits on an example.com template.
 *
 * The load-bearing invariant is the one these tests spend most of their assertions on: `target` is
 * always http:// or https://, whatever the operator pasted. The server parses it with targetParts
 * (internal/web/api_types.go), which knows http, https and no scheme and answers 400 on anything
 * else — so a ws:// target would build a tab whose first Send fails with a message about a scheme
 * the operator never typed into the target field. `protocol` is where the transport lives.
 */
describe("requestFromUrl", () => {
 test("a bare host defaults to https:443, the rest of the UI's convention", () => {
  const built = requestFromUrl("shop.test");
  expect(built).not.toBeNull();
  expect(built!.target).toBe("https://shop.test");
  expect(built!.protocol).toBe("https");
  expect(built!.request).toContain("Host: shop.test");
  expect(built!.request.split("\r\n")[0]).toBe("GET / HTTP/1.1");
 });

 test("an explicit port is kept in both the target and the Host header", () => {
  const built = requestFromUrl("shop.test:8080");
  expect(built!.target).toBe("https://shop.test:8080");
  expect(built!.request).toContain("Host: shop.test:8080");
 });

 test("http:// means http, and the path survives", () => {
  const built = requestFromUrl("http://shop.test/catalog?id=1");
  expect(built!.protocol).toBe("http");
  expect(built!.target).toBe("http://shop.test");
  expect(built!.request.split("\r\n")[0]).toBe("GET /catalog?id=1 HTTP/1.1");
 });

 test("a ws:// URL becomes an upgrade handshake carried over http — not a ws:// target", () => {
  const built = requestFromUrl("ws://shop.test:9001/socket");
  expect(built).not.toBeNull();
  // The bug this pins: `target` used to carry the pasted scheme, and targetParts answers
  // 400 "unknown scheme \"ws\"" on it, so the tab could never send.
  expect(built!.target).toBe("http://shop.test:9001");
  expect(built!.protocol).toBe("http");
  expect(built!.request).toContain("Upgrade: websocket");
  expect(built!.request).toContain("Sec-WebSocket-Version: 13");
  expect(built!.request).toContain("Host: shop.test:9001");
 });

 test("wss:// is the same handshake over https", () => {
  const built = requestFromUrl("wss://shop.test/socket");
  expect(built!.target).toBe("https://shop.test");
  expect(built!.protocol).toBe("https");
  expect(built!.request).toContain("Upgrade: websocket");
 });

 test("a scheme the transport cannot carry is refused here, not three clicks later on Send", () => {
  expect(requestFromUrl("ftp://files.test/pub")).toBeNull();
  expect(requestFromUrl("file:///etc/passwd")).toBeNull();
  expect(requestFromUrl("chrome-extension://abc/page.html")).toBeNull();
 });

 test("nothing that can name an origin means null, not a tab pointed at nowhere", () => {
  expect(requestFromUrl("")).toBeNull();
  expect(requestFromUrl("   ")).toBeNull();
  expect(requestFromUrl("http://")).toBeNull();
  expect(requestFromUrl("two words")).toBeNull();
 });
});
