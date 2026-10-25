import { describe, expect, test } from "bun:test";
import { decodedMarker, messageReading } from "./message-decoded";

const RAW = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n\u001f�\b\u0000";
const DECODED = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n<html>hello</html>";

describe("a stored message's reading", () => {
 test("a decodable message reads decoded by default, marked as such", () => {
  const reading = messageReading({ text: RAW, decoded: DECODED, content_encoding: "gzip" }, false);
  expect(reading).toEqual({ text: DECODED, decoded: true, canDecode: true, encoding: "gzip", decodeError: undefined });
  expect(decodedMarker(reading.encoding)).toBe("decoded view (Content-Encoding: gzip)");
 });

 test("the operator can switch back to the captured bytes", () => {
  const reading = messageReading({ text: RAW, decoded: DECODED, content_encoding: "gzip" }, true);
  expect(reading.text).toBe(RAW);
  expect(reading.decoded).toBe(false);
  expect(reading.canDecode).toBe(true);
 });

 test("a failed decode shows the captured bytes and carries the reason", () => {
  const reading = messageReading({ text: RAW, content_encoding: "br", decode_error: 'no decoder for Content-Encoding "br"' }, false);
  expect(reading.text).toBe(RAW);
  expect(reading.decoded).toBe(false);
  expect(reading.canDecode).toBe(false);
  expect(reading.encoding).toBe("br");
  expect(reading.decodeError).toBe('no decoder for Content-Encoding "br"');
 });

 test("an uncompressed message is just its text, with nothing to mark", () => {
  const reading = messageReading({ text: "GET / HTTP/1.1\r\n\r\n" }, false);
  expect(reading).toEqual({ text: "GET / HTTP/1.1\r\n\r\n", decoded: false, canDecode: false, encoding: undefined, decodeError: undefined });
 });

 test("an empty decoded body is still a decoded rendering, not an absence", () => {
  const reading = messageReading({ text: RAW, decoded: "", content_encoding: "gzip" }, false);
  expect(reading.decoded).toBe(true);
  expect(reading.text).toBe("");
 });
});
