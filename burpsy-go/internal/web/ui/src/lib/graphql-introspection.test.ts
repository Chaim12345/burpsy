import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
 INTROSPECTION_QUERY,
 LEGACY_INTROSPECTION_QUERY,
 graphqlPlacement,
 isIntrospectionAnswer,
 setGraphQLQuery,
} from "./graphql-introspection";
import { parseMessage } from "./message";

describe("Burp's introspection documents (burpsy-react-ui-7v1e)", () => {
 test("are the decompiled burp.Zu6 strings, byte for byte", () => {
  // Fingerprints of the two literals as extracted from out/deobf_merged/burp/Zu6.java (lines 79-80).
  // A hand edit that "tidies" either document changes what the server is asked and fails here.
  const sha = (text: string) => createHash("sha256").update(text).digest("hex");
  expect(INTROSPECTION_QUERY.length).toBe(1310);
  expect(sha(INTROSPECTION_QUERY)).toBe("56ee230a295b9d7900b9965cfc3d8baf25c4c689dae1c75b7c7d44282e35115f");
  expect(LEGACY_INTROSPECTION_QUERY.length).toBe(1301);
  expect(sha(LEGACY_INTROSPECTION_QUERY)).toBe("4ac5e1a9778bcc80935f25a715d530bdee30d6ae3635db856f84b62782bb44e1");
 });

 test("the legacy variant is the one without subscriptionType and with the onOperation flags", () => {
  expect(INTROSPECTION_QUERY).toContain("subscriptionType");
  expect(INTROSPECTION_QUERY).toContain("locations");
  expect(LEGACY_INTROSPECTION_QUERY).not.toContain("subscriptionType");
  expect(LEGACY_INTROSPECTION_QUERY).toContain("onOperation\n            onFragment\n            onField");
 });
});

describe("setGraphQLQuery", () => {
 test("a JSON body keeps its other members, gets the query, empty variables, and a true Content-Length", () => {
  const body = '{"query":"{ me { id } }","variables":{"x":1},"operationName":"Me","extensions":{"a":1}}';
  const raw = `POST /graphql HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
  expect(graphqlPlacement(raw)).toBe("body");
  const next = setGraphQLQuery(raw, INTROSPECTION_QUERY);
  const parsed = JSON.parse(parseMessage(next).body);
  expect(parsed.query).toBe(INTROSPECTION_QUERY);
  expect(parsed.variables).toEqual({});
  expect(parsed.operationName).toBe("IntrospectionQuery");
  expect(parsed.extensions).toEqual({ a: 1 });
  const length = new TextEncoder().encode(parseMessage(next).body).length;
  expect(next).toContain(`Content-Length: ${length}\r\n`);
  expect(next.startsWith("POST /graphql HTTP/1.1\r\nHost: h\r\n")).toBe(true);
 });

 test("a GET carrying ?query= is rewritten in the URL, other parameters kept", () => {
  const raw = "GET /graphql?query=%7Bme%7D&debug=1 HTTP/1.1\r\nHost: h\r\n\r\n";
  expect(graphqlPlacement(raw)).toBe("url");
  const next = setGraphQLQuery(raw, LEGACY_INTROSPECTION_QUERY);
  const line = next.split("\r\n")[0]!;
  expect(line.startsWith("GET /graphql?")).toBe(true);
  expect(line.endsWith(" HTTP/1.1")).toBe(true);
  const params = new URLSearchParams(line.split(" ")[1]!.split("?")[1]);
  expect(params.get("query")).toBe(LEGACY_INTROSPECTION_QUERY);
  expect(params.get("debug")).toBe("1");
  expect(next.endsWith("\r\nHost: h\r\n\r\n")).toBe(true);
 });

 test("a POST with no GraphQL anywhere gets a JSON body and a Content-Type", () => {
  const raw = "POST /api HTTP/1.1\r\nHost: h\r\n\r\n";
  const next = setGraphQLQuery(raw, INTROSPECTION_QUERY);
  expect(next).toContain("Content-Type: application/json\r\n");
  expect(JSON.parse(parseMessage(next).body).query).toBe(INTROSPECTION_QUERY);
 });

 test("a bare GET gets the query as a URL parameter", () => {
  expect(graphqlPlacement("GET /graphql HTTP/1.1\r\nHost: h\r\n\r\n")).toBe("url");
 });
});

describe("isIntrospectionAnswer", () => {
 test("data.__schema is the test; errors alone and other JSON are not", () => {
  expect(isIntrospectionAnswer('HTTP/1.1 200 OK\r\n\r\n{"data":{"__schema":{"types":[]}}}')).toBe(true);
  expect(isIntrospectionAnswer('HTTP/1.1 200 OK\r\n\r\n{"errors":[{"message":"no"}]}')).toBe(false);
  expect(isIntrospectionAnswer("HTTP/1.1 200 OK\r\n\r\n<html>")).toBe(false);
 });
});
