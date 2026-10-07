import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { editableBodyBase64, requestTargetPath } from "./message";

// burpsy-react-ui-3pco: a loaded .proto names protobuf fields — but only in an editor that can hold the
// body byte-exact, because a binary body's `text` arrives already mangled and the Protobuf tab never
// appears. So "covers the full surface" is a property of every pane, and this pins it for every pane.

const pages = join(import.meta.dir, "..", "pages");

/** Every <HttpEditor ... /> block in the console's pages, with the file it is in. */
function editorBlocks(): { file: string; block: string }[] {
 const out: { file: string; block: string }[] = [];
 for (const name of readdirSync(pages).filter((n) => n.endsWith(".tsx"))) {
  const text = readFileSync(join(pages, name), "utf8");
  for (const m of text.matchAll(/<HttpEditor\b[\s\S]*?\/>/g)) out.push({ file: name, block: m[0] });
 }
 return out;
}

describe("every editor showing a stored message carries its body bytes", () => {
 const blocks = editorBlocks();

 test("the scan found the editors, not a fragment of them", () => {
  // A floor, so a scan that silently matched nothing cannot pass the check below.
  expect(blocks.length).toBeGreaterThan(25);
 });

 test("a pane whose value is a stored MessageView's text also passes its body_base64", () => {
  // `X.data?.text` is the signature of a stored message (useMessage/useResource over /api/message).
  // Such a pane must pass bodyBase64 too, or real gRPC traffic there has no Protobuf tab at all.
  // views={false} panes render no typed tabs, so they are exempt.
  const missing = blocks
   .filter(({ block }) => /\.data\??\.text\b/.test(block) && !/views=\{false\}/.test(block))
   .filter(({ block }) => !/bodyBase64=/.test(block))
   .map(({ file, block }) => `${file}: ${/label=\{?["`]?([^"`}\n]*)/.exec(block)?.[1] ?? block.slice(0, 60)}`);
  expect(missing).toEqual([]);
 });

 test("a response pane over a stored exchange names its request path, so gRPC resolves the reply type", () => {
  const missing = blocks
   .filter(({ block }) => /label="Response"/.test(block) && /response\.data\??\.text|savedResponse\.data\??\.text/.test(block))
   .filter(({ block }) => !/requestPath=/.test(block))
   .map(({ file }) => file);
  expect(missing).toEqual([]);
 });
});

describe("requestTargetPath", () => {
 test("reads the path off a request line, origin- or absolute-form", () => {
  expect(requestTargetPath("POST /acme.v1.Users/Get HTTP/2\r\n\r\n")).toBe("/acme.v1.Users/Get");
  expect(requestTargetPath("POST https://api.example/acme.v1.Users/Get HTTP/1.1\r\n\r\n")).toBe("/acme.v1.Users/Get");
 });
 test("is undefined for a response or anything that is not a request", () => {
  expect(requestTargetPath("HTTP/1.1 200 OK\r\n\r\n")).toBeUndefined();
  expect(requestTargetPath("")).toBeUndefined();
 });
});

describe("editableBodyBase64 — only a plain wire body may back an editable surface", () => {
 const b64 = btoa("\x08\x96\x01");
 test("a plain binary body is carried", () => {
  expect(editableBodyBase64({ text: "POST / HTTP/1.1\r\n\r\n?", body_base64: b64 })).toBe(b64);
 });
 test("a Content-Encoded body is not: head + decoded bytes would resend under a gzip head", () => {
  expect(editableBodyBase64({ text: "POST / HTTP/1.1\r\n\r\n?", body_base64: b64, content_encoding: "gzip" })).toBeUndefined();
  expect(editableBodyBase64({ text: "POST / HTTP/1.1\r\n\r\n?", body_base64: b64, content_encoding: "identity" })).toBe(b64);
 });
 test("a chunked body is not, for the same reason", () => {
  expect(editableBodyBase64({ text: "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n?", body_base64: b64 })).toBeUndefined();
 });
 test("no body_base64 means nothing to carry", () => {
  expect(editableBodyBase64({ text: "POST / HTTP/1.1\r\n\r\nhi" })).toBeUndefined();
 });
});

describe("the editable surfaces resend binary bodies byte-exact", () => {
 const intercept = readFileSync(join(pages, "intercept.tsx"), "utf8");
 const actions = readFileSync(join(import.meta.dir, "actions.ts"), "utf8");

 test("intercept forwards a protobuf edit as raw_base64 and an unedited message without raw", () => {
  expect(intercept).toMatch(/rawBase64: faithfulRequestBase64\(body, rawBodyBase64\)/);
  // A bulk forward must not send target.raw back: for a binary body that is the mangled text.
  expect(intercept).not.toMatch(/raw: target\.raw/);
 });

 test("send-to-Repeater carries only an editable (plain wire) body", () => {
  expect(actions).toMatch(/requestBodyBase64: editableBodyBase64\(message\)/);
 });
});
