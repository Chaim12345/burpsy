/**
 * Tests for body-encoding.ts — Burp's "Change body encoding" (burpsy-react-ui-wv5).
 * Run with `bun test src/lib` from internal/web/ui.
 *
 * The assertions are on WHOLE messages, for the reason message.test.ts gives:
 * what leaves this function goes over the wire, so "Content-Type now says JSON"
 * is not the claim worth checking. The claims worth checking are that every
 * parameter survived, in order, that Content-Length still describes the body,
 * and that a conversion that cannot be made faithfully produces no message at
 * all rather than a half-converted one.
 */

import { describe, expect, test } from "bun:test";
import { BODY_ENCODING_LABELS, changeBodyEncoding, detectBodyEncoding, type BodyEncoding } from "./body-encoding";
import { byteLength, headerValue, parseMessage } from "./message";

/** The literal the multipart writer starts from, so the expected bytes are spelled out here too. */
const BOUNDARY = "----burpsyBodyEncoding";

const message = (contentType: string, body: string): string =>
  [`POST /login HTTP/1.1`, `Host: shop.example`, `Content-Type: ${contentType}`, `Content-Length: ${byteLength(body)}`, ``, body].join("\r\n");

const FORM_BODY = "user=alice&pass=s3cr%3Ft";
const FORM = message("application/x-www-form-urlencoded", FORM_BODY);

const JSON_BODY = '{"user":"alice","pass":"s3cr?t"}';
const JSON_MESSAGE = message("application/json", JSON_BODY);

const MULTIPART_BODY =
  `--${BOUNDARY}\r\nContent-Disposition: form-data; name="user"\r\n\r\nalice\r\n` +
  `--${BOUNDARY}\r\nContent-Disposition: form-data; name="pass"\r\n\r\ns3cr?t\r\n` +
  `--${BOUNDARY}--\r\n`;
const MULTIPART = message(`multipart/form-data; boundary=${BOUNDARY}`, MULTIPART_BODY);

/** The converted message, or a failure whose reason is shown when the conversion was expected to work. */
function converted(raw: string, target: BodyEncoding): string {
  const result = changeBodyEncoding(raw, target);
  if (!result.ok) throw new Error(`expected a conversion to ${target}, got a refusal: ${result.reason}`);
  return result.raw;
}

/** The refusal reason, or a failure when the conversion went through and should not have. */
function refusal(raw: string, target: BodyEncoding): string {
  const result = changeBodyEncoding(raw, target);
  if (result.ok) throw new Error(`expected a refusal converting to ${target}, but a message came back:\n${result.raw}`);
  return result.reason;
}

describe("the encoding is read from Content-Type, never sniffed", () => {
  test("each of the three types is recognised, including a +json suffix type", () => {
    expect(detectBodyEncoding(FORM)).toBe("urlencoded");
    expect(detectBodyEncoding(MULTIPART)).toBe("multipart");
    expect(detectBodyEncoding(JSON_MESSAGE)).toBe("json");
    expect(detectBodyEncoding(message("application/vnd.api+json", "{}"))).toBe("json");
  });

  test("a form-shaped body under text/plain is not a form, because sniffing would invent a type the operator never set", () => {
    expect(detectBodyEncoding(message("text/plain", "a=1&b=2"))).toBeNull();
    expect(refusal(message("text/plain", "a=1&b=2"), "json")).toContain("is not a form, multipart or JSON body");
  });
});

describe("form URL-encoding to JSON and back", () => {
  test("converting a form body to JSON rewrites the body, the type and the length, and nothing else", () => {
    expect(converted(FORM, "json")).toBe(
      ["POST /login HTTP/1.1", "Host: shop.example", "Content-Type: application/json", `Content-Length: ${JSON_BODY.length}`, "", JSON_BODY].join("\r\n"),
    );
  });

  test("form -> JSON -> form returns the original bytes, so nothing is lost in the pair round trip", () => {
    expect(converted(converted(FORM, "json"), "urlencoded")).toBe(FORM);
  });

  test("percent-escapes decode into the JSON value rather than riding along as literal text", () => {
    const raw = message("application/x-www-form-urlencoded", "q=a%20b%26c");
    expect(parseMessage(converted(raw, "json")).body).toBe('{"q":"a b&c"}');
  });

  test("a value holding a JSON metacharacter is escaped, not injected into the object", () => {
    const raw = message("application/x-www-form-urlencoded", "q=%22%2C%22evil%22%3A%221");
    expect(parseMessage(converted(raw, "json")).body).toBe('{"q":"\\",\\"evil\\":\\"1"}');
  });
});

describe("multipart encoding", () => {
  test("converting a form body to multipart writes one part per parameter with a deterministic boundary", () => {
    expect(converted(FORM, "multipart")).toBe(MULTIPART);
  });

  test("form -> multipart -> form returns the original bytes", () => {
    expect(converted(converted(FORM, "multipart"), "urlencoded")).toBe(FORM);
  });

  test("multipart -> JSON -> multipart returns the original bytes, because the boundary this writer picks is the one it reads back", () => {
    expect(converted(converted(MULTIPART, "json"), "multipart")).toBe(MULTIPART);
  });

  test("a boundary quoted in the Content-Type is read the same as a bare one", () => {
    const quoted = message(`multipart/form-data; boundary="${BOUNDARY}"`, MULTIPART_BODY);
    expect(parseMessage(converted(quoted, "urlencoded")).body).toBe(FORM_BODY);
  });

  test("the generated boundary is extended until it appears in no value, so the delimiter can never be forged from the data", () => {
    const raw = message("application/x-www-form-urlencoded", `note=${encodeURIComponent(`--${BOUNDARY}`)}`);
    const body = parseMessage(converted(raw, "multipart")).body;
    expect(body).toContain(`--${BOUNDARY}x\r\nContent-Disposition: form-data; name="note"\r\n\r\n--${BOUNDARY}\r\n`);
    expect(body.endsWith(`--${BOUNDARY}x--\r\n`)).toBe(true);
  });
});

describe("parameters keep their order and their number", () => {
  test("an integer-like name does not get hoisted ahead of the rest, which Object.entries would have done", () => {
    const raw = message("application/json", '{"b":"1","2":"2"}');
    expect(parseMessage(converted(raw, "urlencoded")).body).toBe("b=1&2=2");
    expect(parseMessage(converted(message("application/x-www-form-urlencoded", "b=1&2=2"), "json")).body).toBe('{"b":"1","2":"2"}');
  });

  test("a repeated parameter survives form -> multipart -> form instead of being collapsed", () => {
    const raw = message("application/x-www-form-urlencoded", "id=1&id=2&id=3");
    expect(parseMessage(converted(raw, "multipart")).body.match(/name="id"/g)).toHaveLength(3);
    expect(converted(converted(raw, "multipart"), "urlencoded")).toBe(raw);
  });
});

describe("Content-Length keeps telling the truth", () => {
  test("the declared length counts the converted body's BYTES, not its characters", () => {
    const raw = message("application/x-www-form-urlencoded", "name=caf%C3%A9");
    const next = converted(raw, "json");
    const body = parseMessage(next).body;
    expect(body).toBe('{"name":"café"}');
    expect(headerValue(parseMessage(next).headers, "content-length")).toBe(String(byteLength(body)));
    expect(byteLength(body)).not.toBe(body.length);
  });
});

describe("the declared normalisations, stated as claims rather than discovered later", () => {
  test("JSON -> form -> JSON returns every value as a string, because a form body carries no types", () => {
    const raw = message("application/json", '{"qty":2,"ok":true,"note":null}');
    expect(parseMessage(converted(raw, "urlencoded")).body).toBe("qty=2&ok=true&note=null");
    expect(parseMessage(converted(converted(raw, "urlencoded"), "json")).body).toBe('{"qty":"2","ok":"true","note":"null"}');
  });

  test("the form writer canonicalises percent-encoding, so a body written with '+' comes back with %20", () => {
    const raw = message("application/json", '{"q":"a b"}');
    expect(parseMessage(converted(raw, "urlencoded")).body).toBe("q=a%20b");
    expect(parseMessage(converted(message("application/x-www-form-urlencoded", "q=a+b"), "json")).body).toBe('{"q":"a b"}');
  });

  test("the JSON writer is compact, so a pretty-printed source body comes back without its whitespace", () => {
    const raw = message("application/json", '{\n  "a": "1"\n}');
    expect(parseMessage(converted(converted(raw, "urlencoded"), "json")).body).toBe('{"a":"1"}');
  });
});

describe("a conversion that cannot be made faithfully is refused, with a reason and no message", () => {
  test("a chunked request is refused and names the toggle that undoes the framing, rather than writing a body the framing contradicts", () => {
    const raw = ["POST /login HTTP/1.1", "Host: shop.example", "Content-Type: application/x-www-form-urlencoded", "Transfer-Encoding: chunked", "", "18\r\n" + FORM_BODY + "\r\n0\r\n\r\n"].join("\r\n");
    expect(refusal(raw, "json")).toContain("Toggle chunked transfer framing");
  });

  test("a request with no body is refused, because there is nothing to re-encode", () => {
    expect(refusal(["GET / HTTP/1.1", "Host: shop.example", "Content-Type: application/json", "", ""].join("\r\n"), "urlencoded")).toContain("no body");
  });

  test("a request with two Content-Type headers is refused rather than the first one being assumed", () => {
    const raw = ["POST /login HTTP/1.1", "Host: shop.example", "Content-Type: application/json", "Content-Type: application/x-www-form-urlencoded", `Content-Length: ${JSON_BODY.length}`, "", JSON_BODY].join("\r\n");
    expect(refusal(raw, "urlencoded")).toContain("two Content-Type headers");
  });

  test("converting to the encoding the body is already in is refused instead of rewriting it in place", () => {
    expect(refusal(FORM, "urlencoded")).toBe(`the body is already ${BODY_ENCODING_LABELS.urlencoded}`);
  });

  test("a body carrying the replacement character is refused, because the text view already lost those bytes", () => {
    expect(refusal(message("application/json", '{"a":"�"}'), "urlencoded")).toContain("could not represent");
  });

  test("a repeated parameter is refused on the way to JSON, where one of them would be dropped without a word", () => {
    const raw = message("application/x-www-form-urlencoded", "id=1&id=2");
    expect(refusal(raw, "json")).toContain('the parameter "id" appears more than once');
  });

  test("a nested JSON value is refused, because a form body has no way to express it", () => {
    expect(refusal(message("application/json", '{"user":{"name":"a"}}'), "urlencoded")).toContain("object or an array");
    expect(refusal(message("application/json", '{"ids":[1,2]}'), "multipart")).toContain("object or an array");
  });

  test("a JSON array or scalar at the top level is refused, because it has no named parameters", () => {
    expect(refusal(message("application/json", '["a","b"]'), "urlencoded")).toContain("top level is not an object");
    expect(refusal(message("application/json", '"a"'), "urlencoded")).toContain("top level is not an object");
  });

  test("duplicate JSON member names are refused, since JSON.parse keeps only the last and the operator wrote two", () => {
    expect(refusal(message("application/json", '{"a":"1","a":"2"}'), "urlencoded")).toContain("duplicate member names");
  });

  test("a malformed JSON body is refused rather than partly read", () => {
    expect(refusal(message("application/json", '{"a":"1"'), "urlencoded")).toContain("not valid JSON");
  });

  test("a multipart body whose Content-Type declares no boundary is refused, because its parts cannot be located", () => {
    expect(refusal(message("multipart/form-data", MULTIPART_BODY), "json")).toContain("no boundary parameter");
  });

  test("a multipart file part is refused, because a filename and a part type cannot survive into a form or JSON body", () => {
    const body =
      `--${BOUNDARY}\r\nContent-Disposition: form-data; name="avatar"; filename="a.png"\r\nContent-Type: image/png\r\n\r\nPNG\r\n--${BOUNDARY}--\r\n`;
    expect(refusal(message(`multipart/form-data; boundary=${BOUNDARY}`, body), "json")).toContain("headers beyond Content-Disposition");
  });

  test("a multipart part carrying its own Content-Type is refused even without a filename", () => {
    const body = `--${BOUNDARY}\r\nContent-Disposition: form-data; name="meta"\r\nContent-Type: application/json\r\n\r\n{}\r\n--${BOUNDARY}--\r\n`;
    expect(refusal(message(`multipart/form-data; boundary=${BOUNDARY}`, body), "urlencoded")).toContain("headers beyond Content-Disposition");
  });

  test("a multipart body with a preamble, an epilogue or no closing boundary is refused rather than silently trimmed", () => {
    const type = `multipart/form-data; boundary=${BOUNDARY}`;
    const one = `--${BOUNDARY}\r\nContent-Disposition: form-data; name="a"\r\n\r\n1\r\n`;
    expect(refusal(message(type, `preamble\r\n${one}--${BOUNDARY}--\r\n`), "json")).toContain("does not start at its first boundary");
    expect(refusal(message(type, `${one}--${BOUNDARY}--\r\nepilogue`), "json")).toContain("epilogue");
    expect(refusal(message(type, one), "json")).toContain("no closing boundary");
  });

  test("a form body with a stray '&' or a valueless parameter is refused, because neither is expressible as a pair", () => {
    expect(refusal(message("application/x-www-form-urlencoded", "a=1&&b=2"), "json")).toContain("empty parameter");
    expect(refusal(message("application/x-www-form-urlencoded", "a=1&b"), "json")).toContain("no '='");
  });

  test("a percent-escape that is not UTF-8 text is refused, rather than re-encoded into a different request", () => {
    // `q=%FF` is a deliberate raw-byte probe. message.ts's safeDecode returns it unchanged, so a
    // naive re-encode would send `q=%25FF` — the literal five characters, not the byte.
    expect(refusal(message("application/x-www-form-urlencoded", "q=%FF"), "json")).toContain("does not decode as UTF-8 text");
    expect(refusal(message("application/x-www-form-urlencoded", "q=%zz"), "multipart")).toContain("does not decode as UTF-8 text");
  });

  test("a JSON value holding an unpaired surrogate is refused rather than thrown, so the click handler never sees an exception", () => {
    const raw = message("application/json", '{"a":"\\ud800"}');
    expect(() => changeBodyEncoding(raw, "urlencoded")).not.toThrow();
    expect(refusal(raw, "urlencoded")).toContain("unpaired surrogate");
  });

  test("a Content-Disposition carrying a parameter beyond the name is refused, because the rewrite would drop it", () => {
    const body = `--${BOUNDARY}\r\nContent-Disposition: form-data; name="a"; charset="utf-8"\r\n\r\n1\r\n--${BOUNDARY}--\r\n`;
    expect(refusal(message(`multipart/form-data; boundary=${BOUNDARY}`, body), "json")).toContain("not exactly form-data with a quoted name");
  });

  test("a parameter name holding a quote is refused on the way to multipart, where the part name is quoted with no escape", () => {
    const raw = message("application/json", '{"a\\"b":"1"}');
    expect(refusal(raw, "multipart")).toContain("cannot quote");
  });
});
