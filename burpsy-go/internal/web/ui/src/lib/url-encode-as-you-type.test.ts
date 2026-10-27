// URL-encode as you type (burpsy-react-ui-js1): the key-character set the mode reuses.
//
// The DOM half (typing & and seeing %26 land under the cursor, keystrokes only, persistence) is pinned
// by rendering the editor: ui/editor-url-encode.test.tsx (vln1).
import { describe, expect, test } from "bun:test";
import { urlEncodeKeyChars } from "./transforms";

describe("the key-character set the mode reuses", () => {
 test("encodes the characters that change a request's structure, and leaves prose readable", () => {
  expect(urlEncodeKeyChars("a=b&c")).toBe("a%3Db%26c");
  expect(urlEncodeKeyChars("hello world")).toBe("hello%20world");
  expect(urlEncodeKeyChars("/api/v2/users")).toBe("%2Fapi%2Fv2%2Fusers");
 });

 test("the percent itself is a key character — typing %41 encodes the % so the literal survives", () => {
  expect(urlEncodeKeyChars("%41")).toBe("%2541");
 });
});
