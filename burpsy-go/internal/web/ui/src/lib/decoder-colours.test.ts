import { describe, expect, test } from "bun:test";
import { ALL_ENCODING_VALUES, encodingFamily, familyForValue } from "./decoder-colours";

describe("decoder colour-coding is tied to the real transform", () => {
  test("every encoding the console can send maps to a family", () => {
    for (const value of ALL_ENCODING_VALUES) {
      expect(familyForValue(value)).not.toBeNull();
    }
  });

  test("an unknown encoding returns no family rather than a fallback tint", () => {
    expect(familyForValue("rot47")).toBeNull();
    expect(familyForValue("")).toBeNull();
    expect(familyForValue("base32")).toBeNull();
  });

  test("the same encoding class shares one family across encode and decode", () => {
    expect(encodingFamily("encode", "base64", null)).toBe("base64");
    expect(encodingFamily("decode", "base64", null)).toBe("base64");
    // base64url is the URL-safe alphabet of the same class.
    expect(encodingFamily("encode", "base64url", null)).toBe("base64");
    // gzip and deflate are one compression family.
    expect(encodingFamily("decode", "gzip", null)).toBe("compress");
    expect(encodingFamily("encode", "deflate", null)).toBe("compress");
    // hex, octal and binary are one numeric-base (radix) family.
    expect(encodingFamily("decode", "hex", null)).toBe("radix");
    expect(encodingFamily("encode", "octal", null)).toBe("radix");
    expect(encodingFamily("decode", "binary", null)).toBe("radix");
    // every digest is one hash family.
    expect(encodingFamily("hash", "md5", null)).toBe("hash");
    expect(encodingFamily("hash", "sha512", null)).toBe("hash");
  });

  test("a smart decode is coloured by the layer it actually peeled, not by 'auto'", () => {
    // familyForValue("auto") is null; the colour must come from the applied layer.
    expect(familyForValue("auto")).toBeNull();
    // Output is the plaintext after the LAST layer came off, so that layer colours it.
    expect(encodingFamily("decode", "auto", ["base64", "url"])).toBe("url");
    expect(encodingFamily("decode", "auto", ["url", "base64"])).toBe("base64");
    expect(encodingFamily("decode", "auto", ["jwt"])).toBe("jwt");
  });

  test("a smart decode that detected nothing has no colour", () => {
    expect(encodingFamily("decode", "auto", [])).toBeNull();
    expect(encodingFamily("decode", "auto", null)).toBeNull();
  });
});
