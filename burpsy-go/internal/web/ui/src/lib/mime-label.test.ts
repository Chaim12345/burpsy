// How an empty MIME renders, pinned as a function.
//
// The History and Sitemap MIME columns were shipped against `Exchange.mime`, which nothing on the
// wire ever set — so the column was blank on every row and the type filter emptied the table for
// every value an operator could pick. The Go side now populates it (core.Exchange.Mime,
// core.MimeEssence), and this pins the part of the fix that is a presentation decision: "" is two
// different facts and must not render as one glyph.
import { expect, test, describe } from "bun:test";
import { mimeLabel } from "./api";

describe("mimeLabel", () => {
  test("a media type renders as itself", () => {
    expect(mimeLabel({ mime: "text/html", response: 7 })).toBe("text/html");
    expect(mimeLabel({ mime: "application/json", response: 0 })).toBe("application/json");
  });

  test("response 0 is a real response, not an absent one", () => {
    // Message ids are dense from zero, so `response: 0` is a legitimate id and must not be read as
    // falsy. This is the same trap core.ExchangeID documents on the Go side; getting it wrong here
    // would label the very first captured exchange as having no response.
    expect(mimeLabel({ mime: "", response: 0 })).toBe("untyped");
  });

  test("no response at all reads as an em dash, matching every other not-applicable cell", () => {
    expect(mimeLabel({ mime: "", response: null })).toBe("—");
  });

  test("a response that declared no Content-Type says so in a word", () => {
    // The distinction the whole helper exists for: this row and the one above both carry mime "",
    // and rendering them identically is what made a blank column unreadable.
    expect(mimeLabel({ mime: "", response: 12 })).toBe("untyped");
    expect(mimeLabel({ mime: "", response: null })).not.toBe(mimeLabel({ mime: "", response: 12 }));
  });

  test("an absent mime field is treated as an empty one, not as undefined leaking into the cell", () => {
    // The field is required on the wire, but the parameter is structural and the CSV's row type still
    // has it optional — so a caller passing a row without it must not render "undefined".
    expect(mimeLabel({ response: 3 })).toBe("untyped");
    expect(mimeLabel({ response: null })).toBe("—");
  });
});
