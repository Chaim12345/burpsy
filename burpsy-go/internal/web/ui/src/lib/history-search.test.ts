// The history search field's compile step (burpsy-react-ui-vlf).
//
// The modifiers used to be compiled against the DSL query box, where "Regular expression"
// turned a plain query into a pattern that matches nothing and emptied the table. The
// contract now is: a dedicated string, compiled here; empty string means no search is
// active no matter what the checkboxes hold; an invalid regex is an error, not a silent
// "no matches".
import { expect, test, describe } from "bun:test";
import { compileHistorySearch } from "./history-search";

describe("compileHistorySearch", () => {
  test("an empty field is no search, whatever the modifiers hold", () => {
    for (const regex of [false, true]) {
      for (const caseSensitive of [false, true]) {
        const { matcher, error } = compileHistorySearch("", { regex, caseSensitive });
        expect(matcher).toBeNull();
        expect(error).toBeNull();
      }
    }
  });

  test("a whitespace-only field is no search either", () => {
    const { matcher } = compileHistorySearch("   ", { regex: false, caseSensitive: false });
    expect(matcher).toBeNull();
  });

  test("plain text matches case-insensitively by default", () => {
    const { matcher, error } = compileHistorySearch("API", { regex: false, caseSensitive: false });
    expect(error).toBeNull();
    expect(matcher!("GET https://api.example.com/login")).toBe(true);
    expect(matcher!("GET https://other.example.com/")).toBe(false);
  });

  test("case sensitive matches only the exact case", () => {
    const { matcher } = compileHistorySearch("API", { regex: false, caseSensitive: true });
    expect(matcher!("GET https://api.example.com/")).toBe(false);
    expect(matcher!("GET https://API.example.com/")).toBe(true);
  });

  test("regex mode compiles the field as a pattern", () => {
    const { matcher, error } = compileHistorySearch("api.example", { regex: true, caseSensitive: false });
    expect(error).toBeNull();
    expect(matcher!("GET https://api.example.com/x")).toBe(true);
    // A dot in the input is a pattern dot, not a literal — the documented behaviour of a
    // regex search and exactly what a plain-text search must not do.
    expect(matcher!("GET https://apiXexample.com/x")).toBe(true);
  });

  test("regex mode honours the case flag", () => {
    const { matcher } = compileHistorySearch("API", { regex: true, caseSensitive: true });
    expect(matcher!("https://api.example.com")).toBe(false);
    expect(matcher!("https://API.example.com")).toBe(true);
  });

  test("an invalid regex is an error with a null matcher, not a silent no-match", () => {
    const { matcher, error } = compileHistorySearch("api(", { regex: true, caseSensitive: false });
    expect(matcher).toBeNull();
    expect(error).not.toBeNull();
  });

  test("special regex characters are literal in plain-text mode", () => {
    // The operator searched for a literal "a.b" — an unescaped pattern would be a regex the
    // field never promised. This is the case that made the old shared-input design unsafe.
    const { matcher, error } = compileHistorySearch("a.b", { regex: false, caseSensitive: false });
    expect(error).toBeNull();
    expect(matcher!("GET https://axb.example.com/")).toBe(false);
    expect(matcher!("GET https://a.b.example.com/")).toBe(true);
  });

  test("negation composes at the call site as an exact inversion", () => {
    // The page drops a row when `matcher(hay) === negate`; these are the four cells of that
    // table for one matcher, so "negative match" cannot quietly become something else.
    const { matcher } = compileHistorySearch("api", { regex: false, caseSensitive: false });
    const hit = "GET https://api.example.com/";
    const miss = "GET https://other.example.com/";
    // Negate off: keep hits, drop misses. Negate on: the exact inverse.
    expect(matcher!(hit) === false).toBe(false); // dropped
    expect(matcher!(miss) === false).toBe(true); // kept
    expect(matcher!(hit) === true).toBe(true); // dropped
    expect(matcher!(miss) === true).toBe(false); // kept
  });
});
