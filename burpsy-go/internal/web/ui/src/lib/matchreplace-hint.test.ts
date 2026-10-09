import { describe, expect, test } from "bun:test";
import { matchPlaceholder } from "./matchreplace-hint";
import type { MatchReplaceTarget } from "./types.policy";

describe("matchPlaceholder (burpsy-react-ui-p5zu)", () => {
  test("only header rules advertise the blank-match add-a-header meaning", () => {
    expect(matchPlaceholder("request_header", "literal")).toBe("empty = add this header");
    expect(matchPlaceholder("response_header", "regex")).toBe("empty = add this header");
  });

  test("every other target gets a neutral placeholder", () => {
    const others: MatchReplaceTarget[] = [
      "request_first_line",
      "request_body",
      "request_param_name",
      "request_param_value",
      "response_body",
      "websocket_to_server",
      "websocket_to_client",
    ];
    for (const target of others) {
      expect(matchPlaceholder(target, "literal")).toBe("text to match");
      expect(matchPlaceholder(target, "regex")).toBe("regex to match");
      expect(matchPlaceholder(target, "literal")).not.toContain("empty");
    }
  });
});
