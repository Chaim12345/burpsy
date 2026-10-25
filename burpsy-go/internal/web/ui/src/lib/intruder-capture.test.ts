import { describe, expect, test } from "bun:test";
import { NOT_STORED, captureFilterField, describeCaptureFilter, missingReason, storageFields } from "./intruder-capture";
import { emptyIntruderConfig } from "./store";

describe("the results capture filter (ip2b)", () => {
  test("off by default, and off sends nothing", () => {
    expect(emptyIntruderConfig().captureFilterEnabled).toBe(false);
    expect(captureFilterField({ ...emptyIntruderConfig(), captureTerm: "ignored while off" })).toEqual({});
  });

  test("every setting reaches the request; all four classes ticked is the server's default and not sent", () => {
    const on = { ...emptyIntruderConfig(), captureFilterEnabled: true };
    expect(captureFilterField(on)).toEqual({
      capture_filter: { discard_no_response: false, term: "", regex: false, case_sensitive: false, negate: false },
    });
    expect(
      captureFilterField({
        ...on,
        captureDiscardNoResponse: true,
        captureTerm: "welcome",
        captureRegex: true,
        captureCaseSensitive: true,
        captureNegate: true,
        captureStatuses: ["5xx", "2xx"],
      }),
    ).toEqual({
      capture_filter: {
        discard_no_response: true,
        term: "welcome",
        regex: true,
        case_sensitive: true,
        negate: true,
        statuses: ["2xx", "5xx"],
      },
    });
    expect(captureFilterField({ ...on, captureStatuses: [] }).capture_filter?.statuses).toEqual([]);
  });

  test("the filter reads back as one line, Burp's filter-bar wording", () => {
    expect(describeCaptureFilter(null)).toBe("Capturing all items");
    expect(
      describeCaptureFilter({ discard_no_response: true, term: "error", regex: false, case_sensitive: false, negate: true, statuses: ["2xx", "3xx"] }),
    ).toBe("Discarding items without responses; discarding 4xx, 5xx; not matching expression error");
    expect(describeCaptureFilter({ discard_no_response: false, term: "", regex: false, case_sensitive: false, negate: false })).toBe(
      "Capturing all items",
    );
  });
});

describe("Store requests / Store responses (nqww)", () => {
  test("on by default, and only an off switch is sent", () => {
    const config = emptyIntruderConfig();
    expect(config.storeRequests).toBe(true);
    expect(config.storeResponses).toBe(true);
    expect(storageFields(config)).toEqual({});
    expect(storageFields({ storeRequests: false, storeResponses: true })).toEqual({ store_requests: false });
    expect(storageFields({ storeRequests: true, storeResponses: false })).toEqual({ store_responses: false });
  });

  test("a row's missing bytes are explained by the setting when the attack had it off", () => {
    expect(missingReason(false, "fallback")).toBe(NOT_STORED);
    expect(missingReason(true, "fallback")).toBe("fallback");
    expect(missingReason(undefined, "fallback")).toBe("fallback");
  });
});
