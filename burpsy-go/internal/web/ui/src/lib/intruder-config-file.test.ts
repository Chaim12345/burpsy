import { describe, expect, test } from "bun:test";
import {
  ATTACK_CONFIG_FIELDS,
  ATTACK_CONFIG_FORMAT,
  ATTACK_CONFIG_VERSION,
  attackConfigFilename,
  parseAttackConfig,
  serializeAttackConfig,
} from "./intruder-config-file";
import { emptyIntruderConfig, type IntruderConfig } from "./store";

// ---- Save attack config / Load attack config must round-trip the WHOLE attack -------------------
//
// The menubar's Save/Load pair is only honest if the file carries every field the Intruder page
// holds. A loader that quietly defaulted a field the writer never saved would hand back an attack
// that reads like the saved one and sends different requests — the payload processing rules and the
// resource-pool binding are the two that change what goes on the wire while leaving the form
// looking right. So: a full-fat configuration must survive serialize→parse identically, and
// anything that cannot be restored must be REFUSED by name rather than dropped.

/** An attack with every field set to something other than its default, so a dropped field shows. */
function fullConfig(): IntruderConfig {
  return {
    msgId: "42",
    target: "https://target.example:8443",
    label: "#7 POST /login",
    mode: "cluster_bomb",
    allPoints: true,
    points: [
      { index: 0, kind: "param_body", label: "user", offset: 120, len: 5, current: "admin" },
      { index: 1, kind: "header", label: "X-Token", offset: 60, len: 8, current: "deadbeef" },
    ],
    selected: [0, 1],
    payloadTexts: ["admin\nroot", "a\nb\nc"],
    payloadTypes: ["list", "brute_force"],
    payloadNumbers: [
      { from: "1", to: "50", step: "2" },
      { from: "0", to: "9", step: "1" },
    ],
    payloadFiles: ["/usr/share/wordlists/users.txt", ""],
    payloadBrute: [
      { charset: "abc", min_len: "1", max_len: "3" },
      { charset: "0123456789", min_len: "2", max_len: "4" },
    ],
    payloadDates: [
      { from: "2024-01-01", to: "2024-03-01", step: "7", format: "yyyy-MM-dd" },
      { from: "2025-01-01", to: "2025-01-05", step: "1", format: "dd/MM/yyyy" },
    ],
    payloadCustom: [
      { positions: "a,b\nc,d", separator: "-" },
      { positions: "x,y", separator: "" },
    ],
    payloadNulls: ["10", "25"],
    rules: [
      { rule: "add_prefix", text: "pre-", pattern: "", replace: "", all: false, layer: "url", algorithm: "sha256" },
      { rule: "replace", text: "", pattern: "a+", replace: "b", all: true, layer: "url", algorithm: "sha256" },
      { rule: "hash", text: "", pattern: "", replace: "", all: false, layer: "url", algorithm: "md5" },
    ],
    grepMatch: "Welcome back",
    grepMatchMode: "regex",
    grepExtract: "id=(\\d+)",
    poolName: "slow-pool",
    maxRequests: 25_000,
    maxInFlight: 3,
    rps: "12",
  };
}

describe("a saved attack configuration round-trips every field", () => {
  test("the file format knows exactly the fields the store declares", () => {
    // The static half of this guard is the `Record<keyof IntruderConfig, Check>` in
    // intruder-config-file.ts, which fails tsc when a field is added and not checked. This is the
    // runtime half: it fails when a field is added to IntruderConfig and nowhere else, which is the
    // moment Save silently stops saving it.
    expect([...ATTACK_CONFIG_FIELDS].sort() as string[]).toEqual(Object.keys(emptyIntruderConfig()).sort());
  });

  test("a fully-populated attack loads back identical to what was saved", () => {
    const saved = fullConfig();
    const result = parseAttackConfig(serializeAttackConfig(saved));
    if (!result.ok) throw new Error(`the round-trip refused its own output: ${result.reason}`);
    expect(result.config).toEqual(saved);
    // Field-by-field as well as deep-equal: toEqual on a missing key against undefined is the one
    // way this could pass while a field was lost.
    for (const key of ATTACK_CONFIG_FIELDS) {
      expect(Object.keys(result.config)).toContain(key);
      expect(result.config[key]).toEqual(saved[key]);
    }
  });

  test("an empty attack round-trips too, so Save works before anything is configured", () => {
    const result = parseAttackConfig(serializeAttackConfig(emptyIntruderConfig()));
    if (!result.ok) throw new Error(result.reason);
    expect(result.config).toEqual(emptyIntruderConfig());
  });

  test("two saves of one attack are byte-identical, so a file can be diffed", () => {
    const config = fullConfig();
    expect(serializeAttackConfig(config)).toBe(serializeAttackConfig({ ...config }));
  });

  test("the document says what it is, so a stray JSON file is not mistaken for an attack", () => {
    const file = JSON.parse(serializeAttackConfig(fullConfig())) as Record<string, unknown>;
    expect(file.format).toBe(ATTACK_CONFIG_FORMAT);
    expect(file.version).toBe(ATTACK_CONFIG_VERSION);
  });
});

describe("a configuration that cannot be restored in full is refused by name", () => {
  function withoutField(key: keyof IntruderConfig): string {
    const file = JSON.parse(serializeAttackConfig(fullConfig())) as { config: Record<string, unknown> };
    delete file.config[key];
    return JSON.stringify(file);
  }

  test("every single missing field is refused, and the refusal names it", () => {
    // Every field, not a sample: the whole promise of this format is that no field is special-cased
    // into being droppable.
    for (const key of ATTACK_CONFIG_FIELDS) {
      const result = parseAttackConfig(withoutField(key));
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error(`losing ${key} was accepted`);
      expect(result.reason).toContain(`config.${key}`);
    }
  });

  test("a field of the wrong type is refused rather than coerced", () => {
    const file = JSON.parse(serializeAttackConfig(fullConfig())) as { config: Record<string, unknown> };
    file.config.maxRequests = "25000";
    const result = parseAttackConfig(JSON.stringify(file));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("config.maxRequests");
    expect(result.reason).toContain("expected a number");
  });

  test("an unknown attack mode is refused naming the value, not defaulted to sniper", () => {
    const file = JSON.parse(serializeAttackConfig(fullConfig())) as { config: Record<string, unknown> };
    file.config.mode = "shotgun";
    const result = parseAttackConfig(JSON.stringify(file));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('"shotgun"');
    expect(result.reason).toContain("cluster_bomb");
  });

  test("an unknown payload processing rule is refused, because a dropped rule changes the bytes sent", () => {
    const file = JSON.parse(serializeAttackConfig(fullConfig())) as { config: Record<string, unknown> };
    (file.config.rules as Record<string, unknown>[])[1]!.rule = "reverse";
    const result = parseAttackConfig(JSON.stringify(file));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("config.rules");
    expect(result.reason).toContain("[1]");
    expect(result.reason).toContain('"reverse"');
  });

  test("a field a newer burpsy added is refused, not silently ignored", () => {
    const file = JSON.parse(serializeAttackConfig(fullConfig())) as { config: Record<string, unknown> };
    file.config.retryOn5xx = true;
    const result = parseAttackConfig(JSON.stringify(file));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('"retryOn5xx"');
  });

  test("a malformed insertion point is refused with its index", () => {
    const file = JSON.parse(serializeAttackConfig(fullConfig())) as { config: Record<string, unknown> };
    (file.config.points as Record<string, unknown>[])[1]!.offset = "60";
    const result = parseAttackConfig(JSON.stringify(file));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("config.points");
    expect(result.reason).toContain("[1]");
    expect(result.reason).toContain("offset");
  });

  test("NaN and Infinity cannot arrive as limits", () => {
    const file = JSON.parse(serializeAttackConfig(fullConfig())) as { config: Record<string, unknown> };
    // JSON has no NaN literal, so this is what a hand-edited or generated file looks like.
    const text = JSON.stringify(file).replace('"maxInFlight":3', '"maxInFlight":1e999');
    const result = parseAttackConfig(text);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("config.maxInFlight");
  });

  test("a file that is not an attack configuration is refused before any field is read", () => {
    expect(parseAttackConfig("not json at all").ok).toBe(false);
    expect(parseAttackConfig("[1,2,3]").ok).toBe(false);
    const wrongFormat = parseAttackConfig(JSON.stringify({ format: "burpsy-config", version: 1, config: {} }));
    expect(wrongFormat.ok).toBe(false);
    if (!wrongFormat.ok) expect(wrongFormat.reason).toContain("format");
    const wrongVersion = parseAttackConfig(
      JSON.stringify({ format: ATTACK_CONFIG_FORMAT, version: 99, config: {} }),
    );
    expect(wrongVersion.ok).toBe(false);
    if (!wrongVersion.ok) expect(wrongVersion.reason).toContain("version");
  });
});

describe("the saved file names itself", () => {
  test("the filename carries the save time and the .json suffix", () => {
    const name = attackConfigFilename(new Date(Date.UTC(2026, 8, 15, 10, 30, 0)));
    expect(name).toBe("burpsy-attack-2026-09-15T10-30-00-000.json");
  });
});
