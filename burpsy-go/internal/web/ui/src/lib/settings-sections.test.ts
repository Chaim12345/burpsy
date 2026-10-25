// The Settings page's section list (burpsy-react-ui-f6a).
//
// The defect this metadata exists to prevent is drift between three readers of one list: the page
// renders the sections, the rail navigates them, and the command palette opens them. Two of those
// are pinned by the typechecker — SettingsPage's component map is a total Record over
// SettingsSectionId, so a section with no component does not build. The third, the palette, is not
// a type, so it is pinned here: one entry per section, exactly once, no strays.
//
// The rest of this file pins the search's behaviour, because "it filters" is not the claim. The
// claim is that it finds a setting by a word only the *card* prints, which is the whole reason it
// reads rendered text instead of a transcribed index.
import { describe, expect, test } from "bun:test";
import {
 SETTINGS_SECTIONS,
 filterSettingsSections,
 settingsPaletteActions,
 settingsSectionAnchor,
 settingsSectionMatches,
 matchesAllWords,
 requestSettingsSection,
 takePendingSettingsSection,
 type SettingsSection,
} from "./settings-sections";

/** The page hands the filter each card's rendered text; tests hand it a canned body instead. */
function bodies(map: Record<string, string>): (section: SettingsSection) => string {
 return (section) => map[section.id] ?? "";
}

describe("the settings section list", () => {
 test("every section id appears exactly once, because the anchor and the palette entry are both derived from it", () => {
  const ids = SETTINGS_SECTIONS.map((section) => section.id);
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
  expect(
   duplicates,
   "a duplicate id means two cards share one DOM anchor: the rail and the palette would both scroll to whichever rendered first, and the other section would be unreachable",
  ).toEqual([]);
 });

 test("every section titles itself, because the title is what the rail, the palette and the card's own heading all print", () => {
  const untitled = SETTINGS_SECTIONS.filter((section) => !section.title.trim() || !section.summary.trim());
  expect(
   untitled.map((section) => section.id),
   "a section with no title or no summary renders as a blank rail row and a palette entry with nothing to read",
  ).toEqual([]);
 });

 test("an anchor is namespaced to this page, so a section id can never collide with another page's element id", () => {
  expect(
   settingsSectionAnchor("network"),
   "an un-prefixed anchor would let a section claim a generic id another page already uses, and getElementById would return the wrong element",
  ).toBe("settings-network");
 });
});

describe("the command palette's settings entries", () => {
 test("the palette offers exactly one entry per section, and none for a section that does not exist", () => {
  const actions = settingsPaletteActions(() => undefined);
  const sectionIds = SETTINGS_SECTIONS.map((section) => `settings:${section.id}`);
  expect(
   actions.map((action) => action.id).sort(),
   "the palette and the page have drifted: a section is either missing from the palette (unreachable by search, which is the gap this work closed) or the palette offers one the page does not render",
  ).toEqual(sectionIds.sort());
 });

 test("every palette entry names its section, so the palette's own search can find it by the section's words", () => {
  const actions = settingsPaletteActions(() => undefined);
  for (const section of SETTINGS_SECTIONS) {
   const action = actions.find((candidate) => candidate.id === `settings:${section.id}`);
   expect(
    action?.label,
    `the entry for ${section.id} does not carry its title, so typing the section's name in the palette would not surface it`,
   ).toBe(`Settings › ${section.title}`);
  }
 });

 test("running an entry navigates to Settings first and leaves the section pending, in that order", () => {
  const routes: string[] = [];
  const actions = settingsPaletteActions((route) => routes.push(route));
  actions[0]!.run();
  expect(
   routes,
   "the entry did not navigate: it would leave the operator on whatever tool they were in, with a pending scroll nothing will read",
  ).toEqual(["settings"]);
  expect(
   takePendingSettingsSection(),
   "no section was left pending, so Settings would open at the top and the entry would be a plain 'go to Settings'",
  ).toBe(SETTINGS_SECTIONS[0].id);
 });

 test("a pending section is delivered once and then cleared", () => {
  requestSettingsSection("network");
  expect(
   takePendingSettingsSection(),
   "the request did not survive to the page, so a palette jump from another tool would land at the top of Settings",
  ).toBe("network");
  expect(
   takePendingSettingsSection(),
   "the pending id was not cleared: every later render of Settings would scroll away from wherever the operator had moved to",
  ).toBe(null);
 });
});

describe("the settings search", () => {
 test("an empty term keeps every section, in the page's own render order", () => {
  const kept = filterSettingsSections("", () => "");
  expect(
   kept.map((section) => section.id),
   "an empty search dropped or reordered sections: the rail must show the page as it is when nothing has been typed",
  ).toEqual(SETTINGS_SECTIONS.map((section) => section.id));
 });

 test("a word only the card renders finds the section, which is the point of reading rendered text", () => {
  const kept = filterSettingsSections("vacuum", bodies({ "project-backup": "Directory Retention VACUUM INTO" }));
  expect(
   kept.map((section) => section.id),
   "the search missed a word that is on screen inside a card: it is matching metadata only, so any field nobody transcribed into keywords is unfindable — the exact failure this search was built to avoid",
  ).toEqual(["project-backup"]);
 });

 test("a section matches on its metadata even before its card has rendered anything", () => {
  const kept = filterSettingsSections("ntlm", () => "");
  expect(
   kept.map((section) => section.id),
   "a section whose data is still loading became unfindable: the search would answer 'no match' for a setting that exists and is merely slow",
  ).toEqual(["platform-auth"]);
 });

 test("every word has to match, so two words from two different sections match neither", () => {
  const kept = filterSettingsSections("hotkey vacuum", bodies({ "project-backup": "VACUUM INTO", hotkeys: "hotkey chord" }));
  expect(
   kept,
   "the search ORs its words: typing a second word would widen the result instead of narrowing it, and the filter would be useless for anything but a single term",
  ).toEqual([]);
 });

 test("one word from the title and one from a rendered label still match the same section", () => {
  // The two halves of the haystack have to be searched as one. An operator types what they
  // remember of where it lives plus what they remember of the field, and those two words are
  // never adjacent in either source.
  const network = SETTINGS_SECTIONS.find((section) => section.id === "network")!;
  expect(
   settingsSectionMatches(network, "Connect timeout Response timeout", "network timeout"),
   "metadata and rendered text are being matched separately: a term that spans both — the section's name plus a field's name — finds nothing, which is the most natural way to search a page like this",
  ).toBe(true);
 });

 test("the same word rule is available on its own, because the page runs it twice at two scales", () => {
  // The page filters sections with it, then descends into the surviving card with it to find
  // which control matched. If these two could disagree, the page would outline a field the
  // filter had not kept — so there is one rule and both callers use it.
  expect(
   matchesAllWords("Redirections Follow redirects on-site only", "follow redirect"),
   "the inner search is stricter than the outer one: a section would survive the filter and then contain nothing to highlight, and Enter would land on the card heading with no explanation",
  ).toBe(true);
  expect(
   matchesAllWords("Connect timeout", "follow redirect"),
   "the inner search matches text it should not, so the highlight would land on the first unrelated row of the card",
  ).toBe(false);
 });

 test("a term nothing matches produces an empty result, or the filter is decoration", () => {
  expect(
   filterSettingsSections("zzzznothing", () => ""),
   "the filter cannot produce an empty result, which means it is not filtering — the page would show all seventeen sections under a search that matched none of them",
  ).toEqual([]);
 });
});
