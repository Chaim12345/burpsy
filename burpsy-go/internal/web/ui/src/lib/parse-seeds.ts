/**
 * Seed parsing shared by every crawl/scan launcher (f3k): one input, many URLs —
 * Burp's "URLs to scan" is a multi-line box ("Burp will begin crawling from these URLs").
 *
 * One implementation, two launchers (Dashboard's New scan and the Site map's CrawlLauncher):
 * the issue's own note warns that two split-and-trim copies of the same input is how they
 * come to disagree. Blank lines and commas both separate, matching the CrawlLauncher hint.
 */

/** Split a seed box into trimmed, non-empty URLs. */
export function parseSeeds(text: string): string[] {
 return text
  .split(/[\s,]+/)
  .map((s) => s.trim())
  .filter(Boolean);
}
