/**
 * Burp's EDITOR_PREV_PARA / EDITOR_NEXT_PARA (Ctrl+Up / Ctrl+Down) as a pure line computation (2czi).
 *
 * A paragraph is a run of non-blank lines, so an HTTP message is two: the head and the body, split
 * by the blank line between them. Down moves to the next blank line below the current one (or the
 * last line); Up moves to the previous blank line above it (or the first line). That is the
 * behaviour of the common editor binding Burp's names describe, and it makes "jump to the body"
 * one key.
 *
 * Lines are 1-based, as CodeMirror's `doc.line(n)` numbers them.
 */
export function paragraphTarget(lines: readonly string[], fromLine: number, direction: "up" | "down"): number {
 const count = lines.length;
 if (count === 0) return 1;
 const blank = (n: number) => (lines[n - 1] ?? "").trim() === "";
 if (direction === "down") {
  let n = fromLine + 1;
  // Skip the blank lines directly below, so repeated presses walk paragraph to paragraph rather
  // than sticking on a run of blank lines.
  while (n <= count && blank(n)) n += 1;
  while (n <= count && !blank(n)) n += 1;
  return Math.min(n, count);
 }
 let n = fromLine - 1;
 while (n >= 1 && blank(n)) n -= 1;
 while (n >= 1 && !blank(n)) n -= 1;
 return Math.max(n, 1);
}
