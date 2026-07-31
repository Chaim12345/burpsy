# Palette's Journal

## 2026-07-28 - Non-semantic and inaccessible interactive elements
**Learning:** Interactive controls built using plain static elements (like `<span>` with `&times;` or `+` text) are completely inaccessible to screen readers and keyboard-only users. They lack a keyboard focus path, do not respond to Enter/Space natively, and are read as raw symbols (e.g., "times" or "plus") by assistive technologies.
**Action:** Always use semantic `<button>` elements for interactive controls, provide precise `aria-label`s to explain symbol actions, and ensure proper `:focus-visible` styling is present for keyboard navigation.
