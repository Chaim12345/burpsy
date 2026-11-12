## 2025-02-20 - Navigation Tab Accessibility via ARIA Tablist/Tab Roles

**Learning:** Custom tab navigation bars built with `<nav>` and `<button>` elements lack accessible tab semantics for screen readers unless explicitly assigned `role="tablist"` on the container and `role="tab"` + `aria-selected` attributes on interactive tab buttons.
**Action:** When creating or maintaining tabbed interfaces, ensure the container has `role="tablist"` (with an `aria-label`) and children buttons carry `role="tab"` alongside dynamic `aria-selected="true|false"` state updates in JavaScript.
