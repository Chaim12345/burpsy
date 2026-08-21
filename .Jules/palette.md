# Palette's Journal - Critical Learnings

## 2026-08-17 - Fallback naming for tree node toggles when segment is empty
**Learning:** In hierarchical tree views (such as Site Map), root or host nodes may carry an empty `segment` property (`""`). Computing button labels as `aria-label={`Expand ${node.segment}`}` leads to incomplete accessible names (`"Expand "` or `"Collapse "`).
**Action:** Always provide a fallback name (e.g. `node.segment || node.path || "/"`) when generating dynamic ARIA labels for tree toggle buttons.
