# Palette's Journal - Critical UX & Accessibility Learnings

## 2026-08-05 - State-Aware Diagnostics and Multi-Step Copy Utility
**Learning:** In cybersecurity diagnostic interfaces (such as decoders or hashers), operators frequently copy raw processed outputs (hashes, JWTs, Base64 values) to transfer them back to other tabs (Repeater/Intruder) or external terminals. Relying on manual selection is highly frustrating and prone to copying surrounding layout decorations or layout labels. In addition, resetting inputs requires a dedicated clear mechanism to keep the screen reader context clean.
**Action:** Always provide state-aware, accessible "Copy Output" (via the clipboard API) and "Clear All" utility buttons close to text processing result panes. Ensure buttons are dynamically disabled when there is no content to prevent stale operations, and implement aria-labels to make the elements accessible.
