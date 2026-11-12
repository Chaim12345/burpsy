# Palette's Journal - Critical UX/Accessibility Learnings Only

## 2026-08-05 - [Decoder Clipboard Integration]
**Learning:** Adding explicit, contextual action buttons (such as "Copy") to output panes dramatically improves usability by preventing the need for manual, error-prone text selection. For non-text/lossy decodings, we should ensure only the clean, original output text gets copied, bypassing UI-only elements.
**Action:** Expose a clean clipboard workflow in utility tabs, verifying that elements like status code or formatting decorations are not included in the copied payload. Ensure proper ARIA labels are present on all newly introduced interactive helper buttons.
