# Palette's Journal

## 2026-08-06 - Accessible Custom Interactive Controls in Minimal Frontend UI
**Learning:** In highly customized, framework-less TypeScript apps (like burpsy's UI), decorative CSS toggle switches (which use opacity-hidden checkboxes) and tabbed navigation strips (built with generic `div`s) are frequently skipped in standard keyboard focus cycles and are completely silent or confusing for screen readers.
**Action:** Always overlay hidden checkbox inputs fully over the decorative CSS switch layout, supply clear `aria-label`s, and style them using `:focus-visible` to render a visible outline. Similarly, augment generic `div`/`span` tab strips with explicit `tabindex="0"`, appropriate ARIA roles/states, and explicit keydown handlers (for Enter and Space keys) to make them fully keyboard-navigable.
