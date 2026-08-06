## 2025-02-12 - Keyboard Accessibility for Custom Non-Semantic Controls
**Learning:** When using custom HTML elements (such as `span` tags with `tabindex="0"`) as interactive controls like close buttons, simply adding tabindex makes them focusable but does not automatically dispatch click events on key presses. Screen readers and keyboard users expect "Enter" or "Space" to trigger these buttons.
**Action:** Always bind a keydown event listener alongside the click listener on custom controls to handle "Enter" and "Space" keys and trigger the action.
