import { expect, test } from "bun:test";
import { render } from "@testing-library/react";
import { TooltipProvider } from "@radix-ui/react-tooltip";
import { Modal } from "./primitives";

test("a dialog opens with focus on the dialog, not the Close button whose tooltip would eat the first Escape", async () => {
 render(
  <TooltipProvider>
   <Modal open onOpenChange={() => {}} title="Example">
    <p>body</p>
   </Modal>
  </TooltipProvider>,
 );
 await new Promise((resolve) => setTimeout(resolve, 50));
 const active = document.activeElement as HTMLElement | null;
 expect(active?.getAttribute("role")).toBe("dialog");
 expect(active?.getAttribute("aria-label")).not.toBe("Close");
});
