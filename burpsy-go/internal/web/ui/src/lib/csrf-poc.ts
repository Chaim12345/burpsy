import { create } from "zustand";
import type { Exchange } from "./types";

/**
 * The CSRF PoC dialog's open state (burpsy-react-ui-0z10).
 *
 * A separate store rather than a field on the workspace store: the trigger is a context-menu
 * action available from every surface that shows an exchange (History, Logger, Repeater), and a
 * dialog that any of them can open cannot live in any one of them. The workspace store holds
 * state the whole console shares; a transient dialog for one exchange is not that, and putting it
 * there would make every page re-render on a dialog's open and close.
 */
type CsrfPocState = {
 /** The exchange the dialog is generating PoCs for; null means closed. */
 exchange: Exchange | null;
 open: (exchange: Exchange) => void;
 close: () => void;
};

export const useCsrfPoc = create<CsrfPocState>((set) => ({
 exchange: null,
 open: (exchange) => set({ exchange }),
 close: () => set({ exchange: null }),
}));
