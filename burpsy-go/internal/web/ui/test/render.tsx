import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { render, type RenderResult } from "@testing-library/react";
import type { ReactElement } from "react";

/** A client that never retries and never refetches, so a failing request settles at once. */
export function testQueryClient(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity }, mutations: { retry: false } } });
}

/** render() inside the providers every page expects. `rerender` keeps the same wrapper. */
export function renderWithProviders(ui: ReactElement, client: QueryClient = testQueryClient()): RenderResult {
  return render(ui, { wrapper: ({ children }) => <QueryClientProvider client={client}>
      <TooltipPrimitive.Provider>{children}</TooltipPrimitive.Provider>
    </QueryClientProvider> });
}
