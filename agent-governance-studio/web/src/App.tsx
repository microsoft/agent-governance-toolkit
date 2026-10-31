// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const queryClient = new QueryClient();

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <main className="mx-auto max-w-3xl p-8">
        <h1 className="text-3xl font-semibold">AGT Studio</h1>
        <p>Agent Governance Toolkit</p>
      </main>
    </QueryClientProvider>
  );
}
