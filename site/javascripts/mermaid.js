// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

window.mermaid?.initialize({ startOnLoad: false });

document$.subscribe(() => {
  window.mermaid?.run();
});
