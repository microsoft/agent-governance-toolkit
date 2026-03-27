// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Dashboard Entry Point
 *
 * Mounts the React app into the webview DOM.
 */

import { createRoot } from 'react-dom/client';
import { App } from './App';
// CSS loaded via <link> tag in the webview HTML (built by Tailwind CLI)

const container = document.getElementById('root');
if (container) {
    const root = createRoot(container);
    root.render(<App />);
}
