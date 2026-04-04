// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Sidebar Entry Point
 *
 * Mounts the 3-slot sidebar React app into the webview.
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import { Sidebar } from './Sidebar';

const container = document.getElementById('root');
if (container) {
    createRoot(container).render(<Sidebar />);
}
