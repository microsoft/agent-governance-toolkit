// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Detail Entry Point
 *
 * Mounts the SLO detail React app into the webview panel.
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import { SLODetail } from './SLODetail';

const container = document.getElementById('root');
if (container) {
    createRoot(container).render(<SLODetail />);
}
