// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Hub Detail Entry Point
 *
 * Mounts the Governance Hub React app into the webview panel.
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import { HubDetail } from './HubDetail';

const container = document.getElementById('root');
if (container) {
    createRoot(container).render(<HubDetail />);
}
