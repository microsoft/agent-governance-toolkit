// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Topology Detail Entry Point
 *
 * Mounts the topology detail React app into the webview.
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import { TopologyDetail } from './TopologyDetail';

const container = document.getElementById('root');
if (container) {
    createRoot(container).render(<TopologyDetail />);
}
