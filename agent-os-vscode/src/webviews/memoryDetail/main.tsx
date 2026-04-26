// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Memory Detail Entry Point
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryDetail } from './MemoryDetail';

const container = document.getElementById('root');
if (container) {
    createRoot(container).render(<MemoryDetail />);
}
