// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Kernel Detail Entry Point
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import { KernelDetail } from './KernelDetail';

const container = document.getElementById('root');
if (container) {
    createRoot(container).render(<KernelDetail />);
}
