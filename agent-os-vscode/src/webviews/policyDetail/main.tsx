// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Policy Detail Entry Point
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import { PolicyDetail } from './PolicyDetail';

const container = document.getElementById('root');
if (container) {
    createRoot(container).render(<PolicyDetail />);
}
