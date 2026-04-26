// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Stats Detail Entry Point
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import { StatsDetail } from './StatsDetail';

const container = document.getElementById('root');
if (container) {
    createRoot(container).render(<StatsDetail />);
}
