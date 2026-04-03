// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Audit Detail Entry Point
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import { AuditDetail } from './AuditDetail';

const container = document.getElementById('root');
if (container) {
    createRoot(container).render(<AuditDetail />);
}
