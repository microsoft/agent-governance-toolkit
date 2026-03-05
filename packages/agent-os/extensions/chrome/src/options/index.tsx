// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import React from 'react';
import { createRoot } from 'react-dom/client';
import { Settings } from './Settings';
import './styles.css';

const container = document.getElementById('root');
if (container) {
  const root = createRoot(container);
  root.render(<Settings />);
}
