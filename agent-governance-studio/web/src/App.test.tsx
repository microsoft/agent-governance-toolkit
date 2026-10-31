// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import App from './App';

describe('App', () => {
  it('renders the AGT Studio entry point', () => {
    const html = renderToString(<App />);

    expect(html).toContain('AGT Studio');
    expect(html).toContain('Public Preview');
  });
});
