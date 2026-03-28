// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/** @type {import('tailwindcss').Config} */
module.exports = {
    content: ['./src/webviews/**/*.{tsx,ts,jsx,js}'],
    theme: {
        extend: {
            colors: {
                ml: {
                    bg: 'var(--ml-bg)',
                    surface: 'var(--ml-surface)',
                    'surface-hover': 'var(--ml-surface-hover)',
                    border: 'var(--ml-border)',
                    accent: 'var(--ml-accent)',
                    'accent-muted': 'var(--ml-accent-muted)',
                    success: 'var(--ml-success)',
                    warning: 'var(--ml-warning)',
                    error: 'var(--ml-error)',
                    info: 'var(--ml-info)',
                    text: 'var(--ml-text)',
                    'text-muted': 'var(--ml-text-muted)',
                    'text-bright': 'var(--ml-text-bright)',
                },
            },
            fontFamily: {
                sans: ['var(--ml-font)'],
                mono: ['var(--ml-font-mono)'],
            },
            borderRadius: {
                ml: 'var(--ml-radius)',
                'ml-lg': 'var(--ml-radius-lg)',
            },
            spacing: {
                'ml-xs': 'var(--ml-space-xs)',
                'ml-sm': 'var(--ml-space-sm)',
                'ml-md': 'var(--ml-space-md)',
                'ml-lg': 'var(--ml-space-lg)',
                'ml-xl': 'var(--ml-space-xl)',
            },
        },
    },
    plugins: [],
};
