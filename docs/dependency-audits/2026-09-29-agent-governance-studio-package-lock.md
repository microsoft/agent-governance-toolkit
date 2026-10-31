---
title: Dependency audit — AGT Studio web package lockfile
last_reviewed: 2026-10-04
owner: agt-maintainers
---

# Dependency audit — AGT Studio web package lockfile

## Which dependencies changed and why

- `agent-governance-studio/web/package-lock.json` was added for the AGT Studio web package.
- Direct dependencies include:
  - `@tanstack/react-query@5.66.8` for React query/state management.
  - `react@18.3.1` for the React application framework.
  - `react-dom@18.3.1` for React DOM rendering.
- Development dependencies include the ESLint, Vite, TypeScript, Tailwind, PostCSS, and Vitest tooling listed in the lockfile.

## Dependencies introduced

| Package | Version | Type | Reason |
|---|---:|---|---|
| `@tanstack/react-query` | 5.66.8 | runtime | React query/state management for the Studio web application |
| `react` | 18.3.1 | runtime | React application framework |
| `react-dom` | 18.3.1 | runtime | React DOM rendering |
| `@eslint/js` | 9.39.5 | dev | ESLint configuration/tooling |
| `@types/react` | 18.3.18 | dev | TypeScript types for React |
| `@types/react-dom` | 18.3.5 | dev | TypeScript types for React DOM |
| `@vitejs/plugin-react` | 4.3.4 | dev | Vite React integration |
| `autoprefixer` | 10.4.20 | dev | CSS PostCSS processing |
| `eslint` | 9.39.5 | dev | JavaScript/TypeScript linting |
| `eslint-plugin-react-hooks` | 5.2.0 | dev | React Hooks linting |
| `postcss` | 8.5.28 | dev | CSS transformation pipeline |
| `tailwindcss` | 3.4.17 | dev | Utility-first CSS framework |
| `typescript` | 5.7.3 | dev | TypeScript compilation |
| `typescript-eslint` | 8.26.0 | dev | TypeScript ESLint integration |
| `vite` | 6.4.3 | dev | Frontend development/build tooling |
| `vitest` | 4.1.11 | dev | Test runner |

## Lockfile integrity

The Studio web package introduces a new npm lockfile generated against the public npm registry.

The lockfile records resolved package URLs and integrity hashes for the dependency graph.

The lockfile was regenerated using:

```text
npm install --package-lock-only --registry https://registry.npmjs.org/