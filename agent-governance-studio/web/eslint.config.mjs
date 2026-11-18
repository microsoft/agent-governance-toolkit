// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";

export default tseslint.config(
  { ignores: ["dist/", "coverage/"] },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: { globals: globals.browser },
  },
  {
    files: ["vite.config.ts", "*.config.cjs"],
    languageOptions: { globals: globals.node },
  },
);
