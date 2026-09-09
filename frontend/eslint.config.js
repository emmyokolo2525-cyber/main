import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
    },
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    ignores: ['src/safeStorage.ts', 'src/credentialVault.ts', 'src/transactionStateMachine.ts', 'src/**/*.test.{ts,tsx}', 'src/test/**'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector: "MemberExpression[property.name='localStorage']",
          message: 'Use safeLocalStorage from safeStorage.ts.',
        },
        {
          selector: "MemberExpression[property.name='sessionStorage']",
          message: 'Use safeSessionStorage from safeStorage.ts.',
        },
      ],
      'no-restricted-globals': [
        'error',
        {
          name: 'localStorage',
          message: 'Use safeLocalStorage from safeStorage.ts.',
        },
        {
          name: 'sessionStorage',
          message: 'Use safeSessionStorage from safeStorage.ts.',
        },
      ],
    },
  },
])
