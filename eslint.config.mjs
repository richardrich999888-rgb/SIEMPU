import globals from 'globals';
export default [
  { ignores: ['node_modules/**', '.data/**', 'dist/**', 'artifacts/**', 'coverage/**'] },
  {
    files: ['**/*.mjs', '**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: { ...globals.node, ...globals.browser, ...globals.serviceworker },
    },
    rules: {
      'no-unused-vars': [
        'error',
        { args: 'none', caughtErrors: 'none', varsIgnorePattern: '^_', ignoreRestSiblings: true },
      ],
      'no-undef': 'error',
      'no-unreachable': 'error',
      'no-constant-binary-expression': 'error',
      'no-dupe-args': 'error',
      'no-dupe-keys': 'error',
      'valid-typeof': 'error',
      'constructor-super': 'error',
      'no-unsafe-finally': 'error',
      'no-fallthrough': 'error',
    },
  },
];
