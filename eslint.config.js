'use strict';
// Catches undefined variables and other real bugs. Warnings (unused watermark constants etc.) do not fail the build.
const globals = require('globals');

const appGlobals = { ABUtils: 'readonly', SecurityAuditor: 'readonly', ADBConnection: 'readonly', DeviceManager: 'readonly', DeviceToolkit: 'readonly', ApkAnalyzer: 'readonly', SqliteDb: 'readonly', usbSerial: 'readonly' };
const rules = {
    'no-undef': 'error', 'no-dupe-keys': 'error', 'no-redeclare': 'error', 'no-unreachable': 'error', 'no-self-assign': 'error',
    'no-cond-assign': 'error', 'no-const-assign': 'error', 'no-func-assign': 'error', 'no-sparse-arrays': 'error', 'use-isnan': 'error',
    'valid-typeof': 'error', 'no-unsafe-negation': 'error', 'no-dupe-else-if': 'error', 'no-duplicate-case': 'error', 'no-loss-of-precision': 'error',
    'no-unused-vars': ['warn', { args: 'none', caughtErrors: 'none' }], 'no-useless-escape': 'warn'
};

module.exports = [
    { ignores: ['node_modules/**'] },
    { files: ['js/**/*.js', 'sw.js'], languageOptions: { ecmaVersion: 2023, sourceType: 'script', globals: { ...globals.browser, ...globals.serviceworker, ...appGlobals } }, rules },
    { files: ['tests/**/*.js', 'scripts/**/*.js', 'eslint.config.js'], languageOptions: { ecmaVersion: 2023, sourceType: 'commonjs', globals: { ...globals.node } }, rules },
    // e2e page-mock runs inside the browser page
    { files: ['tests/e2e/page-mock.js'], languageOptions: { ecmaVersion: 2023, sourceType: 'script', globals: { ...globals.browser } }, rules }
];
