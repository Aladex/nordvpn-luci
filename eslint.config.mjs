// SPDX-License-Identifier: MIT
// ESLint flat config for this repo's CI. Mirrors the subset of openwrt/luci's
// eslint.config.mjs relevant to a LuCI JS view: js/recommended + the LuCI
// runtime globals, script sourceType with global return. When the luci-app is
// submitted to openwrt/luci, that repo's own config applies instead.

import globals from 'globals';
import js from '@eslint/js';

export default [
	{
		files: ['**/*.js'],
		plugins: { js },
		languageOptions: {
			sourceType: 'script',
			ecmaVersion: 2026,
			globals: {
				...globals.browser,
				_: 'readonly', N_: 'readonly', L: 'readonly', E: 'readonly', TR: 'readonly',
				baseclass: 'readonly', dom: 'readonly', form: 'readonly', fs: 'readonly',
				network: 'readonly', poll: 'readonly', request: 'readonly', session: 'readonly',
				rpc: 'readonly', uci: 'readonly', ui: 'readonly', validation: 'readonly',
				view: 'readonly', widgets: 'readonly'
			},
			parserOptions: { ecmaFeatures: { globalReturn: true } }
		},
		linterOptions: { reportUnusedDisableDirectives: 'off' },
		rules: {
			...js.configs.recommended.rules,
			strict: 0,
			'no-prototype-builtins': 0,
			'no-empty': 0,
			'no-undef': 'warn',
			'no-unused-vars': ['off', { caughtErrors: 'none' }],
			'no-regex-spaces': 0,
			'no-control-regex': 0
		}
	}
];
