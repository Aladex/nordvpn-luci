// SPDX-License-Identifier: MIT
// Minimal in-memory 'uci' module mock for offline ucode tests. Mirrors the real
// ucode uci cursor API used by the backend. Seed and inspect via global.MOCK_UCI:
//   global.MOCK_UCI = { network: { nordvpn: { '.type':'interface', proto:'wireguard' } } };

'use strict';

function store() {
	if (!global.MOCK_UCI)
		global.MOCK_UCI = {};
	return global.MOCK_UCI;
}

export function cursor() {
	let s = store();
	return {
		get: function(c, sec, opt) {
			let section = s[c] ? s[c][sec] : null;
			if (!section)
				return null;
			return (opt != null) ? section[opt] : section['.type'];
		},
		get_all: function(c, sec) {
			if (!s[c])
				return null;
			return (sec != null) ? s[c][sec] : s[c];
		},
		get_first: function(c, t, opt) {
			if (!s[c])
				return null;
			for (let name in s[c])
				if (s[c][name]['.type'] == t)
					return (opt != null) ? s[c][name][opt] : name;
			return null;
		},
		foreach: function(c, t, cb) {
			if (!s[c])
				return false;
			for (let name in s[c]) {
				let section = s[c][name];
				if (t == null || section['.type'] == t) {
					if (cb({ ...section, '.name': name }) === false)
						break;
				}
			}
			return true;
		},
		add: function(c, t) {
			if (!s[c])
				s[c] = {};
			let i = 0, name = t + '_0';
			while (s[c][name]) {
				i++;
				name = t + '_' + i;
			}
			s[c][name] = { '.type': t, '.name': name };
			return name;
		},
		// 4-arg: set option; 3-arg (val==null): create/set section type.
		set: function(c, sec, a, b) {
			if (!s[c])
				s[c] = {};
			if (!s[c][sec])
				s[c][sec] = { '.type': 'unknown', '.name': sec };
			if (b == null)
				s[c][sec]['.type'] = a;
			else
				s[c][sec][a] = b;
		},
		delete: function(c, sec, opt) {
			if (!s[c])
				return;
			if (opt != null) {
				if (s[c][sec]) delete s[c][sec][opt];
			} else {
				delete s[c][sec];
			}
		},
		list_append: function(c, sec, opt, val) {
			if (!s[c] || !s[c][sec])
				return;
			let cur = s[c][sec][opt];
			if (type(cur) != 'array')
				cur = (cur != null) ? [cur] : [];
			push(cur, val);
			s[c][sec][opt] = cur;
		},
		save: function() { return true; },
		commit: function() { return true; },
		changes: function() { return []; },
		revert: function() { return true; },
		error: function() { return null; }
	};
}
