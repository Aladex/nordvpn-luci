#!/usr/bin/ucode -S
// SPDX-License-Identifier: 0BSD
// Offline fixture test for the cache normalizer. No network or account needed.
// Run via tests/run.sh (passes the fixture path as the `fixture` global).

'use strict';

import { readfile } from 'fs';
const normalize = require('nordvpn.cache').normalize;

let raw = readfile(fixture);
if (!raw) {
	warn('cannot read fixture: ' + fixture + '\n');
	exit(2);
}

let out = normalize(json(raw));

let ok = true;
function check(label, got, want) {
	if (got != want) {
		ok = false;
		printf('FAIL %s: got %J want %J\n', label, got, want);
	} else {
		printf('ok   %s = %J\n', label, got);
	}
}

// Fixture: 5 servers — 4 WireGuard (1 multihop de-nl, 1 onion nl-onion),
// 1 non-WireGuard (skipped).
check('countries', out.stats.countries, 3);
check('cities', out.stats.cities, 3);
check('gateways', out.stats.gateways, 4);
check('servers_seen', out.stats.servers_seen, 5);

let multihop = 0, onion = 0, single = 0;
for (let c in out.countries)
	for (let ci in c.cities)
		for (let r in ci.relays)
			r.multihop ? multihop++ : (r.onion ? onion++ : single++);
check('multihop_relays', multihop, 1);
check('onion_relays', onion, 1);
check('single_relays', single, 2);

// Countries are sorted alphabetically.
check('first_country', out.countries[0].name, 'Estonia');

exit(ok ? 0 : 1);
