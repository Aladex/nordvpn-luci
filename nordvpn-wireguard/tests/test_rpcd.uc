#!/usr/bin/ucode -S
// SPDX-License-Identifier: 0BSD
// Integration test for the rpcd ubus object. loadfile()s the object and calls
// its methods against the mock uci/ubus and a fixture-built cache. Globals
// `RPCD`, `fixture` and `KEY` are supplied by run.sh.

'use strict';

import { readfile, mkdir } from 'fs';
const _cache = require('nordvpn.cache');
const normalize = _cache.normalize, write_cache = _cache.write_cache;
import { cursor } from 'uci';

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) { ok(l, sprintf('%J', g) == sprintf('%J', w)); }

// Load the rpcd program; its top-level return is { nordvpn: methods }.
let obj = loadfile(RPCD)();
let m = obj ? obj.nordvpn : null;
ok('rpcd object present', m != null);
ok('read methods present', type(m.status.call) == 'function' && type(m.locations.call) == 'function' && type(m.refresh_status.call) == 'function' && type(m.instances.call) == 'function');
ok('write methods present', type(m.set_credentials.call) == 'function' && type(m.apply.call) == 'function' && type(m.rotate_now.call) == 'function' && type(m.refresh_locations.call) == 'function');

// Build a cache on disk.
let cache = normalize(json(readfile(fixture)));
let cdir = '/tmp/nvrpcd_' + time();
mkdir(cdir);
write_cache(cache, cdir + '/nordvpn_servers_cache.json');

// status: not configured
global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn', cache_dir: cdir } }, network: {} };
global.MOCK_UBUS = {};
eq('status not_configured', m.status.call().state, 'not_configured');
eq('status rejects unknown instance', m.status.call({ args: { instance: 'nope' } }).error, 'no such instance');
eq('instances lists main', length(m.instances.call().instances), 1);

// locations from cache
let loc = m.locations.call();
eq('locations available', loc.available, true);
eq('locations ready', loc.state, 'ready');
eq('locations country count', length(loc.countries), 3);

// refresh_status idle when no job file
eq('refresh_status idle', m.refresh_status.call().state, 'idle');

// set_credentials rejects a malformed token (never reaches the network)
eq('set_credentials bad token', m.set_credentials.call({ args: { token: 'nope' } }).error, 'invalid token format');

// apply chooses a server for the configured selection
global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn',
	country_code: 'ee', city_code: '', hop_mode: 'single', cache_dir: cdir } },
	network: { nordvpn: { '.type': 'interface', private_key: KEY } } };
ok('apply returns a state object', m.apply.call().state != null);

// rotate_now is a no-op when a fixed server is pinned
global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn',
	fixed_server: 'ee70.nordvpn.com', cache_dir: cdir } },
	network: { nordvpn: { '.type': 'interface', private_key: KEY } } };
ok('rotate_now skipped with fixed server', m.rotate_now.call().skipped == true);

printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL RPCD TESTS PASSED');
exit(fails ? 1 : 0);
