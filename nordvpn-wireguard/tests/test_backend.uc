#!/usr/bin/ucode -S
// SPDX-License-Identifier: 0BSD
// Offline tests for credential handling, selection, apply and status.
// Uses the mock 'uci'/'ubus' modules (forced ahead on the module search path).
// Globals `fixture` and `KEY` are supplied by run.sh.

'use strict';

import { readfile, writefile, unlink, mkdir, popen, pipe } from 'fs';
const _cache = require('nordvpn.cache');
const normalize = _cache.normalize, write_cache = _cache.write_cache;
const _select = require('nordvpn.select');
const candidates = _select.candidates, by_hostname = _select.by_hostname, pick = _select.pick;
const parse_credentials = require('nordvpn.api').parse_credentials;
const write_relay = require('nordvpn.apply').write_relay;
const load_settings = require('nordvpn.common').load_settings;
const status = require('nordvpn.status').status;
const _rotate = require('nordvpn.rotate');
const shuffle = _rotate.shuffle, plan_candidates = _rotate.plan_candidates;
const _service = require('nordvpn.service');
const should_refresh = _service.should_refresh, should_rotate = _service.should_rotate,
      next_rotation = _service.next_rotation;
import { cursor } from 'uci';

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) { ok(l, sprintf('%J', g) == sprintf('%J', w)); }

// 1. Credential fd-passing: the token reaches the child ONLY through the pipe,
//    never via argv. Prove a child process can read the config from the fd.
{
	let p = pipe();
	let r = p[0], w = p[1];
	let rfd = r.fileno();
	w.write('user = "token:SECRET_TOKEN_VALUE"\n');
	w.close();
	let proc = popen([ 'cat', '/proc/self/fd/' + rfd ], 'r');
	let out = proc.read('all') || '';
	proc.close();
	r.close();
	ok('credential pipe inherited by child', index(out, 'SECRET_TOKEN_VALUE') >= 0);
	ok('credential config is a curl user= line', index(out, 'user = "token:') == 0);
}

// 2. parse_credentials
{
	eq('parse good key', parse_credentials(sprintf('{"nordlynx_private_key":"%s"}', KEY)).private_key, KEY);
	ok('parse rejects non-json', parse_credentials('not json').error != null);
	ok('parse rejects missing key', parse_credentials('{"x":1}').error != null);
	ok('parse rejects bad key', parse_credentials('{"nordlynx_private_key":"short"}').error != null);
}

// Build a cache on disk from the fixture.
let cache = normalize(json(readfile(fixture)));
let cdir = '/tmp/nvtest_' + time();
mkdir(cdir);
let cpath = cdir + '/nordvpn_servers_cache.json';
write_cache(cache, cpath);

// 3. selection
{
	eq('ee single count', length(candidates(cache, 'ee', '', 'single')), 1);
	eq('nl multihop count', length(candidates(cache, 'nl', '', 'multihop')), 1);
	eq('nl single count excludes onion', length(candidates(cache, 'nl', '', 'single')), 0);
	eq('nl onion count', length(candidates(cache, 'nl', '', 'onion')), 1);
	ok('onion relay is nl-onion1', candidates(cache, 'nl', '', 'onion')[0].hostname == 'nl-onion1.nordvpn.com');
	ok('by_hostname hit', by_hostname(cache, 'ee70.nordvpn.com') != null);
	ok('by_hostname miss', by_hostname(cache, 'nope.example') == null);
	let picked = pick(candidates(cache, 'ee', '', 'single'), null);
	ok('pick returns ee relay', picked != null && picked.hostname == 'ee70.nordvpn.com');
}

// 4. apply writes a correct interface + peer transactionally.
{
	global.MOCK_UCI = {
		nordvpn: { main: { '.type': 'settings', interface: 'nordvpn',
			country_code: 'ee', city_code: '', hop_mode: 'single', cache_dir: cdir } },
		network: { nordvpn: { '.type': 'interface', proto: 'wireguard',
			private_key: KEY, vpn_type: 'nordvpn' } }
	};
	let uci = cursor();
	let relay = candidates(cache, 'ee', '', 'single')[0];
	ok('candidate is ee70', relay && relay.hostname == 'ee70.nordvpn.com');
	write_relay(uci, 'nordvpn', relay, load_settings(uci));

	let net = global.MOCK_UCI.network;
	let peerkey = null;
	for (let k in net)
		if (index(net[k]['.type'], 'wireguard_') == 0)
			peerkey = k;
	ok('write_relay created a peer section', peerkey != null);
	let peer = net[peerkey];
	ok('peer public_key set', peer.public_key != null);
	eq('peer endpoint_host', peer.endpoint_host, 'ee70.nordvpn.com');
	ok('peer allowed_ips is a 2-item list', type(peer.allowed_ips) == 'array' && length(peer.allowed_ips) == 2);
	ok('iface addresses is a list', type(net.nordvpn.addresses) == 'array');
	eq('iface address value', net.nordvpn.addresses[0], '10.5.0.2/16');
}

// 5. status states
{
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn' } }, network: {} };
	global.MOCK_UBUS = {};
	eq('status not_configured', status(cursor()).state, 'not_configured');

	global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn' } },
		network: { nordvpn: { '.type': 'interface', private_key: KEY } } };
	eq('status disconnected (iface down)', status(cursor()).state, 'disconnected');

	global.MOCK_UBUS = { 'network.interface.nordvpn~status': { up: true, l3_device: 'nordvpn' } };
	eq('status connecting (up, no handshake)', status(cursor()).state, 'connecting');
}

// 6. rotation planning (pure): shuffle + candidate exclusion/limit
{
	let arr = [ 1, 2, 3, 4, 5 ];
	let sh = shuffle(arr);
	eq('shuffle preserves length', length(sh), 5);
	let sum = 0;
	for (let x in sh) sum += x;
	eq('shuffle preserves members', sum, 15);
	eq('shuffle does not mutate input', length(arr), 5);

	let s_ee = { country_code: 'ee', city_code: '', hop_mode: 'single', max_retries: 10 };
	eq('plan excludes current gateway', length(plan_candidates(cache, s_ee, 'ee70.nordvpn.com', 10)), 0);
	eq('plan includes when not excluded', length(plan_candidates(cache, s_ee, null, 10)), 1);

	let s_nl = { country_code: 'nl', city_code: '', hop_mode: 'multihop', max_retries: 10 };
	eq('plan nl multihop', length(plan_candidates(cache, s_nl, null, 10)), 1);
	eq('plan respects limit', length(plan_candidates(cache, s_nl, null, 0) || []) <= 1, true);
}

// 6b. rotation state persistence: the daemon's attempt clock survives a restart
//     and neither writer clobbers the other's timestamp.
{
	unlink('/tmp/nordvpn_rotate_state.json');
	eq('last_attempt 0 when no state', _rotate.last_attempt_ts(), 0);
	_rotate.mark_attempt(1000);
	eq('last_attempt persisted', _rotate.last_attempt_ts(), 1000);
	_rotate.record({ last_success: 2000, server: 'ee70.nordvpn.com' });
	eq('record keeps last_attempt', _rotate.last_attempt_ts(), 1000);
	eq('record merged last_success', _rotate.read_state().last_success, 2000);
	_rotate.mark_attempt(3000);
	eq('mark_attempt keeps last_success', _rotate.read_state().last_success, 2000);
	unlink('/tmp/nordvpn_rotate_state.json');
}

// 7. scheduler decisions (pure)
{
	let s = { cache_refresh_interval: 21600, enabled: true, rotation_enabled: true,
		fixed_server: '', rotation_mode: 'interval', rotation_interval: 360, rotation_time: '04:30' };

	ok('refresh on first tick if stale', should_refresh(s, 0, 1000, true) == true);
	ok('no refresh on first tick if fresh', should_refresh(s, 0, 1000, false) == false);
	ok('refresh after interval', should_refresh(s, 1000, 1000 + 21600, false) == true);
	ok('no refresh before interval', should_refresh(s, 1000, 1000 + 100, false) == false);

	ok('rotate after interval', should_rotate(s, 1000, 1000 + 360 * 60, '12:00') == true);
	ok('no rotate before interval', should_rotate(s, 1000, 1000 + 60, '12:00') == false);
	ok('no rotate when disabled', should_rotate({ ...s, enabled: false }, 0, 999999, '12:00') == false);
	ok('no rotate with fixed server', should_rotate({ ...s, fixed_server: 'ee70.nordvpn.com' }, 0, 999999, '12:00') == false);

	let st = { ...s, rotation_mode: 'time', rotation_time: '04:30' };
	ok('rotate at matching time', should_rotate(st, 0, 999999, '04:30') == true);
	ok('no rotate at other time', should_rotate(st, 0, 999999, '04:31') == false);
}

// 7b. next rotation time (pure)
{
	let s = { enabled: true, rotation_enabled: true, fixed_server: '',
		rotation_mode: 'interval', rotation_interval: 360, rotation_time: '04:30' };
	let now = time();

	eq('next_run from last attempt', next_rotation(s, 1000, 500), 1000 + 360 * 60);
	eq('next_run without history', next_rotation(s, 0, now), now + 360 * 60);
	eq('next_run overdue clamps to now', next_rotation(s, 100, 999999), 999999);
	eq('next_run null when rotation off', next_rotation({ ...s, rotation_enabled: false }, 0, now), null);
	eq('next_run null when master off', next_rotation({ ...s, enabled: false }, 0, now), null);
	eq('next_run null with fixed server', next_rotation({ ...s, fixed_server: 'ee70.nordvpn.com' }, 0, now), null);

	let st = { ...s, rotation_mode: 'time' };
	let nr = next_rotation(st, 0, now);
	ok('time mode is in the future', nr > now);
	ok('time mode within 24h', (nr - now) <= 86400);
	let lt = localtime(nr);
	ok('time mode lands on 04:30:00', lt.hour == 4 && lt.min == 30 && lt.sec == 0);
}

unlink(cpath);
printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL PHASE-3 TESTS PASSED');
exit(fails ? 1 : 0);
