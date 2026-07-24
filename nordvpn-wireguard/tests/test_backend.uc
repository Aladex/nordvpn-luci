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
const _cmn = require('nordvpn.common');
const load_settings = _cmn.load_settings, list_instances = _cmn.list_instances;
const status = require('nordvpn.status').status;
const _rotate = require('nordvpn.rotate');
const shuffle = _rotate.shuffle, plan_candidates = _rotate.plan_candidates;
const _service = require('nordvpn.service');
const should_refresh = _service.should_refresh, should_rotate = _service.should_rotate,
      next_rotation = _service.next_rotation;
const _routing = require('nordvpn.routing');
const detect_routing = _routing.detect, enforce_routing = _routing.enforce;
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

// 8. routing detection and enforcement (mock uci; stamped objects only)
{
	let mks = function(over) {
		let base = { interface: 'nordvpn', routing_table: '', auto_routing: false,
			killswitch: false, block_ipv6: true, use_vpn_dns: false };
		for (let k in over)
			base[k] = over[k];
		return base;
	};
	let mknet = function() {
		return {
			nordvpn: { '.type': 'interface', proto: 'wireguard', private_key: KEY },
			peer: { '.type': 'wireguard_nordvpn', interface: 'nordvpn', endpoint_host: 'x.nordvpn.com' }
		};
	};
	let mkfw = function() {
		return {
			zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
			zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] }
		};
	};

	// A custom routing table means manual mode.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	let uci = cursor();
	eq('routing: manual via table', detect_routing(uci, mks({ routing_table: 'vpn' }), false).mode, 'manual');

	// A user route referencing the interface means manual mode, and enforce()
	// must not change a single byte even with every toggle on.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	global.MOCK_UCI.network.myroute = { '.type': 'route', interface: 'nordvpn', target: '0.0.0.0/0' };
	uci = cursor();
	eq('routing: manual via user route', detect_routing(uci, mks({ auto_routing: true }), false).mode, 'manual');
	let before = sprintf('%J', global.MOCK_UCI);
	let res = enforce_routing(uci, mks({ auto_routing: true, killswitch: true, use_vpn_dns: true }));
	eq('routing: manual scheme untouched', sprintf('%J', global.MOCK_UCI), before);
	eq('routing: manual reports no changes', res.changed_network || res.changed_firewall, false);

	// Fresh install with automatic routing: zone, forwarding, default route,
	// kill switch and IPv6 block appear; everything stamped.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	uci = cursor();
	let pristine = sprintf('%J', global.MOCK_UCI);
	res = enforce_routing(uci, mks({ auto_routing: true, killswitch: true }));
	ok('routing: auto changed firewall', res.changed_firewall);
	ok('routing: auto changed network', res.changed_network);
	let det = detect_routing(uci, mks({ auto_routing: true }), false);
	eq('routing: auto mode', det.mode, 'auto');
	eq('routing: zone created', det.zone, 'nordvpn');
	ok('routing: zone is stamped', det.zone_managed);
	ok('routing: default route set', det.route_allowed_ips);
	ok('routing: kill switch installed', det.killswitch);
	ok('routing: ipv6 block installed', det.ipv6_block);

	// Idempotent: a second run changes nothing.
	res = enforce_routing(uci, mks({ auto_routing: true, killswitch: true }));
	eq('routing: idempotent', res.changed_network || res.changed_firewall, false);

	// Turning a single toggle off removes exactly that object.
	res = enforce_routing(uci, mks({ auto_routing: true, killswitch: false }));
	ok('routing: kill switch removed', !detect_routing(uci, mks({ auto_routing: true }), false).killswitch);

	// Turning automatic mode off restores the pristine configuration.
	res = enforce_routing(uci, mks({ auto_routing: false }));
	eq('routing: off restores pristine config', sprintf('%J', global.MOCK_UCI), pristine);
}

// 8b. source-network steering: lookup/prohibit rules, reconciliation, teardown
{
	let ssteer = function(over) {
		let base = { interface: 'nordvpn_rs', routing_table: 'nv_media', auto_routing: false,
			killswitch: false, block_ipv6: true, use_vpn_dns: false, source_networks: [ 'media' ] };
		for (let k in over)
			base[k] = over[k];
		return base;
	};
	global.MOCK_UCI = { network: {
		nordvpn_rs: { '.type': 'interface', proto: 'wireguard', private_key: KEY },
		peer_rs: { '.type': 'wireguard_nordvpn_rs', interface: 'nordvpn_rs', endpoint_host: 'x.nordvpn.com' },
		media: { '.type': 'interface', proto: 'static', ipaddr: '10.9.1.1', netmask: '255.255.255.0' },
		guest: { '.type': 'interface', proto: 'static', ipaddr: '10.9.2.1/24' },
		hetzroute: { '.type': 'route', interface: 'wgx', target: '10.28.0.0', netmask: '255.255.255.0' },
		wgxpeer: { '.type': 'wireguard_wgx', interface: 'wgx', route_allowed_ips: '1',
			allowed_ips: [ '10.29.0.0/24', '0.0.0.0/0' ] }
	}, firewall: {
		zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
		zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] },
		zmedia: { '.type': 'zone', name: 'media', network: [ 'media' ] }
	} };
	let uci = cursor();
	let pris = sprintf('%J', global.MOCK_UCI);

	let res = enforce_routing(uci, ssteer({}));
	ok('steer: changed network', res.changed_network);
	ok('steer: changed firewall', res.changed_firewall);
	let det = detect_routing(uci, ssteer({}), false);
	eq('steer: mode', det.mode, 'steered');
	eq('steer: zone named after iface', det.zone, 'nordvpn_rs');
	ok('steer: default route into table', det.route_allowed_ips);
	ok('steer: v6 block on by default', det.ipv6_block);
	ok('steer: no kill switch by default', !det.killswitch);
	ok('steer: networks listed', index(det.networks, 'media') >= 0 && index(det.networks, 'nordvpn_rs') < 0);

	let lookup = null;
	for (let k in global.MOCK_UCI.network) {
		let sec = global.MOCK_UCI.network[k];
		if (sec['.type'] == 'rule' && sec['in'] == 'media' && sec.nordvpn_managed == '1' && sec.lookup)
			lookup = sec;
	}
	ok('steer: media lookup rule targets the table', lookup != null && lookup.lookup == 'nv_media');

	// Local subnets get stamped bypass routes in the instance table.
	let localr = 0;
	for (let k in global.MOCK_UCI.network) {
		let sec = global.MOCK_UCI.network[k];
		if (sec['.type'] == 'route' && sec.nordvpn_role == 'steer_local' && sec.table == 'nv_media')
			localr++;
	}
	eq('steer: local bypass routes created', localr, 4);
	let mirrored = 0;
	for (let k in global.MOCK_UCI.network) {
		let sec = global.MOCK_UCI.network[k];
		if (sec['.type'] == 'route' && sec.nordvpn_role == 'steer_local' &&
		    (sec.target == '10.28.0.0/24' || sec.target == '10.29.0.0/24'))
			mirrored++;
	}
	eq('steer: user route and wg allowed_ips mirrored', mirrored, 2);

	// An unstamped user route for the same subnet (netmask form) is respected:
	// no duplicate is created and an existing stamped twin is withdrawn.
	global.MOCK_UCI.network.userlocal = { '.type': 'route', interface: 'media',
		target: '10.9.1.0', netmask: '255.255.255.0', table: 'nv_media' };
	enforce_routing(uci, ssteer({}));
	let dup = 0;
	for (let k in global.MOCK_UCI.network) {
		let sec = global.MOCK_UCI.network[k];
		if (sec['.type'] == 'route' && sec.table == 'nv_media' &&
		    (sec.target == '10.9.1.0/24' || sec.target == '10.9.1.0'))
			dup++;
	}
	eq('steer: user companion route not duplicated', dup, 1);
	delete global.MOCK_UCI.network.userlocal;
	enforce_routing(uci, ssteer({}));

	// Reconciliation: switch the steering to another network, kill switch on.
	res = enforce_routing(uci, ssteer({ source_networks: [ 'guest' ], killswitch: true }));
	let media_rules = 0, guest_rules = 0;
	for (let k in global.MOCK_UCI.network) {
		let sec = global.MOCK_UCI.network[k];
		if ((sec['.type'] == 'rule' || sec['.type'] == 'rule6') && sec.nordvpn_managed == '1') {
			if (sec['in'] == 'media') media_rules++;
			if (sec['in'] == 'guest') guest_rules++;
		}
	}
	eq('steer: old network rules removed', media_rules, 0);
	eq('steer: new network gets lookup+ks+v6', guest_rules, 3);

	// A user route inside the instance's table is a companion, not a manual
	// scheme — steering stays; a route referencing the interface forces manual.
	global.MOCK_UCI.network.companion = { '.type': 'route', interface: 'lan',
		target: '10.0.0.0/24', table: 'nv_media' };
	eq('steer: companion route in table keeps steering',
		detect_routing(uci, ssteer({ source_networks: [ 'guest' ] }), false).mode, 'steered');
	global.MOCK_UCI.network.takeover = { '.type': 'route', interface: 'nordvpn_rs', target: '0.0.0.0/0' };
	eq('steer: interface route forces manual',
		detect_routing(uci, ssteer({ source_networks: [ 'guest' ] }), false).mode, 'manual');
	delete global.MOCK_UCI.network.companion;
	delete global.MOCK_UCI.network.takeover;

	// A missing routing table disables steering with a note, creating nothing.
	global.MOCK_UCI = { network: { nordvpn_rs: { '.type': 'interface', proto: 'wireguard' } }, firewall: {} };
	uci = cursor();
	let before = sprintf('%J', global.MOCK_UCI);
	res = enforce_routing(uci, ssteer({ routing_table: '' }));
	eq('steer: no table -> untouched', sprintf('%J', global.MOCK_UCI), before);
	ok('steer: no table -> note', length(res.notes) > 0);

	// Teardown restores the pristine configuration.
	global.MOCK_UCI = { network: {
		nordvpn_rs: { '.type': 'interface', proto: 'wireguard', private_key: KEY },
		peer_rs: { '.type': 'wireguard_nordvpn_rs', interface: 'nordvpn_rs', endpoint_host: 'x.nordvpn.com' },
		media: { '.type': 'interface', proto: 'static', ipaddr: '10.9.1.1', netmask: '255.255.255.0' },
		guest: { '.type': 'interface', proto: 'static', ipaddr: '10.9.2.1/24' }
	}, firewall: {
		zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
		zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] },
		zmedia: { '.type': 'zone', name: 'media', network: [ 'media' ] }
	} };
	uci = cursor();
	pris = sprintf('%J', global.MOCK_UCI);
	enforce_routing(uci, ssteer({ killswitch: true }));
	enforce_routing(uci, ssteer({ source_networks: [] }));
	eq('steer: teardown restores pristine config', sprintf('%J', global.MOCK_UCI), pris);
}

// 9. multi-instance: settings, listing, isolated state, per-instance status
{
	global.MOCK_UCI = { nordvpn: {
		main: { '.type': 'instance', interface: 'nordvpn', country_code: 'de', cache_dir: '/shared' },
		media: { '.type': 'instance', interface: 'nordvpn_rs', country_code: 'rs' }
	}, network: {} };
	let uci = cursor();
	eq('instances listed, main first', list_instances(uci), [ 'main', 'media' ]);
	eq('instance interface', load_settings(uci, 'media').interface, 'nordvpn_rs');
	eq('instance country', load_settings(uci, 'media').country_code, 'rs');
	eq('cache options shared from main', load_settings(uci, 'media').cache_dir, '/shared');
	eq('default instance is main', load_settings(uci).name, 'main');
	eq('invalid instance falls back to main', load_settings(uci, '../evil').name, 'main');

	// A legacy `config settings 'main'` is still listed.
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn' } }, network: {} };
	uci = cursor();
	eq('legacy settings section listed', list_instances(uci), [ 'main' ]);

	// Rotation state files are isolated per instance ('main' keeps the old path).
	unlink('/tmp/nordvpn_rotate_state.json');
	unlink('/tmp/nordvpn_rotate_state_media.json');
	_rotate.mark_attempt(1000);
	_rotate.mark_attempt(2000, 'media');
	eq('main rotate state isolated', _rotate.last_attempt_ts(), 1000);
	eq('media rotate state isolated', _rotate.last_attempt_ts('media'), 2000);
	unlink('/tmp/nordvpn_rotate_state.json');
	unlink('/tmp/nordvpn_rotate_state_media.json');

	// Status is per instance and reports its name.
	global.MOCK_UCI = { nordvpn: {
		main: { '.type': 'instance', interface: 'nordvpn' },
		media: { '.type': 'instance', interface: 'nordvpn_rs' }
	}, network: { nordvpn_rs: { '.type': 'interface', private_key: KEY } } };
	global.MOCK_UBUS = {};
	uci = cursor();
	eq('status per instance: media configured', status(uci, 'media').configured, true);
	eq('status per instance: main not configured', status(uci, 'main').configured, false);
	eq('status carries the instance name', status(uci, 'media').instance, 'media');
}

unlink(cpath);
printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL PHASE-3 TESTS PASSED');
exit(fails ? 1 : 0);
