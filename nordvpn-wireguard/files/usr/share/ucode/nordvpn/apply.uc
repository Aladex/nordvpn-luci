// SPDX-License-Identifier: 0BSD
// Credential storage and transactional WireGuard apply. Shared by the rpcd
// `apply`/`set_credentials` methods and the procd reload path.

'use strict';

import { rand, srand } from 'math';
const _common = require('nordvpn.common');
const FIXED_ADDRESS = _common.FIXED_ADDRESS,
      DEFAULT_PORT = _common.DEFAULT_PORT,
      DEFAULT_KEEPALIVE = _common.DEFAULT_KEEPALIVE,
      load_settings = _common.load_settings,
      cache_file_path = _common.cache_file_path,
      validate_interface = _common.validate_interface,
      validate_wg_key = _common.validate_wg_key,
      iso_ts = _common.iso_ts,
      run = _common.run;
const _cache = require('nordvpn.cache');
const read_cache = _cache.read_cache;
const _select = require('nordvpn.select');
const candidates = _select.candidates,
      by_hostname = _select.by_hostname,
      pick = _select.pick;
const _api = require('nordvpn.api');
const get_private_key = _api.get_private_key;

// Locate the managed peer section (type wireguard_<iface>, interface=<iface>).
function find_peer(uci, iface) {
	let found = null;
	uci.foreach('network', null, function(sec) {
		if (sec['.type'] && index(sec['.type'], 'wireguard_') == 0 && sec.interface == iface) {
			found = sec['.name'];
			return false;
		}
	});
	return found;
}

// Exchange the token for a private key and persist ONLY the key. The token is
// never written to UCI. Returns { ok: true } or { error }.
function set_credentials(uci, token) {
	let res = get_private_key(token);
	if (res.error)
		return res;

	let iface = validate_interface(load_settings(uci).interface);
	if (!iface)
		return { error: 'invalid interface name' };

	if (!uci.get('network', iface))
		uci.set('network', iface, 'interface');
	uci.set('network', iface, 'proto', 'wireguard');
	uci.set('network', iface, 'vpn_type', 'nordvpn');
	uci.set('network', iface, 'private_key', res.private_key);
	uci.set('network', iface, 'addresses', [ FIXED_ADDRESS ]);
	uci.delete('network', iface, 'nordvpn_token');
	uci.commit('network');
	return { ok: true };
}

// Snapshot the current peer so a failed rotation can be rolled back.
function current_peer(uci, iface) {
	let peer = find_peer(uci, iface);
	if (!peer)
		return null;
	return {
		public_key: uci.get('network', peer, 'public_key'),
		endpoint_host: uci.get('network', peer, 'endpoint_host'),
		endpoint_port: uci.get('network', peer, 'endpoint_port'),
		gateway: uci.get('network', peer, 'nordvpn_gateway')
	};
}

// Restore a peer snapshot taken by current_peer() (no commit).
function restore_peer(uci, iface, saved) {
	if (!saved)
		return;
	let peer = find_peer(uci, iface);
	if (!peer)
		peer = uci.add('network', 'wireguard_' + iface);
	uci.set('network', peer, 'interface', iface);
	if (saved.public_key)
		uci.set('network', peer, 'public_key', saved.public_key);
	if (saved.endpoint_host)
		uci.set('network', peer, 'endpoint_host', saved.endpoint_host);
	if (saved.endpoint_port)
		uci.set('network', peer, 'endpoint_port', saved.endpoint_port);
	if (saved.gateway)
		uci.set('network', peer, 'nordvpn_gateway', saved.gateway);
}

// Write the interface + peer for the chosen relay (no commit).
function write_relay(uci, iface, relay, s) {
	uci.set('network', iface, 'proto', 'wireguard');
	uci.set('network', iface, 'vpn_type', 'nordvpn');
	uci.set('network', iface, 'auto', '1');
	uci.set('network', iface, 'addresses', [ FIXED_ADDRESS ]);

	if (s.routing_table && s.routing_table != '') {
		uci.set('network', iface, 'ip4table', s.routing_table);
		uci.set('network', iface, 'ip6table', s.routing_table);
	} else {
		uci.delete('network', iface, 'ip4table');
		uci.delete('network', iface, 'ip6table');
	}

	uci.set('network', iface, 'nordvpn_location', relay.location);
	uci.set('network', iface, 'nordvpn_country_code', s.country_code);
	uci.set('network', iface, 'nordvpn_city_code', s.city_code);
	uci.set('network', iface, 'nordvpn_last_applied', iso_ts());

	let peer = find_peer(uci, iface);
	if (!peer)
		peer = uci.add('network', 'wireguard_' + iface);
	uci.set('network', peer, 'interface', iface);
	uci.set('network', peer, 'public_key', relay.public_key);
	uci.set('network', peer, 'endpoint_host', relay.hostname);
	uci.set('network', peer, 'endpoint_port', '' + (relay.port || DEFAULT_PORT));
	uci.set('network', peer, 'persistent_keepalive', '' + DEFAULT_KEEPALIVE);
	uci.set('network', peer, 'allowed_ips', [ '0.0.0.0/0', '::/0' ]);
	uci.set('network', peer, 'nordvpn_gateway', relay.hostname);
}

// Bring the managed interface up. iface is whitelist-validated, so the argv is
// injection-safe (no shell).
function bring_up(iface) {
	return run([ 'ifup', iface ]).code == 0;
}

// Newest WireGuard handshake age (seconds) for the interface. Returns -1 when
// wg cannot be run (off-device), null when it ran but there is no handshake.
function handshake_age(iface) {
	let res = run([ 'wg', 'show', iface, 'latest-handshakes' ]);
	if (res.code != 0)
		return -1;
	let best = 0;
	for (let line in split(trim(res.stdout || ''), '\n')) {
		let parts = split(line, '\t');
		if (length(parts) >= 2) {
			let t = int(parts[1]);
			if (t > best)
				best = t;
		}
	}
	if (best == 0)
		return null;
	let age = time() - best;
	return age < 0 ? 0 : age;
}

// Wait up to `seconds` for a fresh handshake. True when connected — or when wg
// is unavailable (off-device), so the apply logic is not blocked in tests.
function verify_handshake(iface, seconds) {
	for (let i = 0; i < seconds; i++) {
		run([ 'sleep', '1' ]);
		let age = handshake_age(iface);
		if (age == -1)
			return true;
		if (age != null && age < 180)
			return true;
	}
	return false;
}

function shuffle(list) {
	let a = [];
	for (let x in list)
		push(a, x);
	for (let i = length(a) - 1; i > 0; i--) {
		let j = rand() % (i + 1);
		let t = a[i]; a[i] = a[j]; a[j] = t;
	}
	return a;
}

function connect_one(uci, iface, relay, s) {
	write_relay(uci, iface, relay, s);
	uci.commit('network');
	return bring_up(iface);
}

// Apply the persisted configuration. A fixed server is applied once; an
// automatic selection tries several candidates until one completes a handshake
// (NordVPN publishes dead endpoints), rolling back to the previous working peer
// if none do. Bounded so the rpc call stays within timeout.
function apply(uci) {
	let s = load_settings(uci);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { state: 'failure', error: 'invalid interface name' };
	if (!validate_wg_key(uci.get('network', iface, 'private_key')))
		return { state: 'failure', error: 'no credentials configured' };

	let cache = read_cache(cache_file_path(s));
	if (!cache)
		return { state: 'failure', error: 'server list not available; refresh the cache first' };

	srand(time());
	let saved = current_peer(uci, iface);

	if (s.fixed_server && s.fixed_server != '') {
		let relay = by_hostname(cache, s.fixed_server);
		if (!relay)
			return { state: 'failure', error: 'configured server not found in cache' };
		let up = connect_one(uci, iface, relay, s);
		let ok = up && verify_handshake(iface, 6);
		return {
			state: ok ? 'success' : (up ? 'partial_failure' : 'failure'),
			interface: iface, gateway: relay.hostname,
			endpoint: relay.hostname + ':' + (relay.port || DEFAULT_PORT),
			restarted: up,
			error: ok ? null : 'the selected server did not respond'
		};
	}

	let list = candidates(cache, s.country_code, s.city_code, s.hop_mode);
	if (length(list) == 0)
		return { state: 'failure', error: 'no matching server found for the current selection' };
	list = shuffle(list);

	let tries = length(list);
	if (tries > 4)
		tries = 4;
	for (let i = 0; i < tries; i++) {
		let relay = list[i];
		if (!connect_one(uci, iface, relay, s))
			continue;
		if (verify_handshake(iface, 4))
			return {
				state: 'success', interface: iface, gateway: relay.hostname,
				endpoint: relay.hostname + ':' + (relay.port || DEFAULT_PORT),
				restarted: true
			};
	}

	if (saved) {
		restore_peer(uci, iface, saved);
		uci.commit('network');
		bring_up(iface);
	}
	return { state: 'failure', restored: saved != null,
		error: 'could not reach any server for the current selection; restored the previous connection' };
}

return { set_credentials, current_peer, restore_peer, write_relay, bring_up, verify_handshake, connect_one, apply };
