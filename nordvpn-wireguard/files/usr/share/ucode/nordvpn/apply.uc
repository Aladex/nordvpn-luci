// SPDX-License-Identifier: 0BSD
// Credential storage and transactional WireGuard apply. Shared by the rpcd
// `apply`/`set_credentials` methods and the procd reload path.

'use strict';

import {
	FIXED_ADDRESS, DEFAULT_PORT, DEFAULT_KEEPALIVE,
	load_settings, cache_file_path, validate_interface, validate_wg_key,
	iso_ts, run, log
} from 'nordvpn.common';
import { srand } from 'math';
import { read_cache } from 'nordvpn.cache';
import { candidates, by_hostname, pick } from 'nordvpn.select';
import { get_private_key } from 'nordvpn.api';

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
export function set_credentials(uci, token) {
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
export function current_peer(uci, iface) {
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
export function restore_peer(uci, iface, saved) {
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
export function write_relay(uci, iface, relay, s) {
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
export function bring_up(iface) {
	return run([ 'ifup', iface ]).code == 0;
}

// Select a relay from the cache honoring settings. Returns a relay or { error }.
function choose_relay(uci) {
	let s = load_settings(uci);
	let cache = read_cache(cache_file_path(s));
	if (!cache)
		return { error: 'server list not available; refresh the cache first' };

	if (s.fixed_server && s.fixed_server != '') {
		let r = by_hostname(cache, s.fixed_server);
		return r ? r : { error: 'configured server not found in cache' };
	}
	let list = candidates(cache, s.country_code, s.city_code, s.hop_mode);
	let r = pick(list, null);
	return r ? r : { error: 'no matching server found for the current selection' };
}

// Apply the persisted configuration: pick a relay, write the interface/peer
// transactionally, commit, and bring the interface up. Returns an apply-state
// object; the caller polls status to confirm the handshake.
export function apply(uci) {
	let s = load_settings(uci);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { state: 'failure', error: 'invalid interface name' };
	if (!validate_wg_key(uci.get('network', iface, 'private_key')))
		return { state: 'failure', error: 'no credentials configured' };

	srand(time());
	let relay = choose_relay(uci);
	if (relay.error)
		return { state: 'failure', error: relay.error };

	write_relay(uci, iface, relay, s);
	uci.commit('network');

	let up = bring_up(iface);
	return {
		state: up ? 'applying' : 'partial_failure',
		interface: iface,
		gateway: relay.hostname,
		endpoint: relay.hostname + ':' + (relay.port || DEFAULT_PORT),
		restarted: up,
		error: up ? null : 'configuration saved but the interface failed to start'
	};
}
