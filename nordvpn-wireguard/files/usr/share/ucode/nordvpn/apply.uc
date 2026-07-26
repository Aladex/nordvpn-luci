// SPDX-License-Identifier: MIT
// Credential storage and transactional WireGuard apply. Shared by the rpcd
// `apply`/`set_credentials` methods and the procd reload path.

'use strict';

import { rand, srand } from 'math';
import { cursor } from 'uci';
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
const selection_candidates = _select.selection_candidates,
      by_hostname = _select.by_hostname,
      pick = _select.pick;
const _api = require('nordvpn.api');
const get_private_key = _api.get_private_key;
const _routing = require('nordvpn.routing');
const enforce_routing = _routing.enforce;

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

// Exchange the token for a private key and persist ONLY the key, on the
// instance's own interface — every instance carries its own credentials (a
// shared key reportedly risks being locked by NordVPN when reused). The token
// is never written to UCI. Returns { ok: true } or { error }.
function set_credentials(uci, token, instance) {
	let res = get_private_key(token);
	if (res.error)
		return res;

	let iface = validate_interface(load_settings(uci, instance).interface);
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

	// Optional MTU override; empty falls back to netifd's WireGuard default.
	if (s.mtu)
		uci.set('network', iface, 'mtu', '' + s.mtu);
	else
		uci.delete('network', iface, 'mtu');

	uci.set('network', iface, 'nordvpn_location', relay.location);
	// Stamp the ACTUAL server's country/city: with a location set the
	// connected relay may sit in any of the set's countries, and the status
	// must reflect where the tunnel really exits (exit country for multihop).
	uci.set('network', iface, 'nordvpn_country_code', relay.exit_country_code || s.country_code);
	uci.set('network', iface, 'nordvpn_city_code', relay.location || s.city_code);
	uci.set('network', iface, 'nordvpn_last_applied', iso_ts());

	let peer = find_peer(uci, iface);
	if (!peer)
		peer = uci.add('network', 'wireguard_' + iface);
	uci.set('network', peer, 'interface', iface);
	// Managed routing stamps the interface; the peer's allowed-IPs routes
	// (netifd-installed, into ip4table when set) follow it.
	if (uci.get('network', iface, 'nordvpn_managed_routing') == '1')
		uci.set('network', peer, 'route_allowed_ips', '1');
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

// A global netifd reload has been observed (OpenWrt 24.10) to remove the
// kernel's main IPv4 default route while netifd still reports it as
// installed, cutting WAN connectivity. Self-heal: when the kernel lost the
// default but netifd claims a gateway route on an up interface, re-add it.
function restore_wan_default() {
	// The reload applies asynchronously; the route can disappear a moment
	// after an immediate check passes, so probe a few times.
	for (let attempt = 0; attempt < 3; attempt++) {
		run([ 'sleep', '2' ]);
		let r = run([ 'ip', '-4', 'route', 'show', 'default' ]);
		if (r.code != 0)
			return false;
		if (length(trim(r.stdout || '')) > 0)
			continue;
		let d = run([ 'ubus', 'call', 'network.interface', 'dump' ]);
		if (d.code != 0)
			return false;
		let data;
		try {
			data = json(d.stdout);
		} catch (e) {
			return false;
		}
		for (let ifc in ((data ? data.interface : null) || [])) {
			if (!ifc.up || !ifc.l3_device)
				continue;
			for (let rt in (ifc.route || [])) {
				if (rt.target == '0.0.0.0' && rt.mask == 0 && rt.nexthop && rt.nexthop != '0.0.0.0') {
					let res = run([ 'ip', 'route', 'add', 'default', 'via', rt.nexthop, 'dev', ifc.l3_device ]);
					_common.log('restored missing WAN default route via ' + rt.nexthop + ' on ' + ifc.l3_device);
					if (res.code != 0)
						return false;
				}
			}
		}
	}
	return true;
}

// Apply the persisted configuration. A fixed server is applied once; an
// automatic selection tries several candidates until one completes a handshake
// (NordVPN publishes dead endpoints), rolling back to the previous working peer
// if none do. Bounded so the rpc call stays within timeout.
function apply_inner(uci, instance) {
	let s = load_settings(uci, instance);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { state: 'failure', error: 'invalid interface name' };
	if (!validate_wg_key(uci.get('network', iface, 'private_key')))
		return { state: 'failure', error: 'no credentials configured' };

	let cache = read_cache(cache_file_path(s));
	if (!cache)
		return { state: 'failure', error: 'server list not available; refresh the cache first' };

	// Applying implies the user wants the instance on — undo a disable, both
	// in the config and in the already-loaded settings the enforcement uses.
	if (!s.enabled) {
		uci.set('nordvpn', s.name, 'enabled', '1');
		uci.commit('nordvpn');
		s.enabled = true;
	}

	// Reconcile the managed routing/firewall objects with the settings. Only
	// stamped objects are ever touched; a detected manual scheme is left alone.
	let routing = enforce_routing(uci, s);
	if (routing.changed_firewall) {
		uci.commit('firewall');
		run([ '/etc/init.d/firewall', 'reload' ]);
	}
	if (routing.changed_network) {
		uci.commit('network');
		// Steering/prohibit rules are plain netifd config; a reload makes
		// netifd apply the delta (unchanged interfaces are left alone).
		run([ 'ubus', 'call', 'network', 'reload' ]);
	}
	if (routing.changed_network || routing.changed_firewall) {
		// Committing deletions invalidates the cursor's section iteration
		// state (find_peer silently missed sections) — start fresh.
		uci = cursor();
	}
	for (let note in routing.notes)
		_common.log('routing: ' + note);

	srand(time());
	let saved = current_peer(uci, iface);

	if (s.fixed_server && s.fixed_server != '') {
		let relay = by_hostname(cache, s.fixed_server);
		if (!relay)
			return { state: 'failure', error: 'configured server not found in cache' };
		let up = connect_one(uci, iface, relay, s);
		let ok = up && verify_handshake(iface, s.verify_timeout);
		return {
			state: ok ? 'success' : (up ? 'partial_failure' : 'failure'),
			interface: iface, gateway: relay.hostname,
			endpoint: relay.hostname + ':' + (relay.port || DEFAULT_PORT),
			restarted: up,
			error: ok ? null : 'the selected server did not respond'
		};
	}

	let list = selection_candidates(cache, s);
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
		if (verify_handshake(iface, s.verify_timeout))
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

function apply(uci, instance) {
	let res = apply_inner(uci, instance);
	restore_wan_default();
	return res;
}

// Disable the instance: tunnel down and kept down (auto '0'), scheduled
// rotation stopped, and every managed routing/firewall object released so the
// steered networks return to normal networking — IPv6 included. The next
// apply re-enables and recreates everything.
function disconnect(uci, instance) {
	let s = load_settings(uci, instance);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { error: 'invalid interface name' };
	uci.set('nordvpn', s.name, 'enabled', '0');
	uci.commit('nordvpn');

	s.enabled = false;
	let routing = enforce_routing(uci, s);
	if (routing.changed_firewall) {
		uci.commit('firewall');
		run([ '/etc/init.d/firewall', 'reload' ]);
	}
	if (routing.changed_network) {
		uci.commit('network');
		run([ 'ubus', 'call', 'network', 'reload' ]);
	}
	if (routing.changed_network || routing.changed_firewall)
		uci = cursor();

	if (uci.get('network', iface) != null) {
		uci.set('network', iface, 'auto', '0');
		uci.commit('network');
	}
	run([ 'ifdown', iface ]);
	restore_wan_default();
	return { ok: true, interface: iface };
}

// Forget the stored WireGuard key and peer so the instance goes back to
// "not configured". The selection (country, schedule, …) is kept so entering
// a new token restores the previous behaviour.
function clear_credentials(uci, instance) {
	let s = load_settings(uci, instance);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { error: 'invalid interface name' };
	run([ 'ifdown', iface ]);
	let peer = find_peer(uci, iface);
	if (peer)
		uci.delete('network', peer);
	if (uci.get('network', iface) != null) {
		uci.delete('network', iface, 'private_key');
		uci.set('network', iface, 'auto', '0');
	}
	uci.commit('network');
	return { ok: true, interface: iface };
}

// Create a new VPN instance section with its own interface. Committed
// atomically here (not via the UI's staged-apply machinery, whose rollback
// window makes programmatic section creation fragile).
function create_instance(uci, name) {
	let valid = _common.validate_instance(name);
	if (!valid || valid != name)
		return { error: 'invalid instance name' };
	if (name == 'globals')
		return { error: 'this name is reserved' };
	if (uci.get('nordvpn', name) != null)
		return { error: 'an instance with this name already exists' };

	let iface = validate_interface('nv_' + name);
	if (!iface)
		return { error: 'instance name is too long for an interface name' };
	let taken = false;
	for (let other in _common.list_instances(uci))
		if (load_settings(uci, other).interface == iface)
			taken = true;
	if (taken || uci.get('network', iface) != null)
		return { error: 'interface ' + iface + ' already exists' };

	uci.set('nordvpn', name, 'instance');
	uci.set('nordvpn', name, 'interface', iface);
	uci.set('nordvpn', name, 'enabled', '1');
	uci.commit('nordvpn');
	return { ok: true, instance: name, interface: iface };
}

// Tear down a VPN instance: stamped routing/firewall objects, the netifd
// interface + peer, and the config section. 'main' is special — it anchors
// the shared cache options and the UI, so instead of deleting the section its
// options are reset to the shipped defaults (the migration stamp is kept).
function delete_instance(uci, name) {
	if (uci.get('nordvpn', name) == null)
		return { error: 'no such instance' };

	let s = load_settings(uci, name);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { error: 'invalid interface name' };

	// Remove stamped artifacts by enforcing the all-off state.
	s.auto_routing = false;
	s.killswitch = false;
	s.block_ipv6 = false;
	s.vpn_dns = 'off';
	s.use_vpn_dns = false;
	s.source_networks = [];
	let routing = enforce_routing(uci, s);
	if (routing.changed_firewall) {
		uci.commit('firewall');
		run([ '/etc/init.d/firewall', 'reload' ]);
	}
	if (routing.changed_network) {
		uci.commit('network');
		run([ 'ubus', 'call', 'network', 'reload' ]);
	}
	if (routing.changed_network || routing.changed_firewall)
		uci = cursor(); // see apply(): committed deletions break iteration

	run([ 'ifdown', iface ]);
	let peer = find_peer(uci, iface);
	if (peer)
		uci.delete('network', peer);
	if (uci.get('network', iface) != null && uci.get('network', iface, 'vpn_type') == 'nordvpn')
		uci.delete('network', iface);
	uci.commit('network');

	if (name == 'main') {
		let all = uci.get_all('nordvpn', 'main');
		for (let k in all) {
			if (substr(k, 0, 1) == '.' || k == 'config_version')
				continue;
			uci.delete('nordvpn', 'main', k);
		}
		uci.commit('nordvpn');
		restore_wan_default();
		return { ok: true, reset: name, interface: iface };
	}

	uci.delete('nordvpn', name);
	uci.commit('nordvpn');
	restore_wan_default();
	return { ok: true, deleted: name, interface: iface };
}

return { set_credentials, clear_credentials, current_peer, restore_peer, write_relay, bring_up, verify_handshake, connect_one, apply, disconnect, create_instance, delete_instance, restore_wan_default };
