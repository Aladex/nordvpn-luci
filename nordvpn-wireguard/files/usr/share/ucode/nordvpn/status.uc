// SPDX-License-Identifier: 0BSD
// Runtime status for the UI/RPC. Combines UCI config, netifd (ubus) interface
// state and the WireGuard handshake age. Never returns any secret.

'use strict';

import { connect } from 'ubus';
const _common = require('nordvpn.common');
const load_settings = _common.load_settings,
      validate_wg_key = _common.validate_wg_key,
      run = _common.run;

// Newest WireGuard handshake age in seconds for device `dev`, or null.
function handshake_age(dev) {
	let res = run([ 'wg', 'show', dev, 'latest-handshakes' ]);
	if (res.code != 0)
		return null;
	let best = 0;
	for (let line in split(trim(res.stdout || ''), '\n')) {
		let parts = split(line, '\t');
		if (length(parts) >= 2) {
			let ts = int(parts[1]);
			if (ts > best)
				best = ts;
		}
	}
	if (best == 0)
		return null;
	let age = time() - best;
	return age < 0 ? 0 : age;
}

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

// Build the runtime status object for one instance ('main' by default).
// `next_run` is filled in by the caller/scheduler.
function status(uci, instance) {
	let s = load_settings(uci, instance);
	let iface = s.interface;

	let has_key = validate_wg_key(uci.get('network', iface, 'private_key')) != null;
	let peer = find_peer(uci, iface);
	let endpoint_host = peer ? uci.get('network', peer, 'endpoint_host') : null;
	let endpoint_port = peer ? uci.get('network', peer, 'endpoint_port') : null;

	let result = {
		instance: s.name,
		configured: has_key,
		// Administrative master switch, distinct from the runtime state: a
		// disabled instance is deliberately down, not merely disconnected. The UI
		// keys button visibility (Enable vs Reconnect/Disable) on this.
		enabled: s.enabled,
		// A pinned server disables rotation, so the UI hides "Rotate now".
		fixed: (s.fixed_server && s.fixed_server != '') ? true : false,
		state: has_key ? 'disconnected' : 'not_configured',
		interface: iface,
		location: {
			country: uci.get('network', iface, 'nordvpn_country_code'),
			// Prefer the connected server's actual location (stored on every
			// apply/rotate) over the configured selection, which is empty when
			// the city is on Automatic.
			city: uci.get('network', iface, 'nordvpn_location') ||
				uci.get('network', iface, 'nordvpn_city_code')
		},
		gateway: peer ? uci.get('network', peer, 'nordvpn_gateway') : null,
		endpoint: endpoint_host ? (endpoint_host + ':' + (endpoint_port || '')) : null,
		latest_handshake_seconds: null,
		rotation: {
			enabled: s.rotation_enabled,
			mode: s.rotation_mode,
			interval: s.rotation_interval,
			time: s.rotation_time,
			next_run: null
		}
	};

	if (!has_key)
		return result;

	// Interface up? and its L3 device name, via netifd.
	let ifup = false, l3dev = iface;
	let ub = connect();
	if (ub) {
		let st = ub.call('network.interface.' + iface, 'status', {});
		if (st) {
			ifup = st.up ? true : false;
			if (st.l3_device)
				l3dev = st.l3_device;
		}
	}

	let hs = handshake_age(l3dev);
	if (hs != null)
		result.latest_handshake_seconds = hs;

	if (!ifup)
		result.state = 'disconnected';
	else if (hs == null)
		result.state = 'connecting';
	else if (hs <= 180)
		result.state = 'connected';
	else
		result.state = 'degraded';

	return result;
}

return { status };
