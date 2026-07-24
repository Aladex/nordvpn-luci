// SPDX-License-Identifier: 0BSD
// Traffic-routing detection and enforcement. Detects whether the user manages
// routing themselves (custom routing table or static routes/rules referencing
// the VPN interface) and, only when automatic routing is enabled AND no manual
// scheme is detected, maintains the firewall zone, the kill-switch and
// IPv6-leak rules and the DNS override. Every object this module creates is
// stamped with `nordvpn_managed`/`nordvpn_role`, and only stamped objects are
// ever modified or removed — user configuration is never touched.

'use strict';

const _common = require('nordvpn.common');
const run = _common.run;

const MARK = 'nordvpn_managed';
const ROLE = 'nordvpn_role';
const VPN_DNS = '103.86.96.100 103.86.99.100';

// ── Small uci helpers ────────────────────────────────────────────────

// Normalize a zone/forwarding 'network' option (string or list) to an array.
function as_list(v) {
	if (v == null)
		return [];
	if (type(v) == 'array')
		return v;
	return split('' + v, ' ');
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

// Zone whose network list contains the interface: { name, section, managed }.
function find_zone_of(uci, iface) {
	let found = null;
	uci.foreach('firewall', 'zone', function(sec) {
		for (let n in as_list(sec.network)) {
			if (n == iface) {
				found = { name: sec.name, section: sec['.name'], managed: sec[MARK] == '1' };
				return false;
			}
		}
	});
	return found;
}

// Best-effort WAN zone: prefer a masquerading zone, fall back to name 'wan'.
function find_wan_zone(uci) {
	let masq = null, named = null;
	uci.foreach('firewall', 'zone', function(sec) {
		if (sec[MARK] == '1')
			return;
		if (sec.masq == '1' && !masq)
			masq = sec.name;
		if (sec.name == 'wan' && !named)
			named = sec.name;
	});
	return masq || named;
}

// Best-effort LAN zone: name 'lan', else a zone containing network 'lan'.
function find_lan_zone(uci) {
	let named = null, holding = null;
	uci.foreach('firewall', 'zone', function(sec) {
		if (sec[MARK] == '1')
			return;
		if (sec.name == 'lan' && !named)
			named = sec.name;
		for (let n in as_list(sec.network))
			if (n == 'lan' && !holding)
				holding = sec.name;
	});
	return named || holding;
}

// User (unstamped) static routes/rules referencing the interface or its table.
function count_user_routes(uci, iface, table) {
	let n = 0;
	let check = function(sec) {
		if (sec[MARK] == '1')
			return;
		if (sec.interface == iface)
			n++;
		else if (table && table != '' && sec.table == table)
			n++;
	};
	for (let t in [ 'route', 'route6', 'rule', 'rule6' ])
		uci.foreach('network', t, check);
	return n;
}

// Stamped firewall section (rule/forwarding/zone) with the given role, or null.
function find_managed(uci, sectype, role) {
	let found = null;
	uci.foreach('firewall', sectype, function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == role) {
			found = sec['.name'];
			return false;
		}
	});
	return found;
}

// True when the WAN has a default IPv6 route (potential leak path).
function wan_has_ipv6() {
	let r = run([ 'ip', '-6', 'route', 'show', 'default' ]);
	return r.code == 0 && length(trim(r.stdout || '')) > 0;
}

// ── Detection (read-only) ────────────────────────────────────────────

// Classify the routing situation for the UI and for enforce(). `runtime`
// enables checks that need external commands (disabled in offline tests).
function detect(uci, s, runtime) {
	let iface = s.interface;
	let zone = find_zone_of(uci, iface);
	let peer = find_peer(uci, iface);
	let user_routes = count_user_routes(uci, iface, s.routing_table);
	let manual = (s.routing_table != null && s.routing_table != '') || user_routes > 0;

	return {
		mode: manual ? 'manual' : (s.auto_routing ? 'auto' : 'none'),
		zone: zone ? zone.name : null,
		zone_managed: zone ? zone.managed : false,
		user_routes: user_routes,
		route_allowed_ips: peer ? (uci.get('network', peer, 'route_allowed_ips') == '1') : false,
		killswitch: find_managed(uci, 'rule', 'killswitch') != null,
		ipv6_block: find_managed(uci, 'rule', 'ipv6block') != null,
		wan_zone: find_wan_zone(uci),
		lan_zone: find_lan_zone(uci),
		ipv6_wan: runtime ? wan_has_ipv6() : null
	};
}

// ── Enforcement ──────────────────────────────────────────────────────

// Bring the stamped configuration in line with the settings. Creates objects
// only in automatic mode; removes ONLY stamped objects when their toggle (or
// automatic mode itself) is off. Does not commit — the caller owns the
// transaction. Returns { changed_network, changed_firewall, notes }.
function enforce(uci, s) {
	let notes = [];
	let cn = false, cf = false;
	let iface = s.interface;
	let det = detect(uci, s, false);
	let auto = s.auto_routing && det.mode != 'manual';
	let peer = find_peer(uci, iface);

	// 1. Default route via the tunnel (netifd routes for allowed_ips). Stamped
	//    on the interface so a user-set route_allowed_ips is never removed.
	if (auto) {
		if (peer && uci.get('network', peer, 'route_allowed_ips') != '1') {
			uci.set('network', peer, 'route_allowed_ips', '1');
			uci.set('network', iface, MARK + '_routing', '1');
			cn = true;
		}
	} else if (uci.get('network', iface, MARK + '_routing') == '1') {
		if (peer)
			uci.delete('network', peer, 'route_allowed_ips');
		uci.delete('network', iface, MARK + '_routing');
		cn = true;
		if (det.mode == 'manual')
			push(notes, 'manual routing detected; automatic default route removed');
	}

	// 2. Firewall zone + forwarding from the LAN zone.
	if (auto) {
		if (!det.zone) {
			let clash = false;
			uci.foreach('firewall', 'zone', function(sec) {
				if (sec.name == 'nordvpn') {
					clash = true;
					return false;
				}
			});
			if (clash) {
				push(notes, 'a firewall zone named nordvpn already exists; add the interface to a zone manually');
			} else {
				let z = uci.add('firewall', 'zone');
				uci.set('firewall', z, 'name', 'nordvpn');
				uci.set('firewall', z, 'input', 'REJECT');
				uci.set('firewall', z, 'output', 'ACCEPT');
				uci.set('firewall', z, 'forward', 'REJECT');
				uci.set('firewall', z, 'masq', '1');
				uci.set('firewall', z, 'mtu_fix', '1');
				uci.set('firewall', z, 'network', [ iface ]);
				uci.set('firewall', z, MARK, '1');
				uci.set('firewall', z, ROLE, 'zone');
				cf = true;
				det.zone = 'nordvpn';
			}
		}
		if (det.zone && !find_managed(uci, 'forwarding', 'forwarding')) {
			let has_fwd = false;
			uci.foreach('firewall', 'forwarding', function(sec) {
				if (sec.dest == det.zone) {
					has_fwd = true;
					return false;
				}
			});
			if (!has_fwd) {
				if (det.lan_zone) {
					let f = uci.add('firewall', 'forwarding');
					uci.set('firewall', f, 'src', det.lan_zone);
					uci.set('firewall', f, 'dest', det.zone);
					uci.set('firewall', f, MARK, '1');
					uci.set('firewall', f, ROLE, 'forwarding');
					cf = true;
				} else {
					push(notes, 'could not determine the LAN zone; add a forwarding to the VPN zone manually');
				}
			}
		}
	} else {
		let f = find_managed(uci, 'forwarding', 'forwarding');
		if (f) {
			uci.delete('firewall', f);
			cf = true;
		}
		let z = find_managed(uci, 'zone', 'zone');
		if (z) {
			uci.delete('firewall', z);
			cf = true;
		}
	}

	// 3. Kill switch: our own REJECT rule LAN->WAN. fw4 evaluates traffic rules
	//    before zone forwardings, so the user's forwardings stay untouched.
	let want_ks = auto && s.killswitch;
	let ks = find_managed(uci, 'rule', 'killswitch');
	if (want_ks && !ks) {
		if (det.lan_zone && det.wan_zone) {
			let r = uci.add('firewall', 'rule');
			uci.set('firewall', r, 'name', 'NordVPN kill switch');
			uci.set('firewall', r, 'src', det.lan_zone);
			uci.set('firewall', r, 'dest', det.wan_zone);
			uci.set('firewall', r, 'proto', 'all');
			uci.set('firewall', r, 'target', 'REJECT');
			uci.set('firewall', r, MARK, '1');
			uci.set('firewall', r, ROLE, 'killswitch');
			cf = true;
		} else {
			push(notes, 'could not determine the LAN/WAN zones; kill switch not installed');
		}
	} else if (!want_ks && ks) {
		uci.delete('firewall', ks);
		cf = true;
	}

	// 4. IPv6 leak block: same shape, family ipv6 only.
	let want_v6 = auto && s.block_ipv6;
	let v6 = find_managed(uci, 'rule', 'ipv6block');
	if (want_v6 && !v6) {
		if (det.lan_zone && det.wan_zone) {
			let r = uci.add('firewall', 'rule');
			uci.set('firewall', r, 'name', 'NordVPN IPv6 leak block');
			uci.set('firewall', r, 'family', 'ipv6');
			uci.set('firewall', r, 'src', det.lan_zone);
			uci.set('firewall', r, 'dest', det.wan_zone);
			uci.set('firewall', r, 'proto', 'all');
			uci.set('firewall', r, 'target', 'REJECT');
			uci.set('firewall', r, MARK, '1');
			uci.set('firewall', r, ROLE, 'ipv6block');
			cf = true;
		} else {
			push(notes, 'could not determine the LAN/WAN zones; IPv6 block not installed');
		}
	} else if (!want_v6 && v6) {
		uci.delete('firewall', v6);
		cf = true;
	}

	// 5. DNS override on the interface (stamped, netifd-managed lifecycle).
	let want_dns = auto && s.use_vpn_dns;
	if (want_dns && uci.get('network', iface, MARK + '_dns') != '1') {
		uci.set('network', iface, 'dns', split(VPN_DNS, ' '));
		uci.set('network', iface, MARK + '_dns', '1');
		cn = true;
	} else if (!want_dns && uci.get('network', iface, MARK + '_dns') == '1') {
		uci.delete('network', iface, 'dns');
		uci.delete('network', iface, MARK + '_dns');
		cn = true;
	}

	return { changed_network: cn, changed_firewall: cf, notes: notes };
}

return { detect, enforce, find_wan_zone, find_lan_zone, count_user_routes };
