// SPDX-License-Identifier: 0BSD
// Traffic-routing detection and enforcement. Detects whether the user manages
// routing themselves (custom routing table or static routes/rules referencing
// the VPN interface) and, only when automatic routing is enabled AND no manual
// scheme is detected, maintains the firewall zone, the kill-switch and
// IPv6-leak rules and the DNS override. Every object this module creates is
// stamped with `nordvpn_managed`/`nordvpn_role`, and only stamped objects are
// ever modified or removed — user configuration is never touched.

'use strict';

import { readfile } from 'fs';
const _common = require('nordvpn.common');
const run = _common.run,
      atomic_write = _common.atomic_write;

const MARK = 'nordvpn_managed';
const ROLE = 'nordvpn_role';
const VPN_DNS = '103.86.96.100 103.86.99.100';
const RT_TABLES = '/etc/iproute2/rt_tables';

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

// Stamped firewall section (rule/forwarding/zone) with the given role, or
// null. Zone/forwarding objects are per-interface (pass `iface`); the kill
// switch and IPv6 block are global (leave `iface` null).
function find_managed(uci, sectype, role, iface) {
	let found = null;
	uci.foreach('firewall', sectype, function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == role && (iface == null || sec.nordvpn_iface == iface)) {
			found = sec['.name'];
			return false;
		}
	});
	return found;
}

// netifd resolves named routing tables through /etc/iproute2/rt_tables; an
// unregistered name makes ip4table and lookup rules silently inert. Register
// the instance's table with a stamped line (best effort). Numeric tables and
// already-registered names need nothing.
function ensure_rt_table(name) {
	if (match(name, /^[0-9]+$/))
		return true;
	let data = readfile(RT_TABLES) || '';
	let used = {};
	for (let line in split(data, '\n')) {
		let m = match(line, /^[ \t]*([0-9]+)[ \t]+([^ \t#]+)/);
		if (!m)
			continue;
		if (m[2] == name)
			return true;
		used[m[1]] = true;
	}
	for (let n = 100; n <= 252; n++) {
		if (used['' + n])
			continue;
		return atomic_write(RT_TABLES,
			data + (length(data) && substr(data, -1) != '\n' ? '\n' : '') +
			sprintf('%d\t%s # %s\n', n, name, MARK));
	}
	return false;
}

// Remove ONLY a stamped rt_tables line for `name`; user entries are kept.
function drop_rt_table(name) {
	if (name == null || name == '' || match(name, /^[0-9]+$/))
		return;
	let data = readfile(RT_TABLES);
	if (!data || index(data, MARK) < 0)
		return;
	let kept = [];
	let changed = false;
	for (let line in split(data, '\n')) {
		let m = match(line, /^[ \t]*[0-9]+[ \t]+([^ \t#]+)[ \t]*#[ ]*nordvpn_managed/);
		if (m && m[1] == name) {
			changed = true;
			continue;
		}
		push(kept, line);
	}
	if (changed)
		atomic_write(RT_TABLES, join('\n', kept));
}

// True when the WAN has a default IPv6 route (potential leak path).
function wan_has_ipv6() {
	let r = run([ 'ip', '-6', 'route', 'show', 'default' ]);
	return r.code == 0 && length(trim(r.stdout || '')) > 0;
}

// Logical networks a user could steer through an instance: every interface
// section except loopback and WireGuard tunnels.
function available_networks(uci) {
	let out = [];
	uci.foreach('network', 'interface', function(sec) {
		if (sec['.name'] == 'loopback' || sec.proto == 'wireguard')
			return;
		push(out, sec['.name']);
	});
	return out;
}

// Stamped netifd rule sections (rule/rule6) of one instance and role.
function find_managed_rules(uci, sectype, role, iface) {
	let out = [];
	uci.foreach('network', sectype, function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == role && sec.nordvpn_iface == iface)
			push(out, { section: sec['.name'], net: sec['in'] });
	});
	return out;
}

// Reconcile stamped netifd rules with the desired source-network list:
// delete stamped rules for nets no longer wanted, create missing ones.
// `mkopts(net)` returns the option map for a new rule. Returns true on change.
function reconcile_rules(uci, sectype, role, iface, want_nets, mkopts) {
	let changed = false;
	let have = find_managed_rules(uci, sectype, role, iface);
	for (let r in have) {
		if (index(want_nets, r.net) < 0) {
			uci.delete('network', r.section);
			changed = true;
		}
	}
	for (let net in want_nets) {
		let present = false;
		for (let r in have)
			if (r.net == net)
				present = true;
		if (!present) {
			let sec = uci.add('network', sectype);
			let opts = mkopts(net);
			for (let k in opts)
				uci.set('network', sec, k, opts[k]);
			uci.set('network', sec, MARK, '1');
			uci.set('network', sec, ROLE, role);
			uci.set('network', sec, 'nordvpn_iface', iface);
			changed = true;
		}
	}
	return changed;
}

// Reconcile stamped firewall forwardings (into the instance zone) with the
// desired source-zone list. Returns true on change.
function reconcile_forwardings(uci, iface, dest_zone, want_srcs) {
	let changed = false;
	let have = [];
	uci.foreach('firewall', 'forwarding', function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == 'forwarding' && sec.nordvpn_iface == iface)
			push(have, { section: sec['.name'], src: sec.src });
	});
	for (let f in have) {
		if (index(want_srcs, f.src) < 0) {
			uci.delete('firewall', f.section);
			changed = true;
		}
	}
	for (let src in want_srcs) {
		let present = false;
		for (let f in have)
			if (f.src == src)
				present = true;
		if (!present) {
			let sec = uci.add('firewall', 'forwarding');
			uci.set('firewall', sec, 'src', src);
			uci.set('firewall', sec, 'dest', dest_zone);
			uci.set('firewall', sec, MARK, '1');
			uci.set('firewall', sec, ROLE, 'forwarding');
			uci.set('firewall', sec, 'nordvpn_iface', iface);
			changed = true;
		}
	}
	return changed;
}

// ── Detection (read-only) ────────────────────────────────────────────

// Classify the routing situation for the UI and for enforce(). `runtime`
// enables checks that need external commands (disabled in offline tests).
// Modes: 'manual'  — unstamped user routes/rules reference the interface or
//                    its table, or a table is set without steering: never touch;
//        'auto'    — route everything (auto_routing);
//        'steered' — route the configured source networks via the instance table;
//        'none'    — tunnel only, no managed routing.
function detect(uci, s, runtime) {
	let iface = s.interface;
	let zone = find_zone_of(uci, iface);
	let peer = find_peer(uci, iface);
	let user_routes = count_user_routes(uci, iface, s.routing_table);
	let steering = length(s.source_networks || []) > 0;
	let manual = user_routes > 0 ||
		(!steering && s.routing_table != null && s.routing_table != '');

	return {
		mode: manual ? 'manual' : (s.auto_routing ? 'auto' : (steering ? 'steered' : 'none')),
		zone: zone ? zone.name : null,
		zone_managed: zone ? zone.managed : false,
		user_routes: user_routes,
		source_networks: s.source_networks || [],
		route_allowed_ips: peer ? (uci.get('network', peer, 'route_allowed_ips') == '1') : false,
		killswitch: find_managed(uci, 'rule', 'killswitch') != null ||
			length(find_managed_rules(uci, 'rule', 'steer_ks', iface)) > 0,
		ipv6_block: find_managed(uci, 'rule', 'ipv6block') != null ||
			length(find_managed_rules(uci, 'rule6', 'steer_v6', iface)) > 0,
		wan_zone: find_wan_zone(uci),
		lan_zone: find_lan_zone(uci),
		networks: available_networks(uci),
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
	let auto = (det.mode == 'auto');
	let steer = (det.mode == 'steered');
	if (steer && (s.routing_table == null || s.routing_table == '')) {
		push(notes, 'steering needs a routing table; set one for this instance');
		steer = false;
	}
	let managed = auto || steer;
	let peer = find_peer(uci, iface);

	// 1. Routes via the tunnel (netifd routes for allowed_ips; they land in the
	//    instance's ip4table when a routing table is set). Stamped on the
	//    interface so a user-set route_allowed_ips is never removed.
	if (managed) {
		// Stamp the interface even before the first peer exists — write_relay
		// propagates the stamp to route_allowed_ips when it creates the peer.
		if (uci.get('network', iface, MARK + '_routing') != '1') {
			uci.set('network', iface, MARK + '_routing', '1');
			cn = true;
		}
		if (peer && uci.get('network', peer, 'route_allowed_ips') != '1') {
			uci.set('network', peer, 'route_allowed_ips', '1');
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

	// 1b. Steering rules: per source network, a lookup rule into the instance
	//     table, plus prohibit rules that act as kill switch (IPv4, only when
	//     enabled) and IPv6 leak block (the tunnel carries no IPv6). Prohibit
	//     sits between the lookup and the main table, so it only fires when
	//     the tunnel's table cannot serve the traffic.
	let steer_nets = steer ? s.source_networks : [];
	let table = s.routing_table;
	if (steer) {
		if (!ensure_rt_table(table))
			push(notes, 'could not register routing table ' + table + ' in ' + RT_TABLES);
	} else {
		drop_rt_table(s.routing_table);
	}
	if (reconcile_rules(uci, 'rule', 'steer_lookup', iface, steer_nets, function(net) {
		return { 'in': net, lookup: table, priority: '20000' };
	}))
		cn = true;
	if (reconcile_rules(uci, 'rule', 'steer_ks', iface, (steer && s.killswitch) ? steer_nets : [], function(net) {
		return { 'in': net, action: 'prohibit', priority: '21000' };
	}))
		cn = true;
	if (reconcile_rules(uci, 'rule6', 'steer_v6', iface, (steer && s.block_ipv6) ? steer_nets : [], function(net) {
		return { 'in': net, action: 'prohibit', priority: '21000' };
	}))
		cn = true;

	// 2. Firewall zone (named after the interface, one per instance) and
	//    forwardings into it from the source zones: the LAN zone in auto mode,
	//    the zones holding the steered networks in steered mode. Sources
	//    already covered by an unstamped user forwarding are skipped.
	if (managed) {
		if (!det.zone) {
			let clash = false;
			uci.foreach('firewall', 'zone', function(sec) {
				if (sec.name == iface) {
					clash = true;
					return false;
				}
			});
			if (clash) {
				push(notes, 'a firewall zone named ' + iface + ' already exists; add the interface to a zone manually');
			} else {
				let z = uci.add('firewall', 'zone');
				uci.set('firewall', z, 'name', iface);
				uci.set('firewall', z, 'input', 'REJECT');
				uci.set('firewall', z, 'output', 'ACCEPT');
				uci.set('firewall', z, 'forward', 'REJECT');
				uci.set('firewall', z, 'masq', '1');
				uci.set('firewall', z, 'mtu_fix', '1');
				uci.set('firewall', z, 'network', [ iface ]);
				uci.set('firewall', z, MARK, '1');
				uci.set('firewall', z, ROLE, 'zone');
				uci.set('firewall', z, 'nordvpn_iface', iface);
				cf = true;
				det.zone = iface;
			}
		}
		if (det.zone) {
			let want_srcs = [];
			if (auto) {
				if (det.lan_zone)
					push(want_srcs, det.lan_zone);
				else
					push(notes, 'could not determine the LAN zone; add a forwarding to the VPN zone manually');
			} else {
				for (let net in steer_nets) {
					let z = find_zone_of(uci, net);
					if (!z)
						push(notes, 'network ' + net + ' is in no firewall zone; add a forwarding to the VPN zone manually');
					else if (index(want_srcs, z.name) < 0)
						push(want_srcs, z.name);
				}
			}
			let filtered = [];
			for (let src in want_srcs) {
				let covered = false;
				uci.foreach('firewall', 'forwarding', function(sec) {
					if (sec[MARK] != '1' && sec.dest == det.zone && sec.src == src) {
						covered = true;
						return false;
					}
				});
				if (!covered)
					push(filtered, src);
			}
			if (reconcile_forwardings(uci, iface, det.zone, filtered))
				cf = true;
		}
	} else {
		if (reconcile_forwardings(uci, iface, det.zone || '', []))
			cf = true;
		let z = find_managed(uci, 'zone', 'zone', iface);
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
	let want_dns = managed && s.use_vpn_dns;
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
