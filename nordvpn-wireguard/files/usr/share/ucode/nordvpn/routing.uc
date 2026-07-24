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

// ── Local subnets (steering bypass) ──────────────────────────────────
// A steered table's default swallows traffic to OTHER local subnets too, so
// LAN↔VLAN and LAN↔tunnel-services connectivity would silently die. Steering
// therefore maintains stamped bypass routes for every local IPv4 subnet.

function ip4_to_int(a) {
	let m = match(a, /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/);
	if (!m)
		return null;
	let o1 = int(m[1]), o2 = int(m[2]), o3 = int(m[3]), o4 = int(m[4]);
	if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255)
		return null;
	return ((o1 * 256 + o2) * 256 + o3) * 256 + o4;
}

function int_to_ip4(n) {
	return sprintf('%d.%d.%d.%d',
		(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
}

function mask_len(netmask) {
	let n = ip4_to_int(netmask);
	if (n == null)
		return null;
	let len = 0;
	while (len < 32 && (n & 0x80000000)) {
		len++;
		n = (n << 1) & 0xffffffff;
	}
	return (n & 0xffffffff) == 0 ? len : null;
}

// Normalized 'a.b.c.d/len' network of a uci route section, accepting both the
// CIDR target form and the separate target+netmask form. Null when unparsable.
function route_cidr(sec) {
	let t = '' + (sec.target || '');
	let addr = null, len = null;
	let m = match(t, /^([0-9.]+)\/([0-9]+)$/);
	if (m) {
		addr = m[1];
		len = int(m[2]);
	} else if (sec.netmask) {
		addr = t;
		len = mask_len('' + sec.netmask);
	} else {
		return null;
	}
	if (len == null || len < 0 || len > 32)
		return null;
	let ip = ip4_to_int(addr);
	if (ip == null)
		return null;
	let mask = (len == 0) ? 0 : ((0xffffffff << (32 - len)) & 0xffffffff);
	return sprintf('%s/%d', int_to_ip4(ip & mask), len);
}

// Every local IPv4 subnet as { target: 'a.b.c.d/len', iface: <logical name> },
// from the static config plus (when available) netifd's runtime state, which
// also covers DHCP-assigned networks and tunnels like a user WireGuard link.
// `skip` maps interface names to ignore (the nordvpn instances themselves —
// they all share the fixed NordLynx range).
function local_subnets(uci, skip) {
	let out = [];
	let seen = {};
	let add = function(name, addr, len) {
		if (name == 'loopback' || skip[name] || addr == null || len == null || len < 1 || len > 30)
			return;
		let ip = ip4_to_int(addr);
		if (ip == null)
			return;
		let mask = (0xffffffff << (32 - len)) & 0xffffffff;
		let target = sprintf('%s/%d', int_to_ip4(ip & mask), len);
		if (target == '10.5.0.0/16' || seen[target])
			return;
		seen[target] = 1;
		push(out, { target: target, iface: name });
	};

	uci.foreach('network', 'interface', function(sec) {
		if (sec.proto != 'static')
			return;
		let addrs = sec.ipaddr;
		if (type(addrs) != 'array')
			addrs = (addrs != null) ? [ addrs ] : [];
		for (let a in addrs) {
			let m = match('' + a, /^([0-9.]+)\/([0-9]+)$/);
			if (m)
				add(sec['.name'], m[1], int(m[2]));
			else if (sec.netmask)
				add(sec['.name'], '' + a, mask_len(sec.netmask));
		}
	});

	// User static routes in the main table (e.g. a subnet behind their own
	// WireGuard link, where the interface address is a /32) are local
	// destinations too — mirror them.
	uci.foreach('network', 'route', function(sec) {
		if (sec[MARK] == '1' || (sec.table != null && sec.table != ''))
			return;
		let c = route_cidr(sec);
		if (c) {
			let m = match(c, /^([0-9.]+)\/([0-9]+)$/);
			add(sec.interface, m[1], int(m[2]));
		}
	});

	// Subnets routed through the user's OWN WireGuard links (peer allowed_ips
	// with route_allowed_ips) — e.g. services behind a personal wg tunnel.
	uci.foreach('network', null, function(sec) {
		if (!sec['.type'] || index(sec['.type'], 'wireguard_') != 0)
			return;
		if (sec.route_allowed_ips != '1' || sec.interface == null || skip[sec.interface])
			return;
		let ips = sec.allowed_ips;
		if (type(ips) != 'array')
			ips = (ips != null) ? [ ips ] : [];
		for (let a in ips) {
			let m = match('' + a, /^([0-9.]+)\/([0-9]+)$/);
			if (m)
				add(sec.interface, m[1], int(m[2]));
		}
	});

	let d = run([ 'ubus', 'call', 'network.interface', 'dump' ]);
	if (d.code == 0) {
		let data;
		try {
			data = json(d.stdout);
		} catch (e) {
			data = null;
		}
		let dev2iface = {};
		for (let ifc in ((data ? data.interface : null) || [])) {
			if (ifc.l3_device)
				dev2iface[ifc.l3_device] = ifc.interface;
			for (let a in (ifc['ipv4-address'] || []))
				add(ifc.interface, a.address, a.mask);
		}

		// Pinned exception routes and foreign connected subnets in the main
		// table, any prefix length. netifd/scripted routes carry proto static,
		// hand-added `ip route add` ones proto boot, and connected subnets of
		// interfaces netifd does not manage itself (docker bridges etc.) carry
		// proto kernel — mirror all three so steered clients keep every local
		// or pinned destination. Only on-device (needs ubus for the mapping).
		let pin_lines = [];
		for (let proto in [ 'static', 'boot', 'kernel' ]) {
			let rt = run([ 'ip', '-4', 'route', 'show', 'table', 'main', 'proto', proto ]);
			if (rt.code == 0)
				for (let l in split(trim(rt.stdout || ''), '\n'))
					push(pin_lines, l);
		}
		{
			for (let line in pin_lines) {
				let m = match(line, /^([0-9.]+(\/[0-9]+)?) +via +([0-9.]+) +dev +([^ ]+)/);
				let target = null, gw = null, dev = null;
				if (m) {
					target = m[1];
					gw = m[3];
					dev = m[4];
				} else {
					m = match(line, /^([0-9.]+(\/[0-9]+)?) +dev +([^ ]+)/);
					if (m) {
						target = m[1];
						dev = m[3];
					}
				}
				if (!target || target == 'default' || !dev2iface[dev] || skip[dev2iface[dev]])
					continue;
				if (index(target, '/') < 0)
					target += '/32';
				if (seen[target])
					continue;
				seen[target] = 1;
				push(out, { target: target, iface: dev2iface[dev], gateway: gw });
			}
		}
	}
	return out;
}

// Reconcile the stamped bypass routes of one instance with the desired subnet
// list. Subnets already covered by an unstamped user route in the same table
// are left to the user's route. Returns true on change.
function reconcile_local_routes(uci, iface, table, desired) {
	let changed = false;
	let have = [];
	let covered = {};
	uci.foreach('network', 'route', function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == 'steer_local' && sec.nordvpn_iface == iface) {
			push(have, { section: sec['.name'], target: sec.target, table: sec.table });
		} else if (sec[MARK] != '1' && sec.table == table) {
			let c = route_cidr(sec);
			if (c)
				covered[c] = true;
		}
	});
	for (let h in have) {
		// A user route for the same subnet wins over ours.
		let keep = (h.table == table) && !covered[h.target];
		if (keep) {
			keep = false;
			for (let d in desired)
				if (d.target == h.target)
					keep = true;
		}
		if (!keep) {
			uci.delete('network', h.section);
			changed = true;
		}
	}
	for (let d in desired) {
		let present = false;
		for (let h in have)
			if (h.target == d.target && h.table == table && !covered[h.target])
				present = true;
		if (covered[d.target] || present)
			continue;
		let sec = uci.add('network', 'route');
		uci.set('network', sec, 'interface', d.iface);
		uci.set('network', sec, 'target', d.target);
		if (d.gateway)
			uci.set('network', sec, 'gateway', d.gateway);
		uci.set('network', sec, 'table', table);
		uci.set('network', sec, MARK, '1');
		uci.set('network', sec, ROLE, 'steer_local');
		uci.set('network', sec, 'nordvpn_iface', iface);
		changed = true;
	}
	return changed;
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
	let steering = length(s.source_networks || []) > 0;
	// With steering active, extra user routes INSIDE the instance's table are
	// legitimate companions (e.g. a media→LAN route); only routes referencing
	// the interface itself signal a hand-built scheme. Without steering, a
	// table reference is the manual-mode signal it always was.
	let user_routes = count_user_routes(uci, iface, steering ? '' : s.routing_table);
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
	// A disabled instance releases all managed objects: an explicit Disable
	// means "give me normal networking back" (IPv6 included); the next apply
	// recreates everything. Missing `enabled` (test fixtures) counts as on.
	let active = (s.enabled == null) ? true : !!s.enabled;
	let auto = (det.mode == 'auto') && active;
	let steer = (det.mode == 'steered') && active;
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

	// 1c. Bypass routes for local subnets, so the steered default does not
	//     swallow LAN↔VLAN or LAN↔local-tunnel traffic. The nordvpn instances'
	//     own interfaces are excluded (they share the fixed NordLynx range).
	let locals = [];
	if (steer) {
		let skip = {};
		for (let n in _common.list_instances(uci))
			skip[_common.load_settings(uci, n).interface] = true;
		locals = local_subnets(uci, skip);
	}
	if (reconcile_local_routes(uci, iface, table || '', locals))
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
