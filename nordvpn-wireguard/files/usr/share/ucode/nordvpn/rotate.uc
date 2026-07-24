// SPDX-License-Identifier: 0BSD
// One-shot rotation worker. Builds the candidate set once, tries servers
// without replacement, binds the connectivity test to the tunnel, and restores
// the previously working peer if every candidate fails. Overlapping runs are
// prevented with a lock.

'use strict';

import { rand, srand } from 'math';
import { readfile } from 'fs';
import { cursor } from 'uci';
import {
	load_settings, cache_file_path, ping_through, iso_ts, atomic_write,
	acquire_lock, release_lock, run, log
} from 'nordvpn.common';
import { read_cache } from 'nordvpn.cache';
import { candidates } from 'nordvpn.select';
import { write_relay, bring_up, current_peer, restore_peer } from 'nordvpn.apply';

const ROTATE_LOCK = '/tmp/nordvpn_rotate.lock';
const ROTATE_STATE = '/tmp/nordvpn_rotate_state.json';
const SETTLE_SECONDS = 3;

// Fisher-Yates shuffle (in a copy). Exported for testing.
export function shuffle(list) {
	let a = [ ...list ];
	for (let i = length(a) - 1; i > 0; i--) {
		let j = rand() % (i + 1);
		let t = a[i]; a[i] = a[j]; a[j] = t;
	}
	return a;
}

// Ordered candidate list: matching relays, current gateway excluded, shuffled
// and capped at `limit`. Pure/testable.
export function plan_candidates(cache, settings, current_gateway, limit) {
	let list = candidates(cache, settings.country_code, settings.city_code, settings.hop_mode);
	if (current_gateway)
		list = filter(list, function(r) { return r.hostname != current_gateway; });
	list = shuffle(list);
	if (limit && length(list) > limit)
		list = slice(list, 0, limit);
	return list;
}

// Last rotation state ({ last_success, server, updated_at }) or null.
export function read_state() {
	let f = readfile(ROTATE_STATE);
	if (!f)
		return null;
	try {
		return json(f);
	} catch (e) {
		return null;
	}
}

function write_state(obj) {
	obj.updated_at = iso_ts();
	atomic_write(ROTATE_STATE, sprintf('%J', obj));
}

function rotate_inner(uci) {
	let s = load_settings(uci);
	if (s.fixed_server && s.fixed_server != '')
		return { skipped: true, reason: 'fixed server configured' };

	let iface = s.interface;
	let cache = read_cache(cache_file_path(s));
	if (!cache)
		return { error: 'server list not available; refresh the cache first' };

	srand(time());
	let saved = current_peer(uci, iface);
	let current_gw = saved ? saved.gateway : null;
	let plan = plan_candidates(cache, s, current_gw, s.max_retries);
	if (length(plan) == 0)
		return { error: 'no candidate servers for the current selection' };

	for (let relay in plan) {
		write_relay(uci, iface, relay, s);
		uci.commit('network');
		if (!bring_up(iface))
			continue;
		run([ 'sleep', '' + SETTLE_SECONDS ]);
		if (ping_through(iface, s.ping_count, s.ping_timeout)) {
			write_state({ last_success: time(), server: relay.hostname });
			log('rotated to ' + relay.hostname);
			return { ok: true, server: relay.hostname };
		}
	}

	// Every candidate failed — roll back to the last working peer.
	if (saved) {
		restore_peer(uci, iface, saved);
		uci.commit('network');
		bring_up(iface);
	}
	return { error: 'no working server found', restored: saved != null };
}

// Public entry point: serialize with any other rotation via a lock.
export function rotate(uci) {
	uci = uci || cursor();
	let lock = acquire_lock(ROTATE_LOCK, 300);
	if (!lock)
		return { skipped: true, reason: 'rotation already running' };

	let res;
	try {
		res = rotate_inner(uci);
	} catch (e) {
		res = { error: 'rotation error: ' + e };
	}
	release_lock(lock);
	return res;
}
