// SPDX-License-Identifier: 0BSD
// One-shot rotation worker. Builds the candidate set once, tries servers
// without replacement, binds the connectivity test to the tunnel, and restores
// the previously working peer if every candidate fails. Overlapping runs are
// prevented with a lock.

'use strict';

import { rand, srand } from 'math';
import { readfile } from 'fs';
import { cursor } from 'uci';
const _common = require('nordvpn.common');
const load_settings = _common.load_settings,
      cache_file_path = _common.cache_file_path,
      iso_ts = _common.iso_ts,
      atomic_write = _common.atomic_write,
      acquire_lock = _common.acquire_lock,
      release_lock = _common.release_lock,
      log = _common.log;
const read_cache = require('nordvpn.cache').read_cache;
const candidates = require('nordvpn.select').candidates;
const _apply = require('nordvpn.apply');
const bring_up = _apply.bring_up,
      current_peer = _apply.current_peer,
      restore_peer = _apply.restore_peer,
      connect_one = _apply.connect_one,
      verify_handshake = _apply.verify_handshake;

const ROTATE_LOCK = '/tmp/nordvpn_rotate.lock';
const ROTATE_STATE = '/tmp/nordvpn_rotate_state.json';

// Fisher-Yates shuffle (in a copy). Exported for testing.
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

// Ordered candidate list: matching relays, current gateway excluded, shuffled
// and capped at `limit`. Pure/testable.
function plan_candidates(cache, settings, current_gateway, limit) {
	let list = candidates(cache, settings.country_code, settings.city_code, settings.hop_mode);
	if (current_gateway)
		list = filter(list, function(r) { return r.hostname != current_gateway; });
	list = shuffle(list);
	if (limit && length(list) > limit)
		list = slice(list, 0, limit);
	return list;
}

// Last rotation state ({ last_attempt, last_success, server, updated_at }) or null.
function read_state() {
	let f = readfile(ROTATE_STATE);
	if (!f)
		return null;
	try {
		return json(f);
	} catch (e) {
		return null;
	}
}

// Merge fields into the persisted state and rewrite it atomically. Callers only
// touch the keys they own (the daemon writes last_attempt; the worker writes
// last_success + server), so neither clobbers the other's timestamp.
function record(fields) {
	let st = read_state() || {};
	for (let k in fields)
		st[k] = fields[k];
	st.updated_at = iso_ts();
	atomic_write(ROTATE_STATE, sprintf('%J', st));
	return st;
}

// Epoch of the last rotation attempt (0 when unknown). The daemon schedules from
// this persisted value instead of an in-memory counter, so a restart — e.g.
// after every config save — does not reset the rotation clock and fire again.
function last_attempt_ts() {
	let st = read_state();
	return (st && type(st.last_attempt) == 'int') ? st.last_attempt : 0;
}

// Record that a rotation was attempted at `ts`. The daemon calls this before it
// forks the worker so overlapping ticks cannot double-fire.
function mark_attempt(ts) {
	record({ last_attempt: ts });
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
		if (!connect_one(uci, iface, relay, s))
			continue;
		// Verify the tunnel by its WireGuard handshake, not by a ping routed
		// through it: NordVPN publishes dead endpoints, and a routed ping can
		// fail on a perfectly good server, which made rotation cycle servers.
		if (verify_handshake(iface, 5)) {
			record({ last_success: time(), server: relay.hostname });
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
function rotate(uci) {
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

return { shuffle, plan_candidates, read_state, record, last_attempt_ts, mark_attempt, rotate };
