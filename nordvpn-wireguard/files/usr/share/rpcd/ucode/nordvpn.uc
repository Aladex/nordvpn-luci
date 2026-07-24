#!/usr/bin/env ucode
// SPDX-License-Identifier: 0BSD
// rpcd ubus object 'nordvpn'. Thin glue over the backend modules with a fixed
// request schema per method. Read methods never mutate; write methods delegate
// to the shared apply/rotation workers. No secret is ever returned.

'use strict';

import { cursor } from 'uci';
const _common = require('nordvpn.common');
const validate_token = _common.validate_token,
      load_settings = _common.load_settings,
      cache_file_path = _common.cache_file_path;
const status = require('nordvpn.status').status;
const _apply = require('nordvpn.apply');
const apply = _apply.apply, set_credentials = _apply.set_credentials;
const _rotate = require('nordvpn.rotate');
const rotate = _rotate.rotate,
      read_state = _rotate.read_state,
      last_attempt_ts = _rotate.last_attempt_ts;
const next_rotation = require('nordvpn.service').next_rotation;
const _cache = require('nordvpn.cache');
const read_cache = _cache.read_cache,
      read_fetch_status = _cache.read_fetch_status,
      cache_is_stale = _cache.cache_is_stale,
      locations_tree = _cache.locations_tree,
      city_relays = _cache.city_relays;

const methods = {};

// ── Read methods ─────────────────────────────────────────────────────

methods.status = {
	call: function() {
		let uci = cursor();
		let st = status(uci);
		let state = read_state();
		if (state && state.last_success)
			st.rotation.last_success = state.last_success;
		st.rotation.next_run = next_rotation(load_settings(uci), last_attempt_ts(), time());
		return st;
	}
};

methods.locations = {
	call: function() {
		let s = load_settings(cursor());
		let path = cache_file_path(s);
		let cache = read_cache(path);
		if (!cache)
			return { available: false, state: 'missing' };
		return {
			available: true,
			state: cache_is_stale(path) ? 'stale' : 'ready',
			countries: locations_tree(cache),
			stats: cache.stats,
			cache_info: cache.cache_info,
			cached_at: cache.cached_at
		};
	}
};

methods.servers = {
	args: { country: '', city: '', hop_mode: '' },
	call: function(request) {
		let a = request.args || {};
		let cache = read_cache(cache_file_path(load_settings(cursor())));
		if (!cache)
			return { relays: [] };
		return { relays: city_relays(cache, a.country, a.city, a.hop_mode) };
	}
};

methods.refresh_status = {
	call: function() {
		return read_fetch_status() || { state: 'idle' };
	}
};

// ── Write methods ────────────────────────────────────────────────────

methods.set_credentials = {
	args: { token: '' },
	call: function(request) {
		let token = request.args ? request.args.token : null;
		if (!validate_token(token))
			return { error: 'invalid token format' };
		return set_credentials(cursor(), token);
	}
};

methods.apply = {
	call: function() {
		return apply(cursor());
	}
};

methods.refresh_locations = {
	call: function() {
		let running = read_fetch_status();
		if (running && running.state == 'running')
			return { job: running.started_at, already_running: true };
		// Detached one-shot worker; fixed command, no user input, no shell injection.
		system('/usr/bin/nordvpn-cache-update >/dev/null 2>&1 &');
		return { job: '' + time(), started: true };
	}
};

methods.rotate_now = {
	call: function() {
		return rotate(cursor());
	}
};

return { nordvpn: methods };
