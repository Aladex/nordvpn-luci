#!/usr/bin/env ucode
// SPDX-License-Identifier: 0BSD
// rpcd ubus object 'nordvpn'. Thin glue over the backend modules with a fixed
// request schema per method. Read methods never mutate; write methods delegate
// to the shared apply/rotation workers. No secret is ever returned.

'use strict';

import { cursor } from 'uci';
import { validate_token, load_settings, cache_file_path } from 'nordvpn.common';
import { status } from 'nordvpn.status';
import { apply, set_credentials } from 'nordvpn.apply';
import { rotate, read_state } from 'nordvpn.rotate';
import { read_cache, read_fetch_status, cache_is_stale } from 'nordvpn.cache';

const methods = {};

// ── Read methods ─────────────────────────────────────────────────────

methods.status = {
	call: function() {
		let st = status(cursor());
		let state = read_state();
		if (state && state.last_success)
			st.rotation.last_success = state.last_success;
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
			countries: cache.countries,
			stats: cache.stats,
			cache_info: cache.cache_info,
			cached_at: cache.cached_at
		};
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
