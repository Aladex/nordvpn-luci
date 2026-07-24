#!/usr/bin/env ucode
// SPDX-License-Identifier: 0BSD
// rpcd ubus object 'nordvpn'. Thin glue over the backend modules with a fixed
// request schema per method. Read methods never mutate; write methods delegate
// to the shared apply/rotation workers. No secret is ever returned.

'use strict';

import { cursor } from 'uci';
const _common = require('nordvpn.common');
const validate_token = _common.validate_token,
      validate_instance = _common.validate_instance,
      load_settings = _common.load_settings,
      list_instances = _common.list_instances,
      cache_file_path = _common.cache_file_path;
const status = require('nordvpn.status').status;
const _apply = require('nordvpn.apply');
const apply = _apply.apply,
      set_credentials = _apply.set_credentials,
      create_instance = _apply.create_instance,
      delete_instance = _apply.delete_instance;
const _rotate = require('nordvpn.rotate');
const rotate = _rotate.rotate,
      read_state = _rotate.read_state,
      last_attempt_ts = _rotate.last_attempt_ts;
const next_rotation = require('nordvpn.service').next_rotation;
const detect_routing = require('nordvpn.routing').detect;
const _cache = require('nordvpn.cache');
const read_cache = _cache.read_cache,
      read_fetch_status = _cache.read_fetch_status,
      cache_is_stale = _cache.cache_is_stale,
      locations_tree = _cache.locations_tree,
      city_relays = _cache.city_relays;

const methods = {};

// Resolve and validate the requested instance name ('main' by default).
// Returns the name, or null when the section does not exist.
function req_instance(uci, request) {
	let a = (request && request.args) ? request.args : {};
	let name = (a.instance == null || a.instance == '') ? 'main' : validate_instance(a.instance);
	if (!name || uci.get('nordvpn', name) == null)
		return null;
	return name;
}

function build_status(uci, name) {
	let st = status(uci, name);
	let state = read_state(name);
	if (state && state.last_success)
		st.rotation.last_success = state.last_success;
	let s = load_settings(uci, name);
	st.rotation.next_run = next_rotation(s, last_attempt_ts(name), time());
	st.routing = detect_routing(uci, s, true);
	return st;
}

// ── Read methods ─────────────────────────────────────────────────────

methods.status = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return build_status(uci, name);
	}
};

methods.instances = {
	call: function() {
		let uci = cursor();
		let out = [];
		for (let name in list_instances(uci))
			push(out, build_status(uci, name));
		return { instances: out };
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
	args: { token: '', instance: '' },
	call: function(request) {
		let token = request.args ? request.args.token : null;
		if (!validate_token(token))
			return { error: 'invalid token format' };
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return set_credentials(uci, token, name);
	}
};

methods.apply = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return apply(uci, name);
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

methods.create_instance = {
	args: { instance: '' },
	call: function(request) {
		let a = request.args || {};
		return create_instance(cursor(), a.instance);
	}
};

methods.delete_instance = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return delete_instance(uci, name);
	}
};

methods.rotate_now = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return rotate(uci, name);
	}
};

return { nordvpn: methods };
