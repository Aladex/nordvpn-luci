// SPDX-License-Identifier: 0BSD
// Server-list cache/API module for nordvpn-wireguard. Handles NordVPN API
// pagination, server normalization (country/city/relay), multihop
// classification, atomic cache writes, a single-writer lock and a schema
// version. Shared by the cache-update worker, the rotation worker and rpcd.

'use strict';

import { readfile } from 'fs';
const _common = require('nordvpn.common');
const open_cmd = _common.open_cmd,
      SERVERS_URL = _common.SERVERS_URL,
      PAGE_SIZE = _common.PAGE_SIZE,
      MAX_PAGES = _common.MAX_PAGES,
      DEFAULT_PORT = _common.DEFAULT_PORT,
      CACHE_MAX_AGE = _common.CACHE_MAX_AGE,
      CACHE_SCHEMA_VERSION = _common.CACHE_SCHEMA_VERSION,
      FETCH_STATUS_FILE = _common.FETCH_STATUS_FILE,
      CACHE_LOCK_FILE = _common.CACHE_LOCK_FILE,
      relay_kind = _common.relay_kind,
      atomic_write = _common.atomic_write,
      acquire_lock = _common.acquire_lock,
      release_lock = _common.release_lock,
      iso_ts = _common.iso_ts,
      log = _common.log;

const MAX_RESPONSE = 16 * 1024 * 1024; // hard cap per API response
const CONNECT_TIMEOUT = 15;
const TOTAL_TIMEOUT = 60;

// ── JSON / HTTP helpers ──────────────────────────────────────────────

function safe_json(str) {
	try {
		return json(str);
	} catch (e) {
		return null;
	}
}

// Fetch a URL with curl (argv array, no shell) and return the body, bounded to
// MAX_RESPONSE bytes. Returns { ok, body, error }.
function http_get(url) {
	let argv = [
		'curl', '-g', '-s', '-S',
		'--connect-timeout', '' + CONNECT_TIMEOUT,
		'--max-time', '' + TOTAL_TIMEOUT,
		'-H', 'Accept: application/json',
		url
	];
	let proc = open_cmd(argv, 'r');
	if (!proc)
		return { ok: false, error: 'failed to start curl' };

	let body = '';
	while (length(body) < MAX_RESPONSE) {
		let chunk = proc.read(65536);
		if (chunk == null || chunk == '')
			break;
		body += chunk;
	}
	let code = proc.close();

	if (length(body) >= MAX_RESPONSE)
		return { ok: false, error: 'response exceeded size limit' };
	if (code != 0)
		return { ok: false, error: 'curl exit ' + code };
	return { ok: true, body: body };
}

// ── Fetch-status file (progress for the UI) ──────────────────────────

function write_fetch_status(status) {
	status.updated_at = iso_ts();
	return atomic_write(FETCH_STATUS_FILE, sprintf('%J', status));
}

function read_fetch_status() {
	let data = readfile(FETCH_STATUS_FILE);
	if (!data)
		return null;
	return safe_json(data);
}

// ── Normalization ────────────────────────────────────────────────────

function new_accumulator() {
	return {
		country_index: {},
		location_index: {},
		country_list: [],
		stats: { countries: 0, cities: 0, gateways: 0, servers_seen: 0 }
	};
}

function ensure_country(acc, country_name, country_code) {
	if (!acc.country_index[country_name]) {
		let c = {
			code: country_code,
			name: country_name,
			display_name: country_name,
			cities: [],
			gateway_count: 0
		};
		acc.country_index[country_name] = c;
		push(acc.country_list, c);
	}
	return acc.country_index[country_name];
}

function ensure_city(acc, country, loc_code, city_name, lat, lon, country_code) {
	if (!acc.location_index[loc_code]) {
		let city = {
			code: loc_code,
			name: city_name,
			country: country.name,
			country_code: country_code,
			latitude: lat || 0,
			longitude: lon || 0,
			relays: [],
			gateway_count: 0
		};
		acc.location_index[loc_code] = city;
		push(country.cities, city);
	}
	return acc.location_index[loc_code];
}

function extract_public_key(server) {
	let techs = server.technologies;
	if (type(techs) != 'array')
		return null;
	for (let tech in techs) {
		if (tech.identifier == 'wireguard_udp') {
			let md = tech.metadata;
			if (type(md) == 'array')
				for (let meta in md)
					if (meta.name == 'public_key')
						return meta.value;
			return null;
		}
	}
	return null;
}

// Add one raw API server object to the accumulator.
function add_server(acc, server) {
	acc.stats.servers_seen++;

	let locs = server.locations;
	if (type(locs) != 'array' || length(locs) == 0)
		return;
	let loc = locs[0];
	let cinfo = loc.country;
	if (!cinfo)
		return;

	let country_name = cinfo.name;
	let country_code = lc(cinfo.code || '');
	let city_name = (cinfo.city && cinfo.city.name) ? cinfo.city.name : 'Unknown';
	let location_code = country_code + '-' + replace(lc(city_name), /[^a-z0-9]/g, '');

	let public_key = extract_public_key(server);
	if (!public_key)
		return;

	let country = ensure_country(acc, country_name, country_code);
	let city = ensure_city(acc, country, location_code, city_name,
		loc.latitude, loc.longitude, country_code);

	let hostname = server.hostname || '';
	let friendly = server.name || '';

	// Multihop: hostname cc1-cc2##.nordvpn.com, or name "CountryA - CountryB #".
	// POSIX ERE only ([.] for literal dots; no \s/\w/non-greedy).
	let entry_code = null, entry_name = null;
	let hm = match(hostname, /^([a-z][a-z])-([a-z][a-z])[0-9]+[.]nordvpn[.]com$/);
	if (hm) {
		entry_code = hm[1];
	} else if (friendly) {
		let nm = match(friendly, /^ *([A-Za-z0-9 ]+)-([A-Za-z0-9 ]+)#/);
		if (nm)
			entry_name = trim(nm[1]);
	}

	let multihop = false;
	if (entry_code && entry_code != country_code)
		multihop = true;
	else if (entry_name && lc(entry_name) != lc(country_name))
		multihop = true;

	// Onion Over VPN: hostname cc-onionNN.nordvpn.com (exit through Tor).
	// Kept out of both the single and multihop pools so it is an explicit choice.
	let onion = false;
	if (match(hostname, /^[a-z][a-z]-onion[0-9]+[.]nordvpn[.]com$/))
		onion = true;
	else if (friendly && match(friendly, / Onion #/))
		onion = true;

	push(city.relays, {
		hostname: hostname,
		ip_address: server.station || '',
		name: friendly,
		public_key: public_key,
		load: server.load || 0,
		location: location_code,
		port: DEFAULT_PORT,
		active: true,
		multihop: multihop,
		onion: onion,
		entry_country_code: entry_code,
		entry_country: entry_name || (entry_code ? uc(entry_code) : null),
		exit_country_code: country_code,
		exit_country: country_name
	});
	city.gateway_count++;
	acc.stats.gateways++;
}

function finalize(acc) {
	let filtered = [];
	for (let country in acc.country_list) {
		let valid = [];
		country.gateway_count = 0;
		for (let city in country.cities) {
			if (length(city.relays) > 0) {
				sort(city.relays, function(a, b) {
					return (a.name < b.name) ? -1 : (a.name > b.name) ? 1 : 0;
				});
				push(valid, city);
				country.gateway_count += length(city.relays);
				acc.stats.cities++;
			}
		}
		sort(valid, function(a, b) {
			return (a.name < b.name) ? -1 : (a.name > b.name) ? 1 : 0;
		});
		country.cities = valid;
		if (length(valid) > 0)
			push(filtered, country);
	}
	sort(filtered, function(a, b) {
		return (a.name < b.name) ? -1 : (a.name > b.name) ? 1 : 0;
	});
	acc.stats.countries = length(filtered);

	return {
		countries: filtered,
		stats: acc.stats,
		source: SERVERS_URL,
		generated_at: iso_ts()
	};
}

// Trimmed country/city tree for the UI (no per-relay data). Small enough to
// return over ubus, which caps message size — the full list is multi-MB.
function locations_tree(cache) {
	let out = [];
	if (!cache || type(cache.countries) != 'array')
		return out;
	for (let c in cache.countries) {
		let cities = [], cs = 0, cm = 0, co = 0;
		for (let city in c.cities) {
			let s = 0, m = 0, o = 0;
			for (let r in city.relays) {
				let k = relay_kind(r);
				if (k == 'multihop')
					m++;
				else if (k == 'onion')
					o++;
				else
					s++;
			}
			push(cities, { code: city.code, name: city.name, single: s, multi: m, onion: o });
			cs += s;
			cm += m;
			co += o;
		}
		push(out, { code: c.code, name: c.name, single: cs, multi: cm, onion: co, cities: cities });
	}
	return out;
}

// Trimmed relay list for one city, optionally filtered by hop mode.
function city_relays(cache, country_code, city_code, hop_mode) {
	let out = [];
	if (!cache || type(cache.countries) != 'array')
		return out;
	let cc = country_code ? lc(country_code) : null;
	let want = (hop_mode == null || hop_mode == '') ? null
		: (hop_mode == 'multihop' || hop_mode == 'onion') ? hop_mode : 'single';
	for (let c in cache.countries) {
		if (cc && lc(c.code) != cc)
			continue;
		for (let city in c.cities) {
			if (city.code != city_code)
				continue;
			for (let r in city.relays) {
				let k = relay_kind(r);
				if (want == null || k == want)
					push(out, { hostname: r.hostname, name: r.name, load: r.load,
						multihop: k == 'multihop', onion: k == 'onion' });
			}
			return out;
		}
	}
	return out;
}

// Normalize an array of raw API server objects into the cache structure.
// Exported for fixture tests (no network access required).
function normalize(list) {
	let acc = new_accumulator();
	for (let server in list)
		add_server(acc, server);
	return finalize(acc);
}

// ── Full paginated fetch ─────────────────────────────────────────────

function fetch_servers() {
	let acc = new_accumulator();
	let offset = 0, pages = 0, last_page = 0;
	let started = iso_ts();

	write_fetch_status({ state: 'running', started_at: started, page_size: PAGE_SIZE,
		pages: 0, loaded: 0, gateways: 0, source: SERVERS_URL });

	while (pages < MAX_PAGES) {
		let url = sprintf('%s?limit=%d&offset=%d&filters[servers_technologies][identifier]=wireguard_udp',
			SERVERS_URL, PAGE_SIZE, offset);
		let r = http_get(url);
		if (!r.ok) {
			write_fetch_status({ state: 'error', message: r.error, pages: pages,
				page_size: PAGE_SIZE, loaded: acc.stats.servers_seen,
				gateways: acc.stats.gateways, source: SERVERS_URL });
			return { error: r.error };
		}

		let data = safe_json(r.body);
		if (type(data) != 'array') {
			// Detect Cloudflare/NordVPN rate limiting from an HTML body.
			let lower = lc(r.body || '');
			let msg = (index(lower, 'rate limit') >= 0 || index(lower, 'error 1015') >= 0 ||
				index(lower, 'banned you temporarily') >= 0)
				? 'NordVPN API rate limited (Cloudflare); wait a few minutes and retry'
				: 'failed to parse NordVPN server response';
			write_fetch_status({ state: 'error', message: msg, pages: pages,
				page_size: PAGE_SIZE, loaded: acc.stats.servers_seen,
				gateways: acc.stats.gateways, source: SERVERS_URL });
			return { error: msg };
		}

		last_page = length(data);
		if (last_page == 0)
			break;

		for (let server in data)
			add_server(acc, server);

		pages++;
		offset += PAGE_SIZE;
		write_fetch_status({ state: 'running', started_at: started, page_size: PAGE_SIZE,
			pages: pages, last_page: last_page, loaded: acc.stats.servers_seen,
			gateways: acc.stats.gateways, source: SERVERS_URL });

		if (last_page < PAGE_SIZE)
			break;
	}

	if (pages >= MAX_PAGES) {
		let msg = 'pagination safety limit reached';
		write_fetch_status({ state: 'error', message: msg, pages: pages,
			page_size: PAGE_SIZE, loaded: acc.stats.servers_seen,
			gateways: acc.stats.gateways, source: SERVERS_URL });
		return { error: msg };
	}

	let resp = finalize(acc);
	resp.pagination = { page_size: PAGE_SIZE, pages: pages,
		servers_seen: acc.stats.servers_seen, last_page_size: last_page };

	write_fetch_status({ state: 'done', page_size: PAGE_SIZE, pages: pages,
		last_page: last_page, loaded: acc.stats.servers_seen,
		gateways: resp.stats.gateways, finished_at: iso_ts(), source: SERVERS_URL });

	return resp;
}

// ── Cache read/write ─────────────────────────────────────────────────

// Read the cache, rejecting malformed or schema-incompatible content.
function read_cache(path) {
	let data = readfile(path);
	if (!data)
		return null;
	let obj = safe_json(data);
	if (type(obj) != 'object' || obj.schema_version != CACHE_SCHEMA_VERSION)
		return null;
	return obj;
}

// True when the cache is missing, unreadable, incompatible or older than the
// staleness threshold.
function cache_is_stale(path) {
	let obj = read_cache(path);
	if (!obj || type(obj.cached_at) != 'int')
		return true;
	return (time() - obj.cached_at) > CACHE_MAX_AGE;
}

function write_cache(response, path) {
	response.cached_at = time();
	response.schema_version = CACHE_SCHEMA_VERSION;
	response.cache_info = {
		created: iso_ts(),
		expires_at: iso_ts(time() + CACHE_MAX_AGE)
	};
	let data = sprintf('%J', response);
	if (!data || length(data) == 0)
		return false;
	return atomic_write(path, data);
}

// Fetch all pages and persist the cache under a single-writer lock. Keeps the
// previous cache when the refresh fails. Returns the response or { error }.
function fetch_and_build(path) {
	let lock = acquire_lock(CACHE_LOCK_FILE);
	if (!lock)
		return { error: 'refresh already in progress' };

	let resp = fetch_servers();
	if (!resp || resp.error) {
		release_lock(lock);
		return resp || { error: 'fetch failed' };
	}

	let ok = write_cache(resp, path);
	release_lock(lock);
	if (!ok)
		return { error: 'failed to write cache file: ' + path };

	return resp;
}

return {
	write_fetch_status, read_fetch_status, add_server, normalize,
	locations_tree, city_relays,
	fetch_servers, read_cache, cache_is_stale, write_cache, fetch_and_build
};
