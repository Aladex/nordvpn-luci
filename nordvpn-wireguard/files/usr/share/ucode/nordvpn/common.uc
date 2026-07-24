// SPDX-License-Identifier: 0BSD
// Shared helpers for the nordvpn-wireguard backend: constants, strict input
// validation, /etc/config/nordvpn loading, logging with credential redaction,
// and injection-safe filesystem/process helpers.
//
// Imported as an ES module: `import { validate_token, ... } from 'nordvpn.common';`
// (resolves to /usr/share/ucode/nordvpn/common.uc via the ucode search path).

'use strict';

import { open, stat, unlink, rename, popen } from 'fs';

// ── Constants ────────────────────────────────────────────────────────

// Stamped with PKG_VERSION-rPKG_RELEASE at install time by the Makefile.
export const VERSION = 'dev';

export const API_BASE = 'https://api.nordvpn.com/v1';
export const CREDS_URL = API_BASE + '/users/services/credentials';
export const SERVERS_URL = API_BASE + '/servers';

export const DEFAULT_INTERFACE = 'nordvpn';
export const DEFAULT_PORT = 51820;
export const DEFAULT_KEEPALIVE = 25;
export const FIXED_ADDRESS = '10.5.0.2/16';

export const CACHE_FILENAME = 'nordvpn_servers_cache.json';
export const DEFAULT_CACHE_DIR = '/tmp';
export const FETCH_STATUS_FILE = '/tmp/nordvpn_fetch_status.json';
export const CACHE_LOCK_FILE = '/tmp/nordvpn_cache.lock';
export const CACHE_MAX_AGE = 86400;          // 24h staleness threshold
export const CACHE_SCHEMA_VERSION = 1;
export const PAGE_SIZE = 250;
export const MAX_PAGES = 200;                // pagination safety guard

// Bounds shared by validation and the UI contract.
export const MIN_ROTATION_INTERVAL = 5;      // minutes
export const MAX_ROTATION_INTERVAL = 44640;  // 31 days
export const MIN_CACHE_REFRESH = 60;         // seconds
export const MAX_CACHE_REFRESH = 604800;     // 7 days

// ── Primitive validators ─────────────────────────────────────────────
// Each returns a normalized value or null; callers treat null as invalid.

// Coerce to an integer within [min, max], else null.
export function bounded_int(v, min, max) {
	let n;
	let t = type(v);
	if (t == 'int') {
		n = v;
	} else if (t == 'double') {
		n = int(v);
	} else if (t == 'string') {
		if (!match(v, /^-?[0-9]+$/))
			return null;
		n = int(v);
	} else {
		return null;
	}
	if (n < min || n > max)
		return null;
	return n;
}

// Interface name: UCI section name and Linux device name, so keep it strict.
export function validate_interface(name) {
	if (type(name) != 'string')
		return null;
	if (length(name) < 1 || length(name) > 15)
		return null;
	return match(name, /^[A-Za-z0-9_]+$/) ? name : null;
}

// Exactly 64 hex characters.
export function validate_token(t) {
	if (type(t) != 'string')
		return null;
	return match(t, /^[0-9a-fA-F]{64}$/) ? t : null;
}

// WireGuard base64 key: 32 bytes -> 43 base64 chars + one '=' pad. Checked
// char-by-char (no regex) since '/' is awkward inside POSIX ERE literals.
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function validate_wg_key(k) {
	if (type(k) != 'string' || length(k) != 44 || substr(k, 43, 1) != '=')
		return null;
	for (let i = 0; i < 43; i++)
		if (index(BASE64_ALPHABET, substr(k, i, 1)) < 0)
			return null;
	return k;
}

// NordVPN hostname or a plain IPv4/IPv6 literal (charset check only).
export function validate_hostname(h) {
	if (type(h) != 'string' || length(h) < 1 || length(h) > 253)
		return null;
	return match(h, /^[A-Za-z0-9._:-]+$/) ? h : null;
}

export function validate_port(p) {
	return bounded_int(p, 1, 65535);
}

export function validate_hop_mode(m) {
	return (m == 'single' || m == 'multihop') ? m : null;
}

export function validate_rotation_mode(m) {
	return (m == 'interval' || m == 'time') ? m : null;
}

export function validate_interval(v) {
	return bounded_int(v, MIN_ROTATION_INTERVAL, MAX_ROTATION_INTERVAL);
}

export function validate_time(s) {
	if (type(s) != 'string')
		return null;
	return match(s, /^([01][0-9]|2[0-3]):[0-5][0-9]$/) ? s : null;
}

export function validate_country_code(c) {
	if (type(c) != 'string')
		return null;
	return match(c, /^[A-Za-z]{2}$/) ? lc(c) : null;
}

// Location/city slug, e.g. "ee-tallinn".
export function validate_location_code(c) {
	if (type(c) != 'string')
		return null;
	return match(c, /^[A-Za-z0-9-]+$/) ? c : null;
}

// Empty (main table) or a table name/number.
export function validate_routing_table(t) {
	if (t == null || t == '')
		return '';
	if (type(t) != 'string')
		return null;
	return match(t, /^[A-Za-z0-9_]+$/) ? t : null;
}

// Absolute path, no shell/traversal-hostile characters. Char-by-char (no regex)
// to keep the '/' handling unambiguous.
const DIR_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-';

export function validate_dir(d) {
	if (d == null || d == '')
		return '';
	if (type(d) != 'string' || substr(d, 0, 1) != '/')
		return null;
	for (let i = 0; i < length(d); i++)
		if (index(DIR_ALPHABET, substr(d, i, 1)) < 0)
			return null;
	return d;
}

// ── Settings ─────────────────────────────────────────────────────────

// Load and normalize the non-secret settings from /etc/config/nordvpn.
// `uci` is a connected uci cursor. Numeric/bounded fields fall back to the
// documented defaults when missing or invalid.
export function load_settings(uci) {
	let g = function(opt, dflt) {
		let v = uci.get('nordvpn', 'main', opt);
		return (v == null || v == '') ? dflt : v;
	};
	let bi = function(opt, dflt, min, max) {
		let v = bounded_int(g(opt, dflt), min, max);
		return (v == null) ? int(dflt) : v;
	};

	return {
		enabled: g('enabled', '0') == '1',
		interface: validate_interface(g('interface', DEFAULT_INTERFACE)) || DEFAULT_INTERFACE,
		routing_table: g('routing_table', ''),
		hop_mode: validate_hop_mode(g('hop_mode', 'single')) || 'single',
		country_code: g('country_code', ''),
		city_code: g('city_code', ''),
		fixed_server: g('fixed_server', ''),
		rotation_enabled: g('rotation_enabled', '0') == '1',
		rotation_mode: validate_rotation_mode(g('rotation_mode', 'interval')) || 'interval',
		rotation_interval: bi('rotation_interval', '360', MIN_ROTATION_INTERVAL, MAX_ROTATION_INTERVAL),
		rotation_time: validate_time(g('rotation_time', '04:30')) || '04:30',
		ping_count: bi('ping_count', '10', 1, 60),
		ping_timeout: bi('ping_timeout', '2', 1, 60),
		max_retries: bi('max_retries', '10', 1, 50),
		cache_dir: g('cache_dir', ''),
		cache_refresh_interval: bi('cache_refresh_interval', '21600', MIN_CACHE_REFRESH, MAX_CACHE_REFRESH),
	};
}

// Resolve the cache file path from the configured directory, falling back to
// /tmp when the directory is missing or invalid.
export function cache_file_path(settings) {
	let dir = validate_dir(settings ? settings.cache_dir : '');
	if (!dir || dir == '')
		dir = DEFAULT_CACHE_DIR;
	return dir + '/' + CACHE_FILENAME;
}

// UTC ISO-8601 timestamp, e.g. "2026-07-24T18:30:00Z".
export function iso_ts(ts) {
	let t = gmtime(ts != null ? ts : time());
	return sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ',
		t.year, t.mon, t.mday, t.hour, t.min, t.sec);
}

// ── Logging ──────────────────────────────────────────────────────────

// Replace anything that looks like a 64-hex token with a placeholder.
export function redact(str) {
	if (type(str) != 'string')
		return str;
	return replace(str, /[0-9a-fA-F]{64}/g, '<redacted-token>');
}

export function log(msg) {
	warn('nordvpn: ' + redact('' + msg) + '\n');
}

// ── Filesystem helpers ───────────────────────────────────────────────

// Write data to `path` atomically: create a unique temp file in the same
// directory, write it, then rename over the target so readers never observe a
// half-written file. Returns true on success.
export function atomic_write(path, data) {
	let fh = null;
	let tmp = null;
	let n = 0;
	while (n < 1000) {
		tmp = path + '.tmp.' + time() + '.' + n;
		fh = open(tmp, 'wx'); // exclusive create; retry on collision
		if (fh)
			break;
		n++;
	}
	if (!fh)
		return false;

	let ok = fh.write(data);
	fh.close();
	if (ok == null) {
		unlink(tmp);
		return false;
	}
	if (!rename(tmp, path)) {
		unlink(tmp);
		return false;
	}
	return true;
}

// Best-effort exclusive lock via an O_EXCL lock file. Returns a token to pass
// to release_lock(), or null when another holder is active. Stale locks older
// than `max_age` seconds are reclaimed.
export function acquire_lock(path, max_age) {
	max_age = max_age || 600;
	let fh = open(path, 'wx');
	if (!fh) {
		let st = stat(path);
		if (st && st.mtime && (time() - st.mtime) > max_age) {
			unlink(path);
			fh = open(path, 'wx');
		}
	}
	if (!fh)
		return null;
	fh.write(sprintf('%d\n', time()));
	fh.close();
	return path;
}

export function release_lock(token) {
	if (token)
		unlink(token);
}

// Run an external command as an argv array (no shell, no interpolation).
// Returns { code, stdout }. `code` is -1 when the process could not start.
export function run(argv) {
	let proc = popen(argv, 'r');
	if (!proc)
		return { code: -1, stdout: '' };
	let out = proc.read('all') || '';
	let code = proc.close();
	return { code: code, stdout: out };
}

// Connectivity test bound to the VPN device so it traverses the tunnel even
// with a custom routing table. Succeeds when >= 70% of pings reach the target.
export function ping_through(iface, count, timeout, target) {
	count = count || 10;
	timeout = timeout || 2;
	target = target || '8.8.8.8';
	let ok = 0;
	for (let i = 0; i < count; i++) {
		let r = run([ 'ping', '-c', '1', '-W', '' + timeout, '-I', iface, target ]);
		if (r.code == 0)
			ok++;
	}
	return (ok * 10) >= (count * 7);
}
