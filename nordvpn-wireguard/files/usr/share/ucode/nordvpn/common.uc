// SPDX-License-Identifier: MIT
// Shared helpers for the nordvpn-wireguard backend: constants, strict input
// validation, /etc/config/nordvpn loading, logging with credential redaction,
// and injection-safe filesystem/process helpers.
//
// Loaded via `require('nordvpn.common')` (resolves to
// /usr/share/ucode/nordvpn/common.uc on the ucode search path). ucode on
// OpenWrt 24.10 does not support ES `export`, so modules use CommonJS return.

'use strict';

import { open, stat, unlink, rename, popen } from 'fs';

// ── Constants ────────────────────────────────────────────────────────

// Stamped with PKG_VERSION-rPKG_RELEASE at install time by the Makefile.
const VERSION = 'dev';

const API_BASE = 'https://api.nordvpn.com/v1';
const CREDS_URL = API_BASE + '/users/services/credentials';
const SERVERS_URL = API_BASE + '/servers';

const DEFAULT_INTERFACE = 'nordvpn';
const DEFAULT_PORT = 51820;
const DEFAULT_KEEPALIVE = 25;
const FIXED_ADDRESS = '10.5.0.2/16';

const CACHE_FILENAME = 'nordvpn_servers_cache.json';
const DEFAULT_CACHE_DIR = '/tmp';
const FETCH_STATUS_FILE = '/tmp/nordvpn_fetch_status.json';
const CACHE_LOCK_FILE = '/tmp/nordvpn_cache.lock';
const CACHE_MAX_AGE = 86400;          // 24h staleness threshold
const CACHE_SCHEMA_VERSION = 1;
const PAGE_SIZE = 250;
const MAX_PAGES = 200;                // pagination safety guard

// Bounds shared by validation and the UI contract.
const MIN_ROTATION_INTERVAL = 5;      // minutes
const MAX_ROTATION_INTERVAL = 44640;  // 31 days
const MIN_CACHE_REFRESH = 60;         // seconds
const MAX_CACHE_REFRESH = 604800;     // 7 days
const MIN_VERIFY_TIMEOUT = 2;         // seconds to wait for a handshake
const MAX_VERIFY_TIMEOUT = 30;

// Watchdog (auto-reconnect) tuning: how long an instance must stay unhealthy
// before recovering, and the min/max pause between recovery attempts
// (exponential backoff from BASE, clamped to MAX, reset on reconnect).
const WATCHDOG_GRACE = 60;
const WATCHDOG_COOLDOWN_BASE = 120;
const WATCHDOG_COOLDOWN_MAX = 900;

// ── Primitive validators ─────────────────────────────────────────────
// Each returns a normalized value or null; callers treat null as invalid.

// Coerce to an integer within [min, max], else null.
function bounded_int(v, min, max) {
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
function validate_interface(name) {
	if (type(name) != 'string')
		return null;
	if (length(name) < 1 || length(name) > 15)
		return null;
	return match(name, /^[A-Za-z0-9_]+$/) ? name : null;
}

// Exactly 64 hex characters.
function validate_token(t) {
	if (type(t) != 'string')
		return null;
	return match(t, /^[0-9a-fA-F]{64}$/) ? t : null;
}

// WireGuard base64 key: 32 bytes -> 43 base64 chars + one '=' pad. Checked
// char-by-char (no regex) since '/' is awkward inside POSIX ERE literals.
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function validate_wg_key(k) {
	if (type(k) != 'string' || length(k) != 44 || substr(k, 43, 1) != '=')
		return null;
	for (let i = 0; i < 43; i++)
		if (index(BASE64_ALPHABET, substr(k, i, 1)) < 0)
			return null;
	return k;
}

// NordVPN hostname or a plain IPv4/IPv6 literal (charset check only).
function validate_hostname(h) {
	if (type(h) != 'string' || length(h) < 1 || length(h) > 253)
		return null;
	return match(h, /^[A-Za-z0-9._:-]+$/) ? h : null;
}

function validate_port(p) {
	return bounded_int(p, 1, 65535);
}

function validate_hop_mode(m) {
	return (m == 'single' || m == 'multihop' || m == 'onion') ? m : null;
}

// DNS override mode while connected: 'off' (system/WAN resolver), 'standard'
// (NordVPN's plain resolver) or 'threat' (NordVPN Threat Protection, blocks
// ads and malware). null for anything else so the caller can fall back.
function validate_dns_mode(m) {
	return (m == 'off' || m == 'standard' || m == 'threat') ? m : null;
}

// Classify a relay from the normalized cache: 'multihop' (Double VPN),
// 'onion' (Onion Over VPN) or 'single'. Falls back to the hostname pattern so
// caches written before the onion flag existed still classify correctly.
function relay_kind(r) {
	if (!r)
		return 'single';
	if (r.multihop)
		return 'multihop';
	if (r.onion || match(r.hostname || '', /^[a-z][a-z]-onion[0-9]+[.]/))
		return 'onion';
	return 'single';
}

function validate_rotation_mode(m) {
	return (m == 'interval' || m == 'time') ? m : null;
}

function validate_interval(v) {
	return bounded_int(v, MIN_ROTATION_INTERVAL, MAX_ROTATION_INTERVAL);
}

function validate_time(s) {
	if (type(s) != 'string')
		return null;
	return match(s, /^([01][0-9]|2[0-3]):[0-5][0-9]$/) ? s : null;
}

function validate_country_code(c) {
	if (type(c) != 'string')
		return null;
	return match(c, /^[A-Za-z]{2}$/) ? lc(c) : null;
}

// Location/city slug, e.g. "ee-tallinn".
function validate_location_code(c) {
	if (type(c) != 'string')
		return null;
	return match(c, /^[A-Za-z0-9-]+$/) ? c : null;
}

// Instance section name (also used in state-file paths, so keep it strict).
function validate_instance(n) {
	if (type(n) != 'string' || length(n) < 1 || length(n) > 32)
		return null;
	return match(n, /^[A-Za-z0-9_]+$/) ? n : null;
}

// Empty (main table) or a table name/number.
function validate_routing_table(t) {
	if (t == null || t == '')
		return '';
	if (type(t) != 'string')
		return null;
	return match(t, /^[A-Za-z0-9_]+$/) ? t : null;
}

// Absolute path, no shell/traversal-hostile characters. Char-by-char (no regex)
// to keep the '/' handling unambiguous.
const DIR_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-';

function validate_dir(d) {
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

// VPN instance section names: every `config instance` section, plus a legacy
// `config settings 'main'`. 'main' always sorts first.
function list_instances(uci) {
	let names = [];
	uci.foreach('nordvpn', 'instance', function(sec) {
		push(names, sec['.name']);
	});
	if (uci.get('nordvpn', 'main') != null && index(names, 'main') < 0)
		push(names, 'main');
	sort(names, function(a, b) {
		if (a == 'main') return -1;
		if (b == 'main') return 1;
		return (a < b) ? -1 : (a > b) ? 1 : 0;
	});
	return names;
}

// Section carrying the shared (cache) options: an explicit 'globals' section
// when present, the 'main' instance otherwise.
function globals_section(uci) {
	return (uci.get('nordvpn', 'globals') != null) ? 'globals' : 'main';
}

// Load and normalize the non-secret settings of one VPN instance from
// /etc/config/nordvpn (`instance` defaults to 'main'). `uci` is a connected
// uci cursor. Numeric/bounded fields fall back to the documented defaults
// when missing or invalid. The server-list cache options are shared between
// instances and always come from the globals/'main' section.
function load_settings(uci, instance) {
	let name = validate_instance(instance) || 'main';
	let g = function(opt, dflt) {
		let v = uci.get('nordvpn', name, opt);
		return (v == null || v == '') ? dflt : v;
	};
	let bi = function(opt, dflt, min, max) {
		let v = bounded_int(g(opt, dflt), min, max);
		return (v == null) ? int(dflt) : v;
	};
	let shared = globals_section(uci);
	let gs = function(opt, dflt) {
		let v = uci.get('nordvpn', shared, opt);
		return (v == null || v == '') ? dflt : v;
	};

	// `list source_network` — logical networks steered through this instance.
	let sn = uci.get('nordvpn', name, 'source_network');
	let source_networks = [];
	if (type(sn) == 'array') {
		for (let x in sn)
			if (validate_interface(x))
				push(source_networks, x);
	} else if (type(sn) == 'string' && validate_interface(sn)) {
		push(source_networks, sn);
	}

	// `list locations` — the instance's location set: countries ('de') and/or
	// cities ('de-berlin') that both the initial connect and the rotation pick
	// from. Empty = the legacy country_code/city_code selection. A city code
	// always carries its country prefix, so entries without a '-' are only
	// valid as country codes.
	let rp = uci.get('nordvpn', name, 'locations');
	let locations = [];
	let rp_add = function(x) {
		let cc = validate_country_code(x);
		if (cc) {
			push(locations, cc);
			return;
		}
		let loc = validate_location_code(x);
		if (loc && index(loc, '-') > 0)
			push(locations, loc);
	};
	if (type(rp) == 'array') {
		for (let x in rp)
			rp_add(x);
	} else if (type(rp) == 'string') {
		rp_add(rp);
	}

	return {
		name: name,
		source_networks: source_networks,
		locations: locations,
		enabled: g('enabled', '0') == '1',
		interface: validate_interface(g('interface', DEFAULT_INTERFACE)) || DEFAULT_INTERFACE,
		routing_table: g('routing_table', ''),
		// Optional WireGuard interface MTU override; null = keep the netifd
		// default (1420). Clamped to the valid Ethernet/IPv6 range.
		mtu: (function() {
			let v = int(g('mtu', '0'));
			return (v >= 1280 && v <= 1500) ? v : null;
		})(),
		hop_mode: validate_hop_mode(g('hop_mode', 'single')) || 'single',
		country_code: g('country_code', ''),
		city_code: g('city_code', ''),
		fixed_server: g('fixed_server', ''),
		rotation_enabled: g('rotation_enabled', '0') == '1',
		rotation_mode: validate_rotation_mode(g('rotation_mode', 'interval')) || 'interval',
		rotation_interval: bi('rotation_interval', '360', MIN_ROTATION_INTERVAL, MAX_ROTATION_INTERVAL),
		rotation_time: validate_time(g('rotation_time', '04:30')) || '04:30',
		// Optional watchdog: auto-reconnect (rotate away) when the tunnel stays
		// unhealthy. Off by default; never fires with a pinned fixed_server.
		watchdog: g('watchdog', '0') == '1',
		verify_timeout: bi('verify_timeout', '8', MIN_VERIFY_TIMEOUT, MAX_VERIFY_TIMEOUT),
		max_retries: bi('max_retries', '10', 1, 50),
		// Automatic traffic routing (zone + default route via the tunnel). The
		// shipped config enables it for fresh installs; the load-time default
		// stays off so upgraded/migrated setups keep their manual scheme.
		auto_routing: g('auto_routing', '0') == '1',
		killswitch: g('killswitch', '0') == '1',
		block_ipv6: g('block_ipv6', '1') == '1',
		// DNS override mode. Prefer the enum; fall back to the legacy boolean
		// (use_vpn_dns=1 meant the standard resolver) so upgraded configs keep
		// working before the migration/save rewrites the key. use_vpn_dns stays
		// as a derived boolean for the enforce condition and any other consumer.
		vpn_dns: (function() {
			let m = validate_dns_mode(g('vpn_dns', ''));
			if (m)
				return m;
			return (g('use_vpn_dns', '0') == '1') ? 'standard' : 'off';
		})(),
		use_vpn_dns: validate_dns_mode(g('vpn_dns', '')) ?
			(g('vpn_dns', '') != 'off') : (g('use_vpn_dns', '0') == '1'),
		cache_dir: gs('cache_dir', ''),
		cache_refresh_interval: (function() {
			let v = bounded_int(gs('cache_refresh_interval', '21600'), MIN_CACHE_REFRESH, MAX_CACHE_REFRESH);
			return (v == null) ? 21600 : v;
		})(),
	};
}

// Resolve the cache file path from the configured directory, falling back to
// /tmp when the directory is missing or invalid.
function cache_file_path(settings) {
	let dir = validate_dir(settings ? settings.cache_dir : '');
	if (!dir || dir == '')
		dir = DEFAULT_CACHE_DIR;
	return dir + '/' + CACHE_FILENAME;
}

// UTC ISO-8601 timestamp, e.g. "2026-07-24T18:30:00Z".
function iso_ts(ts) {
	let t = gmtime(ts != null ? ts : time());
	return sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ',
		t.year, t.mon, t.mday, t.hour, t.min, t.sec);
}

// ── Logging ──────────────────────────────────────────────────────────

// Replace anything that looks like a 64-hex token with a placeholder.
function redact(str) {
	if (type(str) != 'string')
		return str;
	return replace(str, /[0-9a-fA-F]{64}/g, '<redacted-token>');
}

function log(msg) {
	warn('nordvpn: ' + redact('' + msg) + '\n');
}

// ── Filesystem helpers ───────────────────────────────────────────────

// Write data to `path` atomically: create a unique temp file in the same
// directory, write it, then rename over the target so readers never observe a
// half-written file. Returns true on success.
function atomic_write(path, data) {
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
function acquire_lock(path, max_age) {
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

function release_lock(token) {
	if (token)
		unlink(token);
}

// Single-quote a value for safe inclusion in a /bin/sh command line.
function sh_quote(s) {
	return "'" + replace('' + s, /'/g, "'\\''") + "'";
}

// Open a process from an argv array. ucode on OpenWrt 24.10 only supports the
// string (shell) form of popen(), so we build a shell command with every
// argument single-quoted. All interpolated values are whitelist-validated
// before reaching here, so no shell metacharacter can survive the quoting.
function open_cmd(argv, mode) {
	let parts = [];
	for (let a in argv)
		push(parts, sh_quote(a));
	return popen(join(' ', parts), mode || 'r');
}

// Run an external command (argv array) and capture stdout.
// Returns { code, stdout }. `code` is -1 when the process could not start.
function run(argv) {
	let proc = open_cmd(argv, 'r');
	if (!proc)
		return { code: -1, stdout: '' };
	let out = proc.read('all') || '';
	let code = proc.close();
	return { code: code, stdout: out };
}

// CommonJS export (ucode on OpenWrt 24.10 does not support ES `export`).
return {
	VERSION, API_BASE, CREDS_URL, SERVERS_URL,
	DEFAULT_INTERFACE, DEFAULT_PORT, DEFAULT_KEEPALIVE, FIXED_ADDRESS,
	CACHE_FILENAME, DEFAULT_CACHE_DIR, FETCH_STATUS_FILE, CACHE_LOCK_FILE,
	CACHE_MAX_AGE, CACHE_SCHEMA_VERSION, PAGE_SIZE, MAX_PAGES,
	MIN_ROTATION_INTERVAL, MAX_ROTATION_INTERVAL, MIN_CACHE_REFRESH, MAX_CACHE_REFRESH,
	MIN_VERIFY_TIMEOUT, MAX_VERIFY_TIMEOUT,
	WATCHDOG_GRACE, WATCHDOG_COOLDOWN_BASE, WATCHDOG_COOLDOWN_MAX,
	bounded_int, validate_interface, validate_token, validate_wg_key, validate_hostname,
	validate_port, validate_hop_mode, validate_dns_mode, relay_kind, validate_rotation_mode, validate_interval, validate_time,
	validate_country_code, validate_location_code, validate_instance, validate_routing_table, validate_dir,
	load_settings, list_instances, globals_section, cache_file_path, iso_ts, redact, log,
	atomic_write, acquire_lock, release_lock, sh_quote, open_cmd, run
};
