// SPDX-License-Identifier: MIT
// Pure scheduling decisions for the nordvpn procd daemon. Kept separate from
// the uloop event loop so the timing logic can be unit-tested offline.

'use strict';

const _common = require('nordvpn.common');
const WATCHDOG_GRACE = _common.WATCHDOG_GRACE,
      WATCHDOG_COOLDOWN_BASE = _common.WATCHDOG_COOLDOWN_BASE,
      WATCHDOG_COOLDOWN_MAX = _common.WATCHDOG_COOLDOWN_MAX;

// Refresh when the interval elapsed, or on first tick if the cache is stale.
function should_refresh(settings, last_cache, now, cache_stale) {
	if (last_cache == 0 && cache_stale)
		return true;
	return (now - last_cache) >= settings.cache_refresh_interval;
}

// `hm` is the current local time as "HH:MM". Rotation only runs when enabled,
// rotation is on, and no fixed server is pinned.
function should_rotate(settings, last_rotate, now, hm) {
	if (!settings.enabled || !settings.rotation_enabled)
		return false;
	if (settings.fixed_server && settings.fixed_server != '')
		return false;
	if (settings.rotation_mode == 'time')
		return (hm == settings.rotation_time && (now - last_rotate) > 90);
	return (now - last_rotate) >= (settings.rotation_interval * 60);
}

// Epoch seconds of the next scheduled rotation, or null when rotation cannot
// run (master switch off, rotation disabled, or a fixed server pinned).
// `last_rotate` is the persisted last-attempt epoch, 0 when unknown. Mirrors
// the gating of should_rotate() so the UI never announces a rotation that the
// daemon would refuse to perform.
function next_rotation(settings, last_rotate, now) {
	if (!settings.enabled || !settings.rotation_enabled)
		return null;
	if (settings.fixed_server && settings.fixed_server != '')
		return null;
	if (settings.rotation_mode == 'time') {
		let hm = split(settings.rotation_time, ':');
		let tm = localtime(now);
		tm.hour = int(hm[0]);
		tm.min = int(hm[1]);
		tm.sec = 0;
		let t = timelocal(tm);
		if (t <= now) {
			tm.mday += 1; // timelocal() normalizes month/year overflow
			t = timelocal(tm);
		}
		return t;
	}
	let base = (last_rotate && last_rotate > 0) ? last_rotate : now;
	let t = base + settings.rotation_interval * 60;
	return t < now ? now : t;
}

// States that may trigger a watchdog recovery. The grace period gives a fresh
// connection time to complete its first handshake.
function is_unhealthy(state) {
	return state == 'connecting' || state == 'degraded' ||
		state == 'disconnected';
}

// Watchdog decision: recover a persistently unhealthy instance by rotating
// away from the dead server. Requires the master switch and the per-instance
// watchdog option; a pinned server disables it (mirrors should_rotate). The
// grace period absorbs transient rekeys and the post-apply connecting window;
// the cooldown backs off exponentially per failed attempt so a dead pool is
// not hammered. All timers come from the persisted per-instance state:
// `degraded_since` (0 = healthy), `last_recover` (0 = never), `fails`.
function should_recover(settings, state, degraded_since, last_recover, fails, now) {
	if (!settings.enabled || !settings.watchdog)
		return false;
	if (settings.fixed_server && settings.fixed_server != '')
		return false;
	if (!is_unhealthy(state))
		return false;
	if (!degraded_since || now - degraded_since < WATCHDOG_GRACE)
		return false;
	// Clamp the shift so a long-dead instance cannot overflow it.
	let shift = fails > 0 ? fails - 1 : 0;
	if (shift > 20)
		shift = 20;
	let cooldown = WATCHDOG_COOLDOWN_BASE * (1 << shift);
	if (cooldown > WATCHDOG_COOLDOWN_MAX)
		cooldown = WATCHDOG_COOLDOWN_MAX;
	return last_recover == 0 || now - last_recover >= cooldown;
}

// Next watchdog timers from the observed state transition. Inactive,
// unconfigured, and connected instances start with a clean recovery episode.
// `st` is { degraded_since, last_recover, recover_fails } from persisted state.
function watchdog_update(state, st, now, active) {
	let ds = (st && st.degraded_since > 0) ? st.degraded_since : 0;
	let last = (st && st.last_recover > 0) ? st.last_recover : 0;
	let fails = (st && st.recover_fails > 0) ? st.recover_fails : 0;
	if (!active || state == 'connected' || state == 'not_configured')
		return { degraded_since: 0, last_recover: 0, recover_fails: 0 };
	if (is_unhealthy(state) && ds == 0)
		ds = now;
	return { degraded_since: ds, last_recover: last, recover_fails: fails };
}

// Fold a completed recovery worker result into the failure counter. Losing the
// rotation-lock race is not a recovery failure; the active worker owns it.
function watchdog_result_update(result, fails) {
	let n = (type(fails) == 'int' && fails > 0) ? fails : 0;
	if (result && result.ok)
		return n;
	if (result && result.skipped && result.reason == 'rotation already running')
		return n;
	return n + 1;
}

return {
	should_refresh, should_rotate, next_rotation, should_recover,
	watchdog_update, watchdog_result_update
};
