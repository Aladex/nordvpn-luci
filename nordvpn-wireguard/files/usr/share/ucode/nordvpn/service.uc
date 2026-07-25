// SPDX-License-Identifier: MIT
// Pure scheduling decisions for the nordvpn procd daemon. Kept separate from
// the uloop event loop so the timing logic can be unit-tested offline.

'use strict';

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

return { should_refresh, should_rotate, next_rotation };
