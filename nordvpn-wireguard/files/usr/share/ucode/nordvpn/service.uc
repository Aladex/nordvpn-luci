// SPDX-License-Identifier: 0BSD
// Pure scheduling decisions for the nordvpn procd daemon. Kept separate from
// the uloop event loop so the timing logic can be unit-tested offline.

'use strict';

// Refresh when the interval elapsed, or on first tick if the cache is stale.
export function should_refresh(settings, last_cache, now, cache_stale) {
	if (last_cache == 0 && cache_stale)
		return true;
	return (now - last_cache) >= settings.cache_refresh_interval;
}

// `hm` is the current local time as "HH:MM". Rotation only runs when enabled,
// rotation is on, and no fixed server is pinned.
export function should_rotate(settings, last_rotate, now, hm) {
	if (!settings.enabled || !settings.rotation_enabled)
		return false;
	if (settings.fixed_server && settings.fixed_server != '')
		return false;
	if (settings.rotation_mode == 'time')
		return (hm == settings.rotation_time && (now - last_rotate) > 90);
	return (now - last_rotate) >= (settings.rotation_interval * 60);
}
