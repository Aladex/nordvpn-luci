// SPDX-License-Identifier: 0BSD
// Shared server selection over the normalized cache. Pure and testable; used by
// both the apply path (single pick) and the rotation worker (try many).

'use strict';

import { rand } from 'math';

// All relays matching country/city/hop_mode. city_code '' means any city.
function candidates(cache, country_code, city_code, hop_mode) {
	let out = [];
	if (!cache || type(cache.countries) != 'array')
		return out;

	let want_multi = (hop_mode == 'multihop');
	let cc = (country_code && country_code != '') ? lc(country_code) : null;

	for (let country in cache.countries) {
		if (cc && lc(country.code) != cc)
			continue;
		for (let city in country.cities) {
			if (city_code && city_code != '' && city.code != city_code)
				continue;
			for (let relay in city.relays) {
				let is_multi = relay.multihop ? true : false;
				if (want_multi == is_multi)
					push(out, relay);
			}
		}
	}
	return out;
}

// Find a specific relay by its gateway hostname.
function by_hostname(cache, hostname) {
	if (!cache || type(cache.countries) != 'array' || !hostname)
		return null;
	for (let country in cache.countries)
		for (let city in country.cities)
			for (let relay in city.relays)
				if (relay.hostname == hostname)
					return relay;
	return null;
}

// Random pick from a list, optionally excluding a hostname (falls back to the
// full list when the exclusion would leave nothing).
function pick(list, exclude_hostname) {
	if (type(list) != 'array' || length(list) == 0)
		return null;
	let pool = list;
	if (exclude_hostname) {
		pool = filter(list, function(r) { return r.hostname != exclude_hostname; });
		if (length(pool) == 0)
			pool = list;
	}
	return pool[rand() % length(pool)];
}

return { candidates, by_hostname, pick };
