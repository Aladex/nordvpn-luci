// SPDX-License-Identifier: MIT
// Shared server selection over the normalized cache. Pure and testable; used by
// both the apply path (single pick) and the rotation worker (try many).

'use strict';

import { rand } from 'math';
const relay_kind = require('nordvpn.common').relay_kind;

// All relays matching country/city/hop_mode. city_code '' means any city.
// hop_mode 'multihop' and 'onion' select exactly that kind; anything else
// selects plain single-hop relays (Onion Over VPN is never picked implicitly).
function candidates(cache, country_code, city_code, hop_mode) {
	let out = [];
	if (!cache || type(cache.countries) != 'array')
		return out;

	let want = (hop_mode == 'multihop' || hop_mode == 'onion') ? hop_mode : 'single';
	let cc = (country_code && country_code != '') ? lc(country_code) : null;

	for (let country in cache.countries) {
		if (cc && lc(country.code) != cc)
			continue;
		for (let city in country.cities) {
			if (city_code && city_code != '' && city.code != city_code)
				continue;
			for (let relay in city.relays) {
				if (relay_kind(relay) == want)
					push(out, relay);
			}
		}
	}
	return out;
}

// Union of candidates() over a location set: entries are country codes
// ('de') or city codes ('de-berlin', the country derived from the prefix).
// Deduped by hostname so a city inside a set country appears once.
// Garbage entries contribute nothing.
function location_candidates(cache, locations, hop_mode) {
	let out = [], seen = {};
	if (type(locations) != 'array')
		return out;
	for (let entry in locations) {
		let list = [];
		if (match(entry, /^[A-Za-z]{2}$/))
			list = candidates(cache, entry, '', hop_mode);
		else if (type(entry) == 'string' && index(entry, '-') > 0)
			list = candidates(cache, split(entry, '-')[0], entry, hop_mode);
		for (let r in list) {
			if (seen[r.hostname])
				continue;
			seen[r.hostname] = true;
			push(out, r);
		}
	}
	return out;
}

// The instance's candidate set, shared by apply and rotation: a non-empty
// location set wins; otherwise the legacy country/city selection.
function selection_candidates(cache, settings) {
	let loc = settings ? settings.locations : null;
	if (loc && length(loc) > 0)
		return location_candidates(cache, loc, settings.hop_mode);
	return candidates(cache, settings.country_code, settings.city_code, settings.hop_mode);
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

return { candidates, location_candidates, selection_candidates, by_hostname, pick };
