// SPDX-License-Identifier: MIT
// Minimal 'ubus' module mock for offline ucode tests. Seed responses keyed by
// "<object>~<method>" via global.MOCK_UBUS:
//   global.MOCK_UBUS = { 'network.interface.nordvpn~status': { up: true, l3_device: 'nordvpn' } };
//
// Connections are counted in global.MOCK_UBUS_OPEN so tests can assert that
// callers close what they open: a connection leaked once per daemon tick
// exhausts ubusd's file descriptors and takes the whole router's ubus down.

'use strict';

export function connect() {
	let err = null;
	global.MOCK_UBUS_OPEN = (global.MOCK_UBUS_OPEN || 0) + 1;
	let closed = false;
	return {
		call: function(object, method, args) {
			let key = object + '~' + method;
			let resp = global.MOCK_UBUS ? global.MOCK_UBUS[key] : null;
			if (resp == null) {
				err = 'Method not found';
				return null;
			}
			err = null;
			return resp;
		},
		error: function() { return err; },
		disconnect: function() {
			// Ignore a double close, like the real module does.
			if (!closed) {
				closed = true;
				global.MOCK_UBUS_OPEN = (global.MOCK_UBUS_OPEN || 1) - 1;
			}
			return null;
		}
	};
}
