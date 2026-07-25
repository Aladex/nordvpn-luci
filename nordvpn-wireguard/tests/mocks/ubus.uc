// SPDX-License-Identifier: MIT
// Minimal 'ubus' module mock for offline ucode tests. Seed responses keyed by
// "<object>~<method>" via global.MOCK_UBUS:
//   global.MOCK_UBUS = { 'network.interface.nordvpn~status': { up: true, l3_device: 'nordvpn' } };

'use strict';

export function connect() {
	let err = null;
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
		disconnect: function() { return null; }
	};
}
