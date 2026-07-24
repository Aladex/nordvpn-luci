// SPDX-License-Identifier: 0BSD
// NordVPN credential exchange. The access token is handed to curl only through
// an anonymous pipe (curl --config on /proc/self/fd/<r>), never via argv, an
// environment variable, a named temp file, or any log line.

'use strict';

import { pipe } from 'fs';
const _common = require('nordvpn.common');
const CREDS_URL = _common.CREDS_URL,
      open_cmd = _common.open_cmd,
      validate_token = _common.validate_token,
      validate_wg_key = _common.validate_wg_key;

// Pure: parse the credential API JSON into { private_key } or { error }.
// Exported so it can be unit-tested without any network access.
function parse_credentials(body) {
	let data;
	try {
		data = json(body);
	} catch (e) {
		return { error: 'failed to parse credential response' };
	}
	if (type(data) != 'object')
		return { error: 'unexpected credential response' };
	let key = data.nordlynx_private_key;
	if (!validate_wg_key(key))
		return { error: 'no valid private key in credential response' };
	return { private_key: key };
}

// Exchange a 64-hex token for the NordLynx WireGuard private key.
function get_private_key(token) {
	if (!validate_token(token))
		return { error: 'invalid token format' };

	let p = pipe();
	if (!p)
		return { error: 'failed to create credential pipe' };
	let r = p[0], w = p[1];
	let rfd = r.fileno();

	// curl computes the Basic auth header itself; the token exists only in the
	// pipe buffer. Close the write end before exec so curl sees EOF.
	w.write('user = "token:' + token + '"\n');
	w.close();

	let argv = [
		'curl', '-g', '-s', '-S', '--fail',
		'--connect-timeout', '15', '--max-time', '30',
		'-H', 'Accept: application/json',
		'--config', '/proc/self/fd/' + rfd,
		CREDS_URL
	];
	let proc = open_cmd(argv, 'r');
	if (!proc) {
		r.close();
		return { error: 'failed to start curl' };
	}

	let body = '';
	while (length(body) < 65536) {
		let chunk = proc.read(4096);
		if (chunk == null || chunk == '')
			break;
		body += chunk;
	}
	let code = proc.close();
	r.close();

	if (code == 22)
		return { error: 'invalid or expired token' };
	if (code != 0)
		return { error: 'credential request failed' };

	return parse_credentials(body);
}

return { parse_credentials, get_private_key };
