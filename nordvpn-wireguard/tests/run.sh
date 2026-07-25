#!/bin/sh
# SPDX-License-Identifier: MIT
# Offline ucode unit/fixture tests for nordvpn-wireguard. No network or account.
# Requires ucode + ucode-mod-fs + ucode-mod-math. 'uci'/'ubus' are mocked and
# forced ahead of the real modules on the search path, so no device is needed.
#
# Dev overrides for a locally-built ucode:
#   UCODE=/path/to/ucode          (default: ucode from PATH)
#   UCODE_EXTRA_L="/builddir/*.so" (extra -L pattern, e.g. host-built fs.so/math.so)

here="$(cd "$(dirname "$0")" && pwd)"
lib="$here/../files/usr/share/ucode"
mocks="$here/mocks"
fixture="$here/fixtures/servers_sample.json"
rpcd="$here/../files/usr/share/rpcd/ucode/nordvpn.uc"
key="$(printf '00000000000000000000000000000001' | base64)"
UCODE="${UCODE:-ucode}"

if ! command -v "$UCODE" >/dev/null 2>&1; then
	echo "ucode not found (set \$UCODE to a built interpreter); skipping" >&2
	exit 2
fi

status=0
for t in "$here"/test_*.uc; do
	echo "== ${t##*/} =="
	if [ -n "$UCODE_EXTRA_L" ]; then
		"$UCODE" -L "$mocks/*.uc" -L "$lib/*.uc" -L "$UCODE_EXTRA_L" \
			-D fixture="$fixture" -D KEY="$key" -D RPCD="$rpcd" -S "$t" || status=1
	else
		"$UCODE" -L "$mocks/*.uc" -L "$lib/*.uc" \
			-D fixture="$fixture" -D KEY="$key" -D RPCD="$rpcd" -S "$t" || status=1
	fi
done

[ "$status" = 0 ] && echo "ALL TESTS PASSED" || echo "TESTS FAILED"
exit "$status"
