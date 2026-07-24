# NordVPN WireGuard for OpenWrt

Configure NordVPN's WireGuard (NordLynx) service on OpenWrt, with a one-time
credential exchange, country/city/server selection, automatic rotation, custom
routing tables and a native LuCI page.

> **Unofficial.** This project is not affiliated with, endorsed by, or supported
> by Nord Security. "NordVPN" and "NordLynx" are trademarks of their respective
> owners. Use your own NordVPN account and access token.

## Architecture

The project ships as **two packages** so the VPN service is useful without a web
interface and the LuCI app stays a thin frontend:

- **`nordvpn-wireguard`** — the backend (targets `openwrt/packages`,
  `net/nordvpn-wireguard`). ucode + procd + an rpcd/ubus object. Does credential
  exchange, server-list caching, WireGuard interface/peer generation,
  connectivity checks, scheduled rotation and runtime status. Works from the CLI
  and over ubus with no LuCI installed.
- **`luci-app-nordvpn`** — the LuCI frontend (targets `openwrt/luci`,
  `applications/luci-app-nordvpn`). A JavaScript view that calls the backend's
  ubus methods. Performs no privileged filesystem or network-config operations
  itself.

The browser never receives the access token or the WireGuard private key.

## Repository layout

```
nordvpn-wireguard/                         # backend package (packages feed)
├── Makefile
├── test.sh                                # CI version smoke test
├── files/etc/config/nordvpn               # non-secret settings (owns config)
├── files/etc/init.d/nordvpn               # consolidated procd service
├── files/etc/uci-defaults/90-nordvpn-migrate
├── files/usr/bin/nordvpn-service          # uloop scheduler daemon
├── files/usr/bin/nordvpn-cache-update     # one-shot cache worker
├── files/usr/bin/nordvpn-rotate           # one-shot rotation worker
├── files/usr/share/rpcd/ucode/nordvpn.uc  # ubus object 'nordvpn'
├── files/usr/share/ucode/nordvpn/*.uc     # shared ucode modules
└── tests/                                 # offline ucode fixture/unit tests

luci-app-nordvpn/                          # LuCI frontend (luci feed)
├── Makefile
├── htdocs/luci-static/resources/view/nordvpn/overview.js
├── po/templates/nordvpn.pot
└── root/usr/share/{luci/menu.d,rpcd/acl.d}/luci-app-nordvpn.json
```

## Supported releases

- **Primary:** current OpenWrt master / snapshots (uses `apk`).
- **Secondary:** OpenWrt 25.12 where APIs and dependencies match.
- Older releases only via a separately maintained downstream build.

## Installation

### From a package feed / snapshot build

Build with the OpenWrt SDK for your target. The backend is a plain packages-feed
package; the LuCI app builds inside an `openwrt/luci` checkout.

```bash
# backend (packages feed style)
cp -r nordvpn-wireguard "$SDK/package/nordvpn-wireguard"
cd "$SDK" && ./scripts/feeds update -a && ./scripts/feeds install -a
make defconfig
make package/nordvpn-wireguard/compile

# frontend (from an openwrt/luci checkout)
cp -r luci-app-nordvpn openwrt-luci/applications/luci-app-nordvpn
# build via the luci feed as usual
```

Install the resulting packages on the router:

```bash
apk add ./nordvpn-wireguard-*.apk ./luci-app-nordvpn-*.apk   # 25.x / snapshots
# or: opkg install ./nordvpn-wireguard_*.ipk ./luci-app-nordvpn_*.ipk   # 24.10
```

Installing `nordvpn-wireguard` alone gives a working CLI/service; add
`luci-app-nordvpn` for the web UI.

## Usage

1. Open LuCI → **VPN → NordVPN**.
2. Click **Set credentials** and paste your 64-character NordVPN access token.
   It is exchanged once for the WireGuard private key and is **never stored**.
3. Pick **Country** (required), optionally **City** and **Server**. Leave City
   and Server on *Automatic* to rotate within the country.
4. Optionally enable **Automatic rotation** and a schedule.
5. Click **Save and reconnect**.

Get a token at
<https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/> →
**Generate new token** (a non-expiring token is fine).

A saved configuration and an established tunnel are shown as **different
states** — the page never claims "Connected" just because settings were saved.

## Configuration (`/etc/config/nordvpn`)

The backend owns non-secret settings here; a fresh install ships **disabled**.

```
config settings 'main'
	option enabled '0'
	option interface 'nordvpn'
	option routing_table ''
	option hop_mode 'single'          # or 'multihop'
	option country_code 'ee'
	option city_code 'ee-tallinn'
	option fixed_server ''            # pin a gateway; disables rotation
	option rotation_enabled '0'
	option rotation_mode 'interval'  # or 'time'
	option rotation_interval '360'   # minutes
	option rotation_time '04:30'     # HH:MM, router local time
	option ping_count '10'
	option ping_timeout '2'
	option max_retries '10'
	option cache_dir ''              # empty = /tmp
	option cache_refresh_interval '21600'
```

The generated WireGuard interface/peer live in `/etc/config/network` and are
backend-owned. The private key is stored there for netifd but never appears in
any status/ubus response.

## ubus API

All methods are on the `nordvpn` object. Read methods never mutate; secrets are
never returned.

```bash
ubus call nordvpn status            # runtime state, location, handshake age
ubus call nordvpn locations         # cached country/city/server list
ubus call nordvpn refresh_status    # cache-refresh job progress
ubus call nordvpn set_credentials '{"token":"<64-hex-token>"}'
ubus call nordvpn apply             # rebuild the peer and bring the tunnel up
ubus call nordvpn rotate_now        # one-shot rotation
ubus call nordvpn refresh_locations # start an async server-list refresh
```

Access is gated by the `luci-app-nordvpn` ACL: read methods for read sessions,
write methods for write sessions. A read-only LuCI account cannot call the write
methods, and the raw private key is not reachable through UCI or ubus.

## Services and logs

```bash
service nordvpn status
service nordvpn version        # installed version
logread -e nordvpn
```

One procd-supervised daemon (`nordvpn-service`) refreshes the cache and runs
scheduled rotation, re-reading `/etc/config/nordvpn` on every tick; a config
reload restarts it. Scheduled rotation runs `nordvpn-rotate`, which picks a
server within your selection, updates the peer, then pings through the tunnel
(bound to the VPN device) and retries another server if the link is dead — up to
`max_retries`. A failed rotation restores the last working peer.

## Custom routing tables

Set **Routing table** (Advanced) to route VPN traffic through a separate table
(`ip4table`/`ip6table` on the interface), then add rules under
**Network → Routing → Policy Routing**.

## Security

- The access token is exchanged for the private key through an anonymous pipe
  (curl reads it from a config on `/proc/self/fd`); it never appears in argv, an
  environment variable, a temp file, or logs, and is never persisted.
- Every external command runs as an argv array (no shell), so interface names,
  hostnames, schedules and cache paths cannot inject shell syntax.
- All ubus inputs have a fixed schema and are range/format validated.
- Cache writes are atomic (temp file + rename) and refreshes are serialized by a
  lock; a failed refresh keeps the last good cache.

## Upgrade / downgrade

Upgrading from the legacy Lua `luci-app-nordvpn` runs a one-time, idempotent
migration (`uci-defaults`) that copies non-secret settings into
`/etc/config/nordvpn`, preserves the existing private key and active peer,
removes any stored token, and drops old cron entries. It does not disconnect a
working tunnel. Downgrading to the legacy Lua package is not supported (the new
config layout is not read by it).

## Development

Offline ucode tests (no account or network needed):

```bash
# with ucode + ucode-mod-fs + ucode-mod-math available
sh nordvpn-wireguard/tests/run.sh
```

CI runs shell/JSON static checks, LuCI ESLint on the JS view, the ucode tests,
and a snapshot-SDK build of the backend. See `.github/workflows/build.yml`.

## License

[0BSD](LICENSE) — do whatever you want with it.
