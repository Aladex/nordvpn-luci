# NordVPN WireGuard for OpenWrt

Configure NordVPN's WireGuard (NordLynx) service on OpenWrt, with a one-time
credential exchange, country/city/server selection (including Double VPN and
Onion over VPN), automatic rotation, multiple parallel VPN instances,
per-network traffic steering with kill switch and IPv6 leak protection, and a
native LuCI page.

> **Unofficial.** This project is not affiliated with, endorsed by, or supported
> by Nord Security. "NordVPN" and "NordLynx" are trademarks of their respective
> owners. Use your own NordVPN account and access token.

![LuCI overview page](docs/screenshots/overview.png)

## Architecture

The project ships as **two packages** so the VPN service is useful without a web
interface and the LuCI app stays a thin frontend:

- **`nordvpn-wireguard`** — the backend (targets `openwrt/packages`,
  `net/nordvpn-wireguard`). ucode + procd + an rpcd/ubus object. Does credential
  exchange, server-list caching, WireGuard interface/peer generation,
  handshake verification, scheduled rotation and runtime status. Works from the
  CLI and over ubus with no LuCI installed.
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

docs/screenshots/                          # LuCI page screenshots (README)
```

## Supported releases

- **Primary:** current OpenWrt master / snapshots (uses `apk`).
- **Secondary:** OpenWrt 25.12 where APIs and dependencies match.
- Older releases only via a separately maintained downstream build.

## Installation

### From the signed package feed (recommended)

CI publishes signed, architecture-independent packages for every release to
<https://aladex.github.io/nordvpn-luci/>.

**OpenWrt 24.10 (opkg):**

```sh
wget -O /etc/opkg/keys/6bf1f0b6d25ceaad \
  https://aladex.github.io/nordvpn-luci/keys/6bf1f0b6d25ceaad
echo 'src/gz nordvpn_luci https://aladex.github.io/nordvpn-luci/packages/opkg' \
  >> /etc/opkg/customfeeds.conf
opkg update
opkg install luci-app-nordvpn        # or just nordvpn-wireguard for headless
```

**OpenWrt snapshots / 25.x (apk):**

```sh
wget -O /etc/apk/keys/nordvpn-luci-apk.pem \
  https://aladex.github.io/nordvpn-luci/keys/nordvpn-luci-apk.pem
echo 'https://aladex.github.io/nordvpn-luci/packages/apk/packages.adb' \
  >> /etc/apk/repositories.d/customfeeds.list
apk update
apk add luci-app-nordvpn
```

Log out of LuCI and back in after installing, then open **VPN → NordVPN**.

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

   ![Credentials dialog](docs/screenshots/credentials-modal.png)

3. Pick a **Hop mode**:
   - **Single hop** — a regular VPN server.
   - **Multihop** (Double VPN) — the selected country is the **exit** country
     (your visible IP); traffic enters through the partner country shown in the
     server name ("United Kingdom - Netherlands #10" enters in the UK and exits
     in the Netherlands).
   - **Onion over VPN** — traffic leaves the VPN server through the Tor
     network. Noticeably slower, and some sites block Tor exit nodes. These
     servers never appear in the other modes, so Tor is always an explicit
     choice.

   ![Onion over VPN mode](docs/screenshots/onion-mode.png)

4. Pick **Country** (required), optionally **City** and **Server**. Country
   names carry emoji flags (plain names on systems without flag glyphs). Leave
   City and Server on *Automatic* to rotate within the country.
5. Optionally enable **Automatic rotation** and a schedule. When rotation is
   active the page shows the concrete **Next rotation** time (router-scheduled,
   shown in your browser's local time zone).

   ![Automatic rotation](docs/screenshots/rotation.png)

6. Click **Save and reconnect**.

Get a token at
<https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/> →
**Generate new token** (a non-expiring token is fine).

A saved configuration and an established tunnel are shown as **different
states** — the page never claims "Connected" just because settings were saved.

## Configuration (`/etc/config/nordvpn`)

The backend owns non-secret settings here; a fresh install ships **disabled**.
One `config instance` section per VPN instance ('main' is the default and also
carries the shared cache options).

```
config instance 'main'
	option enabled '0'
	option interface 'nordvpn'
	option routing_table ''
	option hop_mode 'single'          # 'multihop' (Double VPN) / 'onion' (via Tor)
	option country_code 'ee'
	option city_code 'ee-tallinn'
	option fixed_server ''            # pin a gateway; disables rotation
	option rotation_enabled '0'
	option rotation_mode 'interval'  # or 'time'
	option rotation_interval '360'   # minutes
	option rotation_time '04:30'     # HH:MM, router local time
	option verify_timeout '8'        # seconds to wait for a WG handshake
	option max_retries '10'          # candidate servers per rotation
	option auto_routing '1'          # route all LAN traffic via the VPN
	list source_network 'media'      # or: steer only these networks (see below)
	option killswitch '0'            # block steered traffic while VPN is down
	option block_ipv6 '1'            # block direct IPv6 (leak prevention)
	option use_vpn_dns '0'           # push NordVPN resolvers while connected
	option cache_dir ''              # empty = /tmp, shared by all instances
	option cache_refresh_interval '21600'   # seconds, background refresh
```

All of these are editable from the LuCI page (most under **Advanced settings**):

![Advanced settings](docs/screenshots/advanced.png)

The generated WireGuard interface/peer live in `/etc/config/network` and are
backend-owned. The private key is stored there for netifd but never appears in
any status/ubus response.

## ubus API

All methods are on the `nordvpn` object. Read methods never mutate; secrets are
never returned.

```bash
ubus call nordvpn status            # runtime state, location, handshake age
ubus call nordvpn instances         # status of every configured VPN instance
ubus call nordvpn external_ip       # public IP as seen through the tunnel
ubus call nordvpn disconnect        # take the tunnel down, pause rotation
ubus call nordvpn clear_credentials # forget the stored WireGuard key
ubus call nordvpn locations         # cached country/city tree (+ per-city counts)
ubus call nordvpn servers '{"country":"de","city":"de-berlin","hop_mode":"single"}'
ubus call nordvpn refresh_status    # cache-refresh job progress
ubus call nordvpn set_credentials '{"token":"<64-hex-token>"}'
ubus call nordvpn apply             # rebuild the peer and bring the tunnel up
ubus call nordvpn rotate_now        # one-shot rotation
ubus call nordvpn refresh_locations # start an async server-list refresh
```

`status` distinguishes *configured* from *connected*: `connected` requires a
WireGuard handshake fresher than 3 minutes, `degraded` means the interface is
up but the handshake went stale, and `rotation.next_run` is the epoch of the
next scheduled rotation (`null` when rotation cannot run).

### Multiple VPN instances

`/etc/config/nordvpn` may contain several `config instance '<name>'` sections
('main' is the default). Each instance runs its own tunnel on its own
interface with its own credentials and rotation schedule — e.g. the main
route through Germany and a media network through Serbia. Issue a separate
NordVPN access token per instance: reusing one key from several places has
reportedly led to NordVPN locking it. `status`, `apply`, `rotate_now` and
`set_credentials` accept an `instance` argument (default `main`);
`create_instance`/`delete_instance` manage the lifecycle, and
`nordvpn-rotate <name>` rotates one instance from the CLI. The server-list
cache is shared.

The LuCI page lists every instance with its state, server and next rotation;
clicking a row selects it and the whole form (credentials, country, rotation,
routing) applies to the selected instance. **Add instance** creates one (it
gets interface `nv_<name>`), **Delete** tears the tunnel down and removes its
interface, stamped firewall objects and settings; for 'main' the button is
**Reset** — the section stays but every option returns to its default. The
status band shows the connected server's actual city and the public IP seen
through the tunnel, and offers **Disconnect** (tunnel down, rotation paused
until the next connect). Credentials can be removed without deleting the
instance.

To steer only some networks through an instance, pick them under **Steered
networks** in its Traffic routing panel: the backend maintains stamped policy
rules (`in <network> lookup <table>`, priority 20000) plus prohibit rules that
act as a per-network kill switch (optional) and IPv6 leak block (default on) —
they fire only when the tunnel's table cannot serve the traffic. So that the
steered default does not swallow local destinations, the backend also mirrors
every local IPv4 subnet into the instance's table (interface subnets, static
routes and the allowed-IPs of your own WireGuard links; your own routes for
the same subnet always win). Or keep using your own policy-routing rules
(manual mode is detected and left alone).

![VPN instances](docs/screenshots/instances.png)

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
scheduled rotation, re-reading `/etc/config/nordvpn` on every 30-second tick; a
config change restarts it. The rotation clock is persisted in
`/tmp/nordvpn_rotate_state.json`, so daemon restarts do not reset the schedule
or trigger a spurious rotation.

### Server verification (apply and rotation)

NordVPN's server list includes dead endpoints, and all WireGuard servers in a
country share one public key — so a bad endpoint still brings the interface
"up" without error. Both **apply** and **rotation** therefore verify each
candidate by waiting up to `verify_timeout` seconds for an actual **WireGuard
handshake** (`wg show latest-handshakes`), not by pinging through the tunnel.
Rotation only ever moves to a **different** server: the current gateway is
excluded from the candidate set, so a rotation reported as successful has always
changed the server. It tries up to `max_retries` shuffled candidates and, if none
complete a handshake, restores the last working peer rather than leaving a dead
tunnel. When the selection matches no server other than the current one, rotation
is a no-op and keeps the working tunnel. Apply behaves the same way for automatic
selections. (`max_retries` is a deliberate bound: a rotation worker must finish
well within the lock's staleness window so the next scheduled tick cannot start a
second, overlapping rotation.)

### Rotation across hop modes

Rotation is hop-mode aware — it only considers servers of the instance's own
kind. A **Multihop** instance rotates among Double VPN servers with the same
**exit** country (the entry country may change between rotations); an **Onion
over VPN** instance rotates among onion servers only; single-hop never mixes in
either. Because the Double VPN and Onion pools are far smaller than the
single-hop pool, a country — or a pinned city — may expose only one server of
that kind, in which case there is nothing to rotate to and the current tunnel is
kept. Onion over VPN exists in only a handful of countries at all, so pairing it
with a country that has none leaves rotation with no candidates.

### Server-list cache

The daemon refreshes the cache automatically: on its first tick after start it
refreshes if the on-disk cache is older than 24 h, and afterwards every
`cache_refresh_interval` seconds (6 h by default). The **Refresh server list**
button in the UI starts the same one-shot worker (`nordvpn-cache-update`)
asynchronously. Cache writes are atomic (temp file + rename), refreshes are
serialized with a lock, and a failed refresh keeps the previous good cache.

## Traffic routing & firewall

The **Traffic routing** panel decides how traffic reaches the tunnel.
On every apply the backend first *detects* the current scheme:

- **Manual** — unstamped routes/rules referencing the VPN interface exist, or
  a routing table is configured without steering. The package then never
  touches routing or firewall; the panel is purely informational (with an
  IPv6-leak warning when the WAN has IPv6).

  ![Manual routing detected](docs/screenshots/routing-manual.png)

- **Automatic** — *Route all LAN traffic through the VPN* is enabled (the
  default on fresh installs) and no manual scheme is detected. The backend
  then maintains: `route_allowed_ips` on the peer (netifd installs the default
  route via the tunnel and removes it when the interface goes down — the WAN
  default is never modified), a masquerading firewall zone for the interface,
  and a forwarding from the LAN zone. Optional toggles add a **kill switch**
  (a REJECT rule LAN→WAN, so LAN clients get no internet while the VPN is
  down), an **IPv6 block** (family-ipv6 REJECT LAN→WAN, on by default —
  NordLynx is IPv4-only inside, so direct IPv6 would bypass the tunnel), and
  **NordVPN DNS** on the interface.

- **Steered** — specific networks are ticked under *Steered networks*
  (`list source_network`). Only their traffic is policy-routed into the
  instance's table; the router's own traffic and other networks are untouched.
  The kill switch / IPv6 toggles become per-network prohibit rules that fire
  only when the tunnel cannot serve the traffic, and every local IPv4 subnet
  is mirrored into the table so VLAN-to-VLAN and local services stay
  reachable (your own routes for a subnet always win).

  ![Steered networks](docs/screenshots/routing-steered.png)

Everything the automatic mode creates is stamped with `nordvpn_managed`;
disabling a toggle (or automatic mode) removes exactly the stamped objects and
nothing else. User-created zones, forwardings, routes and rules are never
modified. Upgrades from the legacy Lua app keep `auto_routing '0'`.

### Custom routing tables (manual mode)

Set **Routing table** (Advanced) to route VPN traffic through a separate table
(`ip4table`/`ip6table` on the interface), then add rules under
**Network → Routing → Policy Routing**.

## Security

- The access token is exchanged for the private key through an anonymous pipe
  (curl reads it from a config on `/proc/self/fd`); it never appears in argv, an
  environment variable, a temp file, or logs, and is never persisted.
- Every external command is built from an argv list with each argument
  single-quoted for the shell, and every interpolated value (interface names,
  hostnames, schedules, cache paths) is whitelist-validated first, so no shell
  syntax can be injected.
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

## Related projects

- [**NordVPN Lite**](https://nordvpn.com/blog/nordvpn-for-openwrt-routers/) —
  the official, deliberately minimal OpenWrt client: one NordLynx connection,
  CLI/basic LuCI setup. This project is the power-user alternative: multiple
  parallel instances with separate credentials, per-network steering with kill
  switch and IPv6 leak protection, scheduled rotation verified by WireGuard
  handshake, Double VPN / Onion over VPN as explicit modes, and detection-first
  safety around hand-built routing.
- [**NordVPN-Easy-OpenWrt**](https://github.com/tis24dev/NordVPN-Easy-OpenWrt)
  — a shell-based community integration with health checks and recovery. This
  project instead uses native ucode/rpcd/procd with an offline test suite, and
  covers multi-instance, steering and rotation.
- Config generators (e.g.
  [NordVPN-WireGuard-Config-Generator](https://github.com/mustafachyi/NordVPN-WireGuard-Config-Generator))
  produce static `.conf` files and leave routing, rotation and recovery to you.

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
