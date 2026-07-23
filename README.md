# NordVPN LuCI Module

Web interface for configuring NordVPN WireGuard on OpenWrt/LuCI with automatic server rotation and custom routing tables. Ships as a standard OpenWrt package (`luci-app-nordvpn`) with procd services.

## Features

- **Token-based authentication**: Enter a 64-char access token once — the module generates a private WireGuard key via the NordVPN API. The token is not stored; only the private key is saved in UCI.
- **Fixed tunnel address**: Uses the standard `10.5.0.2/16` address for all users.
- **Server selection**: Country → city → server, with per-server load info. Multihop (double VPN) servers are supported via a hop-mode toggle.
- **Server list caching**: The full server list is fetched once (paginated, with progress shown in the UI) and cached locally; the `nordvpn-cache` service keeps it fresh in the background.
- **Auto rotation**: The `nordvpn-rotate` service rotates to a random server on a schedule — either every N minutes or daily at a fixed HH:MM time. Rotation scope follows your selection (whole country or a specific city).
- **Connectivity testing**: After each rotation the script pings through the tunnel and retries with another server if the connection is dead (configurable ping count, timeout and max attempts).
- **Custom routing tables**: Route VPN traffic through a separate routing table (`ip4table`/`ip6table`) for policy-based routing.
- **Native LuCI design**: Matches the standard OpenWrt interface.

## Repository layout

```
Makefile                           # OpenWrt package definition (luci.mk)
luasrc/controller/nordvpn.lua      # LuCI controller (UI backend + JSON API)
luasrc/nordvpn/cache.lua           # Shared server-list cache logic
luasrc/view/nordvpn/overview.htm   # LuCI view template
root/usr/bin/nordvpn-rotate        # Rotation worker (called by the service)
root/usr/bin/nordvpn-cache-update  # One-shot cache refresh (called by the service)
root/etc/init.d/nordvpn-rotate     # procd service: rotation scheduler
root/etc/init.d/nordvpn-cache      # procd service: cache refresher
root/etc/config/nordvpn            # Default UCI config
install.sh                         # Manual (scp/ssh) installer, no package build needed
```

## Installation

### As an ipk package (recommended)

Build with the OpenWrt SDK:

```bash
git clone https://github.com/Aladex/nordvpn-luci.git package/luci-app-nordvpn
./scripts/feeds update -a
./scripts/feeds install -a
make package/luci-app-nordvpn/compile
```

The package lands in `bin/packages/*/luci_app_nordvpn/`. Copy it to the router and install:

```bash
opkg install luci-app-nordvpn_1.0.0-1_all.ipk
```

The postinst enables and starts both services and clears the LuCI cache.

### Manually

```bash
./install.sh 192.168.1.1 root
```

## Usage

1. Open LuCI: `https://<router>/cgi-bin/luci`
2. Navigate to **VPN → NordVPN**
3. Configure:
   - **Interface Name**: default `nordvpn`
   - **Routing Table**: optional custom table name (leave empty for `main`)
   - **Access Token**: your 64-character hex NordVPN token (one-time use)
   - **Server Selection**: country → city → server, or leave random
   - **Auto Rotation**: enable and pick a schedule
4. The private key is generated automatically via the API; the tunnel address is fixed at `10.5.0.2/16`.
5. Click **Apply Configuration** — the module creates the WireGuard interface if missing, writes the peer config and restarts the interface.

**Note**: The token is never stored; only the generated private key is kept in UCI.

### Getting a NordVPN access token

Log in at https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/ → **Generate new token** and copy it (you can choose a non-expiring token).

## Services

Two procd services are installed and enabled by default:

```bash
service nordvpn-cache status     # background server-list cache refresh
service nordvpn-rotate status    # rotation scheduler

logread -e nordvpn-cache         # cache refresh logs
logread -e nordvpn-rotate        # rotation logs
```

The rotation service reads the schedule directly from UCI on every iteration — changes applied in the UI take effect without a service restart. Cron entries installed by older cron-based versions of this module are removed automatically on service start.

## Auto Rotation

1. **Enable Auto Rotation** in the UI.
2. **Choose a schedule**:
   - *Interval*: rotate every N minutes.
   - *Time*: rotate daily at a specific HH:MM (router local time).
3. **Rotation scope**:
   - Country only: rotates across all servers in the country.
   - Country + city: rotates within the city.
   - Specific server: rotation is disabled (fixed server).

When a rotation is due, the service runs `/usr/bin/nordvpn-rotate <interface>`. The worker fetches a fresh server list, picks a random server within the configured scope, updates the peer, restarts the interface, then pings `8.8.8.8` through the tunnel. If fewer than 70% of pings succeed, it retries with another server (up to `nordvpn_max_retries` attempts).

Relevant UCI options on the interface (all optional, with defaults):

```
option nordvpn_rotation_enabled '1'
option nordvpn_rotation_mode 'interval'    # or 'time'
option nordvpn_rotation_interval '360'     # minutes
option nordvpn_rotation_time '04:30'       # HH:MM
option nordvpn_country_code 'ee'
option nordvpn_city_code 'ee-tallinn'
option nordvpn_hop_mode 'single'           # or 'multihop'
option nordvpn_ping_count '10'
option nordvpn_ping_timeout '2'
option nordvpn_max_retries '10'
```

## Server list cache

The controller caches the full WireGuard server list in `nordvpn_servers_cache.json` (default directory `/tmp`, configurable in the UI — stored as `nordvpn_cache_dir` on the interface). The locations page is served from this cache; a manual **Refresh** forces a re-fetch with progress tracking.

The `nordvpn-cache` service refreshes the cache every 6 hours by default. Change the interval in `/etc/config/nordvpn`:

```
config settings 'settings'
	option cache_refresh_interval '21600'    # seconds
```

## Custom Routing Tables

1. Enter a routing table name (e.g. `vpn_table`) in the **Routing Table** field.
2. The module sets `ip4table` and `ip6table` on the interface.
3. Configure rules in **Network → Routing → Policy Routing**.

Example:

```
config interface 'nordvpn'
	option proto 'wireguard'
	option ip4table 'vpn_table'
	option ip6table 'vpn_table'
	...

config rule
	option src '192.168.1.0/24'
	option lookup 'vpn_table'
```

## API Endpoints

All under `/cgi-bin/luci/admin/vpn/nordvpn`:

- `GET /` — web interface
- `GET /status?interface=nordvpn` — current config incl. private key (JSON)
- `GET /config?interface=nordvpn` — current config without private key (JSON)
- `GET /locations` — cached server list (JSON)
- `GET /locations_refresh` — force re-fetch from the API
- `GET /locations_progress` — fetch progress state (JSON)
- `GET /locations_progress_reset` — reset progress state
- `POST /apply` — apply configuration (JSON payload with token or private_key, relay, rotation settings)
- `GET|POST /settings` — read/update cache directory settings

## Requirements

- OpenWrt with LuCI
- WireGuard: `opkg install luci-proto-wireguard kmod-wireguard`
- `openssl` for Base64: `opkg install openssl-util`
- `curl` (used for authenticated API calls)
- `luci-lib-jsonc` for JSON parsing

All of the above except the kernel module are pulled in automatically as package dependencies.

## Troubleshooting

- **Token validation fails**: ensure exactly 64 hex chars and a valid, unexpired NordVPN token.
- **No servers in the list**: wait for the background fetch or hit **Refresh**; check `logread -e nordvpn-cache` for fetch errors.
- **Rotation not working**: check `logread -e nordvpn-rotate`, verify the service is running (`service nordvpn-rotate status`), or run `/usr/bin/nordvpn-rotate nordvpn` manually to see full output.
- **Private key not set**: the token must generate a valid 44-char base64 key — re-enter a fresh token.
- **JSON errors**: install `luci-lib-jsonc`.

## License

[0BSD](LICENSE) — do whatever you want with it.
