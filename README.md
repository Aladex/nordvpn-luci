# NordVPN LuCI Module

Web interface for configuring NordVPN WireGuard on OpenWrt/LuCI with support for custom routing tables and automatic server rotation.

## Features

- **Token-based authentication**: Enter a 64-char access token once — the module generates a private WireGuard key via the NordVPN API. The token is not stored; only the private key is saved in UCI.
- **Fixed tunnel address**: Uses the standard `10.5.0.2/16` address for all users.
- **Server selection**: Country → city → server, with per-server load info. Multihop (double VPN) servers are supported via a hop-mode toggle.
- **Server list caching**: The full server list is fetched once (paginated, with progress shown in the UI) and cached locally; a background cron job keeps the cache fresh.
- **Auto rotation**: Rotate to a random server on a schedule — either every N minutes or daily at a fixed HH:MM time. Rotation scope follows your selection (whole country or a specific city).
- **Connectivity testing**: After each rotation the script pings through the tunnel and retries with another server if the connection is dead (configurable ping count, timeout and max attempts).
- **Custom routing tables**: Route VPN traffic through a separate routing table (`ip4table`/`ip6table`) for policy-based routing.
- **Native LuCI design**: Matches the standard OpenWrt interface.

## Repository layout

```
luasrc/controller/nordvpn.lua      # LuCI controller (UI backend + JSON API)
luasrc/view/nordvpn/overview.htm   # LuCI view template
nordvpn-rotate                     # Rotation script (runs from cron)
install.sh                         # scp/ssh-based installer
```

## Installation

### With the install script

```bash
./install.sh 192.168.1.1 root
```

### Manually

```bash
# Copy controller
scp luasrc/controller/nordvpn.lua root@router:/usr/lib/lua/luci/controller/

# Copy view template
ssh root@router "mkdir -p /usr/lib/lua/luci/view/nordvpn"
scp luasrc/view/nordvpn/overview.htm root@router:/usr/lib/lua/luci/view/nordvpn/

# Copy rotation script (make executable)
scp nordvpn-rotate root@router:/usr/bin/
ssh root@router "chmod +x /usr/bin/nordvpn-rotate"

# Clear LuCI cache
ssh root@router "rm -rf /tmp/luci-*"
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

## Auto Rotation

1. **Enable Auto Rotation** in the UI.
2. **Choose a schedule**:
   - *Interval*: rotate every N minutes (values above 60 are clamped to hourly by cron).
   - *Time*: rotate daily at a specific HH:MM.
3. **Rotation scope**:
   - Country only: rotates across all servers in the country.
   - Country + city: rotates within the city.
   - Specific server: rotation is disabled (fixed server).

Rotation is driven by a cron entry that calls `/usr/bin/nordvpn-rotate <interface>`. The script fetches a fresh server list, picks a random server within the configured scope, updates the peer, restarts the interface, then pings `8.8.8.8` through the tunnel. If fewer than 70% of pings succeed, it retries with another server (up to `nordvpn_max_retries` attempts).

Relevant UCI options on the interface (all optional, with defaults):

```
option nordvpn_rotation_enabled '1'
option nordvpn_country_code 'ee'
option nordvpn_city_code 'ee-tallinn'
option nordvpn_hop_mode 'single'      # or 'multihop'
option nordvpn_ping_count '10'
option nordvpn_ping_timeout '2'
option nordvpn_max_retries '10'
```

## Server list cache

The controller caches the full WireGuard server list in `nordvpn_servers_cache.json` (default directory `/tmp`, configurable in the UI — stored as `nordvpn_cache_dir` on the interface). The locations page is served from this cache; a manual **Refresh** forces a re-fetch with progress tracking.

A background cron job (`/usr/bin/nordvpn-cache-update`, every 6 hours) is registered on first apply to keep the cache warm.

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
- `luci-httpclient` optional, falls back to `sys.httpget`

## Troubleshooting

- **Token validation fails**: ensure exactly 64 hex chars and a valid, unexpired NordVPN token.
- **No servers in the list**: wait for the background fetch or hit **Refresh**; check internet access and API availability.
- **Rotation not working**: verify the cron job with `crontab -l` and that `/usr/bin/nordvpn-rotate` is executable; run it manually to see logs.
- **Private key not set**: the token must generate a valid 44-char base64 key — re-enter a fresh token.
- **JSON errors**: install `luci-lib-jsonc`.
