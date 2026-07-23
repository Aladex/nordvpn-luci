module("luci.controller.nordvpn", package.seeall)

local http = require "luci.http"
local json = require "luci.jsonc"
local sys = require "luci.sys"
local fs_ok, fs_mod = pcall(require, "nixio.fs")
local fs = fs_ok and fs_mod or nil

local cache = require "luci.nordvpn.cache"

local API_BASE = "https://api.nordvpn.com/v1"
local CREDS_URL = API_BASE .. "/users/services/credentials"
local DEFAULT_INTERFACE = "nordvpn"
local DEFAULT_PORT = 51820
local DEFAULT_KEEPALIVE = 25
local FIXED_ADDRESS = "10.5.0.2/16"
local SERVERS_URL = cache.SERVERS_URL
local PAGE_SIZE = cache.PAGE_SIZE
local FETCH_STATUS_FILE = cache.FETCH_STATUS_FILE

local function new_cursor()
	return require("luci.model.uci").cursor()
end

local function iso_ts(ts)
	return os.date("!%Y-%m-%dT%H:%M:%SZ", ts or os.time())
end

-- Seed RNG once
local function seed_rng()
	local clock_part = tostring(os.clock() or ""):gsub("%D", "")
	clock_part = tonumber(clock_part) or 0
	math.randomseed(os.time() + clock_part)
end

seed_rng()

local function find_interface_by_vpn_type(cur, vpn_type)
	local found_interface = nil

	cur:foreach("network", "interface", function(s)
		if s.vpn_type == vpn_type then
			found_interface = s[".name"]
			return false
		end
	end)

	return found_interface
end

local function prepare_json_response(obj, status_code)
	http.status(status_code or 200)
	http.prepare_content("application/json")
	http.write_json(obj or {})
end

local function validate_private_key(key)
	if type(key) ~= "string" then
		return false, "missing private key"
	end

	if #key ~= 44 or not key:match("^[A-Za-z0-9%+/=]+$") then
		return false, "invalid private key format"
	end

	return true
end

local function validate_token(token)
	if type(token) ~= "string" then
		return false, "missing token"
	end

	if #token ~= 64 or not token:match("^[a-fA-F0-9]+$") then
		return false, "invalid token format"
	end

	return true
end

local function get_private_key(token)
	if not validate_token(token) then
		return nil, "invalid token format"
	end

	-- Create Basic Auth header using base64
	local auth_str = "token:" .. token
	local cmd = string.format("echo -n '%s' | openssl base64 -e 2>/dev/null", auth_str)
	local auth_b64 = sys.exec(cmd)
	auth_b64 = auth_b64:gsub("%s+", "")  -- Remove all whitespace including newlines

	if not auth_b64 or #auth_b64 == 0 then
		return nil, "failed to encode auth header"
	end

	-- Use curl for reliable HTTP request with custom headers
	local curl_cmd = string.format(
		"curl -s -H 'Authorization: Basic %s' '%s' 2>/dev/null",
		auth_b64,
		CREDS_URL
	)

	local body = sys.exec(curl_cmd)

	if not body or #body == 0 then
		return nil, "failed to fetch credentials from NordVPN API"
	end

	local data = json.parse(body)
	if not data then
		return nil, "failed to parse API response"
	end

	if not data.nordlynx_private_key then
		return nil, "nordlynx_private_key not found in response"
	end

	return data.nordlynx_private_key
end

local function find_interface_section(cur, name)
	local section

	cur:foreach("network", "interface", function(s)
		if s[".name"] == name then
			section = s
			return false
		end
	end)

	return section
end

local function find_or_create_peer(cur, iface_name)
	local section_name
	local section_to_delete = {}

	cur:foreach("network", nil, function(s)
		if s[".type"] and s[".type"]:match("^wireguard_") then
			-- Only manage sections for OUR interface
			if s.interface == iface_name then
				section_name = s[".name"]
				return false
			-- Delete old sections without interface field ONLY if they belong to our VPN type
			elseif not s.interface and s[".name"]:match("^wireguard_" .. iface_name) then
				table.insert(section_to_delete, s[".name"])
			end
		end
	end)

	-- Clean up old wireguard sections (only ours!)
	for _, name in ipairs(section_to_delete) do
		cur:delete("network", name)
	end

	if section_name then
		return section_name
	end

	local type_name = string.format("wireguard_%s", iface_name)
	section_name = cur:add("network", type_name)
	cur:set("network", section_name, "interface", iface_name)
	return section_name
end

local function get_interface_state(cur, iface_name)
	local iface = cur:get_all("network", iface_name)
	if not iface then
		return nil
	end

	local peer
	cur:foreach("network", nil, function(s)
		if s[".type"] and s[".type"]:match("^wireguard_") and s.interface == iface_name then
			peer = cur:get_all("network", s[".name"])
			peer[".name"] = s[".name"]
			return false
		end
	end)

	return {
		interface = iface,
		peer = peer
	}
end

function index()
	entry({"admin", "vpn"}, firstchild(), "VPN", 60).dependent = false
	entry({"admin", "vpn", "nordvpn"}, template("nordvpn/overview"), _("NordVPN"), 20)
entry({"admin", "vpn", "nordvpn", "status"}, call("get_profile")).leaf = true
entry({"admin", "vpn", "nordvpn", "config"}, call("get_config_only")).leaf = true
entry({"admin", "vpn", "nordvpn", "locations"}, call("list_locations")).leaf = true
entry({"admin", "vpn", "nordvpn", "locations_refresh"}, call("refresh_locations")).leaf = true
entry({"admin", "vpn", "nordvpn", "locations_progress"}, call("locations_progress")).leaf = true
entry({"admin", "vpn", "nordvpn", "locations_progress_reset"}, call("locations_progress_reset")).leaf = true
entry({"admin", "vpn", "nordvpn", "apply"}, call("apply_profile")).leaf = true
entry({"admin", "vpn", "nordvpn", "settings"}, call("cache_settings")).leaf = true
end

function list_locations()
	local ok, err = pcall(function()
		local cache_file, effective_cache_dir, configured_cache_dir, cache_fallback = cache.get_cache_file_path()
		local cache_meta = {
			cache_file = cache_file,
			effective_cache_dir = effective_cache_dir,
			configured_cache_dir = configured_cache_dir,
			cache_dir_fallback = cache_fallback
		}

		-- Load from cache (no age checking - background job keeps it fresh)
		local cached = cache.read_cache(cache_file)
		if cached then
			cache.write_fetch_status({
				state = "idle",
				cache = "hit",
				pages = cached.pagination and cached.pagination.pages or 0,
				page_size = cached.pagination and cached.pagination.page_size or PAGE_SIZE,
				loaded = (cached.stats and (cached.stats.servers_seen or cached.stats.gateways)) or 0,
				source = SERVERS_URL
			})
			cached.from_cache = true
			cached.background_update_available = cache.read_cache_for_update(cache_file)
			for k, v in pairs(cache_meta) do
				cached[k] = v
			end
			prepare_json_response(cached, 200)
			return
		end

		-- Cache miss - return error asking user to wait for background update
		-- The background job (nordvpn-cache service) will populate the cache
		prepare_json_response({
			error = "Server list not available yet",
			message = "The server list is being loaded in the background. Please wait and refresh.",
			code = "CACHE_LOADING",
			cache_file = cache_file,
			suggestion = "This typically takes 30-60 seconds. Refresh this page in a moment."
		}, 202)  -- 202 Accepted (async operation in progress)
	end)

	if not ok then
		prepare_json_response({ error = tostring(err) }, 500)
	end
end

function refresh_locations()
	local ok, err = pcall(function()
		local cache_file, effective_cache_dir, configured_cache_dir, cache_fallback = cache.get_cache_file_path()
		local cache_meta = {
			cache_file = cache_file,
			effective_cache_dir = effective_cache_dir,
			configured_cache_dir = configured_cache_dir,
			cache_dir_fallback = cache_fallback
		}

		-- Force refresh from API
		local response, ferr = cache.fetch_servers()
		if not response then
			prepare_json_response({ error = ferr }, 502)
			return
		end

		response.from_cache = false
		response.refreshed = true

		-- Update cache
		cache.write_cache(response, cache_file)
		for k, v in pairs(cache_meta) do
			response[k] = v
		end

		prepare_json_response(response, 200)
	end)

	if not ok then
		prepare_json_response({ error = tostring(err) }, 500)
	end
end

function locations_progress()
	local status = cache.read_fetch_status()
	if not status then
		status = { state = "idle" }
	end
	status.server_time = iso_ts()
	if not status.page_size then
		status.page_size = PAGE_SIZE
	end
	prepare_json_response(status, 200)
end

function locations_progress_reset()
	-- Remove status file to avoid stale updates
	if fs and fs.stat(FETCH_STATUS_FILE, "type") then
		fs.remove(FETCH_STATUS_FILE)
	end
	prepare_json_response({ state = "idle", reset = true, server_time = iso_ts(), page_size = PAGE_SIZE }, 200)
end

function cache_settings()
	local ok, err = pcall(function()
		local method = http.getenv("REQUEST_METHOD") or "GET"
		local requested_dir = nil
		if method == "POST" then
			local body = http.content() or ""
			local payload = json.parse(body) or {}
			local cache_dir = payload.cache_dir
			requested_dir = cache_dir

			-- Normalize string (simple trim)
			if type(cache_dir) == "string" then
				cache_dir = cache_dir:match("^%s*(.-)%s*$")
			end

			local cur = new_cursor()

			-- Always store on network interface (present on your router)
			cur:load("network")
			local iface_name = find_interface_by_vpn_type(cur, "nordvpn") or DEFAULT_INTERFACE
			if cache_dir and cache_dir ~= "" then
				cur:set("network", iface_name, "nordvpn_cache_dir", cache_dir)
			else
				cur:delete("network", iface_name, "nordvpn_cache_dir")
			end
			local okn, errn = pcall(function()
				cur:save("network")
				cur:commit("network")
			end)
			if not okn then
				error(errn)
			end

			-- Best-effort: also store in dedicated nordvpn config if it exists
			cur:load("nordvpn")
			local section = cur:get_first("nordvpn", "settings")
			if not section then
				section = cur:section("nordvpn", "settings", "settings")
			end
			if cache_dir and cache_dir ~= "" then
				cur:set("nordvpn", section, "cache_dir", cache_dir)
			else
				cur:delete("nordvpn", section, "cache_dir")
			end
			pcall(function()
				cur:save("nordvpn")
				cur:commit("nordvpn")
			end)

			-- Reload to reflect persisted value
			cur:load("network")
			requested_dir = cur:get("network", iface_name, "nordvpn_cache_dir") or requested_dir
			if not requested_dir then
				cur:load("nordvpn")
				requested_dir = cur:get("nordvpn", "settings", "cache_dir")
			end
		end

		local cache_file, effective_cache_dir, configured_cache_dir, cache_fallback = cache.get_cache_file_path()
		-- If we just set a value but couldn't read it back, at least echo the requested one
		configured_cache_dir = configured_cache_dir or requested_dir

		prepare_json_response({
			configured_cache_dir = configured_cache_dir or "",
			effective_cache_dir = effective_cache_dir,
			cache_file = cache_file,
			cache_dir_fallback = cache_fallback,
			using_default = not configured_cache_dir or cache_fallback,
			saved = method ~= "POST" or true
		}, 200)
	end)

	if not ok then
		prepare_json_response({ error = tostring(err) }, 500)
	end
end

function get_config_only()
	local cur = new_cursor()
	local iface_name = DEFAULT_INTERFACE

	-- Always try to find existing NordVPN interface first
	local existing_nordvpn_iface = find_interface_by_vpn_type(cur, "nordvpn")
	if existing_nordvpn_iface then
		iface_name = existing_nordvpn_iface
	end

	local state = get_interface_state(cur, iface_name)
	if not state then
		-- Return empty profile for new interface
		local empty_response = {
			interface = {
				name = iface_name,
				proto = "wireguard",
				private_key_set = false,
				addresses = { FIXED_ADDRESS },
				routing_table = "",
				rotation_enabled = false,
				vpn_type = "nordvpn",
				token = "",
				nordvpn_token_set = false
			},
			peer = nil
		}
		prepare_json_response(empty_response, 200)
		return
	end

	-- Return all saved configuration immediately
	local response = {
		interface = {
			name = iface_name,
			proto = state.interface.proto,
			private_key_set = state.interface.private_key and #state.interface.private_key > 0 or false,
			addresses = state.interface.addresses,
			nordvpn_location = state.interface.nordvpn_location,
			last_applied = state.interface.nordvpn_last_applied,
			ip4table = state.interface.ip4table,
			ip6table = state.interface.ip6table,
			routing_table = state.interface.ip4table or "", -- For UI form field
			rotation_enabled = state.interface.nordvpn_rotation_enabled == "1",
			rotation_mode = state.interface.nordvpn_rotation_mode,
			rotation_interval = state.interface.nordvpn_rotation_interval,
			rotation_time = state.interface.nordvpn_rotation_time,
			country_code = state.interface.nordvpn_country_code,
			city_code = state.interface.nordvpn_city_code,
			location_code = state.interface.nordvpn_location,
			nordvpn_token_set = state.interface.nordvpn_token and #state.interface.nordvpn_token > 0 or false,
			token = state.interface.nordvpn_token or "", -- For UI form field
			vpn_type = state.interface.vpn_type or "nordvpn",
			hop_mode = state.interface.nordvpn_hop_mode or "single",
			fixed_server = state.interface.nordvpn_fixed_server == "1",
			ping_count = state.interface.nordvpn_ping_count or "10",
			ping_timeout = state.interface.nordvpn_ping_timeout or "2",
			max_retries = state.interface.nordvpn_max_retries or "10"
		},
		peer = nil
	}

	-- Include cache info for UI visibility
	local cache_file, effective_cache_dir, configured_cache_dir, cache_fallback = cache.get_cache_file_path()
	response.cache = {
		configured = configured_cache_dir or "",
		effective = effective_cache_dir,
		cache_file = cache_file,
		fallback = cache_fallback
	}

	if state.peer then
		response.peer = {
			name = state.peer[".name"],
			public_key = state.peer.public_key,
			endpoint_host = state.peer.endpoint_host,
			endpoint_port = state.peer.endpoint_port,
			allowed_ips = state.peer.allowed_ips,
			preshared_key_set = state.peer.preshared_key and #state.peer.preshared_key > 0 or false,
			nordvpn_gateway = state.peer.nordvpn_gateway
		}
	end

	prepare_json_response(response, 200)
end

function get_profile()
	local cur = new_cursor()
	local iface_name = DEFAULT_INTERFACE

	-- Always try to find existing NordVPN interface first
	local existing_nordvpn_iface = find_interface_by_vpn_type(cur, "nordvpn")
	if existing_nordvpn_iface then
		iface_name = existing_nordvpn_iface
	end

	local state = get_interface_state(cur, iface_name)
	if not state then
		-- Return empty profile for new interface
		local empty_response = {
			interface = {
				name = iface_name,
				proto = "wireguard",
				private_key_set = false,
				addresses = { FIXED_ADDRESS },
				rotation_enabled = false,
				vpn_type = "nordvpn",
				token = "",
				routing_table = ""
			},
			peer = nil
		}
		prepare_json_response(empty_response, 200)
		return
	end

	-- Return all saved configuration immediately - same as get_config_only but with private_key
	local response = {
		interface = {
			name = iface_name,
			proto = state.interface.proto,
			private_key = state.interface.private_key, -- Include private key for status display
			private_key_set = state.interface.private_key and #state.interface.private_key > 0 or false,
			addresses = state.interface.addresses,
			nordvpn_location = state.interface.nordvpn_location,
			last_applied = state.interface.nordvpn_last_applied,
			ip4table = state.interface.ip4table,
			ip6table = state.interface.ip6table,
			routing_table = state.interface.ip4table or "", -- For UI form field
			rotation_enabled = state.interface.nordvpn_rotation_enabled == "1",
			rotation_mode = state.interface.nordvpn_rotation_mode,
			rotation_interval = state.interface.nordvpn_rotation_interval,
			rotation_time = state.interface.nordvpn_rotation_time,
			country_code = state.interface.nordvpn_country_code,
			city_code = state.interface.nordvpn_city_code,
			location_code = state.interface.nordvpn_location,
			nordvpn_token_set = state.interface.nordvpn_token and #state.interface.nordvpn_token > 0 or false,
			token = state.interface.nordvpn_token or "", -- For UI form field
			vpn_type = state.interface.vpn_type or "nordvpn",
			hop_mode = state.interface.nordvpn_hop_mode or "single",
			fixed_server = state.interface.nordvpn_fixed_server == "1",
			ping_count = state.interface.nordvpn_ping_count or "10",
			ping_timeout = state.interface.nordvpn_ping_timeout or "2",
			max_retries = state.interface.nordvpn_max_retries or "10"
		},
		peer = nil
	}

	-- Include cache info for UI visibility
	local cache_file, effective_cache_dir, configured_cache_dir, cache_fallback = cache.get_cache_file_path()
	response.cache = {
		configured = configured_cache_dir or "",
		effective = effective_cache_dir,
		cache_file = cache_file,
		fallback = cache_fallback
	}

	if state.peer then
		response.peer = {
			name = state.peer[".name"],
			public_key = state.peer.public_key,
			endpoint_host = state.peer.endpoint_host,
			endpoint_port = state.peer.endpoint_port,
			allowed_ips = state.peer.allowed_ips,
			preshared_key_set = state.peer.preshared_key and #state.peer.preshared_key > 0 or false,
			nordvpn_gateway = state.peer.nordvpn_gateway
		}
	end

	prepare_json_response(response, 200)
end

function apply_profile()
	local body = http.content() or ""
	local payload = json.parse(body)

	if type(payload) ~= "table" then
		prepare_json_response({ error = "invalid JSON payload" }, 400)
		return
	end

	local iface_name = payload.interface or DEFAULT_INTERFACE
	local routing_table = payload.routing_table

	-- Check if there's an existing NordVPN interface and use it instead
	local cur = new_cursor()
	local existing_nordvpn_iface = find_interface_by_vpn_type(cur, "nordvpn")
	if existing_nordvpn_iface and not payload.interface then
		iface_name = existing_nordvpn_iface
	end

	local token = payload.token
	local private_key_input = payload.private_key

	if not private_key_input and not token then
		prepare_json_response({ error = "missing private_key or token" }, 400)
		return
	end

	local private_key = private_key_input
	if not private_key then
		local err_msg
		private_key, err_msg = get_private_key(token)
		if not private_key then
			prepare_json_response({ error = "failed to retrieve private key: " .. (err_msg or "unknown error") }, 502)
			return
		end
	end

	local ok_key, key_err = validate_private_key(private_key)
	if not ok_key then
		prepare_json_response({ error = key_err }, 400)
		return
	end

	if type(payload.relay) ~= "table" then
		prepare_json_response({ error = "missing relay selection" }, 400)
		return
	end

	if not payload.relay.public_key or payload.relay.public_key == "" then
		prepare_json_response({ error = "relay public key is required" }, 400)
		return
	end

	local endpoint_host = payload.relay.hostname or payload.relay.ip_address or payload.relay.station or payload.relay.endpoint_host
	if not endpoint_host or endpoint_host == "" then
		prepare_json_response({ error = "relay endpoint host is required" }, 400)
		return
	end

	local endpoint_port = tonumber(payload.relay.port or payload.relay.endpoint_port) or DEFAULT_PORT

	local iface = find_interface_section(cur, iface_name)
	if not iface then
		-- Create interface if it doesn't exist
		cur:set("network", iface_name, "interface")
		cur:save("network")
		cur:commit("network")
	end

	cur:set_list("network", iface_name, "addresses", { FIXED_ADDRESS })
	cur:set("network", iface_name, "private_key", private_key)
	cur:set("network", iface_name, "proto", "wireguard")
	cur:set("network", iface_name, "auto", "1")

	-- Save NordVPN specific settings
	cur:set("network", iface_name, "vpn_type", "nordvpn")
	if token then
		cur:set("network", iface_name, "nordvpn_token", token)
	end
	if payload.hop_mode then
		cur:set("network", iface_name, "nordvpn_hop_mode", payload.hop_mode)
	else
		cur:delete("network", iface_name, "nordvpn_hop_mode")
	end

	-- Set routing table if specified
	if routing_table and routing_table ~= "" then
		cur:set("network", iface_name, "ip4table", routing_table)
		cur:set("network", iface_name, "ip6table", routing_table)
	else
		cur:delete("network", iface_name, "ip4table")
		cur:delete("network", iface_name, "ip6table")
	end

	if payload.location_code then
		cur:set("network", iface_name, "nordvpn_location", payload.location_code)
	else
		cur:delete("network", iface_name, "nordvpn_location")
	end

	-- Save detailed server information for UI display
	if payload.relay then
		cur:set("network", iface_name, "nordvpn_server_name", payload.relay.name or payload.relay.hostname or "")
		cur:set("network", iface_name, "nordvpn_server_hostname", payload.relay.hostname or "")
		if payload.relay_selected then
			cur:set("network", iface_name, "nordvpn_fixed_server", "1")
		else
			cur:delete("network", iface_name, "nordvpn_fixed_server")
		end

		-- Extract country and city from location or relay info
		if payload.selected_country then
			cur:set("network", iface_name, "nordvpn_server_country", payload.selected_country)
		end
		if payload.selected_city then
			cur:set("network", iface_name, "nordvpn_server_city", payload.selected_city)
		end
		if payload.location_display then
			cur:set("network", iface_name, "nordvpn_location_display", payload.location_display)
		end
	end

	cur:set("network", iface_name, "nordvpn_last_applied", os.date("!%Y-%m-%dT%H:%M:%SZ"))

	-- Save country code and city code (always, independent of rotation)
	local country_code = payload.country_code
	if country_code then
		cur:set("network", iface_name, "nordvpn_country_code", country_code)
	end
	local city_code = payload.city_code
	if city_code and city_code ~= "" then
		cur:set("network", iface_name, "nordvpn_city_code", city_code)
	else
		cur:delete("network", iface_name, "nordvpn_city_code")
	end

	-- Save connectivity test settings
	if payload.ping_count and payload.ping_count ~= "" then
		cur:set("network", iface_name, "nordvpn_ping_count", tostring(payload.ping_count))
	end
	if payload.ping_timeout and payload.ping_timeout ~= "" then
		cur:set("network", iface_name, "nordvpn_ping_timeout", tostring(payload.ping_timeout))
	end
	if payload.max_retries and payload.max_retries ~= "" then
		cur:set("network", iface_name, "nordvpn_max_retries", tostring(payload.max_retries))
	end

	-- Save rotation settings
	if payload.rotation_enabled then
		cur:set("network", iface_name, "nordvpn_rotation_enabled", "1")

		-- Save rotation mode
		local rotation_mode = payload.rotation_mode or "interval"
		cur:set("network", iface_name, "nordvpn_rotation_mode", rotation_mode)

		if rotation_mode == "interval" and payload.rotation_interval then
			cur:set("network", iface_name, "nordvpn_rotation_interval", tostring(payload.rotation_interval))
			cur:delete("network", iface_name, "nordvpn_rotation_time")
		elseif rotation_mode == "time" and payload.rotation_time then
			cur:set("network", iface_name, "nordvpn_rotation_time", payload.rotation_time)
			cur:delete("network", iface_name, "nordvpn_rotation_interval")
		end
	else
		cur:delete("network", iface_name, "nordvpn_rotation_enabled")
		cur:delete("network", iface_name, "nordvpn_rotation_mode")
		cur:delete("network", iface_name, "nordvpn_rotation_interval")
		cur:delete("network", iface_name, "nordvpn_rotation_time")
	end

	local peer_name = find_or_create_peer(cur, iface_name)
	cur:set("network", peer_name, "public_key", payload.relay.public_key)
	cur:set("network", peer_name, "endpoint_host", endpoint_host)
	cur:set("network", peer_name, "endpoint_port", tostring(endpoint_port))
	cur:set("network", peer_name, "persistent_keepalive", tostring(payload.keepalive or DEFAULT_KEEPALIVE))
	cur:set_list("network", peer_name, "allowed_ips", { "0.0.0.0/0", "::/0" })

	if payload.relay.hostname then
		cur:set("network", peer_name, "nordvpn_gateway", payload.relay.hostname)
	else
		cur:delete("network", peer_name, "nordvpn_gateway")
	end

	if payload.preshared_key and payload.preshared_key ~= "" then
		cur:set("network", peer_name, "preshared_key", payload.preshared_key)
	else
		cur:delete("network", peer_name, "preshared_key")
	end

	cur:save("network")
	cur:commit("network")

	-- Scheduling is handled by the nordvpn-rotate and nordvpn-cache procd services;
	-- they read the settings persisted above directly from UCI.

	-- Restart network interface
	local restart_result = sys.call(string.format("/sbin/ifup %s >/dev/null 2>&1", iface_name))

	prepare_json_response({
		status = "ok",
		interface = iface_name,
		peer = peer_name,
		endpoint_host = endpoint_host,
		endpoint_port = endpoint_port,
		restarted = restart_result == 0,
		rotation_enabled = payload.rotation_enabled or false
	}, 200)
end

local function extract_location_from_hostname(hostname)
	if not hostname or hostname == "" then
		return nil, nil, nil
	end

	-- NordVPN hostname format: cc##.nordvpn.com (e.g., ee70.nordvpn.com)
	local country_code = hostname:match("^([a-z][a-z])%d+%.nordvpn%.com$")
	if not country_code then
		return nil, nil, nil
	end

	-- Map common country codes to names and cities
	local country_map = {
		ee = { name = "Estonia", cities = { tallinn = "Tallinn" } },
		us = { name = "United States", cities = { newyork = "New York", losangeles = "Los Angeles", chicago = "Chicago" } },
		uk = { name = "United Kingdom", cities = { london = "London", manchester = "Manchester" } },
		de = { name = "Germany", cities = { berlin = "Berlin", frankfurt = "Frankfurt" } },
		fr = { name = "France", cities = { paris = "Paris", marseille = "Marseille" } },
		nl = { name = "Netherlands", cities = { amsterdam = "Amsterdam" } },
		se = { name = "Sweden", cities = { stockholm = "Stockholm" } },
		no = { name = "Norway", cities = { oslo = "Oslo" } },
		ca = { name = "Canada", cities = { toronto = "Toronto", vancouver = "Vancouver" } },
		au = { name = "Australia", cities = { sydney = "Sydney", melbourne = "Melbourne" } }
	}

	local country_info = country_map[country_code]
	if country_info then
		-- For Estonia (ee), default to Tallinn
		local city = "Unknown"
		if country_code == "ee" then
			city = "Tallinn"
		else
			-- Use first city as default
			for _, city_name in pairs(country_info.cities) do
				city = city_name
				break
			end
		end

		local location_code = country_code .. "-" .. city:lower():gsub("[^a-z0-9]", "")
		return country_info.name, city, location_code
	end

	return nil, nil, nil
end
