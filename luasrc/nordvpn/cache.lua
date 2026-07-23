-- Shared server-list cache logic for luci-app-nordvpn.
-- Used by the LuCI controller (luci.controller.nordvpn) and by the
-- standalone /usr/bin/nordvpn-cache-update CLI script, so it must stay
-- requireable outside of the LuCI dispatcher (no HTTP request context).

local json = require "luci.jsonc"
local sys = require "luci.sys"

local fs_ok, fs_mod = pcall(require, "nixio.fs")
local fs = fs_ok and fs_mod or nil

local M = {}

M.SERVERS_URL = "https://api.nordvpn.com/v1/servers"
M.CACHE_FILENAME = "nordvpn_servers_cache.json"
M.DEFAULT_CACHE_DIR = "/tmp"
M.CACHE_MAX_AGE = 86400 -- 24 hours in seconds
M.PAGE_SIZE = 250
M.MAX_PAGES = 200 -- Safety guard to prevent infinite pagination
M.FETCH_STATUS_FILE = "/tmp/nordvpn_fetch_status.json"

local SERVERS_URL = M.SERVERS_URL
local CACHE_FILENAME = M.CACHE_FILENAME
local DEFAULT_CACHE_DIR = M.DEFAULT_CACHE_DIR
local CACHE_MAX_AGE = M.CACHE_MAX_AGE
local PAGE_SIZE = M.PAGE_SIZE
local MAX_PAGES = M.MAX_PAGES
local FETCH_STATUS_FILE = M.FETCH_STATUS_FILE

local DEFAULT_INTERFACE = "nordvpn"
local DEFAULT_PORT = 51820

local function new_cursor()
	return require("luci.model.uci").cursor()
end

function M.iso_ts(ts)
	return os.date("!%Y-%m-%dT%H:%M:%SZ", ts or os.time())
end

local iso_ts = M.iso_ts

function M.write_fetch_status(status)
	if not status then
		return
	end
	status.updated_at = iso_ts()
	local ok, tbl = pcall(function()
		local f = io.open(FETCH_STATUS_FILE, "w")
		if not f then
			return
		end
		f:write(json.stringify(status))
		f:close()
	end)
	return ok and tbl
end

function M.read_fetch_status()
	local f = io.open(FETCH_STATUS_FILE, "r")
	if not f then
		return nil
	end
	local content = f:read("*all")
	f:close()
	if not content or #content == 0 then
		return nil
	end
	return json.parse(content)
end

local write_fetch_status = M.write_fetch_status

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

local function get_configured_cache_dir(cur)
	cur = cur or new_cursor()
	cur:load("network")
	local iface_name = find_interface_by_vpn_type(cur, "nordvpn") or DEFAULT_INTERFACE

	-- Primary: network interface option (always present config)
	local dir = cur:get("network", iface_name, "nordvpn_cache_dir")
	if dir and dir ~= "" then
		return dir
	end

	-- Secondary: dedicated config (if installed)
	cur:load("nordvpn")
	dir = cur:get("nordvpn", "settings", "cache_dir")
	if dir and dir ~= "" then
		return dir
	end

	dir = cur:get_first("nordvpn", "settings", "cache_dir")
	if dir and dir ~= "" then
		return dir
	end
end

function M.get_cache_file_path()
	local configured_dir = get_configured_cache_dir()
	local effective_dir = configured_dir or DEFAULT_CACHE_DIR
	local fallback_used = false

	-- Ensure directory exists or fall back to /tmp
	if fs and effective_dir then
		if not fs.stat(effective_dir, "type") then
			fs.mkdirr(effective_dir)
		end
		if fs.stat(effective_dir, "type") ~= "dir" then
			effective_dir = DEFAULT_CACHE_DIR
			fallback_used = configured_dir and true or false
		end
	elseif not fs and configured_dir then
		-- No filesystem helper; still honor configured path and let io.open handle errors
		effective_dir = configured_dir
		fallback_used = false
	end

	local cache_file = string.format("%s/%s", effective_dir, CACHE_FILENAME)
	return cache_file, effective_dir, configured_dir, fallback_used
end

local function http_fetch(url, options)
	options = options or {}
	local body = sys.httpget(url)
	if body and #body > 0 then
		return body
	end

	return nil, "no httpclient implementation available (check SSL/ca-certificates)"
end

function M.read_cache(cache_file)
	local f = io.open(cache_file, "r")
	if not f then
		return nil
	end

	local content = f:read("*all")
	f:close()

	if not content or #content == 0 then
		return nil
	end

	local data = json.parse(content)
	if not data then
		return nil
	end

	-- No age check - we trust background updates to keep cache fresh
	-- If cache exists, it's good enough to show to the user
	return data
end

function M.read_cache_for_update(cache_file)
	-- Separate function for checking if background update is needed
	-- This checks age and returns true if update is due
	local f = io.open(cache_file, "r")
	if not f then
		return true -- No cache, update needed
	end

	local content = f:read("*all")
	f:close()

	if not content or #content == 0 then
		return true -- Empty cache, update needed
	end

	local data = json.parse(content)
	if not data then
		return true -- Invalid cache, update needed
	end

	-- Check cache age for background update
	if data.cached_at then
		local age = os.time() - data.cached_at
		if age > CACHE_MAX_AGE then
			return true -- Cache expired, update needed
		end
	end

	return false -- Cache is recent, no update needed
end

function M.write_cache(data, cache_file)
	-- Add cache timestamp
	data.cached_at = os.time()
	data.cache_info = {
		created = os.date("!%Y-%m-%dT%H:%M:%SZ"),
		expires_at = os.date("!%Y-%m-%dT%H:%M:%SZ", os.time() + CACHE_MAX_AGE)
	}

	local f = io.open(cache_file, "w")
	if not f then
		return false
	end

	f:write(json.stringify(data))
	f:close()
	return true
end

local function new_location_accumulator()
	return {
		country_index = {},
		location_index = {},
		country_list = {},
		stats = {
			countries = 0,
			cities = 0,
			gateways = 0,
			servers_seen = 0
		}
	}
end

local function ensure_country(acc, country_name, country_code)
	if not acc.country_index[country_name] then
		local country = {
			code = country_code,
			name = country_name,
			display_name = country_name,
			cities = {},
			gateway_count = 0
		}
		acc.country_index[country_name] = country
		table.insert(acc.country_list, country)
	end
	return acc.country_index[country_name]
end

local function ensure_city(acc, country, loc_code, city_name, latitude, longitude, country_code)
	if not acc.location_index[loc_code] then
		local city = {
			code = loc_code,
			name = city_name,
			country = country.name,
			country_code = country_code,
			latitude = latitude or 0,
			longitude = longitude or 0,
			relays = {},
			gateway_count = 0
		}
		acc.location_index[loc_code] = city
		table.insert(country.cities, city)
	end
	return acc.location_index[loc_code]
end

local function add_server(acc, server)
	acc.stats.servers_seen = acc.stats.servers_seen + 1

	if not server.locations or #server.locations == 0 then
		return
	end

	local loc = server.locations[1]
	local country_info = loc.country
	if not country_info then
		return
	end

	local country_name = country_info.name
	local country_code = string.lower(country_info.code or "")
	local city_name = country_info.city and country_info.city.name or "Unknown"
	local location_code = country_code .. "-" .. city_name:lower():gsub("[^a-z0-9]", "")

	local country = ensure_country(acc, country_name, country_code)
	local city = ensure_city(acc, country, location_code, city_name, loc.latitude, loc.longitude, country_code)

	-- Extract public_key
	local public_key = nil
	local technologies = server.technologies or {}
	for _, tech in ipairs(technologies) do
		if tech.identifier == "wireguard_udp" then
			local metadata = tech.metadata or {}
			for _, meta in ipairs(metadata) do
				if meta.name == "public_key" then
					public_key = meta.value
					break
				end
			end
			break
		end
	end

	if public_key then
		local hostname = server.hostname or ""
		local friendly_name = server.name or ""

		-- Detect multihop: hostname like cc1-cc2##.nordvpn.com or name like "CountryA - CountryB #"
		local entry_code, exit_code = hostname:match("^([a-z][a-z])%-([a-z][a-z])%d+%.nordvpn%.com$")
		local entry_name, exit_name = nil, nil
		if not entry_code and friendly_name then
			local a, b = friendly_name:match("^%s*([%w%s]+)%s*%-%s*([%w%s]+)%s*#")
			if a and b then
				entry_name = a:match("^%s*(.-)%s*$")
				exit_name = b:match("^%s*(.-)%s*$")
			end
		end

		local multihop = false
		if entry_code and entry_code ~= country_code then
			multihop = true
		elseif entry_name and entry_name:lower() ~= country_name:lower() then
			multihop = true
		end

		local relay_entry = {
			hostname = hostname,
			ip_address = server.station or "",
			name = friendly_name,
			public_key = public_key,
			load = server.load or 0,
			location = location_code,
			port = DEFAULT_PORT,
			active = true,
			multihop = multihop,
			entry_country_code = entry_code,
			entry_country = entry_name or (entry_code and entry_code:upper() or nil),
			exit_country_code = country_code,
			exit_country = country_name
		}
		table.insert(city.relays, relay_entry)
		city.gateway_count = city.gateway_count + 1
		acc.stats.gateways = acc.stats.gateways + 1
	end
end

local function finalize_locations(acc)
	local filtered_countries = {}
	for _, country in ipairs(acc.country_list) do
		local valid_cities = {}
		country.gateway_count = 0

		for _, city in ipairs(country.cities) do
			if #city.relays > 0 then
				table.sort(city.relays, function(a, b)
					return (a.name or "") < (b.name or "")
				end)
				table.insert(valid_cities, city)
				country.gateway_count = country.gateway_count + #city.relays
				acc.stats.cities = acc.stats.cities + 1
			end
		end

		table.sort(valid_cities, function(a, b)
			return (a.name or a.code or "") < (b.name or b.code or "")
		end)

		country.cities = valid_cities

		if #valid_cities > 0 then
			table.insert(filtered_countries, country)
		end
	end

	table.sort(filtered_countries, function(a, b)
		return a.name < b.name
	end)

	acc.stats.countries = #filtered_countries

	return {
		countries = filtered_countries,
		stats = acc.stats,
		source = SERVERS_URL,
		generated_at = iso_ts()
	}
end

function M.fetch_servers()
	local acc = new_location_accumulator()
	local offset = 0
	local pages = 0
	local last_page_size = 0
	local started_at = iso_ts()

	write_fetch_status({
		state = "running",
		started_at = started_at,
		page_size = PAGE_SIZE,
		pages = pages,
		loaded = 0,
		gateways = 0,
		source = SERVERS_URL
	})

	local params = {
		limit = tostring(PAGE_SIZE),
		offset = tostring(offset),
		["filters[servers_technologies][identifier]"] = "wireguard_udp"
	}
	while pages < MAX_PAGES do
		local query_parts = {}
		for k, v in pairs(params) do
			table.insert(query_parts, k .. "=" .. v)
		end
		local url = SERVERS_URL .. (#query_parts > 0 and "?" .. table.concat(query_parts, "&") or "")

		local body, err = http_fetch(url)
		if not body then
			write_fetch_status({
				state = "error",
				message = err or "unable to fetch NordVPN server list",
				pages = pages,
				page_size = PAGE_SIZE,
				loaded = acc.stats.servers_seen,
				gateways = acc.stats.gateways,
				source = SERVERS_URL
			})
			return nil, err or "unable to fetch NordVPN server list"
		end

		local data = json.parse(body)
		if not data or type(data) ~= "table" then
			-- Detect Cloudflare/NordVPN rate limiting (HTML body with words below)
			if body and #body > 0 then
				local lower = string.lower(body)
				if lower:find("rate limit") or lower:find("banned you temporarily") or lower:find("error 1015") then
					local msg = "NordVPN API rate limited (Cloudflare). Please wait a few minutes and try again."
					write_fetch_status({
						state = "error",
						message = msg,
						pages = pages,
						page_size = PAGE_SIZE,
						loaded = acc.stats.servers_seen,
						gateways = acc.stats.gateways,
						source = SERVERS_URL
					})
					return nil, msg
				end
			end

			write_fetch_status({
				state = "error",
				message = "failed to parse NordVPN server response",
				pages = pages,
				page_size = PAGE_SIZE,
				loaded = acc.stats.servers_seen,
				gateways = acc.stats.gateways,
				source = SERVERS_URL
			})
			return nil, "failed to parse NordVPN server response"
		end

		last_page_size = #data
		if last_page_size == 0 then
			break
		end

		for _, server in ipairs(data) do
			add_server(acc, server)
		end

		pages = pages + 1
		offset = offset + PAGE_SIZE
		params.offset = tostring(offset)

		write_fetch_status({
			state = "running",
			started_at = started_at,
			page_size = PAGE_SIZE,
			pages = pages,
			last_page = last_page_size,
			loaded = acc.stats.servers_seen,
			gateways = acc.stats.gateways,
			source = SERVERS_URL
		})

		if last_page_size < PAGE_SIZE then
			break
		end
	end

	if pages >= MAX_PAGES then
		write_fetch_status({
			state = "error",
			message = "pagination safety limit reached",
			pages = pages,
			page_size = PAGE_SIZE,
			loaded = acc.stats.servers_seen,
			gateways = acc.stats.gateways,
			source = SERVERS_URL
		})
		return nil, "pagination safety limit reached"
	end

	local response = finalize_locations(acc)
	response.pagination = {
		page_size = PAGE_SIZE,
		pages = pages,
		servers_seen = acc.stats.servers_seen,
		last_page_size = last_page_size
	}

	write_fetch_status({
		state = "done",
		page_size = PAGE_SIZE,
		pages = pages,
		last_page = last_page_size,
		loaded = acc.stats.servers_seen,
		gateways = response.stats.gateways,
		finished_at = iso_ts(),
		source = SERVERS_URL
	})

	return response
end

function M.fetch_and_build_cache()
	-- Fetch all pages, build the locations structure and persist the cache
	-- file. The fetch-status file is written by fetch_servers along the way,
	-- so the UI progress endpoint keeps working for CLI-triggered updates.
	local response, err = M.fetch_servers()
	if not response then
		return nil, err
	end

	local cache_file = M.get_cache_file_path()
	if not M.write_cache(response, cache_file) then
		return nil, "failed to write cache file: " .. tostring(cache_file)
	end

	return response
end

return M
