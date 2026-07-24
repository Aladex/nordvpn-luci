'use strict';
'require view';
'require rpc';
'require uci';
'require ui';
'require poll';
'require dom';

/* SPDX-License-Identifier: 0BSD
 * NordVPN WireGuard management view. Talks to the backend 'nordvpn' ubus object
 * (nordvpn-wireguard); performs no direct privileged filesystem or network ops.
 */

var callInstances = rpc.declare({ object: 'nordvpn', method: 'instances' });
var callLocations = rpc.declare({ object: 'nordvpn', method: 'locations' });
var callServers = rpc.declare({ object: 'nordvpn', method: 'servers', params: [ 'country', 'city', 'hop_mode' ] });
var callRefreshStatus = rpc.declare({ object: 'nordvpn', method: 'refresh_status' });
var callSetCredentials = rpc.declare({ object: 'nordvpn', method: 'set_credentials', params: [ 'token', 'instance' ] });
var callApply = rpc.declare({ object: 'nordvpn', method: 'apply', params: [ 'instance' ] });
var callRefreshLocations = rpc.declare({ object: 'nordvpn', method: 'refresh_locations' });
var callRotateNow = rpc.declare({ object: 'nordvpn', method: 'rotate_now', params: [ 'instance' ] });
var callExternalIp = rpc.declare({ object: 'nordvpn', method: 'external_ip', params: [ 'instance' ] });
var callDisconnect = rpc.declare({ object: 'nordvpn', method: 'disconnect', params: [ 'instance' ] });
var callClearCredentials = rpc.declare({ object: 'nordvpn', method: 'clear_credentials', params: [ 'instance' ] });
var callCreateInstance = rpc.declare({ object: 'nordvpn', method: 'create_instance', params: [ 'instance' ] });
var callDeleteInstance = rpc.declare({ object: 'nordvpn', method: 'delete_instance', params: [ 'instance' ] });

var STYLE = '' +
	'.nv-status-main{display:flex;flex-wrap:wrap;align-items:baseline;gap:.75em;font-size:1.05em}' +
	'.nv-state{font-weight:700}' +
	'.nv-status-details{color:var(--text-color-medium,#666);font-size:.9em;margin-top:.3em}' +
	'.nv-status-actions{margin-top:.7em;display:flex;gap:.5em;flex-wrap:wrap}' +
	'.nv-mono{font-family:monospace}' +
	'.nv-inline-note{font-style:italic;color:var(--text-color-medium,#666)}' +
	'.nv-inline{display:flex;align-items:center;gap:.75em;flex-wrap:wrap}' +
	'.nv-radio-group{display:flex;align-items:center;gap:1.25em;flex-wrap:wrap;min-height:1.9em}' +
	'.nv-radio-group label{display:inline-flex;align-items:center;gap:.4em;margin:0;font-weight:normal}' +
	'.nv-check{display:inline-flex;align-items:center;gap:.4em;font-weight:normal}' +
	'.nv-seg{display:inline-flex;flex-wrap:wrap;max-width:100%;border:1px solid #0069d6;border-radius:1.2em;overflow:hidden}' +
	'.nv-seg button{border:0;background:transparent;margin:0;padding:.3em 1.1em;cursor:pointer;font:inherit;color:inherit;line-height:1.3;white-space:nowrap;flex:1 1 auto}' +
	'.nv-seg button+button{border-left:1px solid #0069d6}' +
	'.nv-seg button.active{background:#0069d6;color:#fff}' +
	// The theme stacks tables on max-device-width (the bootstrap breakpoint),
	// which fires on phones even when the browser viewport is desktop-sized —
	// match both conditions so the compact layout replaces the stacking.
	'@media screen and (max-device-width:600px),screen and (max-width:992px){' +
		'.nv-itable .tr.table-titles{display:none!important}' +
		'.nv-itable .tr{display:flex!important;flex-wrap:wrap;align-items:center;gap:.2em .7em;padding:.45em 0;border-bottom:1px solid var(--border-color-medium,#555)}' +
		'.nv-itable .td{display:inline-flex!important;align-items:center;width:auto!important;padding:0!important;border:none!important;background:none!important}' +
		'.nv-itable .td::before{display:none!important}' +
	'}' +
	'.nv-token-field>div{display:block;width:100%}' +
	'.nv-token-field .control-group{display:flex;width:100%}' +
	'.nv-token-field .control-group input{flex:1 1 auto;width:100%}' +
	'details.nv-advanced>summary{cursor:pointer;font-weight:700;padding:.3em 0}' +
	'.hidden{display:none!important}';

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		return Promise.all([
			uci.load('nordvpn'),
			callInstances().catch(function() { return { instances: [] }; }),
			callLocations().catch(function() { return { available: false }; }),
			callRefreshStatus().catch(function() { return { state: 'idle' }; })
		]);
	},

	render: function(data) {
		this.instances = (data[1] && data[1].instances) || [];
		this.instance = this.instances.length ? this.instances[0].instance : 'main';
		this.status = this.instances[0] || {};
		this.locations = data[2] || { available: false };
		this.dirty = false;
		this.refs = {};

		this.instancesNode = E('div');
		this.statusNode = E('div');
		this.formNode = E('div');
		this.updateInstancesTable();
		this.updateStatusBand();
		dom.content(this.formNode, this.buildFormSections());

		var container = E('div', {}, [
			E('style', {}, STYLE),
			E('h2', {}, _('NordVPN')),
			this.instancesNode,
			this.statusNode,
			this.formNode,
			this.buildActions()
		]);

		poll.add(L.bind(this.refreshStatus, this), 5);
		return container;
	},

	/* ---- instances ----------------------------------------------------- */

	statusOf: function(name) {
		var found = null;
		(this.instances || []).forEach(function(st) {
			if (st.instance === name)
				found = st;
		});
		return found;
	},

	updateInstancesTable: function() {
		var rows = [ E('tr', { class: 'tr table-titles' }, [
			E('th', { class: 'th' }, _('Instance')),
			E('th', { class: 'th' }, _('Status')),
			E('th', { class: 'th' }, _('Server')),
			E('th', { class: 'th' }, _('Next rotation')),
			E('th', { class: 'th' }, '')
		]) ];

		(this.instances || []).forEach(L.bind(function(st) {
			var info = this.stateInfo(st.state || 'not_configured');
			var loc = st.location || {};
			var flag = this.countryFlag(loc.country);
			var selected = (st.instance === this.instance);
			var r = st.rotation || {};
			var next = '';
			if (r.enabled && r.next_run)
				next = new Date(r.next_run * 1000).toLocaleTimeString();
			else if (r.enabled)
				next = _('on schedule');

			rows.push(E('tr', {
				class: 'tr',
				style: selected ? 'font-weight:bold' : 'cursor:pointer',
				click: L.bind(this.selectInstance, this, st.instance)
			}, [
				E('td', { class: 'td' }, (selected ? '▸ ' : '') + st.instance),
				E('td', { class: 'td', style: 'color:' + info.color }, info.label),
				E('td', { class: 'td' }, (flag ? flag + ' ' : '') + (st.gateway || '—')),
				E('td', { class: 'td' }, next),
				E('td', { class: 'td' }, E('button', {
					class: 'cbi-button cbi-button-remove',
					click: L.bind(this.showDeleteInstanceModal, this, st.instance)
				}, st.instance === 'main' ? _('Reset') : _('Delete')))
			]));
		}, this));

		dom.content(this.instancesNode, E('fieldset', { class: 'cbi-section' }, [
			E('legend', {}, _('VPN instances')),
			E('div', { class: 'cbi-section-node nv-itable' }, [
				E('table', { class: 'table' }, rows),
				E('div', { style: 'margin-top:.5em' }, [
					E('button', { class: 'cbi-button cbi-button-add', click: L.bind(this.showAddInstanceModal, this) },
						_('Add instance'))
				])
			])
		]));
	},

	selectInstance: function(name) {
		if (name === this.instance)
			return;
		if (this.dirty && !window.confirm(_('Discard unsaved changes?')))
			return;
		this.instance = name;
		this.dirty = false;
		if (this.saveBtn) this.saveBtn.disabled = true;
		if (this.discardBtn) this.discardBtn.disabled = true;
		this.status = this.statusOf(name) || {};
		this.updateInstancesTable();
		this.updateStatusBand();
		dom.content(this.formNode, this.buildFormSections());
	},

	showAddInstanceModal: function() {
		var input = E('input', { type: 'text', class: 'cbi-input-text', placeholder: _('e.g. media') });
		var err = E('div', { class: 'cbi-value-description', style: 'color:var(--error-color,#c0392b)' });
		ui.showModal(_('Add VPN instance'), [
			E('p', {}, _('A new instance runs its own tunnel on its own WireGuard interface with its own credentials and schedule. Issue a separate NordVPN access token for it — reusing one key elsewhere has been known to get it locked.')),
			E('div', { class: 'cbi-value' }, [ input ]),
			err,
			E('div', { class: 'right' }, [
				E('button', { class: 'cbi-button', click: ui.hideModal }, _('Cancel')),
				' ',
				E('button', { class: 'cbi-button cbi-button-action', click: L.bind(this.addInstance, this, input, err) }, _('Add'))
			])
		]);
	},

	addInstance: function(input, err) {
		var name = (input.value || '').trim();
		if (!/^[A-Za-z0-9_]{1,12}$/.test(name)) {
			dom.content(err, _('Use 1-12 letters, digits or underscores.'));
			return;
		}
		return callCreateInstance(name).then(L.bind(function(res) {
			if (res && res.error) {
				dom.content(err, res.error);
				return;
			}
			ui.hideModal();
			uci.unload('nordvpn');
			return uci.load('nordvpn').then(L.bind(function() {
				return this.refreshStatus();
			}, this)).then(L.bind(function() {
				this.selectInstance(name);
				this.notice(_('Instance "%s" created. Set its credentials and pick a country, then save.').format(name), 'info', 6000);
			}, this));
		}, this)).catch(L.bind(function(e) {
			dom.content(err, '' + e);
		}, this));
	},

	showDeleteInstanceModal: function(name, ev) {
		if (ev)
			ev.stopPropagation();
		var main = (name === 'main');
		ui.showModal(main ? _('Reset "main" to defaults?') : _('Delete instance "%s"?').format(name), [
			E('p', {}, main
				? _('The tunnel is taken down, the stored key, interface and firewall objects are removed, and every setting of this instance returns to its default. Other instances are not affected.')
				: _('The tunnel is taken down and its interface, firewall objects and settings are removed. LAN traffic routed through it will fall back to your other routes.')),
			E('div', { class: 'right' }, [
				E('button', { class: 'cbi-button', click: ui.hideModal }, _('Cancel')),
				' ',
				E('button', { class: 'cbi-button cbi-button-negative', click: L.bind(this.deleteInstance, this, name) },
					main ? _('Reset') : _('Delete'))
			])
		]);
	},

	deleteInstance: function(name) {
		ui.hideModal();
		var n = this.notice(_('Deleting instance "%s"…').format(name), 'info');
		return callDeleteInstance(name).then(L.bind(function(res) {
			this.dismiss(n);
			if (res && res.error) {
				this.notice(_('Delete failed: %s').format(res.error), 'error');
				return;
			}
			this.notice(res && res.reset
				? _('Instance "main" reset to defaults.')
				: _('Instance "%s" deleted.').format(name), 'info', 4000);
			uci.unload('nordvpn');
			return uci.load('nordvpn').then(L.bind(function() {
				if (this.instance === name)
					this.instance = 'main';
				return this.refreshStatus().then(L.bind(function() {
					this.status = this.statusOf(this.instance) || {};
					this.updateStatusBand();
					dom.content(this.formNode, this.buildFormSections());
				}, this));
			}, this));
		}, this)).catch(L.bind(function(e) {
			this.dismiss(n);
			this.notice(_('Delete failed: %s').format(e), 'error');
		}, this));
	},

	/* ---- runtime status band ------------------------------------------ */

	stateInfo: function(state) {
		var map = {
			connected:      { label: _('Connected'),      color: 'var(--success-color,#2d8f4e)' },
			connecting:     { label: _('Connecting'),     color: 'var(--warning-color,#b8860b)' },
			degraded:       { label: _('Degraded'),       color: 'var(--warning-color,#b8860b)' },
			disconnected:   { label: _('Disconnected'),   color: 'var(--error-color,#c0392b)' },
			error:          { label: _('Error'),          color: 'var(--error-color,#c0392b)' },
			not_configured: { label: _('Not configured'), color: 'var(--text-color-medium,#666)' }
		};
		return map[state] || { label: _('Unknown'), color: 'var(--text-color-medium,#666)' };
	},

	fmtHandshake: function(sec) {
		if (sec == null)
			return null;
		if (sec < 90)
			return _('Handshake %d seconds ago').format(sec);
		return _('Handshake %d minutes ago').format(Math.floor(sec / 60));
	},

	// Resolve a country code and a city slug to display names from the loaded
	// locations tree, falling back to the raw codes when the list is missing.
	locationNames: function(cc, citySlug) {
		var l = this.locations || {};
		var countries = Array.isArray(l.countries) ? l.countries : [];
		var country = cc, city = citySlug;
		countries.forEach(function(c) {
			if (c.code !== cc)
				return;
			country = c.name || cc;
			(c.cities || []).forEach(function(ct) {
				if (ct.code === citySlug)
					city = ct.name || citySlug;
			});
		});
		return [ country, city ];
	},

	updateStatusBand: function() {
		var s = this.status || {};
		var loc = s.location || {};
		var info = this.stateInfo(s.state || 'not_configured');

		var locText = this.locationNames(loc.country, loc.city).filter(Boolean).join(' / ');
		if (s.gateway)
			locText = locText ? (locText + ' / ' + s.gateway) : s.gateway;
		var flag = this.countryFlag(loc.country);
		if (flag && locText)
			locText = flag + ' ' + locText;

		var details = [];
		var hs = this.fmtHandshake(s.latest_handshake_seconds);
		if (hs)
			details.push(hs);
		if (s.endpoint)
			details.push(_('Endpoint: %s').format(s.endpoint));
		if (s.gateway && /^[a-z]{2}-onion/.test(s.gateway))
			details.push(_('🧅 Onion over VPN'));
		if (s.state !== 'connected' && s.routing && s.routing.killswitch)
			details.push(_('Kill switch is blocking LAN traffic'));
		if (s.state === 'connected') {
			var ipKey = this.instance + '|' + (s.gateway || '');
			if (this.extIp && this.extIp.key === ipKey)
				details.push(_('Public IP: %s').format(this.extIp.ip));
			else
				this.maybeFetchExternalIp(ipKey);
		}
		if (s.rotation && s.rotation.enabled)
			details.push(_('Automatic rotation is on'));

		var legend = _('VPN status');
		if ((this.instances || []).length > 1)
			legend += ' — ' + this.instance;
		dom.content(this.statusNode, E('fieldset', { class: 'cbi-section' }, [
			E('legend', {}, legend),
			E('div', { class: 'cbi-section-node' }, [
				E('div', { 'aria-live': 'polite' }, [
					E('div', { class: 'nv-status-main' }, [
						E('span', { class: 'nv-state', style: 'color:' + info.color }, info.label),
						E('span', {}, locText || '')
					]),
					E('div', { class: 'nv-status-details' }, details.join(' · ')),
					E('div', { class: 'nv-status-actions' }, [
						E('button', { class: 'cbi-button', click: L.bind(this.refreshStatus, this) }, _('Refresh')),
						E('button', {
							class: 'cbi-button cbi-button-apply',
							disabled: !s.configured || null,
							click: L.bind(this.reconnect, this)
						}, _('Reconnect')),
						E('button', {
							class: 'cbi-button',
							disabled: (!s.configured || (s.rotation && s.rotation.enabled !== true)) || null,
							click: L.bind(this.rotateNow, this)
						}, _('Rotate now')),
						E('button', {
							class: 'cbi-button cbi-button-remove',
							disabled: (!s.configured || s.state === 'disconnected' || s.state === 'not_configured') || null,
							click: L.bind(this.disconnect, this)
						}, _('Disable'))
					])
				])
			])
		]));
	},

	// Fetch the tunnel's public IP once per instance+gateway combination (the
	// status poll runs every 5 s; external services would rate-limit that).
	maybeFetchExternalIp: function(key) {
		if (this._extIpPending === key)
			return;
		this._extIpPending = key;
		callExternalIp(this.instance).then(L.bind(function(res) {
			if (this._extIpPending !== key)
				return;
			this._extIpPending = null;
			if (res && res.ip) {
				this.extIp = { key: key, ip: res.ip };
				this.updateStatusBand();
			}
		}, this)).catch(L.bind(function() {
			this._extIpPending = null;
		}, this));
	},

	refreshStatus: function() {
		return callInstances().then(L.bind(function(res) {
			this.instances = (res && res.instances) || [];
			this.status = this.statusOf(this.instance) || {};
			this.updateInstancesTable();
			this.updateStatusBand();
			if (this.rotNextSpan)
				dom.content(this.rotNextSpan, this.nextRotationText());
		}, this)).catch(function() {});
	},

	reconnect: function() {
		var n = this.notice(_('Reconnecting…'), 'info');
		return callApply(this.instance).then(L.bind(function(res) {
			this.dismiss(n);
			if (res && res.error)
				this.notice(_('Reconnect failed: %s').format(res.error), 'error');
			else if (res && res.state === 'success')
				this.notice(_('Connected to %s').format(res.gateway || ''), 'info', 4000);
			else if (res && res.state === 'partial_failure')
				this.notice(_('Interface is up, but the server did not respond.'), 'error');
			else
				this.notice(_('Could not connect: %s').format((res && res.error) || _('unknown error')), 'error');
			return this.refreshStatus();
		}, this)).catch(L.bind(function(e) {
			this.dismiss(n);
			this.notice(_('Reconnect failed: %s').format(e), 'error');
		}, this));
	},

	disconnect: function() {
		var n = this.notice(_('Disabling…'), 'info');
		return callDisconnect(this.instance).then(L.bind(function(res) {
			this.dismiss(n);
			if (res && res.error)
				this.notice(_('Disable failed: %s').format(res.error), 'error');
			else
				this.notice(_('Instance disabled: its networks are back on normal routing (IPv6 included). Reconnect restores the VPN.'), 'info', 6000);
			return this.refreshStatus();
		}, this)).catch(L.bind(function(e) {
			this.dismiss(n);
			this.notice(_('Disable failed: %s').format(e), 'error');
		}, this));
	},

	rotateNow: function() {
		var n = this.notice(_('Rotating to another server…'), 'info');
		return callRotateNow(this.instance).then(L.bind(function(res) {
			this.dismiss(n);
			if (res && res.ok)
				this.notice(_('Rotated to %s').format(res.server), 'info', 4000);
			else if (res && res.skipped)
				this.notice(_('Rotation skipped: %s').format(res.reason || ''), 'info', 4000);
			else
				this.notice(_('Rotation failed: %s').format((res && res.error) || _('unknown error')), 'error');
			return this.refreshStatus();
		}, this)).catch(L.bind(function(e) {
			this.dismiss(n);
			this.notice(_('Rotation failed: %s').format(e), 'error');
		}, this));
	},

	/* ---- form sections ------------------------------------------------ */

	buildFormSections: function() {
		this.refs = {};
		// Building the form fires the same change paths as user input; the
		// guard keeps programmatic construction from marking the form dirty.
		this._building = true;
		var sections = [ this.buildConnection(), this.buildRoutingSection(), this.buildRotation(), this.buildAdvanced() ];
		this._building = false;
		return sections;
	},

	row: function(labelText, fieldNodes, descText) {
		var field = E('div', { class: 'cbi-value-field' }, fieldNodes);
		if (descText)
			field.appendChild(E('div', { class: 'cbi-value-description' }, descText));
		return E('div', { class: 'cbi-value' }, [
			E('label', { class: 'cbi-value-title' }, labelText),
			field
		]);
	},

	input: function(key, type, value, attrs) {
		var el = E('input', Object.assign({
			type: type || 'text',
			class: 'cbi-input-text',
			value: (value != null ? value : '')
		}, attrs || {}));
		el.addEventListener('input', L.bind(this.markDirty, this));
		el.addEventListener('change', L.bind(this.markDirty, this));
		this.refs[key] = el;
		return el;
	},

	buildConnection: function() {
		var s = this.status || {};
		var configured = !!s.configured;

		var credState = E('span', {}, configured ? _('Configured') : _('Not configured'));
		var credBtn = E('button', {
			class: 'cbi-button',
			click: L.bind(this.showCredentialModal, this)
		}, configured ? _('Replace credentials') : _('Set credentials'));
		var credClearBtn = configured ? E('button', {
			class: 'cbi-button cbi-button-remove',
			click: L.bind(this.showClearCredentialsModal, this)
		}, _('Remove')) : '';

		this.countrySel = E('select', { class: 'cbi-input-select', change: L.bind(this.onCountryChange, this) });
		this.citySel = E('select', { class: 'cbi-input-select', change: L.bind(this.onCityChange, this), disabled: true });
		this.serverSel = E('select', { class: 'cbi-input-select', change: L.bind(this.onServerChange, this), disabled: true });

		var hop = uci.get('nordvpn', this.instance, 'hop_mode') || 'single';
		this.hopValue = (hop === 'multihop' || hop === 'onion') ? hop : 'single';
		this.hopButtons = {};
		var seg = E('div', { class: 'nv-seg' }, [
			[ 'single', _('Single hop') ],
			[ 'multihop', _('Multihop') ],
			[ 'onion', _('Onion over VPN') ]
		].map(L.bind(function(o) {
			var b = E('button', { type: 'button', click: L.bind(this.setHopMode, this, o[0]) }, o[1]);
			this.hopButtons[o[0]] = b;
			return b;
		}, this)));
		this.hopNote = E('div', { class: 'cbi-value-description' });
		this.updateHopButtons();

		this.locNote = E('div', { class: 'cbi-value-description hidden' });

		var section = E('fieldset', { class: 'cbi-section' }, [
			E('legend', {}, _('Connection')),
			E('div', { class: 'cbi-section-node' }, [
				this.row(_('Credentials'), [ E('div', { class: 'nv-inline' }, [ credState, credBtn, credClearBtn ]) ]),
				this.row(_('Hop mode'), [ seg, this.hopNote ]),
				this.row(_('Country'), [ this.countrySel, this.locNote ]),
				this.row(_('City'), [ this.citySel ], _('Leave on Automatic to rotate within the country')),
				this.row(_('Server'), [ this.serverSel ], _('Choosing a specific server disables automatic rotation'))
			])
		]);

		this.populateCountries();
		return section;
	},

	// Traffic-routing panel. In a detected manual scheme it is purely
	// informational; otherwise it drives the backend's stamped auto-routing.
	buildRoutingSection: function() {
		var self = this;
		var g = function(o, d) { return uci.get('nordvpn', self.instance, o) || d; };
		var rt = (this.status || {}).routing || {};
		var body = E('div', { class: 'cbi-section-node' });
		this.autoRouting = null;
		this.steerBoxes = {};
		this.steerRow = null;

		if (rt.mode === 'manual') {
			var what = [];
			var table = g('routing_table', '');
			if (table)
				what.push(_('routing table "%s"').format(table));
			if (rt.user_routes)
				what.push(_('%d custom routes/rules').format(rt.user_routes));
			body.appendChild(this.row(_('Mode'), [
				E('span', {}, _('Manual — %s detected. Routing and firewall are left untouched.')
					.format(what.join(' + ') || _('custom configuration')))
			]));
			if (rt.ipv6_wan)
				body.appendChild(this.row('', [ E('span', { class: 'nv-inline-note' },
					_('⚠ IPv6 is active on the WAN and bypasses the VPN unless your rules cover it.')) ]));
		} else {
			this.autoRouting = E('input', { type: 'checkbox', change: L.bind(this.onRoutingToggle, this) });
			this.autoRouting.checked = (g('auto_routing', '0') === '1');
			this.ksBox = E('input', { type: 'checkbox', change: L.bind(this.markDirty, this) });
			this.ksBox.checked = (g('killswitch', '0') === '1');
			this.v6Box = E('input', { type: 'checkbox', change: L.bind(this.onRoutingToggle, this) });
			this.v6Box.checked = (g('block_ipv6', '1') === '1');
			this.dnsBox = E('input', { type: 'checkbox', change: L.bind(this.markDirty, this) });
			this.dnsBox.checked = (g('use_vpn_dns', '0') === '1');
			this.v6Warn = E('div', { class: 'cbi-value-description nv-inline-note hidden' },
				_('⚠ IPv6 stays outside the tunnel and can leak your address.'));

			this.steerBoxes = {};
			var current = uci.get('nordvpn', this.instance, 'source_network');
			var currentList = Array.isArray(current) ? current : (current ? [ current ] : []);
			var nets = rt.networks || [];
			this.steerWrap = E('div', { class: 'nv-inline', style: 'gap:1em' }, nets.map(L.bind(function(n) {
				var cb = E('input', { type: 'checkbox', change: L.bind(this.onRoutingToggle, this) });
				cb.checked = currentList.indexOf(n) >= 0;
				this.steerBoxes[n] = cb;
				return E('label', { class: 'nv-check' }, [ cb, n ]);
			}, this)));

			body.appendChild(this.row(_('Traffic routing'), [
				E('label', { class: 'nv-check' }, [ this.autoRouting, _('Route all LAN traffic through the VPN') ])
			], _('Creates a firewall zone and a default route via the tunnel; disabling removes exactly what was created.')));
			this.steerRow = this.row(_('Steered networks'), [ this.steerWrap ],
				_('Or route only these networks through this instance — policy rules send their traffic into its routing table.'));
			if (nets.length)
				body.appendChild(this.steerRow);
			this.ksRow = this.row(_('Kill switch'), [
				E('label', { class: 'nv-check' }, [ this.ksBox, _('Block LAN internet access while the VPN is down') ])
			]);
			this.v6Row = this.row(_('IPv6'), [
				E('label', { class: 'nv-check' }, [ this.v6Box, _('Block direct IPv6 to prevent leaks') ]),
				this.v6Warn
			]);
			this.dnsRow = this.row(_('DNS'), [
				E('label', { class: 'nv-check' }, [ this.dnsBox, _('Use NordVPN DNS (103.86.96.100) while connected') ])
			]);
			body.appendChild(this.ksRow);
			body.appendChild(this.v6Row);
			body.appendChild(this.dnsRow);
			this.onRoutingToggle(true);
		}

		return E('fieldset', { class: 'cbi-section' }, [
			E('legend', {}, _('Traffic routing')),
			body
		]);
	},

	steeredNetworks: function() {
		var out = [];
		for (var k in (this.steerBoxes || {}))
			if (this.steerBoxes[k].checked)
				out.push(k);
		return out;
	},

	onRoutingToggle: function(init) {
		if (init !== true)
			this.markDirty();
		var auto = this.autoRouting && this.autoRouting.checked;
		var on = auto || this.steeredNetworks().length > 0;
		if (this.steerRow) this.steerRow.classList.toggle('hidden', !!auto);
		if (this.ksRow) this.ksRow.classList.toggle('hidden', !on);
		if (this.v6Row) this.v6Row.classList.toggle('hidden', !on);
		if (this.dnsRow) this.dnsRow.classList.toggle('hidden', !on);
		var rt = (this.status || {}).routing || {};
		if (this.v6Warn)
			this.v6Warn.classList.toggle('hidden', !(on && this.v6Box && !this.v6Box.checked && rt.ipv6_wan));
	},

	buildRotation: function() {
		var enabled = (uci.get('nordvpn', this.instance, 'rotation_enabled') === '1');
		var mode = uci.get('nordvpn', this.instance, 'rotation_mode') || 'interval';
		var interval = uci.get('nordvpn', this.instance, 'rotation_interval') || '360';
		var time = uci.get('nordvpn', this.instance, 'rotation_time') || '04:30';

		this.rotEnable = E('input', { type: 'checkbox', change: L.bind(this.onRotationToggle, this) });
		this.rotEnable.checked = enabled;

		this.rotModeInterval = E('input', { type: 'radio', name: 'nv-rotmode', value: 'interval', change: L.bind(this.onRotationToggle, this) });
		this.rotModeTime = E('input', { type: 'radio', name: 'nv-rotmode', value: 'time', change: L.bind(this.onRotationToggle, this) });
		(mode === 'time' ? this.rotModeTime : this.rotModeInterval).checked = true;

		this.rotInterval = E('select', { class: 'cbi-input-select', change: L.bind(this.markDirty, this) });
		[ [ '60', _('Every hour') ], [ '180', _('Every 3 hours') ], [ '360', _('Every 6 hours') ],
		  [ '720', _('Every 12 hours') ], [ '1440', _('Every 24 hours') ] ].forEach(L.bind(function(o) {
			this.rotInterval.appendChild(E('option', { value: o[0], selected: (o[0] === interval) || null }, o[1]));
		}, this));

		this.rotTime = E('input', { type: 'time', class: 'cbi-input-text', value: time, style: 'width:auto', change: L.bind(this.markDirty, this) });
		this.refs.rotation_interval = this.rotInterval;
		this.refs.rotation_time = this.rotTime;

		this.rotFixedNote = E('div', { class: 'cbi-value-description nv-inline-note hidden' }, _('Automatic rotation is unavailable while a specific server is selected.'));
		this.rotModeRow = this.row(_('Schedule'), [
			E('div', { class: 'nv-radio-group' }, [
				E('label', {}, [ this.rotModeInterval, _('Every N hours') ]),
				E('label', {}, [ this.rotModeTime, _('At specific time') ])
			])
		]);
		this.rotIntervalRow = this.row(_('Rotation interval'), [ this.rotInterval ]);
		this.rotTimeRow = this.row(_('Rotation time'), [ this.rotTime ], _('Router local time'));
		this.rotNextSpan = E('span', {}, this.nextRotationText());
		this.rotNextRow = this.row(_('Next rotation'), [ this.rotNextSpan ]);

		var section = E('fieldset', { class: 'cbi-section', id: 'nv-rotation' }, [
			E('legend', {}, _('Automatic rotation')),
			E('div', { class: 'cbi-section-node' }, [
				this.row(_('Automatic rotation'), [
					E('label', { class: 'nv-check' }, [ this.rotEnable, _('Change server automatically on a schedule') ]),
					this.rotFixedNote
				]),
				this.rotModeRow, this.rotIntervalRow, this.rotTimeRow, this.rotNextRow
			])
		]);

		this.onRotationToggle();
		return section;
	},

	nextRotationText: function() {
		var s = this.status || {};
		var r = s.rotation || {};
		if (!r.enabled)
			return _('Disabled');
		if (!r.next_run)
			return _('On schedule');
		var d = new Date(r.next_run * 1000);
		var diff = Math.floor((d.getTime() - Date.now()) / 1000);
		if (diff < 90)
			return '%s (%s)'.format(d.toLocaleString(), _('due now'));
		var h = Math.floor(diff / 3600), m = Math.floor((diff % 3600) / 60);
		var rel = h > 0 ? _('in %dh %dm').format(h, m) : _('in %dm').format(m);
		return '%s (%s)'.format(d.toLocaleString(), rel);
	},

	// "hr" -> 🇭🇷 via regional-indicator codepoints. Returns '' for anything
	// that is not two ASCII letters, so malformed codes fall back to the
	// plain name.
	countryFlag: function(code) {
		if (typeof code !== 'string' || !/^[A-Za-z]{2}$/.test(code))
			return '';
		var c = code.toLowerCase();
		return String.fromCodePoint(
			0x1F1E6 + (c.charCodeAt(0) - 97),
			0x1F1E6 + (c.charCodeAt(1) - 97));
	},

	buildAdvanced: function() {
		var self = this;
		var g = function(o, d) { return uci.get('nordvpn', self.instance, o) || d; };
		// The server-list cache is shared between instances (owned by 'main').
		var gm = function(o, d) { return uci.get('nordvpn', 'main', o) || d; };
		this.cacheRow = E('span', {}, this.cacheSummary());

		var body = E('div', { class: 'cbi-section-node' }, [
			this.row(_('Interface name'), [ this.input('interface', 'text', g('interface', 'nordvpn')) ],
				_('Name of the managed WireGuard interface')),
			this.row(_('Routing table'), [ this.input('routing_table', 'text', g('routing_table', ''), { placeholder: 'main' }) ],
				_('Custom routing table (leave empty for the main table)')),
			this.row(_('Connection wait (seconds)'), [ this.input('verify_timeout', 'number', g('verify_timeout', '8'), { min: 2, max: 30, style: 'width:80px' }) ],
				_('How long to wait for a WireGuard handshake before giving up on a server')),
			this.maxRetriesRow = this.row(_('Max server attempts'), [ this.input('max_retries', 'number', g('max_retries', '10'), { min: 1, max: 50, style: 'width:80px' }) ],
				_('How many candidate servers a rotation may try')),
			this.row(_('Cache directory'), [ this.input('cache_dir', 'text', gm('cache_dir', ''), { placeholder: '/tmp' }) ],
				_('Where to store the downloaded server list, shared by all instances (leave empty for /tmp)')),
			this.row(_('Server cache'), [
				E('div', { class: 'nv-inline' }, [
					this.cacheRow,
					E('button', { class: 'cbi-button', click: L.bind(this.refreshCache, this) }, _('Refresh server list'))
				])
			])
		]);

		// The connection section is built (and may restore a pinned server)
		// before this row exists — sync the initial visibility.
		if (this.serverSel && this.serverSel.value)
			this.maxRetriesRow.classList.add('hidden');

		return E('details', { class: 'nv-advanced cbi-section' }, [
			E('summary', {}, _('Advanced settings')),
			body
		]);
	},

	cacheSummary: function() {
		var l = this.locations || {};
		if (!l.available)
			return _('Server list not loaded');
		var when = (l.cache_info && l.cache_info.created) ? l.cache_info.created : '';
		var count = (l.stats && l.stats.gateways) ? l.stats.gateways : 0;
		var txt = _('%d servers').format(count);
		if (when)
			txt += ' · ' + _('updated %s').format(when);
		if (l.state === 'stale')
			txt += ' · ' + _('stale');
		return txt;
	},

	buildActions: function() {
		this.saveBtn = E('button', {
			class: 'cbi-button cbi-button-save',
			disabled: true,
			click: L.bind(this.save, this)
		}, _('Save and reconnect'));
		this.discardBtn = E('button', {
			class: 'cbi-button',
			disabled: true,
			click: L.bind(this.discard, this)
		}, _('Discard changes'));
		return E('div', { class: 'cbi-page-actions' }, [ this.saveBtn, ' ', this.discardBtn ]);
	},

	/* ---- selection ---------------------------------------------------- */

	hopMode: function() {
		return this.hopValue || 'single';
	},

	// Key of the per-mode gateway counters in the locations tree.
	hopCountKey: function() {
		var m = this.hopMode();
		return m === 'multihop' ? 'multi' : (m === 'onion' ? 'onion' : 'single');
	},

	setHopMode: function(mode) {
		if (this.hopValue === mode)
			return;
		this.hopValue = mode;
		this.onHopChange();
	},

	updateHopButtons: function() {
		var mode = this.hopMode();
		for (var k in this.hopButtons)
			this.hopButtons[k].classList.toggle('active', k === mode);
		if (this.hopNote) {
			var notes = {
				multihop: _('Country is the exit country (your visible IP); traffic enters through the partner country shown in the server name.'),
				onion: _('Traffic leaves the VPN server through the Tor network. Noticeably slower, and some sites block Tor exits.')
			};
			dom.content(this.hopNote, notes[mode] || '');
			this.hopNote.classList.toggle('hidden', !notes[mode]);
		}
	},

	filteredCountries: function() {
		var l = this.locations || {};
		if (!Array.isArray(l.countries))
			return [];
		var key = this.hopCountKey();
		var out = [];
		l.countries.forEach(function(c) {
			var cities = (c.cities || []).filter(function(city) {
				return (city[key] || 0) > 0;
			});
			var count = c[key] || 0;
			if (cities.length && count > 0)
				out.push(Object.assign({}, c, { cities: cities, gateway_count: count }));
		});
		return out;
	},

	populateCountries: function() {
		var sel = this.countrySel;
		if (!sel)
			return;
		var chosen = uci.get('nordvpn', this.instance, 'country_code') || '';
		dom.content(sel, E('option', { value: '' }, _('-- Select country --')));

		var countries = this.filteredCountries();
		if (!this.locations.available) {
			this.locNote.classList.remove('hidden');
			dom.content(this.locNote, _('Loading server list… use "Refresh server list" in Advanced settings if it does not appear.'));
			sel.disabled = true;
		} else {
			this.locNote.classList.add('hidden');
			sel.disabled = false;
		}
		this._countryData = {};
		countries.forEach(L.bind(function(c) {
			this._countryData[c.code] = c;
			var flag = this.countryFlag(c.code);
			sel.appendChild(E('option', { value: c.code, selected: (c.code === chosen) || null },
				(flag ? flag + ' ' : '') + '%s (%d)'.format(c.name, c.gateway_count || 0)));
		}, this));

		this.onCountryChange();
	},

	onCountryChange: function() {
		this.markDirty();
		var code = this.countrySel.value;
		var c = this._countryData ? this._countryData[code] : null;
		var chosenCity = uci.get('nordvpn', this.instance, 'city_code') || '';

		dom.content(this.citySel, E('option', { value: '' }, _('Automatic city')));
		dom.content(this.serverSel, E('option', { value: '' }, _('Automatic server')));
		this.citySel.disabled = !c;
		this.serverSel.disabled = true;
		this._cityData = {};

		if (c) {
			var key = this.hopCountKey();
			(c.cities || []).forEach(L.bind(function(city) {
				this._cityData[city.code] = city;
				this.citySel.appendChild(E('option', { value: city.code, selected: (city.code === chosenCity) || null },
					'%s (%d)'.format(city.name, city[key] || 0)));
			}, this));
		}
		this.onCityChange();
	},

	onCityChange: function() {
		this.markDirty();
		var city = this._cityData ? this._cityData[this.citySel.value] : null;

		dom.content(this.serverSel, E('option', { value: '' }, _('Automatic server')));
		this.serverSel.disabled = !city;
		this.onServerChange();
		if (!city)
			return;

		var cc = this.countrySel.value;
		var chosenServer = uci.get('nordvpn', this.instance, 'fixed_server') || '';
		callServers(cc, city.code, this.hopMode()).then(L.bind(function(res) {
			var relays = (res && res.relays) || [];
			relays.forEach(function(r) {
				var label = '%s (%s%%)'.format(r.name || r.hostname, r.load != null ? r.load : '?');
				this.serverSel.appendChild(E('option', { value: r.hostname, selected: (r.hostname === chosenServer) || null }, label));
			}, this);
			if (chosenServer) {
				// Restoring the persisted choice is not a user edit.
				this._building = true;
				this.onServerChange();
				this._building = false;
			}
		}, this)).catch(function() {});
	},

	onServerChange: function() {
		this.markDirty();
		this.updateRotationAvailability();
	},

	onHopChange: function() {
		this.markDirty();
		this.updateHopButtons();
		this.populateCountries();
	},

	updateRotationAvailability: function() {
		var fixed = this.serverSel && this.serverSel.value;
		if (this.rotEnable) {
			this.rotEnable.disabled = !!fixed;
			if (fixed)
				this.rotEnable.checked = false;
		}
		if (this.rotFixedNote)
			this.rotFixedNote.classList.toggle('hidden', !fixed);
		// With a pinned server there are no candidates to try.
		if (this.maxRetriesRow)
			this.maxRetriesRow.classList.toggle('hidden', !!fixed);
		this.onRotationToggle();
	},

	onRotationToggle: function() {
		this.markDirty();
		var on = this.rotEnable && this.rotEnable.checked && !(this.serverSel && this.serverSel.value);
		var timeMode = this.rotModeTime && this.rotModeTime.checked;
		if (this.rotModeRow) this.rotModeRow.classList.toggle('hidden', !on);
		if (this.rotIntervalRow) this.rotIntervalRow.classList.toggle('hidden', !on || timeMode);
		if (this.rotTimeRow) this.rotTimeRow.classList.toggle('hidden', !on || !timeMode);
		if (this.rotNextRow) this.rotNextRow.classList.toggle('hidden', !on);
	},

	/* ---- dirty / save / discard --------------------------------------- */

	markDirty: function() {
		if (this._building)
			return;
		this.dirty = true;
		if (this.saveBtn) this.saveBtn.disabled = false;
		if (this.discardBtn) this.discardBtn.disabled = false;
	},

	discard: function() {
		return uci.load('nordvpn').then(L.bind(function() {
			dom.content(this.formNode, this.buildFormSections());
			this.dirty = false;
			if (this.saveBtn) this.saveBtn.disabled = true;
			if (this.discardBtn) this.discardBtn.disabled = true;
		}, this));
	},

	collectIntoUci: function() {
		var inst = this.instance;
		var setv = function(o, v, section) {
			var sec = section || inst;
			if (v == null || v === '')
				uci.unset('nordvpn', sec, o);
			else
				uci.set('nordvpn', sec, o, v);
		};
		[ 'interface', 'routing_table', 'verify_timeout', 'max_retries' ].forEach(L.bind(function(k) {
			if (this.refs[k]) setv(k, (this.refs[k].value || '').trim());
		}, this));
		// The cache directory is shared and lives on the 'main' section.
		if (this.refs.cache_dir)
			setv('cache_dir', (this.refs.cache_dir.value || '').trim(), 'main');

		setv('hop_mode', this.hopMode());
		setv('country_code', this.countrySel ? this.countrySel.value : '');
		setv('city_code', this.citySel ? this.citySel.value : '');

		var fixed = this.serverSel ? this.serverSel.value : '';
		setv('fixed_server', fixed);

		// Routing toggles exist only when no manual scheme was detected; a
		// manual setup's options are never written.
		if (this.autoRouting) {
			var autoOn = this.autoRouting.checked;
			var steered = autoOn ? [] : this.steeredNetworks();
			uci.set('nordvpn', inst, 'auto_routing', autoOn ? '1' : '0');
			uci.set('nordvpn', inst, 'killswitch', (this.ksBox && this.ksBox.checked) ? '1' : '0');
			uci.set('nordvpn', inst, 'block_ipv6', (this.v6Box && this.v6Box.checked) ? '1' : '0');
			uci.set('nordvpn', inst, 'use_vpn_dns', (this.dnsBox && this.dnsBox.checked) ? '1' : '0');
			if (steered.length) {
				uci.set('nordvpn', inst, 'source_network', steered);
				// Steering needs a routing table; default to the interface name.
				var rtb = this.refs.routing_table ? (this.refs.routing_table.value || '').trim()
					: (uci.get('nordvpn', inst, 'routing_table') || '');
				if (!rtb) {
					var ifn = this.refs.interface ? (this.refs.interface.value || '').trim() : '';
					ifn = ifn || uci.get('nordvpn', inst, 'interface') || 'nordvpn';
					uci.set('nordvpn', inst, 'routing_table', ifn);
					if (this.refs.routing_table)
						this.refs.routing_table.value = ifn;
				}
			} else {
				uci.unset('nordvpn', inst, 'source_network');
			}
		}

		var rotOn = this.rotEnable && this.rotEnable.checked && !fixed;
		uci.set('nordvpn', inst, 'rotation_enabled', rotOn ? '1' : '0');
		if (rotOn) {
			var timeMode = this.rotModeTime && this.rotModeTime.checked;
			setv('rotation_mode', timeMode ? 'time' : 'interval');
			setv('rotation_interval', this.rotInterval ? this.rotInterval.value : '360');
			setv('rotation_time', this.rotTime ? this.rotTime.value : '04:30');
		}
	},

	save: function() {
		if (!this.countrySel || !this.countrySel.value) {
			this.notice(_('Please select a country.'), 'error');
			return Promise.resolve();
		}
		this.collectIntoUci();
		this.saveBtn.disabled = true;
		this.discardBtn.disabled = true;
		var p = this.notice(_('Saving configuration…'), 'info');

		return uci.save()
			.then(function() { return uci.apply(); })
			.then(L.bind(function() {
				this.dirty = false;
				this.clearChangeIndicator();
				this.dismiss(p);
				p = this.notice(_('Applying and reconnecting…'), 'info');
				return callApply(this.instance);
			}, this))
			.then(L.bind(function(res) {
				this.dismiss(p);
				if (res && res.error)
					this.notice(_('Apply failed: %s').format(res.error), 'error');
				else if (res && res.state === 'success')
					this.notice(_('Connected to %s').format(res.gateway || ''), 'info', 4000);
				else if (res && res.state === 'partial_failure')
					this.notice(_('Configuration saved, but the server did not respond.'), 'error');
				else
					this.notice(_('Could not connect: %s').format((res && res.error) || _('unknown error')), 'error');
				return this.refreshStatus();
			}, this))
			.catch(L.bind(function(e) {
				this.dismiss(p);
				this.notice(_('Save failed: %s').format(e), 'error');
			}, this));
	},

	/* ---- credentials -------------------------------------------------- */

	showCredentialModal: function() {
		// LuCI's password Textfield renders the input with an inline reveal
		// button in one control-group row.
		var field = new ui.Textfield('', {
			password: true,
			placeholder: _('64-character hexadecimal token')
		});
		var err = E('div', { class: 'cbi-value-description', style: 'color:var(--error-color,#c0392b)' });

		ui.showModal(_('NordVPN credentials'), [
			E('p', {}, _('Paste your 64-character NordVPN access token. It is used once to derive the WireGuard private key and is never stored or shown again.')),
			E('div', { class: 'cbi-value nv-token-field' }, [ field.render() ]),
			err,
			E('div', { class: 'right' }, [
				E('button', { class: 'cbi-button', click: ui.hideModal }, _('Cancel')),
				' ',
				E('button', { class: 'cbi-button cbi-button-action', click: L.bind(this.submitCredentials, this, field, err) }, _('Save credentials'))
			])
		]);
	},

	showClearCredentialsModal: function() {
		ui.showModal(_('Remove credentials?'), [
			E('p', {}, _('The tunnel is taken down and the stored WireGuard key is deleted from this instance. Your selection (country, schedule) is kept — enter a new token to reconnect.')),
			E('div', { class: 'right' }, [
				E('button', { class: 'cbi-button', click: ui.hideModal }, _('Cancel')),
				' ',
				E('button', { class: 'cbi-button cbi-button-negative', click: L.bind(this.clearCredentials, this) }, _('Remove'))
			])
		]);
	},

	clearCredentials: function() {
		ui.hideModal();
		var n = this.notice(_('Removing credentials…'), 'info');
		return callClearCredentials(this.instance).then(L.bind(function(res) {
			this.dismiss(n);
			if (res && res.error) {
				this.notice(_('Failed: %s').format(res.error), 'error');
				return;
			}
			this.notice(_('Credentials removed.'), 'info', 4000);
			return this.refreshStatus().then(L.bind(function() {
				dom.content(this.formNode, this.buildFormSections());
			}, this));
		}, this)).catch(L.bind(function(e) {
			this.dismiss(n);
			this.notice(_('Failed: %s').format(e), 'error');
		}, this));
	},

	submitCredentials: function(field, err, ev) {
		var token = (field.getValue() || '').trim();
		if (!token.match(/^[0-9a-fA-F]{64}$/)) {
			dom.content(err, _('Enter a valid 64-character hexadecimal token.'));
			return;
		}
		var btn = ev.target;
		btn.disabled = true;
		dom.content(err, _('Verifying…'));
		return callSetCredentials(token, this.instance).then(L.bind(function(res) {
			if (res && res.error) {
				btn.disabled = false;
				dom.content(err, res.error);
				return;
			}
			ui.hideModal();
			this.notice(_('Credentials saved.'), 'info');
			return this.refreshStatus().then(L.bind(function() {
				dom.content(this.formNode, this.buildFormSections());
			}, this));
		}, this)).catch(function(e) {
			btn.disabled = false;
			dom.content(err, '' + e);
		});
	},

	/* ---- cache -------------------------------------------------------- */

	refreshCache: function(ev) {
		var btn = ev.target;
		btn.disabled = true;
		dom.content(this.cacheRow, _('Refreshing…'));
		return callRefreshLocations().then(L.bind(function() {
			this._cachePoll = L.bind(this.pollCacheOnce, this, btn);
			poll.add(this._cachePoll, 2);
		}, this)).catch(L.bind(function(e) {
			btn.disabled = false;
			this.notice(_('Refresh failed: %s').format(e), 'error');
		}, this));
	},

	pollCacheOnce: function(btn) {
		return callRefreshStatus().then(L.bind(function(st) {
			var state = st ? st.state : 'idle';
			if (state === 'running') {
				dom.content(this.cacheRow, _('Loading… %d servers so far').format((st && st.gateways) || 0));
				return;
			}
			poll.remove(this._cachePoll);
			btn.disabled = false;
			return callLocations().then(L.bind(function(loc) {
				this.locations = loc || { available: false };
				dom.content(this.cacheRow, this.cacheSummary());
				this.populateCountries();
			}, this));
		}, this));
	},

	/* ---- helpers ------------------------------------------------------ */

	notice: function(text, kind, timeout) {
		var node = ui.addNotification(null, E('p', {}, text), kind || 'info');
		if (timeout)
			setTimeout(L.bind(this.dismiss, this, node), timeout);
		return node;
	},

	dismiss: function(node) {
		try {
			if (node && node.parentNode)
				node.parentNode.removeChild(node);
		} catch (e) {}
	},

	// Our custom save calls uci.apply() directly (the framework's apply would
	// reload the page and abort the reconnect), so clear the global "Unsaved
	// Changes" indicator ourselves once our commit has gone through.
	clearChangeIndicator: function() {
		try {
			if (L.ui && L.ui.changes)
				L.ui.changes.setIndicator(0);
		} catch (e) {}
	}
});
