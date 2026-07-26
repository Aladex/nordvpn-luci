'use strict';
'require view';
'require rpc';
'require uci';
'require ui';
'require poll';
'require dom';

/* SPDX-License-Identifier: MIT
 * NordVPN WireGuard management view. Talks to the backend 'nordvpn' ubus object
 * (nordvpn-wireguard); performs no direct privileged filesystem or network ops.
 */

var callInstances = rpc.declare({ object: 'nordvpn', method: 'instances' });
var callLocations = rpc.declare({ object: 'nordvpn', method: 'locations' });
var callServers = rpc.declare({ object: 'nordvpn', method: 'servers', params: [ 'locations', 'hop_mode' ] });
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
	// Rotation pool chips: a country is filled (like the active segment), a
	// Location chips: one filled pill per country, with borderless edit/remove
	// buttons inside. A stale code (no longer in the server list) is dashed.
	'.nv-pool{display:flex;flex-direction:column;align-items:flex-start;gap:.4em;margin-top:.45em}' +
	'.nv-chip{display:inline-flex;align-items:center;gap:.35em;border:1px solid #0069d6;border-radius:1.2em;padding:.15em .55em;line-height:1.4;white-space:nowrap}' +
	'.nv-chip-country{background:#0069d6;color:#fff}' +
	'.nv-chip-click{cursor:pointer}' +
	'.nv-chip-stale{border-style:dashed;color:var(--text-color-medium,#666)}' +
	'.nv-chip button{border:0;background:transparent;color:inherit;cursor:pointer;padding:0 .1em;margin:0;font:inherit;font-weight:700;line-height:1}' +
	'.nv-pool-count{color:var(--text-color-medium,#666);font-size:.9em}' +
	// Custom location picker: the trigger opens an inline panel that walks
	// countries -> cities (checkbox narrowing) in place. The trigger hides
	// while the panel is open, so there is no duplicate "add" affordance.
	'.nv-pool-wrap{display:block;margin-top:.5em}' +
	'.nv-pool-trigger::after{content:" \\25be"}' +
	'.nv-pool-panel{display:block;margin-top:.35em;width:320px;max-width:100%;max-height:340px;overflow:auto;background:var(--background-color-high,#fff);color:var(--text-color-high,inherit);border:1px solid var(--border-color-medium,#ccc);border-radius:.4em;box-shadow:0 4px 14px rgba(0,0,0,.18);padding:.25em}' +
	'.nv-pool-panel.hidden{display:none}' +
	'.nv-pool-head{display:flex;align-items:center;justify-content:space-between;gap:.5em;padding:.1em .3em .3em;font-weight:600}' +
	'.nv-pool-x{border:0;background:transparent;cursor:pointer;font:inherit;font-weight:700;color:inherit;padding:0 .2em}' +
	'.nv-pool-filter{width:100%;box-sizing:border-box;margin:0 0 .3em 0}' +
	'.nv-pool-row{display:flex;align-items:center;gap:.55em;padding:.34em .5em;border-radius:.3em;cursor:pointer;white-space:nowrap}' +
	'.nv-pool-row:hover{background:rgba(0,105,214,.14)}' +
	'.nv-pool-row.is-in{opacity:.55}' +
	'.nv-pool-row .grow{flex:1;overflow:hidden;text-overflow:ellipsis}' +
	'.nv-pool-row .chev{color:var(--text-color-medium,#888);font-weight:700}' +
	'.nv-pool-row .box{font-weight:700;width:1.15em;text-align:center;flex:none}' +
	'.nv-pool-back{font-weight:600}' +
	'.nv-pool-remove{color:#c0392b;font-weight:600}' +
	'.nv-pool-remove:hover{background:rgba(192,57,43,.12)}' +
	'.nv-pool-sep{border-top:1px solid var(--border-color-medium,#ddd);margin:.25em 0}' +
	'.nv-chip-add{font-weight:700;padding:0 .15em}' +
	// Server picker: same panel, plus a load dot (green/amber/red), a group
	// header per country and quick "Automatic / Lowest load" rows at the top.
	'.nv-srv-trigger{max-width:100%;overflow:hidden;text-overflow:ellipsis;text-align:left}' +
	'.nv-srv-x{border:0;background:transparent;cursor:pointer;font:inherit;font-weight:700;color:inherit;padding:0 .2em;margin-left:.3em}' +
	'.nv-dot{display:inline-block;width:.7em;height:.7em;border-radius:50%;flex:none}' +
	'.nv-dot-lo{background:#3c8c3c}' +
	'.nv-dot-mid{background:#c79100}' +
	'.nv-dot-hi{background:#c0392b}' +
	'.nv-srv-load{color:var(--text-color-medium,#888);font-variant-numeric:tabular-nums;flex:none}' +
	'.nv-srv-cur{color:#3c8c3c;font-weight:600;flex:none}' +
	'.nv-srv-grp{font-weight:600;padding:.35em .5em .15em;color:var(--text-color-medium,#888)}' +
	'.nv-pool-row.nv-srv-quick{font-weight:600}' +
	// Plain flex rows (no LuCI .table classes), so the theme's own responsive
	// table stacking can never apply; wraps naturally down to ~340 px.
	'.nv-inst-row{display:flex;align-items:center;gap:.8em;padding:.55em 0;border-bottom:1px solid var(--border-color-medium,#ccc);cursor:pointer}' +
	'.nv-inst-row:last-child{border-bottom:none}' +
	'.nv-inst-info{display:flex;flex-wrap:wrap;align-items:center;gap:.25em .8em;flex:1;min-width:0}' +
	'.nv-inst-name{font-weight:bold}' +
	'.nv-inst-dim{color:var(--text-color-medium,#666);font-size:.92em}' +
	'.nv-inst-act{flex:none;margin-left:auto}' +
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
		var rows = [];

		(this.instances || []).forEach(L.bind(function(st) {
			var info = this.stateInfo(this.dispState(st));
			var loc = st.location || {};
			var flag = this.countryFlag(loc.country);
			var selected = (st.instance === this.instance);
			var r = st.rotation || {};
			var next = '';
			if (r.enabled && r.next_run)
				next = new Date(r.next_run * 1000).toLocaleTimeString();
			else if (r.enabled)
				next = _('on schedule');

			rows.push(E('div', {
				class: 'nv-inst-row',
				click: L.bind(this.selectInstance, this, st.instance)
			}, [
				E('div', { class: 'nv-inst-info' }, [
					E('span', { class: 'nv-inst-name' }, (selected ? '▸ ' : '') + st.instance),
					E('span', { style: 'color:' + info.color }, info.label),
					E('span', {}, (flag ? flag + ' ' : '') + (st.gateway || '—')),
					next ? E('span', { class: 'nv-inst-dim' }, '⟳ ' + next) : ''
				]),
				E('span', { class: 'nv-inst-act' }, E('button', {
					class: 'cbi-button cbi-button-remove',
					click: L.bind(this.showDeleteInstanceModal, this, st.instance)
				}, st.instance === 'main' ? _('Reset') : _('Delete')))
			]));
		}, this));

		dom.content(this.instancesNode, E('fieldset', { class: 'cbi-section' }, [
			E('legend', {}, _('VPN instances')),
			E('div', { class: 'cbi-section-node' }, [
				E('div', {}, rows),
				E('div', { style: 'margin-top:.6em' }, [
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
			disabled:       { label: _('Disabled'),       color: 'var(--text-color-medium,#666)' },
			error:          { label: _('Error'),          color: 'var(--error-color,#c0392b)' },
			not_configured: { label: _('Not configured'), color: 'var(--text-color-medium,#666)' }
		};
		return map[state] || { label: _('Unknown'), color: 'var(--text-color-medium,#666)' };
	},

	// Runtime state to display: an administratively disabled but configured
	// instance reads as "Disabled" (deliberate), not "Disconnected" (a fault).
	dispState: function(s) {
		if (s && s.configured && s.enabled === false)
			return 'disabled';
		return (s && s.state) || 'not_configured';
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

	// Action buttons for the status band, chosen by state so structurally
	// inapplicable actions are hidden (not greyed): only Refresh until
	// configured, a single Enable/Disable toggle by administrative state, and
	// "Rotate now" only for a live, non-pinned tunnel (greyed while not live).
	actionButtons: function(s) {
		var btns = [ E('button', { class: 'cbi-button', click: L.bind(this.refreshStatus, this) }, _('Refresh')) ];

		if (!s.configured)
			return btns;

		if (s.enabled === false) {
			btns.push(E('button', {
				class: 'cbi-button cbi-button-apply',
				click: L.bind(this.reconnect, this)
			}, _('Enable')));
			return btns;
		}

		btns.push(E('button', {
			class: 'cbi-button cbi-button-apply',
			click: L.bind(this.reconnect, this)
		}, _('Reconnect')));

		if (!s.fixed) {
			var live = (s.state === 'connected' || s.state === 'degraded');
			btns.push(E('button', {
				class: 'cbi-button',
				disabled: !live || null,
				click: L.bind(this.rotateNow, this)
			}, _('Rotate now')));
		}

		btns.push(E('button', {
			class: 'cbi-button cbi-button-remove',
			click: L.bind(this.disconnect, this)
		}, _('Disable')));

		return btns;
	},

	updateStatusBand: function() {
		var s = this.status || {};
		var loc = s.location || {};
		var info = this.stateInfo(this.dispState(s));

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
					E('div', { class: 'nv-status-actions' }, this.actionButtons(s))
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
			// If the detected routing mode changed underneath an idle form (no
			// unsaved edits), rebuild it — the panel's shape depends on the mode,
			// so it must not go stale until a manual page refresh.
			var mode = (this.status.routing || {}).mode;
			if (!this.dirty && this._routingMode != null && mode !== this._routingMode)
				dom.content(this.formNode, this.buildFormSections());
			this._routingMode = mode;
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

		// Server pin picker (custom panel, load-aware). _serverChosen is the
		// source of truth: a hostname, or '' for automatic (rotation picks).
		this._serversReq = 0;
		this._serverChosen = '';
		this._srvOpen = false;
		this._srvFilter = '';
		this.srvTrigger = E('button', { type: 'button', class: 'cbi-button nv-pool-trigger nv-srv-trigger',
			click: L.bind(function(ev) { ev.preventDefault(); ev.stopPropagation(); this.srvTogglePanel(); }, this) },
			_('Automatic server'));
		this.srvPanel = E('div', { class: 'nv-pool-panel hidden',
			click: function(ev) { ev.stopPropagation(); } });
		this.srvWrap = E('span', { class: 'nv-pool-wrap' }, [ this.srvTrigger, this.srvPanel ]);
		if (!this._srvOutsideBound) {
			this._srvOutsideBound = true;
			document.addEventListener('click', L.bind(function(ev) {
				if (this._srvOpen && this.srvWrap && !this.srvWrap.contains(ev.target))
					this.srvClosePanel();
			}, this));
		}

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

		// Location set editor: a combined country/city picker feeding removable
		// chips. The set drives BOTH the initial connect and the rotation. A
		// legacy country_code/city_code selection seeds the chips so upgraded
		// configs see their choice here. Codes no longer in the server list
		// are kept and shown dashed, never silently dropped.
		this.poolEntries = [];
		var locRaw = uci.get('nordvpn', this.instance, 'locations');
		if (typeof locRaw === 'string')
			locRaw = [ locRaw ];
		var seed = Array.isArray(locRaw) ? locRaw.slice() : [];
		if (!seed.length) {
			// A legacy city implies its country, so seed the city alone (not both)
			// or the whole country when no city was pinned. Seeding both would
			// double-count and render the city hidden under the country chip.
			var legacyCity = uci.get('nordvpn', this.instance, 'city_code') || '';
			var legacyCc = uci.get('nordvpn', this.instance, 'country_code') || '';
			if (legacyCity)
				seed.push(legacyCity);
			else if (legacyCc)
				seed.push(legacyCc);
		}
		seed.forEach(L.bind(function(code) {
			var e = this.poolResolve(code);
			if (e)
				this.poolEntries.push(e);
		}, this));
		// Custom picker: a trigger opens a panel that walks countries -> cities
		// in place, with an explicit "back" step. No native <select>, so the
		// navigation and the reset-after-add feel like a small wizard.
		this._poolOpen = false;
		this._poolLevel = 'country';
		this._poolCountry = null;
		this._poolFilter = '';
		this.poolTrigger = E('button', { type: 'button', class: 'cbi-button nv-pool-trigger',
			click: L.bind(function(ev) { ev.preventDefault(); ev.stopPropagation(); this.poolTogglePanel(); }, this) },
			'+ ' + _('Add a location'));
		this.poolPanel = E('div', { class: 'nv-pool-panel hidden',
			click: function(ev) { ev.stopPropagation(); } });
		this.poolWrap = E('span', { class: 'nv-pool-wrap' }, [ this.poolTrigger, this.poolPanel ]);
		// One document-level closer for the whole view (guarded so form rebuilds
		// do not stack listeners); it reads the current poolWrap at click time.
		if (!this._poolOutsideBound) {
			this._poolOutsideBound = true;
			document.addEventListener('click', L.bind(function(ev) {
				if (this._poolOpen && this.poolWrap && !this.poolWrap.contains(ev.target))
					this.poolClosePanel();
			}, this));
		}
		this.poolChips = E('span', { class: 'nv-pool' });
		this.poolCount = E('span', { class: 'nv-pool-count' });
		this.poolNote = E('div', { class: 'cbi-value-description' });
		this.rebuildPoolWidget();

		var section = E('fieldset', { class: 'cbi-section' }, [
			E('legend', {}, _('Connection')),
			E('div', { class: 'cbi-section-node' }, [
				this.row(_('Credentials'), [ E('div', { class: 'nv-inline' }, [ credState, credBtn, credClearBtn ]) ]),
				this.row(_('Hop mode'), [ seg, this.hopNote ]),
				this.row(_('Locations'), [
					E('div', {}, [ this.poolChips ]),
					this.poolWrap,
					this.poolNote
				], _('Countries this instance connects between. Picking a country adds the whole country; open its chip to narrow it to specific cities. The initial connect and the rotation both pick within this set.')),
				this.row(_('Server'), [
					this.srvWrap
				], _('Automatic picks a server from the set (rotation-friendly). Pin a specific one to lock it; pinning disables automatic rotation.'))
			])
		]);

		this.refreshServerList();
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

		// Read-only context: the interface and table this instance uses, so the
		// firewall/routing wiring is visible right here — not only in Advanced.
		var iface = (this.status || {}).interface || g('interface', 'nordvpn');
		var tbl = g('routing_table', '') || iface;
		body.appendChild(this.row(_('Interface / table'), [
			E('span', { class: 'nv-inline-note' },
				_('Interface %s · routing table %s — edit under Advanced settings.').format(iface, tbl))
		]));

		if (rt.mode === 'manual') {
			var what = [];
			if (rt.user_routes)
				what.push(_('%d custom route(s)/rule(s)').format(rt.user_routes));
			var table = g('routing_table', '');
			if (table)
				what.push(_('routing table "%s"').format(table));
			body.appendChild(this.row(_('Mode'), [
				E('div', {}, [
					E('span', {}, _('Manual — %s detected. The app leaves routing and firewall untouched.')
						.format(what.join(' + ') || _('custom configuration'))),
					E('div', { class: 'cbi-value-description' },
						_('Remove your own routes/rules that reference this interface to manage routing from here.'))
				])
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
			// DNS mode: prefer the enum, fall back to the legacy boolean.
			var dnsMode = g('vpn_dns', '');
			if (dnsMode !== 'off' && dnsMode !== 'standard' && dnsMode !== 'threat')
				dnsMode = (g('use_vpn_dns', '0') === '1') ? 'standard' : 'off';
			this.dnsSel = E('select', { class: 'cbi-input-select', change: L.bind(this.markDirty, this) }, [
				E('option', { value: 'off' }, _('Off — use system DNS')),
				E('option', { value: 'standard' }, _('NordVPN — standard')),
				E('option', { value: 'threat' }, _('NordVPN Threat Protection — blocks ads & malware'))
			]);
			this.dnsSel.value = dnsMode;
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
			this.dnsRow = this.row(_('DNS'), [ this.dnsSel ],
				_('Which resolver to use while connected. Threat Protection blocks ads and malware at the DNS level; both NordVPN options only work through the tunnel.'));
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

	/* ---- rotation pool -------------------------------------------------- */

	// Resolve a pool code to display metadata against the current locations
	// tree and hop mode. A code that is not in the tree (removed by NordVPN,
	// or empty for the current hop mode) resolves with name/count null so the
	// chip renders dashed instead of disappearing.
	poolResolve: function(code) {
		if (typeof code !== 'string' || !code)
			return null;
		var key = this.hopCountKey();
		var isCountry = /^[A-Za-z]{2}$/.test(code);
		var flag = this.countryFlag(code.slice(0, 2));
		var countries = this.filteredCountries();
		for (var i = 0; i < countries.length; i++) {
			var c = countries[i];
			if (isCountry && c.code === code)
				return { code: code, kind: 'country', name: c.name, count: c.gateway_count || 0, flag: flag };
			var cities = isCountry ? [] : (c.cities || []);
			for (var j = 0; j < cities.length; j++)
				if (cities[j].code === code)
					return { code: code, kind: 'city', name: cities[j].name, count: cities[j][key] || 0, flag: flag };
		}
		return { code: code, kind: isCountry ? 'country' : 'city', name: null, count: null, flag: flag };
	},

	/* ---- country-first set mutations ---------------------------------- */

	poolCitiesOf: function(cc) {
		return (((this._ccData || {})[cc]) || {}).cities || [];
	},

	// Current state of a country in the set: whole, or a map of picked cities.
	poolCountryHas: function(cc) {
		var whole = false, cities = {};
		(this.poolEntries || []).forEach(function(e) {
			if (e.code === cc) whole = true;
			else if (e.kind === 'city' && e.code.indexOf(cc + '-') === 0) cities[e.code] = true;
		});
		return { whole: whole, cities: cities, has: whole || Object.keys(cities).length > 0 };
	},

	poolStripCountry: function(cc) {
		this.poolEntries = (this.poolEntries || []).filter(function(e) {
			return !(e.code === cc || (e.kind === 'city' && e.code.indexOf(cc + '-') === 0));
		});
	},

	_poolCommit: function() {
		this.markDirty();
		this.rebuildPoolWidget();
		this.refreshServerList();
	},

	// Whole country in the set (stored as the bare country code).
	poolSetWhole: function(cc) {
		this.poolStripCountry(cc);
		var e = this.poolResolve(cc);
		if (e)
			this.poolEntries.push(e);
		this._poolCommit();
	},

	poolRemoveCountry: function(cc) {
		this.poolStripCountry(cc);
		this._poolCommit();
	},

	// Narrow a country to specific city codes. All cities selected collapses
	// back to the whole country; none removes it entirely.
	poolSetCities: function(cc, codes) {
		var all = this.poolCitiesOf(cc).map(function(c) { return c.code; });
		if (!codes.length)
			return this.poolRemoveCountry(cc);
		if (all.length && codes.length >= all.length)
			return this.poolSetWhole(cc);
		this.poolStripCountry(cc);
		codes.forEach(L.bind(function(code) {
			var e = this.poolResolve(code);
			if (e)
				this.poolEntries.push(e);
		}, this));
		this._poolCommit();
	},

	// Toggle one city. From a whole country, the first uncheck expands to
	// "every city except this one".
	poolToggleCity: function(cc, code) {
		var st = this.poolCountryHas(cc);
		var all = this.poolCitiesOf(cc).map(function(c) { return c.code; });
		var sel;
		if (st.whole) {
			sel = all.filter(function(x) { return x !== code; });
		} else {
			sel = Object.keys(st.cities);
			if (sel.indexOf(code) >= 0)
				sel = sel.filter(function(x) { return x !== code; });
			else
				sel.push(code);
		}
		this.poolSetCities(cc, sel);
	},

	// The "whole country" master toggle.
	poolToggleWhole: function(cc) {
		if (this.poolCountryHas(cc).whole)
			this.poolRemoveCountry(cc);
		else
			this.poolSetWhole(cc);
	},

	// Repaint the cascade picker, chips and the counter. Re-resolves entries,
	// so it is also the hop-mode/locations change hook. Also maintains the
	// country-code → name/data maps used by the cascade and server labels.
	rebuildPoolWidget: function() {
		if (!this.poolChips)
			return;
		this.poolEntries = (this.poolEntries || []).map(L.bind(function(e) {
			return this.poolResolve(e.code);
		}, this)).filter(function(e) { return e != null; });

		this._ccNames = {};
		this._ccData = {};
		this.filteredCountries().forEach(L.bind(function(c) {
			this._ccNames[c.code] = c.name;
			this._ccData[c.code] = c;
		}, this));
		// Keep an open panel in sync with the set (✓ marks, counts, city lists).
		if (this._poolOpen)
			this.poolRenderPanel();

		dom.content(this.poolChips, '');
		// One chip per country (country-first model). A whole-country chip shows
		// just the country; a narrowed one lists its picked cities. Remove drops
		// the whole country; the pencil opens its city checklist.
		// Entries not available in the current hop mode are hidden (shown as "not
		// selected") rather than as broken raw codes; switching modes therefore
		// reads as an empty set until valid locations are picked. They stay in
		// poolEntries so a round-trip mode switch does not lose them, and are
		// dropped from what gets saved (collectIntoUci filters the same way).
		var groups = [], byCc = {};
		this.poolEntries.forEach(function(e) {
			if (e.count == null)
				return;
			var cc = e.kind === 'country' ? e.code : e.code.split('-')[0];
			var g = byCc[cc];
			if (!g) {
				g = { cc: cc, flag: e.flag, whole: null, cities: [] };
				byCc[cc] = g;
				groups.push(g);
			}
			if (e.kind === 'country')
				g.whole = e;
			else
				g.cities.push(e);
		});

		var total = 0;
		groups.forEach(function(g) {
			if (g.whole) {
				if (g.whole.count != null) total += g.whole.count;
			} else {
				g.cities.forEach(function(e) { if (e.count != null) total += e.count; });
			}
		});

		groups.forEach(L.bind(function(g) {
			var cname = this._ccNames[g.cc] || (g.whole && g.whole.name) || g.cc.toUpperCase();
			var flag = g.flag || '';
			var label, stale;
			if (g.whole) {
				stale = g.whole.name == null;
				label = (flag ? flag + ' ' : '') + cname +
					(g.whole.count != null ? ' (%d)'.format(g.whole.count) : '');
			} else {
				stale = g.cities.some(function(e) { return e.name == null; });
				var cities = g.cities.map(function(e) { return e.name || e.code; }).join(', ');
				label = (flag ? flag + ' ' : '') + cname + ' · ' + cities;
			}
			// The whole chip opens this country's editor (cities + remove); no
			// separate ×/pencil buttons.
			this.poolChips.appendChild(E('span', {
				class: 'nv-chip nv-chip-country nv-chip-click' + (stale ? ' nv-chip-stale' : ''),
				title: _('Edit or remove'),
				click: L.bind(function(ev) { ev.stopPropagation(); this.poolOpenCountry(g.cc, true); }, this) },
				label));
		}, this));

		var summary = '';
		if (groups.length)
			summary = total ? _('set: %d countries, ~%d servers').format(groups.length, total)
				: _('set: %d countries').format(groups.length);
		this.poolChips.appendChild(this.poolCount);
		dom.content(this.poolCount, summary);

		// Guidance: the server list drives the picker, and the set must not be
		// empty — the connection picks within it.
		var note = '';
		if (!(this.locations || {}).available)
			note = _('Loading server list… use "Refresh server list" in Advanced settings if it does not appear.');
		else if (!groups.length)
			note = _('Add at least one country or city.');
		dom.content(this.poolNote, note);
		this.poolNote.classList.toggle('hidden', !note);
		if (this.poolTrigger)
			this.poolTrigger.disabled = !(this.locations || {}).available;
	},

	/* ---- location picker panel --------------------------------------- */

	poolTogglePanel: function() {
		if (this._poolOpen)
			return this.poolClosePanel();
		this._poolLevel = 'country';
		this._poolCountry = null;
		this._poolFilter = '';
		this._poolOpen = true;
		if (this.poolTrigger) this.poolTrigger.classList.add('hidden');
		this.poolPanel.classList.remove('hidden');
		this.poolRenderPanel();
	},

	poolClosePanel: function() {
		this._poolOpen = false;
		if (this.poolPanel) this.poolPanel.classList.add('hidden');
		if (this.poolTrigger) this.poolTrigger.classList.remove('hidden');
	},

	// Open a country's city checklist. Entering a country selects it whole
	// ("pick a country = whole country in the set"); checkboxes then narrow it.
	// edit=true means we came from a chip (editing that country): no "back to
	// countries", but a "remove this country" action instead. edit=false is the
	// add flow from the country list (keeps a back step).
	poolOpenCountry: function(cc, edit) {
		if (!this.poolCountryHas(cc).has)
			this.poolSetWhole(cc);
		this._poolLevel = 'city';
		this._poolCountry = cc;
		this._poolEdit = !!edit;
		this._poolFilter = '';
		this._poolOpen = true;
		if (this.poolTrigger) this.poolTrigger.classList.add('hidden');
		this.poolPanel.classList.remove('hidden');
		this.poolRenderPanel();
	},

	// City level: a back row, a "Whole country" master toggle, then a checkbox
	// per city. Country level: a header with close, a filter, the country list.
	poolRenderPanel: function() {
		var panel = this.poolPanel;
		if (!panel)
			return;
		dom.content(panel, '');

		if (this._poolLevel === 'city') {
			var cc = this._poolCountry;
			var c = (this._ccData || {})[cc];
			if (this._poolEdit) {
				var cflag = this.countryFlag(cc);
				panel.appendChild(E('div', { class: 'nv-pool-head' }, [
					E('span', {}, (cflag ? cflag + ' ' : '') + (this._ccNames[cc] || cc.toUpperCase())),
					E('button', { type: 'button', class: 'nv-pool-x', title: _('Done'),
						click: L.bind(function(ev) { ev.stopPropagation(); this.poolClosePanel(); }, this) }, '✕')
				]));
			} else {
				panel.appendChild(E('div', { class: 'nv-pool-head' }, [
					E('span', { class: 'nv-pool-back', style: 'cursor:pointer',
						click: L.bind(function(ev) {
							ev.stopPropagation();
							this._poolLevel = 'country';
							this._poolCountry = null;
							this._poolFilter = '';
							this.poolRenderPanel();
						}, this) }, '‹ ' + _('Back to countries')),
					E('button', { type: 'button', class: 'nv-pool-x', title: _('Close'),
						click: L.bind(function(ev) { ev.stopPropagation(); this.poolClosePanel(); }, this) }, '✕')
				]));
			}
			panel.appendChild(E('div', { class: 'nv-pool-sep' }));
			if (!c) {
				panel.appendChild(E('div', { class: 'nv-pool-row is-in' }, _('No cities available')));
				return;
			}
			var st = this.poolCountryHas(cc);
			panel.appendChild(E('div', { class: 'nv-pool-row',
				click: L.bind(function(ev) { ev.stopPropagation(); this.poolToggleWhole(cc); }, this) }, [
					E('span', { class: 'box' }, st.whole ? '☑' : '☐'),
					E('span', { class: 'grow' }, _('Whole country (%d)').format(c.gateway_count || 0))
				]));
			panel.appendChild(E('div', { class: 'nv-pool-sep' }));
			var key = this.hopCountKey();
			(c.cities || []).forEach(L.bind(function(city) {
				var on = st.whole || !!st.cities[city.code];
				panel.appendChild(E('div', { class: 'nv-pool-row',
					click: L.bind(function(ev) { ev.stopPropagation(); this.poolToggleCity(cc, city.code); }, this) }, [
						E('span', { class: 'box' }, on ? '☑' : '☐'),
						E('span', { class: 'grow' }, '%s (%d)'.format(city.name, city[key] || 0))
					]));
			}, this));
			if (this._poolEdit) {
				panel.appendChild(E('div', { class: 'nv-pool-sep' }));
				panel.appendChild(E('div', { class: 'nv-pool-row nv-pool-remove',
					click: L.bind(function(ev) {
						ev.stopPropagation();
						this.poolRemoveCountry(cc);
						this.poolClosePanel();
					}, this) }, [
						E('span', { class: 'box' }, '🗑'),
						E('span', { class: 'grow' }, _('Remove this country'))
					]));
			}
			return;
		}

		panel.appendChild(E('div', { class: 'nv-pool-head' }, [
			E('span', {}, _('Add a location')),
			E('button', { type: 'button', class: 'nv-pool-x', title: _('Close'),
				click: L.bind(function(ev) { ev.stopPropagation(); this.poolClosePanel(); }, this) }, '✕')
		]));
		var filt = E('input', { type: 'text', class: 'cbi-input-text nv-pool-filter',
			placeholder: _('Filter') + '…', value: this._poolFilter });
		filt.addEventListener('input', L.bind(function() {
			this._poolFilter = filt.value;
			this.poolRenderCountryList();
		}, this));
		filt.addEventListener('click', function(ev) { ev.stopPropagation(); });
		panel.appendChild(filt);
		this._poolListEl = E('div', {});
		panel.appendChild(this._poolListEl);
		this.poolRenderCountryList();
		setTimeout(function() { try { filt.focus(); } catch (e) {} }, 0);
	},

	// Country rows, filtered. Mark: whole = check, partial = half, none = blank.
	// Clicking a row opens that country (adding it whole, then narrow-able).
	poolRenderCountryList: function() {
		var el = this._poolListEl;
		if (!el)
			return;
		dom.content(el, '');
		var f = (this._poolFilter || '').toLowerCase();
		var any = false;
		this.filteredCountries().forEach(L.bind(function(c) {
			if (f && c.name.toLowerCase().indexOf(f) < 0 && c.code.toLowerCase().indexOf(f) < 0)
				return;
			any = true;
			var st = this.poolCountryHas(c.code);
			var mark = st.whole ? '☑' : (st.has ? '◐' : '');
			var flag = this.countryFlag(c.code);
			el.appendChild(E('div', { class: 'nv-pool-row' + (st.has ? ' is-in' : ''),
				click: L.bind(function(ev) { ev.stopPropagation(); this.poolOpenCountry(c.code); }, this) }, [
					E('span', { class: 'box' }, mark),
					E('span', { class: 'grow' }, (flag ? flag + ' ' : '') +
						'%s (%d)'.format(c.name, c.gateway_count || 0)),
					E('span', { class: 'chev' }, '›')
				]));
		}, this));
		if (!any)
			el.appendChild(E('div', { class: 'nv-pool-row is-in' }, _('No matches')));
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

		// MTU with a WAN-derived recommendation (backend computes WAN_MTU - 80).
		var rtx = (this.status || {}).routing || {};
		var recMtu = rtx.recommended_mtu;
		var curMtu = g('mtu', '');
		var atRec = recMtu && curMtu !== '' && parseInt(curMtu, 10) === recMtu;
		var mtuInput = this.input('mtu', 'number', g('mtu', ''),
			{ min: 1280, max: 1500, style: 'width:90px', placeholder: recMtu ? ('' + recMtu) : '1420' });
		var mtuCtl = [ mtuInput ];
		if (atRec) {
			mtuCtl.push(' ');
			mtuCtl.push(E('span', { style: 'color:var(--success-color-medium,#3c8c3c);font-weight:600' },
				_('✓ recommended value')));
		} else if (recMtu) {
			mtuCtl.push(' ');
			mtuCtl.push(E('button', { class: 'cbi-button', click: L.bind(function(ev) {
				ev.preventDefault();
				mtuInput.value = recMtu;
				this.markDirty();
			}, this) }, _('Use recommended')));
		}
		var mtuDesc = atRec
			? _('You are on the recommended MTU for your WAN (MTU %d). Empty = the netifd default (1420).').format(rtx.wan_mtu || 0)
			: (recMtu
				? _('Recommended %d for your WAN (MTU %d). Empty = the default (1420). Lower it if sites/Gmail hang or throughput is poor — LTE/5G often need less.').format(recMtu, rtx.wan_mtu || 0)
				: _('WireGuard interface MTU. Empty = the netifd default (1420).'));

		var body = E('div', { class: 'cbi-section-node' }, [
			this.row(_('Interface name'), [ this.input('interface', 'text', g('interface', 'nordvpn')) ],
				_('Name of the managed WireGuard interface. ⚠ Changing it after setup recreates the tunnel under the new name and orphans the old interface’s firewall/routing objects.')),
			this.row(_('Routing table'), [ this.input('routing_table', 'text', g('routing_table', ''), { placeholder: 'main' }) ],
				_('Custom routing table (empty = the interface name when steering, otherwise the main table).')),
			this.row(_('MTU'), mtuCtl, mtuDesc),
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
		if (this._serverChosen)
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

	// Fetch the union server list for the location set (ubus `servers` with the
	// locations argument) and repaint the picker. A pinned server no longer in
	// the set is kept, never dropped.
	refreshServerList: function() {
		if (!this.srvTrigger)
			return;
		var codes = (this.poolEntries || []).map(function(e) { return e.code; });
		var req = ++this._serversReq;
		this._serverData = null;
		this.srvTrigger.disabled = !codes.length;
		if (!codes.length) {
			this.srvRenderTrigger();
			return;
		}
		callServers(codes, this.hopMode()).then(L.bind(function(res) {
			if (req !== this._serversReq)
				return; // a newer rebuild superseded this response
			this._serverData = { relays: ((res && res.relays) || []).slice() };
			// Restoring the persisted pin is not a user edit.
			this._serverChosen = uci.get('nordvpn', this.instance, 'fixed_server') || '';
			this.srvRenderTrigger();
			if (this._srvOpen)
				this.srvRenderPanel();
			this._building = true;
			this.updateRotationAvailability();
			this._building = false;
		}, this)).catch(function() {});
	},

	srvLoadClass: function(load) {
		if (typeof load !== 'number')
			return '';
		return load < 50 ? 'nv-dot-lo' : (load < 80 ? 'nv-dot-mid' : 'nv-dot-hi');
	},

	// The gateway the tunnel is on right now (live status), to flag it.
	srvCurrentGateway: function() {
		return (this.status && this.status.gateway) || '';
	},

	srvRelayByHost: function(host) {
		var found = null;
		((this._serverData && this._serverData.relays) || []).forEach(function(r) {
			if (r.hostname === host) found = r;
		});
		return found;
	},

	srvLowestLoad: function() {
		var best = null;
		((this._serverData && this._serverData.relays) || []).forEach(function(r) {
			if (typeof r.load !== 'number') return;
			if (!best || r.load < best.load) best = r;
		});
		return best;
	},

	// The trigger shows the current pin richly (load dot / flag / city / name),
	// or "Automatic server", with an inline clear when pinned.
	srvRenderTrigger: function() {
		var t = this.srvTrigger;
		if (!t)
			return;
		var host = this._serverChosen;
		if (!host) {
			dom.content(t, _('Automatic server'));
			return;
		}
		var r = this.srvRelayByHost(host);
		var names = this._ccNames || {};
		var kids;
		if (r) {
			var flag = this.countryFlag(r.country_code);
			kids = [
				E('span', { class: 'nv-dot ' + this.srvLoadClass(r.load) }),
				E('span', {}, ' ' + (flag ? flag + ' ' : '') +
					'%s / %s'.format(r.city || '?', r.name || r.hostname) +
					(r.load != null ? ' (%d%%)'.format(r.load) : ''))
			];
		} else {
			kids = [ E('span', {}, host + ' ' + _('(not in the set)')) ];
		}
		kids.push(E('button', { type: 'button', class: 'nv-srv-x', title: _('Clear (back to automatic)'),
			click: L.bind(function(ev) { ev.preventDefault(); ev.stopPropagation(); this.srvSetChosen(''); }, this) }, '×'));
		dom.content(t, kids);
	},

	srvTogglePanel: function() {
		if (this._srvOpen)
			return this.srvClosePanel();
		this._srvFilter = '';
		this._srvOpen = true;
		if (this.srvTrigger) this.srvTrigger.classList.add('hidden');
		this.srvPanel.classList.remove('hidden');
		this.srvRenderPanel();
	},

	srvClosePanel: function() {
		this._srvOpen = false;
		if (this.srvPanel) this.srvPanel.classList.add('hidden');
		if (this.srvTrigger) this.srvTrigger.classList.remove('hidden');
	},

	srvSetChosen: function(host) {
		this._serverChosen = host || '';
		this.markDirty();
		this.updateRotationAvailability();
		this.srvRenderTrigger();
		this.srvClosePanel();
	},

	// Panel: header + filter, quick "Automatic" and "Lowest load" rows, then
	// servers grouped by country and sorted by load (lowest first).
	srvRenderPanel: function() {
		var panel = this.srvPanel;
		if (!panel)
			return;
		dom.content(panel, '');
		panel.appendChild(E('div', { class: 'nv-pool-head' }, [
			E('span', {}, _('Pick a server')),
			E('button', { type: 'button', class: 'nv-pool-x', title: _('Close'),
				click: L.bind(function(ev) { ev.stopPropagation(); this.srvClosePanel(); }, this) }, '✕')
		]));
		var filt = E('input', { type: 'text', class: 'cbi-input-text nv-pool-filter',
			placeholder: _('Filter servers') + '…', value: this._srvFilter });
		filt.addEventListener('input', L.bind(function() {
			this._srvFilter = filt.value;
			this.srvRenderList();
		}, this));
		filt.addEventListener('click', function(ev) { ev.stopPropagation(); });
		panel.appendChild(filt);
		this._srvListEl = E('div', {});
		panel.appendChild(this._srvListEl);
		this.srvRenderList();
		setTimeout(function() { try { filt.focus(); } catch (e) {} }, 0);
	},

	srvRenderList: function() {
		var el = this._srvListEl;
		if (!el)
			return;
		dom.content(el, '');
		var names = this._ccNames || {};
		var chosen = this._serverChosen;
		var current = this.srvCurrentGateway();
		var f = (this._srvFilter || '').toLowerCase();

		el.appendChild(E('div', { class: 'nv-pool-row nv-srv-quick',
			click: L.bind(function(ev) { ev.stopPropagation(); this.srvSetChosen(''); }, this) }, [
				E('span', { class: 'box' }, chosen ? '' : '☑'),
				E('span', { class: 'grow' }, _('Automatic (rotation picks)'))
			]));
		var best = this.srvLowestLoad();
		if (best) {
			var bn = names[best.country_code] || (best.country_code || '').toUpperCase();
			el.appendChild(E('div', { class: 'nv-pool-row nv-srv-quick',
				click: L.bind(function(ev) { ev.stopPropagation(); this.srvSetChosen(best.hostname); }, this) }, [
					E('span', { class: 'box' }, '⚡'),
					E('span', { class: 'grow' }, _('Lowest load') + ' · ' + (best.city || bn) +
						(best.load != null ? ' (%d%%)'.format(best.load) : '')),
					E('span', { class: 'nv-dot ' + this.srvLoadClass(best.load) })
				]));
		}
		el.appendChild(E('div', { class: 'nv-pool-sep' }));

		var groups = [], byCode = {};
		((this._serverData && this._serverData.relays) || []).forEach(L.bind(function(r) {
			var cname = names[r.country_code] || (r.country_code || '').toUpperCase();
			var hay = (cname + ' / ' + (r.city || '') + ' / ' + (r.name || r.hostname)).toLowerCase();
			if (f && r.hostname !== chosen && hay.indexOf(f) < 0)
				return;
			var g = byCode[r.country_code];
			if (!g) {
				g = { name: cname, flag: this.countryFlag(r.country_code), rows: [] };
				byCode[r.country_code] = g;
				groups.push(g);
			}
			g.rows.push(r);
		}, this));
		groups.forEach(L.bind(function(g) {
			g.rows.sort(function(a, b) {
				var al = typeof a.load === 'number' ? a.load : 999;
				var bl = typeof b.load === 'number' ? b.load : 999;
				return al - bl;
			});
			el.appendChild(E('div', { class: 'nv-srv-grp' }, (g.flag ? g.flag + ' ' : '') +
				'%s (%d)'.format(g.name, g.rows.length)));
			g.rows.forEach(L.bind(function(r) {
				var isCur = current && r.hostname === current;
				var isPin = r.hostname === chosen;
				el.appendChild(E('div', { class: 'nv-pool-row' + (isPin ? ' is-in' : ''),
					click: L.bind(function(ev) { ev.stopPropagation(); this.srvSetChosen(r.hostname); }, this) }, [
						E('span', { class: 'nv-dot ' + this.srvLoadClass(r.load) }),
						E('span', { class: 'grow' }, '%s / %s'.format(r.city || '?', r.name || r.hostname)),
						isCur ? E('span', { class: 'nv-srv-cur' }, '● ' + _('current')) : '',
						E('span', { class: 'nv-srv-load' }, r.load != null ? '%d%%'.format(r.load) : '')
					]));
			}, this));
		}, this));

		if (chosen && !this.srvRelayByHost(chosen))
			el.appendChild(E('div', { class: 'nv-pool-row is-in' }, chosen + ' ' + _('(not in the set)')));
		else if (!groups.length)
			el.appendChild(E('div', { class: 'nv-pool-row is-in' }, _('No matches')));
	},

	onHopChange: function() {
		this.markDirty();
		this.updateHopButtons();
		this.rebuildPoolWidget();
		this.refreshServerList();
	},

	updateRotationAvailability: function() {
		var fixed = this._serverChosen;
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
		var on = this.rotEnable && this.rotEnable.checked && !this._serverChosen;
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
		[ 'interface', 'routing_table', 'verify_timeout', 'max_retries', 'mtu' ].forEach(L.bind(function(k) {
			if (this.refs[k]) setv(k, (this.refs[k].value || '').trim());
		}, this));
		// The cache directory is shared and lives on the 'main' section.
		if (this.refs.cache_dir)
			setv('cache_dir', (this.refs.cache_dir.value || '').trim(), 'main');

		setv('hop_mode', this.hopMode());

		// The location set is the single source of truth; the legacy
		// country/city options are cleared so both paths agree.
		var codes = (this.poolEntries || []).map(function(e) { return e.code; });
		if (codes.length)
			uci.set('nordvpn', inst, 'locations', codes);
		else
			uci.unset('nordvpn', inst, 'locations');
		uci.unset('nordvpn', inst, 'country_code');
		uci.unset('nordvpn', inst, 'city_code');

		var fixed = this._serverChosen || '';
		setv('fixed_server', fixed);

		// Routing toggles exist only when no manual scheme was detected; a
		// manual setup's options are never written.
		if (this.autoRouting) {
			var autoOn = this.autoRouting.checked;
			var steered = autoOn ? [] : this.steeredNetworks();
			uci.set('nordvpn', inst, 'auto_routing', autoOn ? '1' : '0');
			uci.set('nordvpn', inst, 'killswitch', (this.ksBox && this.ksBox.checked) ? '1' : '0');
			uci.set('nordvpn', inst, 'block_ipv6', (this.v6Box && this.v6Box.checked) ? '1' : '0');
			uci.set('nordvpn', inst, 'vpn_dns', (this.dnsSel && this.dnsSel.value) || 'off');
			// Drop the legacy boolean so it cannot contradict the enum.
			uci.unset('nordvpn', inst, 'use_vpn_dns');
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
		// Require at least one location valid for the current hop mode; entries
		// carried over from another mode (count null) do not count.
		var validCount = (this.poolEntries || []).filter(function(e) { return e.count != null; }).length;
		if (!validCount) {
			this.notice(_('Please add at least one country or city for this hop mode.'), 'error');
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
				// Rebuild the form, not just the status band: a saved change may
				// have flipped the detected routing mode (e.g. clearing the table
				// leaves manual), and the panel's shape depends on it.
				return this.refreshStatus().then(L.bind(function() {
					dom.content(this.formNode, this.buildFormSections());
				}, this));
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
				this.rebuildPoolWidget();
				this.refreshServerList();
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
