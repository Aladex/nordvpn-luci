#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Behavioural tests for the asynchronous apply: the status file the UI polls,
// the guard that keeps two applies from overlapping, and the recovery of a
// 'running' record whose worker is gone. That last one is the whole point of
// the feature — a wedged record would make the connect button dead forever,
// and nothing else in the suite would notice.
//
// Only offline paths are exercised: the instance under test has no private
// key, so apply() fails at the credential check without touching the network.

'use strict';

import { readfile, unlink, stat } from 'fs';
const _common = require('nordvpn.common');
const _apply = require('nordvpn.apply');
const APPLY_STATUS_FILE = _common.APPLY_STATUS_FILE,
      APPLY_LOCK_FILE = _common.APPLY_LOCK_FILE,
      APPLY_MAX_RUNTIME = _common.APPLY_MAX_RUNTIME;

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) {
	let gs = sprintf('%J', g), ws = sprintf('%J', w);
	ok(l, gs == ws);
	if (gs != ws)
		printf('       got:  %s\n       want: %s\n', gs, ws);
}

// The suite shares /tmp; start from a known-clean state so the branches taken
// below are the ones under test.
unlink(APPLY_STATUS_FILE);
unlink(APPLY_LOCK_FILE);

// Our own pid is the one process guaranteed to be alive for the liveness
// checks; anything above pid_max is guaranteed not to be.
let live_pid = null;
{
	let raw = readfile('/proc/self/stat');
	if (raw)
		live_pid = int(split(trim(raw), ' ')[0]);
}
const DEAD_PID = 1073741824;

// 1. The status file round-trips and stamps updated_at, like the cache fetch
//    status it is modelled on.
{
	eq('no status file reads as null', _apply.read_apply_status(), null);
	ok('a non-object is refused', _apply.write_apply_status('nope') == false);

	let now = time();
	ok('status written', _apply.write_apply_status({ instance: 'main',
		state: 'running', started_at: _common.iso_ts(now),
		started_at_epoch: now }) == true);
	let st = _apply.read_apply_status();
	eq('status round-trips the instance', st.instance, 'main');
	eq('status round-trips the state', st.state, 'running');
	ok('status is stamped for the UI', st.updated_at != null);
	unlink(APPLY_STATUS_FILE);
}

// 2. apply_running() decides whether a 'running' record is still believable.
//    Every false branch here is a wedged connect button that recovers.
{
	let now = 1000000;
	let rec = function(extra) {
		let base = { instance: 'main', state: 'running', started_at_epoch: now };
		for (let k in extra)
			base[k] = extra[k];
		return base;
	};

	ok('a fresh record is running', _apply.apply_running(rec({}), now) == true);
	ok('a terminal record is not running',
		_apply.apply_running(rec({ state: 'done' }), now) == false);
	ok('a failed record is not running',
		_apply.apply_running(rec({ state: 'failed' }), now) == false);
	ok('a missing record is not running', _apply.apply_running(null, now) == false);
	ok('a non-object is not running', _apply.apply_running('running', now) == false);

	// Without a start stamp there is no way to age the record out, so it must
	// never be believed — otherwise a hand-written file wedges the instance.
	ok('a record without a start stamp is not running',
		_apply.apply_running({ instance: 'main', state: 'running' }, now) == false);
	ok('a record with a non-numeric start stamp is not running',
		_apply.apply_running(rec({ started_at_epoch: 'soon' }), now) == false);

	ok('a record just inside the ceiling is running',
		_apply.apply_running(rec({}), now + APPLY_MAX_RUNTIME) == true);
	ok('a record past the ceiling is not running',
		_apply.apply_running(rec({}), now + APPLY_MAX_RUNTIME + 1) == false);
	// Routers have no RTC: the clock jumps forward when NTP lands. A record
	// stamped in the future must age out too, or it would never expire.
	ok('a record stamped in the future is not running',
		_apply.apply_running(rec({ started_at_epoch: now + 3600 }), now) == false);

	// The pid is the fast recovery path: a worker killed a second ago is gone
	// long before the runtime ceiling would notice.
	ok('a record whose worker is alive is running',
		_apply.apply_running(rec({ pid: live_pid }), now) == true);
	ok('a record whose worker is gone is not running',
		_apply.apply_running(rec({ pid: DEAD_PID }), now) == false);
	// No pid (the /proc-less fallback) leaves only the age check.
	ok('a record without a pid falls back to the age check',
		_apply.apply_running(rec({ pid: null }), now) == true);
}

// 3. apply_status_report() is what the rpcd method returns. A stale 'running'
//    record must come back as a terminal failure AND be rewritten, so the UI
//    stops polling and the next start is allowed.
{
	eq('no record reports null', _apply.apply_status_report(), null);

	let now = time();
	_apply.write_apply_status({ instance: 'main', state: 'running', pid: DEAD_PID,
		started_at: _common.iso_ts(now), started_at_epoch: now,
		finished_at: null, result: null, error: null });
	let rep = _apply.apply_status_report();
	eq('a dead worker is reported as failed', rep.state, 'failed');
	eq('the failure is marked as a recovery', rep.stale, true);
	eq('the recovery explains itself', rep.error,
		'the apply worker stopped unexpectedly');
	ok('the recovery stamps a finish time', rep.finished_at != null);
	eq('the recovery is persisted', _apply.read_apply_status().state, 'failed');
	eq('the recovered record keeps its instance', rep.instance, 'main');

	// A live record is passed through untouched.
	_apply.write_apply_status({ instance: 'main', state: 'running', pid: live_pid,
		started_at: _common.iso_ts(now), started_at_epoch: now });
	eq('a live record stays running', _apply.apply_status_report().state, 'running');
	unlink(APPLY_STATUS_FILE);
}

// 4. start_apply() refuses to stack applies. It must NOT spawn a second
//    worker while one is in flight: two applies rewrite the same interface and
//    commit the same config.
{
	eq('start rejects an invalid instance name',
		_apply.start_apply('no way').error, 'invalid instance name');
	eq('start rejects a missing instance name',
		_apply.start_apply(null).error, 'invalid instance name');

	let now = time();
	_apply.write_apply_status({ instance: 'main', state: 'running', pid: live_pid,
		started_at: _common.iso_ts(now), started_at_epoch: now });
	let busy = _apply.start_apply('main');
	eq('start refuses to stack applies', busy.already_running, true);
	eq('start hands back the running record', busy.apply.instance, 'main');
	ok('start spawned nothing', busy.started == null);

	// A stale record is not a running apply: the recovery in the report is what
	// lets the user retry after a worker died.
	_apply.write_apply_status({ instance: 'main', state: 'running', pid: DEAD_PID,
		started_at: _common.iso_ts(now), started_at_epoch: now });
	ok('a stale record does not block a new apply',
		_apply.start_apply('main').already_running == null);
	unlink(APPLY_STATUS_FILE);
	unlink(APPLY_LOCK_FILE);
}

// 5. run_apply() is the worker body: it takes the lock, records the outcome
//    and releases the lock. Run against an instance with no private key, so
//    apply() fails at the credential check without any network access.
{
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings',
		interface: 'nordvpn' } }, network: {} };
	global.MOCK_UBUS = {};

	let res = _apply.run_apply('main');
	eq('the worker reports the apply failure', res.state, 'failure');
	eq('the worker names the missing credentials', res.error, 'no credentials configured');

	let st = _apply.read_apply_status();
	eq('the worker records the instance', st.instance, 'main');
	eq('a failed apply is a terminal failed state', st.state, 'failed');
	ok('the worker records a start time',
		st.started_at != null && type(st.started_at_epoch) == 'int');
	ok('the worker records a finish time',
		st.finished_at != null && type(st.finished_at_epoch) == 'int');
	eq('the worker carries the full apply result', st.result.state, 'failure');
	eq('the worker surfaces the error at the top level', st.error,
		'no credentials configured');
	eq('the finished record carries no pid', st.pid, null);
	// A finished record must not read as running, or the next apply is refused.
	ok('a finished record is not running', _apply.apply_running(st) == false);
	ok('the worker released its lock', stat(APPLY_LOCK_FILE) == null);

	// An unknown/invalid instance name falls back to 'main', like the rotation
	// worker does — the CLI must never act on a section it made up.
	eq('the worker defaults to main', _apply.run_apply('no way').error,
		'no credentials configured');
	eq('the defaulted record names main', _apply.read_apply_status().instance, 'main');
	unlink(APPLY_STATUS_FILE);
}

// 6. The lock, not the status file, is what actually serialises two workers:
//    a second worker started while the lock is held must skip and leave the
//    running apply's record alone.
{
	let token = _common.acquire_lock(APPLY_LOCK_FILE, APPLY_MAX_RUNTIME);
	ok('the apply lock is takeable', token != null);
	let now = time();
	_apply.write_apply_status({ instance: 'other', state: 'running',
		started_at: _common.iso_ts(now), started_at_epoch: now });

	let res = _apply.run_apply('main');
	eq('a second worker skips', res.skipped, true);
	eq('the second worker explains the skip', res.reason, 'apply already running');
	eq('the skipped worker did not touch the record',
		_apply.read_apply_status().instance, 'other');

	// ...but a lock left behind by a killed worker must not outlive the record
	// that proves it is dead, or the retry the user just pressed would be
	// refused for the whole runtime ceiling.
	_apply.write_apply_status({ instance: 'main', state: 'running', pid: DEAD_PID,
		started_at: _common.iso_ts(now), started_at_epoch: now });
	let after = _apply.run_apply('main');
	ok('an orphaned lock is reclaimed', after.skipped == null);
	eq('the reclaiming worker records its own run',
		_apply.read_apply_status().state, 'failed');
	ok('the reclaiming worker released the lock', stat(APPLY_LOCK_FILE) == null);

	// A record that is merely absent is NOT evidence of a dead worker: that is
	// also what a worker which took the lock a millisecond ago looks like.
	token = _common.acquire_lock(APPLY_LOCK_FILE, APPLY_MAX_RUNTIME);
	unlink(APPLY_STATUS_FILE);
	eq('a held lock with no record is left alone',
		_apply.run_apply('main').skipped, true);

	_common.release_lock(token);
	unlink(APPLY_STATUS_FILE);
}

unlink(APPLY_STATUS_FILE);
unlink(APPLY_LOCK_FILE);
printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL APPLY TESTS PASSED');
exit(fails ? 1 : 0);
