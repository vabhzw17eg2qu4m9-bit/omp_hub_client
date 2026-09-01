import test from 'node:test';
import assert from 'node:assert/strict';
import { KeepAliveWatchdog, type KeepAlivePeer, type KaTimers } from '../src/keepalive.js';

/** Fully manual timers: tests drive time, zero real waits. */
class ManualKaTimers {
  private seq = 0;
  private intervals = new Map<number, () => void>();
  private timeouts = new Map<number, () => void>();
  readonly timers: KaTimers = {
    setInterval: (fn) => {
      const id = ++this.seq;
      this.intervals.set(id, fn);
      return id;
    },
    clearInterval: (h) => void this.intervals.delete(h as number),
    setTimeout: (fn) => {
      const id = ++this.seq;
      this.timeouts.set(id, fn);
      return id;
    },
    clearTimeout: (h) => void this.timeouts.delete(h as number),
  };
  tickInterval(): void {
    for (const fn of [...this.intervals.values()]) fn();
  }
  elapseDeadlines(): void {
    for (const fn of [...this.timeouts.values()]) fn();
  }
  get pending(): number {
    return this.timeouts.size;
  }
}

/** Synchronous peer: pong (if it answers) fires DURING ping() — the hardest
 *  ordering case (deadline must be armed before ping). */
function stubPeer(answers: boolean): KeepAlivePeer & { pings: number; killed: boolean } {
  const peer = {
    pings: 0,
    killed: false,
    pongCb: undefined as (() => void) | undefined,
    ping() {
      peer.pings++;
      if (answers) peer.pongCb?.();
    },
    terminate() {
      peer.killed = true;
    },
    on(_event: 'pong', listener: () => void) {
      peer.pongCb = listener;
      return peer;
    },
  };
  return peer;
}

test('watchdog terminates a silent peer once the pong deadline elapses', () => {
  const peer = stubPeer(false); // half-open: pings out, no pong back
  const mt = new ManualKaTimers();
  const wd = new KeepAliveWatchdog({ every: 20, pongDeadline: 50 }, mt.timers);
  wd.start(peer);
  assert.ok(peer.pings >= 1, 'start pings immediately');
  assert.equal(mt.pending, 1, 'one deadline armed');
  mt.elapseDeadlines();
  assert.equal(peer.killed, true, 'dead conn is terminated');
  assert.equal(wd.terminated, true);
});

test('watchdog never terminates a peer that answers pings (sync pong ordering)', () => {
  const peer = stubPeer(true);
  const mt = new ManualKaTimers();
  const wd = new KeepAliveWatchdog({ every: 20, pongDeadline: 50 }, mt.timers);
  wd.start(peer);
  mt.tickInterval();
  mt.tickInterval();
  assert.equal(wd.pingsSent, 3, 'start + two cycles');
  assert.equal(mt.pending, 0, 'every pong cleared its deadline');
  assert.equal(peer.killed, false);
  mt.elapseDeadlines(); // nothing armed — must stay a no-op
  assert.equal(peer.killed, false);
});

test('stopped watchdog clears pending deadlines and never terminates', () => {
  const peer = stubPeer(false);
  const mt = new ManualKaTimers();
  const wd = new KeepAliveWatchdog({ every: 20, pongDeadline: 50 }, mt.timers);
  wd.start(peer);
  assert.equal(mt.pending, 1);
  wd.stop();
  assert.equal(mt.pending, 0, 'deadline disarmed');
  mt.elapseDeadlines();
  assert.equal(peer.killed, false);
});

test('watchdog re-arms on a fresh peer after terminating a dead one', () => {
  const dead = stubPeer(false);
  const mt = new ManualKaTimers();
  const wd = new KeepAliveWatchdog({ every: 20, pongDeadline: 50 }, mt.timers);
  wd.start(dead);
  mt.elapseDeadlines();
  assert.equal(dead.killed, true);
  // Reconnect: same watchdog instance, new socket — must watch again.
  const fresh = stubPeer(false);
  wd.start(fresh);
  assert.equal(fresh.pings, 1, 'fresh peer is pinged immediately');
  mt.elapseDeadlines();
  assert.equal(fresh.killed, true, 'fresh silent peer also gets terminated');
});
