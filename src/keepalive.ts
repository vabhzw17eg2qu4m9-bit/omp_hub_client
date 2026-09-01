// keepalive.ts — client-side liveness watchdog.
//
// A DAP client that sends nothing while idle cannot tell a live hub from a
// half-open connection (laptop sleep, NAT/tunnel timeout): sends buffer
// silently into a dead socket. The watchdog pings the hub every `every` ms
// and expects a pong within `pongDeadline`; a miss terminates the socket so
// the reconnect loop takes over (re-hello, flush, re-join) BEFORE the user
// tries to talk through a corpse.

export interface KeepAliveOptions {
  every: number;
  pongDeadline: number;
}

export const DEFAULT_KEEP_ALIVE: KeepAliveOptions = { every: 20_000, pongDeadline: 10_000 };

/** Minimal peer surface the watchdog needs (both satisfied by ws.WebSocket). */
export interface KeepAlivePeer {
  ping(): void;
  terminate(): void;
  on(event: 'pong', listener: () => void): unknown;
}

export interface KaTimers {
  setInterval(fn: () => void, ms: number): unknown;
  clearInterval(handle: unknown): void;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

const nativeTimers: KaTimers = {
  setInterval: (fn, ms) => {
    const t = setInterval(fn, ms);
    (t as NodeJS.Timeout).unref?.();
    return t;
  },
  clearInterval: (h) => clearInterval(h as NodeJS.Timeout),
  setTimeout: (fn, ms) => {
    const t = setTimeout(fn, ms);
    (t as NodeJS.Timeout).unref?.();
    return t;
  },
  clearTimeout: (h) => clearTimeout(h as NodeJS.Timeout),
};

export class KeepAliveWatchdog {
  pingsSent = 0;
  terminated = false;

  private interval: unknown;
  private deadline: unknown;
  private awaitingPong = false;

  constructor(
    private readonly opts: KeepAliveOptions,
    private readonly timers: KaTimers = nativeTimers,
  ) {}

  start(peer: KeepAlivePeer): void {
    this.stop();
    // A previous incarnation may have terminated its peer; the fresh socket
    // deserves a fresh verdict (without this, connections after one
    // watchdog-terminated reconnect would never be watched again).
    this.terminated = false;
    peer.on('pong', () => {
      this.awaitingPong = false;
      if (this.deadline !== undefined) this.timers.clearTimeout(this.deadline);
      this.deadline = undefined;
    });
    this.interval = this.timers.setInterval(() => this.tick(peer), this.opts.every);
    this.tick(peer);
  }

  stop(): void {
    if (this.interval !== undefined) this.timers.clearInterval(this.interval);
    if (this.deadline !== undefined) this.timers.clearTimeout(this.deadline);
    this.interval = undefined;
    this.deadline = undefined;
    this.awaitingPong = false;
  }

  private tick(peer: KeepAlivePeer): void {
    if (this.terminated || this.awaitingPong) return;
    this.awaitingPong = true;
    // Arm the deadline BEFORE ping(): a synchronous pong must be able to
    // clear it, or a perfectly live peer gets terminated one deadline later.
    this.deadline = this.timers.setTimeout(() => {
      this.terminated = true;
      this.stop();
      peer.terminate();
    }, this.opts.pongDeadline);
    this.pingsSent++;
    peer.ping();
  }
}
