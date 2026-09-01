export interface InboxEntry {
  id: string;
  ts: number;
  from: string;
  channel?: string;
  dm: boolean;
  text: string;
}

/** Bounded inbox (cap 100, omp IrcBus precedent) with optional durable sink. */
export class Inbox {
  private entries: InboxEntry[] = [];

  constructor(
    private readonly cap = 100,
    private readonly persist?: (entry: InboxEntry) => void,
  ) {}

  add(entry: InboxEntry): InboxEntry {
    this.persist?.(entry);
    this.entries.push(entry);
    if (this.entries.length > this.cap) this.entries.shift();
    return entry;
  }

  /** Latest-first, optionally filtered to one channel. */
  list(limit = 20, channel?: string): InboxEntry[] {
    const hits = channel ? this.entries.filter((e) => e.channel === channel) : this.entries;
    return hits.slice(-limit).reverse();
  }

  get size(): number {
    return this.entries.length;
  }
}
