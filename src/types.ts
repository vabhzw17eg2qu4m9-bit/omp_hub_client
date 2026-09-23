/**
 * oh-my-pi ExtensionAPI surface used by this extension
 * (verified against omp's own extensions documentation).
 */

/** Per-session context handed to event handlers. */
export interface SessionCtx {
  ui?: {
    notify(text: string, level?: string): void;
    /** Footer/status-bar line; undefined clears. */
    setStatus?(key: string, text: string | undefined): void;
  };
  hasUI: boolean;
  isIdle(): boolean;
  /** Managed, error-isolated timers (omp only). Upstream pi's
   *  ExtensionContext has NO timer methods — callers must feature-detect
   * (typeof sctx.setInterval === 'function') and fall back to raw timers. */
  setInterval?(fn: () => void, ms: number): unknown;
  clearTimer?(handle: unknown): void;
}

/** Context omp passes to slash-command handlers (ui present in interactive mode). */
export interface CommandCtx {
  ui?: SessionCtx['ui'];
  hasUI?: boolean;
}

export interface SendMessageOptions {
  /** steer injects into the live turn; triggerTurn starts a turn when idle. */
  deliverAs?: 'steer' | 'followUp' | 'nextTurn';
  triggerTurn?: boolean;
}

export interface AgentToolResult {
  content: Array<{ type: 'text'; text: string }>;
  details?: unknown;
}

export interface ToolDefinition {
  name: string;
  /** Human-readable label for the UI (required by upstream pi's
   *  ToolDefinition; optional in omp). */
  label?: string;
  description: string;
  /** Plain JSON Schema ({type:'object', properties, required}). */
  parameters: Record<string, unknown>;
  execute: (
    toolCallId: string,
    params: Record<string, unknown>,
    signal?: unknown,
    onUpdate?: unknown,
    ctx?: unknown,
  ) => Promise<AgentToolResult>;
}

export interface ExtensionAPI {
  /** omp: accepts a plain string. Upstream pi: requires a CustomMessage
   *  object ({ customType, content, display, details }) — a string yields
   *  an empty custom message the model never sees. Dual-host callers must
   *  normalize (see notifyAgent in index.ts). */
  sendMessage(message: string | Record<string, unknown>, opts?: SendMessageOptions): void;
  /** Durable state: append-only entries the harness persists
   *  (customType is a namespaced string, e.g. 'io.dap.message'). */
  appendEntry(customType: string, data: unknown): void;
  on(event: string, handler: (event: unknown, ctx: SessionCtx) => void | Promise<void>): void;
  registerTool(def: ToolDefinition): void;
  /** omp: load-safe extension label — setLabel(label).
   * Upstream pi: entry-scoped setLabel(entryId, label) that THROWS when
   * called during extension loading (action-method stub). */
  setLabel(label: string): void;
  /** Optional: harness slash-command registration (omp). */
  registerCommand?(name: string, def: { description: string; handler: (args: string, cmdCtx?: CommandCtx) => string }): void;
}
