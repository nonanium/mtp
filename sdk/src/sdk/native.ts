import type * as Raw from "../raw/index.js";
import { communicationError } from "./communication-error.js";
import { protectedOpeningError } from "./protection.js";
import { relayOpeningError } from "./relay.js";

type Internals = {
  invoke<T>(command: string, args?: Record<string, unknown>): Promise<T>;
  transformCallback(callback: (event: { payload: unknown }) => void, once?: boolean): number;
  unregisterCallback(id: number): void;
};

export function androidTauri(): Internals | undefined {
  const runtime = globalThis as typeof globalThis & { __TAURI_INTERNALS__?: Internals };
  return typeof navigator !== "undefined" && /Android/i.test(navigator.userAgent)
    ? runtime.__TAURI_INTERNALS__
    : undefined;
}

export class NativeTransport {
  clientId: bigint | null = null;
  publicKeys = new Uint8Array();
  state = 0;
  ping_ms: number | null = null;
  readonly subscriptions = new Map<number, { type: string; handler: (frame: Raw.ParsedFrame) => void }>();
  #nextSubscription = 0;
  #callback?: number;
  #eventId?: number;
  #listening = false;
  #listenPromise?: Promise<void>;
  #generation = 0;
  #pipeHandler: ((request: unknown) => void) | null = null;
  readonly attachmentId = globalThis.crypto.randomUUID();

  constructor(
    readonly runtime: Internals,
    readonly name: string,
    readonly parse: (bytes: Uint8Array) => Raw.ParsedFrame,
    readonly onFrame: (frame: Raw.ParsedFrame) => void,
    readonly report: (error: unknown) => void,
  ) {}

  async call<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
    try {
      return await this.runtime.invoke<T>(`plugin:mtp|mtp_${command}`, { name: this.name, ...args });
    } catch (error) {
      if (command.includes("relay") && command !== "release_relay") throw relayOpeningError(error);
      if (command.includes("protected") || command === "protected_claimed_signer") throw protectedOpeningError(error);
      throw communicationError(error);
    }
  }

  async initialize(options: Record<string, unknown>): Promise<void> {
    const identity = await this.call<{ clientId: string | null; publicKeys: number[] }>("initialize", { options });
    this.clientId = identity.clientId == null ? null : BigInt(identity.clientId);
    this.publicKeys = Uint8Array.from(identity.publicKeys);
    await this.listen();
  }

  private async listen(): Promise<void> {
    if (this.#listenPromise) return this.#listenPromise;
    const promise = this.startListening();
    this.#listenPromise = promise;
    try { await promise; } finally { if (this.#listenPromise === promise) this.#listenPromise = undefined; }
  }

  private async startListening(): Promise<void> {
    if (this.#listening) return;
    const generation = this.#generation;
    this.#callback = this.runtime.transformCallback((event) => {
      const [name, value] = event.payload as [string, number[] | { pipeId: number; description: string }];
      if (name !== this.name) return;
      try {
        if (!Array.isArray(value)) { this.#pipeHandler?.(value); return; }
        const frame = this.parse(Uint8Array.from(value));
        this.onFrame(frame);
        for (const subscription of this.subscriptions.values()) {
          if (subscription.type === frame.type) subscription.handler(frame);
        }
      } catch (error) { this.report(error); }
    });
    try {
      const eventId = await this.runtime.invoke<number>("plugin:event|listen", {
        event: "mtp://event", target: { kind: "Any" }, handler: this.#callback,
      });
      if (generation !== this.#generation) {
        await this.runtime.invoke("plugin:event|unlisten", { event: "mtp://event", eventId });
        return;
      }
      this.#eventId = eventId;
      this.#listening = true;
    } catch (error) {
      this.runtime.unregisterCallback(this.#callback);
      throw error;
    }
  }

  async connect(mode: "connect" | "unauthenticated" | "auth" | "register"): Promise<bigint> {
    const generation = this.#generation;
    await this.listen();
    const result = await this.call<{ clientId: string; state: number }>("connect", { mode });
    if (generation !== this.#generation) throw new Error("native view was disposed during connection");
    this.clientId = BigInt(result.clientId);
    this.state = result.state;
    await this.call("attach", { attachmentId: this.attachmentId });
    return this.clientId;
  }

  send(bytes: Uint8Array): Promise<void> { return this.call("send", { bytes: Array.from(bytes) }); }
  async request(bytes: Uint8Array, responseType: string | null, deadlineMs: number): Promise<Raw.ParsedFrame> {
    const response = await this.call<number[]>("request", { bytes: Array.from(bytes), responseType, deadlineMs });
    return this.parse(Uint8Array.from(response));
  }
  subscribe(type: string, handler: (frame: Raw.ParsedFrame) => void): number {
    const id = ++this.#nextSubscription;
    this.subscriptions.set(id, { type, handler });
    return id;
  }
  unsubscribe(id: number): void { this.subscriptions.delete(id); }
  set_on_pipe_request(handler: ((request: unknown) => void) | null): void { this.#pipeHandler = handler; }
  stop_protocol_pings(): void {}
  disconnect(): void {
    this.#generation += 1;
    this.state = 0;
    void this.call("detach", { attachmentId: this.attachmentId }).catch(this.report);
    if (this.#eventId != null) {
      void this.runtime.invoke("plugin:event|unlisten", { event: "mtp://event", eventId: this.#eventId }).catch(this.report);
    }
    if (this.#callback != null) this.runtime.unregisterCallback(this.#callback);
    this.#callback = undefined;
    this.#eventId = undefined;
    this.#listening = false;
  }
}

/** IPC values are explicit. DataValue payloads cross as encoded bytes, never JSON numbers. */
export function nativeOptions(value: unknown): unknown {
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Uint8Array) return Array.from(value);
  if (Array.isArray(value)) return value.map(nativeOptions);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).filter(([, item]) => typeof item !== "function" && item !== undefined).map(([key, item]) => [key, nativeOptions(item)]));
  }
  return value;
}
