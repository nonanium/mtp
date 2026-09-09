import type { ParsedFrame } from "./client.js";

/** Controls bounded execution of a subscription handler. */
export interface MTPSubscriptionOptions {
  /** Maximum handlers running at once. Defaults to one. */
  concurrency?: number;
  /** Maximum messages waiting for a handler. Defaults to 64. */
  queueCapacity?: number;
  /** Receives handler failures and queue-overflow failures. */
  onError?: (error: unknown, frame: ParsedFrame) => void;
}

/** Identifies a subscription failure caused by the dispatcher itself. */
export class MTPSubscriptionError extends Error {
  readonly code: "queue-overflow";

  constructor(queueCapacity: number) {
    super(`subscription queue capacity (${queueCapacity}) exceeded`);
    this.name = "MTPSubscriptionError";
    this.code = "queue-overflow";
  }
}

export type MTPSubscriptionHandler<T> = (message: T) => void | Promise<void>;

interface SubscriptionDispatcherOptions<T> {
  handler: MTPSubscriptionHandler<T>;
  concurrency?: number;
  queueCapacity?: number;
  reportError: (error: unknown, frame: ParsedFrame) => void;
  onOverflow: () => void;
}

interface QueuedMessage<T> {
  message: T;
  frame: ParsedFrame;
}

const DEFAULT_CONCURRENCY = 1;
const DEFAULT_QUEUE_CAPACITY = 64;

function positiveSafeInteger(
  value: number | undefined,
  fallback: number,
  name: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 1) {
    throw new TypeError(`${name} must be a positive safe integer`);
  }
  return resolved;
}

/**
 * A bounded, per-subscription work queue. Closing discards queued messages;
 * handlers already running are allowed to settle because JavaScript promises
 * cannot be cancelled safely without an explicit cancellation API.
 */
export class SubscriptionDispatcher<T> {
  readonly #handler: MTPSubscriptionHandler<T>;
  readonly #concurrency: number;
  readonly #queueCapacity: number;
  readonly #reportError: (error: unknown, frame: ParsedFrame) => void;
  readonly #onOverflow: () => void;
  readonly #queue: QueuedMessage<T>[] = [];
  #active = true;
  #running = 0;

  constructor(options: SubscriptionDispatcherOptions<T>) {
    this.#handler = options.handler;
    this.#concurrency = positiveSafeInteger(
      options.concurrency,
      DEFAULT_CONCURRENCY,
      "subscription concurrency",
    );
    this.#queueCapacity = positiveSafeInteger(
      options.queueCapacity,
      DEFAULT_QUEUE_CAPACITY,
      "subscription queueCapacity",
    );
    this.#reportError = options.reportError;
    this.#onOverflow = options.onOverflow;
  }

  enqueue(message: T, frame: ParsedFrame): void {
    if (!this.#active) return;
    if (this.#queue.length >= this.#queueCapacity) {
      this.#active = false;
      this.#queue.length = 0;
      this.#reportError(new MTPSubscriptionError(this.#queueCapacity), frame);
      this.#onOverflow();
      return;
    }
    this.#queue.push({ message, frame });
    this.#drain();
  }

  close(): void {
    this.#active = false;
    this.#queue.length = 0;
  }

  #drain(): void {
    while (this.#active && this.#running < this.#concurrency) {
      const next = this.#queue.shift();
      if (!next) return;
      this.#running += 1;
      void this.#run(next);
    }
  }

  async #run(next: QueuedMessage<T>): Promise<void> {
    try {
      if (this.#active) await this.#handler(next.message);
    } catch (error) {
      this.#reportError(error, next.frame);
    } finally {
      this.#running -= 1;
      this.#drain();
    }
  }
}
