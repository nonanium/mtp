import type { MTPRequestOptions, ParsedFrame, Unsubscribe } from "./client.js";
import type { MTPCommunicationType } from "../type-map/index.js";

export interface MTPSchema<Input = unknown, Output = Input> {
  readonly _input: Input;
  readonly _output: Output;
  parseAsync(value: unknown): Promise<Output>;
}

export interface MTPSchemaPair<
  Request extends MTPSchema = MTPSchema,
  Response extends MTPSchema = MTPSchema,
> {
  request: Request;
  response: Response;
}

export type MTPSchemaRegistry = Record<string, MTPSchemaPair>;
export type MTPNoSchemas = Record<never, never>;

export type MTPSchemaInput<Schema extends MTPSchema> = Schema["_input"];
export type MTPSchemaOutput<Schema extends MTPSchema> = Schema["_output"];
export type MTPMessageType<Registry extends MTPSchemaRegistry> =
  keyof Registry & string;

export type MTPFrame<Data = ParsedFrame["data"]> = {
  id?: number;
  type: string;
  data: Data;
  sender?: ParsedFrame["sender"];
  receiver?: ParsedFrame["receiver"];
  raw?: ParsedFrame["raw"];
};

export type MTPTypedFrame<Data = ParsedFrame["data"]> = MTPFrame<Data>;

export type MTPResponseFrame<
  Registry extends MTPSchemaRegistry,
  Type extends MTPMessageType<Registry>,
> = MTPTypedFrame<MTPSchemaOutput<Registry[Type]["response"]>>;

export type MTPRequestData<
  Registry extends MTPSchemaRegistry,
  Type extends MTPMessageType<Registry>,
> = MTPSchemaInput<Registry[Type]["request"]>;

export type MTPRequestFunction<Registry extends MTPSchemaRegistry> = <
  Type extends MTPMessageType<Registry>,
>(
  type: Type,
  data?: MTPRequestData<Registry, Type>,
  options?: MTPRequestOptions,
) => Promise<MTPResponseFrame<Registry, Type>>;

export type MTPSubscriptionFunction<Registry extends MTPSchemaRegistry> = <
  Type extends MTPMessageType<Registry>,
>(
  type: Type,
  handler: (message: MTPResponseFrame<Registry, Type>) => void | Promise<void>,
) => Unsubscribe;

export class MTPValidationError extends Error {
  readonly phase: "request" | "response" | "subscription";
  readonly messageType: string;
  readonly frame?: MTPFrame;

  constructor(
    phase: MTPValidationError["phase"],
    messageType: string,
    cause: unknown,
    frame?: MTPFrame,
  ) {
    super(`${phase} validation failed for ${messageType}`, { cause });
    this.name = "MTPValidationError";
    this.phase = phase;
    this.messageType = messageType;
    this.frame = frame;
  }
}

export class MTPProtocolError extends Error {
  readonly type: string;
  readonly id: number | undefined;
  readonly communicationType: string;
  readonly requestId: number | undefined;
  readonly errorType: string | undefined;
  readonly frame: MTPFrame;

  constructor(frame: MTPFrame) {
    const errorType =
      frame.data &&
      typeof frame.data === "object" &&
      !Array.isArray(frame.data) &&
      typeof (frame.data as Record<string, unknown>).ErrorType === "string"
        ? ((frame.data as Record<string, unknown>).ErrorType as string)
        : undefined;
    super(errorType ? `${frame.type}: ${errorType}` : frame.type);
    this.name = "MTPProtocolError";
    this.type = frame.type;
    this.id = frame.id;
    this.communicationType = frame.type;
    this.requestId = frame.id;
    this.errorType = errorType;
    this.frame = frame;
  }
}

export interface MTPProtocolOptions<Registry extends MTPSchemaRegistry> {
  schemas: Registry;
  throwProtocolErrors?: boolean;
  onValidationError?: (error: MTPValidationError) => void;
}

function isErrorFrame(frame: MTPFrame): boolean {
  return frame.type.startsWith("Error");
}

export class MTPProtocol<Registry extends MTPSchemaRegistry> {
  readonly schemas: Registry;
  readonly #throwProtocolErrors: boolean;
  readonly #onValidationError:
    | ((error: MTPValidationError) => void)
    | undefined;

  constructor(options: MTPProtocolOptions<Registry>) {
    this.schemas = options.schemas;
    this.#throwProtocolErrors = options.throwProtocolErrors ?? false;
    this.#onValidationError = options.onValidationError;
  }

  async parseRequest<Type extends MTPMessageType<Registry>>(
    type: Type,
    data: MTPRequestData<Registry, Type> | undefined,
  ): Promise<MTPSchemaOutput<Registry[Type]["request"]>> {
    try {
      return await this.schemas[type].request.parseAsync(data);
    } catch (error) {
      throw new MTPValidationError("request", type, error);
    }
  }

  async parseResponse<Type extends MTPMessageType<Registry>>(
    requestedType: Type,
    frame: MTPFrame,
    phase: "response" | "subscription" = "response",
  ): Promise<MTPResponseFrame<Registry, Type>> {
    if (isErrorFrame(frame)) {
      if (phase === "response" && this.#throwProtocolErrors) {
        throw new MTPProtocolError(frame);
      }
      return frame as MTPResponseFrame<Registry, Type>;
    }

    const schema =
      this.schemas[frame.type]?.response ??
      this.schemas[requestedType].response;
    try {
      const data = await schema.parseAsync(frame.data);
      return { ...frame, data } as MTPResponseFrame<Registry, Type>;
    } catch (error) {
      throw new MTPValidationError(
        phase,
        frame.type || requestedType,
        error,
        frame,
      );
    }
  }

  reportValidationError(error: unknown): void {
    if (error instanceof MTPValidationError) {
      this.#onValidationError?.(error);
    }
  }
}

export interface MTPProxyAdapter {
  request(
    type: MTPCommunicationType,
    data: Record<string, unknown>,
    options?: MTPRequestOptions,
  ): Promise<MTPFrame>;
  subscribe(
    type: MTPCommunicationType,
    handler: (message: MTPFrame) => void,
  ): Unsubscribe;
}

export class MTPProxyConnection<Registry extends MTPSchemaRegistry> {
  readonly #adapter: MTPProxyAdapter;
  readonly #protocol: MTPProtocol<Registry>;

  constructor(adapter: MTPProxyAdapter, options: MTPProtocolOptions<Registry>) {
    this.#adapter = adapter;
    this.#protocol = new MTPProtocol(options);
  }

  async request<Type extends MTPMessageType<Registry>>(
    type: Type,
    data?: MTPRequestData<Registry, Type>,
    options?: MTPRequestOptions,
  ): Promise<MTPResponseFrame<Registry, Type>> {
    const parsed = await this.#protocol.parseRequest(type, data);
    const response = await this.#adapter.request(
      type,
      (parsed ?? {}) as Record<string, unknown>,
      options,
    );
    return await this.#protocol.parseResponse(type, response);
  }

  subscribe<Type extends MTPMessageType<Registry>>(
    type: Type,
    handler: (
      message: MTPResponseFrame<Registry, Type>,
    ) => void | Promise<void>,
  ): Unsubscribe {
    let active = true;
    const unsubscribe = this.#adapter.subscribe(type, (message) => {
      void this.#protocol.parseResponse(type, message, "subscription").then(
        (parsed) => {
          if (active) void handler(parsed);
        },
        (error) => {
          this.#protocol.reportValidationError(error);
        },
      );
    });
    return () => {
      active = false;
      unsubscribe();
    };
  }
}
