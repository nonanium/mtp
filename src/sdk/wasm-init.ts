import initWasm from "mtp/raw";

type WasmInitInput = Parameters<typeof initWasm>[0];
type WasmExports = Awaited<ReturnType<typeof initWasm>>;
type WasmInitializer = (input?: WasmInitInput) => Promise<WasmExports>;

export function createWasmInitializer(
  initialize: WasmInitializer = initWasm,
): WasmInitializer {
  let wasmInitPromise: Promise<WasmExports> | undefined;

  /**
   * Keep the successful WASM singleton, but make a failed attempt retryable.
   * A rejected promise is never retained in the module cache.
   */
  return (input?: WasmInitInput): Promise<WasmExports> => {
    if (!wasmInitPromise) {
      wasmInitPromise = initialize(input).catch((error) => {
        wasmInitPromise = undefined;
        throw error;
      });
    }
    return wasmInitPromise;
  }
}

export const initWasmOnce = createWasmInitializer();
