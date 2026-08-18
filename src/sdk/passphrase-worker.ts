import initWasm, * as bindings from "mtp/raw";

interface PasswordKdfWorkerRequest {
  passphrase: Uint8Array;
  salt: Uint8Array;
  parameters: {
    memoryKiB: number;
    iterations: number;
    lanes: number;
  };
}

const scope = globalThis as unknown as {
  onmessage: ((event: MessageEvent<PasswordKdfWorkerRequest>) => void) | null;
  postMessage(message: Uint8Array | { error: string }, transfer?: Transferable[]): void;
};

scope.onmessage = async (event) => {
  try {
    await initWasm();
    const { passphrase, salt, parameters } = event.data;
    const key = bindings.wasm_argon2id(
      passphrase,
      salt,
      parameters.memoryKiB,
      parameters.iterations,
      parameters.lanes,
    );
    scope.postMessage(key, [key.buffer]);
  } catch (error) {
    scope.postMessage({ error: String(error) });
  }
};
