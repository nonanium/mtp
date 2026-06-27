import init, {
  WasmClient,
  ConnectionConfig,
  ConnectionState,
  WasmKeyring,
  ed25519_generate,
  keyring_from_ed25519,
  build_demo_message,
  format_frame,
} from "mtp-wasm";

const STATUS = document.getElementById("status")!;
const KEY_STATUS = document.getElementById("key-status")!;
const SERVER_URL = document.getElementById("server-url") as HTMLInputElement;
const HOST_PUBLIC_KEY = document.getElementById("host-public-key") as HTMLTextAreaElement;
const CLIENT_PUBLIC_KEY = document.getElementById("client-public-key") as HTMLTextAreaElement;
const GENERATE_KEYPAIR = document.getElementById("generate-keypair") as HTMLButtonElement;
const CONNECT = document.getElementById("connect") as HTMLButtonElement;
const CLEAR_KEYS = document.getElementById("clear-keys") as HTMLButtonElement;

const STORAGE_KEY = "mtp-web-client-keys";

type SavedKeys = {
  clientId: string | null;
  keyring: number[];
  hostPublicKey?: number[];
};

let keyringBytes: Uint8Array | null = null;
let clientId: bigint | null = null;
let devCertHash = "";

function log(msg: string, cls = "") {
  const line = document.createElement("div");
  line.textContent = msg;
  if (cls) line.className = cls;
  STATUS.appendChild(line);
}

function setKeyStatus(msg: string) {
  KEY_STATUS.textContent = msg;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value: string): Uint8Array {
  const hex = value.replace(/[^0-9a-fA-F]/g, "");
  if (hex.length === 0) throw new Error("host public key is required");
  if (hex.length % 2 !== 0) throw new Error("host public key hex has an odd length");

  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function saveKeys() {
  if (!keyringBytes) {
    return;
  }

  let hostPublicKey: number[] | undefined;
  try {
    hostPublicKey = Array.from(hexToBytes(HOST_PUBLIC_KEY.value));
  } catch {
    hostPublicKey = undefined;
  }

  const data: SavedKeys = {
    clientId: clientId?.toString() ?? null,
    keyring: Array.from(keyringBytes),
    hostPublicKey,
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
}

function loadKeys() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    setKeyStatus("No client keypair generated yet.");
    return;
  }

  const data = JSON.parse(raw) as SavedKeys;
  keyringBytes = new Uint8Array(data.keyring);
  clientId = data.clientId ? BigInt(data.clientId) : null;
  CLIENT_PUBLIC_KEY.value = publicKeyHexFromKeyring(keyringBytes);
  if (data.hostPublicKey) {
    HOST_PUBLIC_KEY.value = bytesToHex(new Uint8Array(data.hostPublicKey));
  }

  setKeyStatus(
    clientId
      ? `Loaded saved client keypair for client ${clientId}.`
      : "Loaded generated client keypair. Not registered yet.",
  );
}

async function loadHostPublicKey() {
  try {
    const response = await fetch("/host_public_key_bundle.hex", { cache: "no-store" });
    if (!response.ok) return;

    const hostPublicKey = (await response.text()).trim();
    if (!hostPublicKey) return;

    HOST_PUBLIC_KEY.value = hostPublicKey;
    saveKeys();
    log(`Loaded host public key bundle (${hostPublicKey.length / 2} bytes).`);
  } catch {
    // Manual paste still works when the server has not exported the file yet.
  }
}

async function loadDevCertHash() {
  try {
    const response = await fetch("/mtp_dev_cert_hash.txt", { cache: "no-store" });
    if (!response.ok) return;

    devCertHash = (await response.text()).trim();
    if (devCertHash) {
      log(`Loaded WebTransport certificate hash: ${devCertHash}`);
    }
  } catch {
    devCertHash = "";
  }
}

async function initWasm() {
  log("Loading WASM module...");
  await init();
  log(`WASM loaded. WebTransport supported: ${WasmClient.is_supported()}`);
  CONNECT.disabled = !WasmClient.is_supported();
}

function createClient(): WasmClient {
  return new WasmClient(
    (state: number) =>
      log(`[state] ${ConnectionState[state] ?? state}`, "state"),
    (data: Uint8Array) => {
      try {
        log(`Received: ${format_frame(data)}`, "received");
      } catch (e) {
        log(`[message parse error] ${e}`, "error");
      }
    },
    (err: any) => log(`[error] ${err}`, "error"),
  );
}

function generateKeyringBytes(): Uint8Array {
  const gen = ed25519_generate();
  const sk = gen.secretKey as Uint8Array;
  const pk = gen.publicKey as Uint8Array;
  gen.signer.free();
  return keyring_from_ed25519(sk, pk);
}

function publicKeyHexFromKeyring(bytes: Uint8Array): string {
  const keyring = WasmKeyring.from_bytes(bytes);
  const publicBundle = keyring.public_key_bundle();
  const publicHex = bytesToHex(publicBundle.to_bytes());
  publicBundle.free();
  keyring.free();
  return publicHex;
}

async function connect() {
  STATUS.textContent = "";

  if (!WasmClient.is_supported()) {
    log("WebTransport is not supported in this browser.", "error");
    return;
  }
  if (!keyringBytes) {
    log("Generate a client keypair first.", "error");
    return;
  }

  const hostPk = hexToBytes(HOST_PUBLIC_KEY.value);
  await loadDevCertHash();

  const client = createClient();
  const serverUrl = SERVER_URL.value.trim();
  const config = new ConnectionConfig(serverUrl);
  if (devCertHash) {
    log(`Pinning WebTransport certificate hash: sha-256:${devCertHash}`);
    config.server_certificate_hashes = [`sha-256:${devCertHash}`];
  } else {
    log("No WebTransport certificate hash loaded; relying on browser trust store.", "state");
  }

  try {
    let activeClientId: bigint;
    if (clientId !== null) {
      log(`Using saved client ID ${clientId}...`);
      activeClientId = await client.auth_connect(
        config,
        hostPk,
        keyringBytes,
        clientId,
      );
      log(`Authenticated as client ${activeClientId}`);
    } else {
      log("Registering generated client keypair...");
      activeClientId = await client.auth_register(config, hostPk, keyringBytes);
      clientId = activeClientId;
      saveKeys();
      log(`Registered with ID: ${activeClientId}`);
    }

    log("\nSending demo message...");
    const frame = build_demo_message(activeClientId, keyringBytes, hostPk);
    log(`Sending: ${format_frame(frame)}`, "state");
    await client.send(frame);
    log(`Sent ${frame.length} bytes`);

    log("\nClient running. Waiting for incoming messages...");
  } finally {
    config.free();
  }
}

GENERATE_KEYPAIR.addEventListener("click", () => {
  try {
    keyringBytes = generateKeyringBytes();
    clientId = null;
    saveKeys();
    CLIENT_PUBLIC_KEY.value = publicKeyHexFromKeyring(keyringBytes);
    setKeyStatus("Generated client keypair. Not registered yet.");
    log("Generated and saved a new client keypair.");
  } catch (e) {
    log(`Key generation failed: ${e}`, "error");
    console.error(e);
  }
});

CONNECT.addEventListener("click", () => {
  connect().catch((e) => {
    log(`Fatal error: ${e}`, "error");
    log(
      `[fatal context] clientId=${clientId?.toString() ?? "unregistered"}, server=${SERVER_URL.value.trim()}, hostPkChars=${HOST_PUBLIC_KEY.value.replace(/[^0-9a-fA-F]/g, "").length}, keyringBytes=${keyringBytes?.length ?? 0}, certHash=${devCertHash || "none"}`,
      "error",
    );
    console.error(e);
  });
});

CLEAR_KEYS.addEventListener("click", () => {
  keyringBytes = null;
  clientId = null;
  CLIENT_PUBLIC_KEY.value = "";
  localStorage.removeItem(STORAGE_KEY);
  setKeyStatus("No client keypair generated yet.");
  log("Cleared saved client keys.");
});

HOST_PUBLIC_KEY.addEventListener("change", saveKeys);

initWasm()
  .then(() => {
    loadKeys();
    return Promise.all([loadHostPublicKey(), loadDevCertHash()]);
  })
  .catch((e) => {
    log(`Fatal error: ${e}`, "error");
    console.error(e);
  });
