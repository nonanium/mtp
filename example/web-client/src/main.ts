import { MTPClient } from "mtp";
import type { MTPCredentialStorage, MTPLogEvent, ParsedFrame } from "mtp";

const STATUS = document.getElementById("status")!;
const KEY_STATUS = document.getElementById("key-status")!;
const SERVER_URL = document.getElementById("server-url") as HTMLInputElement;
const HOST_PUBLIC_KEY = document.getElementById("host-public-key") as HTMLTextAreaElement;
const CLIENT_CREDENTIALS = document.getElementById("client-credentials") as HTMLTextAreaElement;
const GENERATE_KEYPAIR = document.getElementById("generate-keypair") as HTMLButtonElement;
const CONNECT = document.getElementById("connect") as HTMLButtonElement;
const CLEAR_KEYS = document.getElementById("clear-keys") as HTMLButtonElement;

const CREDENTIALS_KEY = "mtp-web-client-credentials";
const HOST_PUBLIC_KEY_KEY = "mtp-web-client-host-public-key";

type SavedKeys = {
  clientId: string | null;
  keyring?: number[];
  keyringBytes?: number[];
  hostPublicKey?: number[];
};

let clientId: bigint | null = null;
let devCertHash = "";

const credentialStorage: MTPCredentialStorage = {
  getItem: (key) => localStorage.getItem(key),
  setItem: (key, value) => localStorage.setItem(key, value),
  removeItem: (key) => localStorage.removeItem(key),
};

function log(msg: string, cls = "") {
  const line = document.createElement("div");
  line.textContent = msg;
  if (cls) line.className = cls;
  STATUS.appendChild(line);
}

function renderStructured(value: unknown): string {
  return JSON.stringify(value, (_key, item) => {
    if (typeof item === "bigint") {
      return item.toString();
    }
    if (item instanceof Uint8Array) {
      return { bytes: item.length, hex: bytesToHex(item.slice(0, 32)) };
    }
    return item;
  });
}

function formatParsedFrame(frame: ParsedFrame): string {
  return renderStructured({
    id: frame.id,
    type: frame.type,
    sender: frame.sender,
    receiver: frame.receiver,
    data: frame.data,
    rawBytes: frame.raw.length,
  });
}

function renderLoggerEvent(event: MTPLogEvent): string {
  return event.hint === "error"
    ? `[${event.hint}] ${event.type}: ${event.error}`
    : `[${event.hint}] ${event.type}: ${renderStructured(event.data)}`;
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

function saveHostPublicKey() {
  try {
    localStorage.setItem(HOST_PUBLIC_KEY_KEY, bytesToHex(hexToBytes(HOST_PUBLIC_KEY.value)));
  } catch {
    localStorage.removeItem(HOST_PUBLIC_KEY_KEY);
  }
}

function loadKeys() {
  const raw = localStorage.getItem(CREDENTIALS_KEY);
  const savedHostPublicKey = localStorage.getItem(HOST_PUBLIC_KEY_KEY);
  if (savedHostPublicKey) {
    HOST_PUBLIC_KEY.value = savedHostPublicKey;
  }

  if (!raw) {
    CLIENT_CREDENTIALS.value = "";
    setKeyStatus("No saved SDK credentials. The next connection will generate and store a reusable keyring.");
    return;
  }

  const data = JSON.parse(raw) as SavedKeys;
  clientId = data.clientId ? BigInt(data.clientId) : null;
  const keyringLength = (data.keyring ?? data.keyringBytes ?? []).length;
  CLIENT_CREDENTIALS.value = renderStructured({
    clientId: data.clientId,
    keyringBytes: keyringLength,
    hostPublicKeyBytes: data.hostPublicKey?.length ?? 0,
  });
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
    saveHostPublicKey();
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
  await MTPClient.create({ url: SERVER_URL.value, storage: credentialStorage, credentialsStorageKey: CREDENTIALS_KEY });
  const supported = MTPClient.isSupported();
  log(`WASM loaded. WebTransport supported: ${supported}`);
  CONNECT.disabled = !supported;
}

async function connect() {
  STATUS.textContent = "";

  if (!MTPClient.isSupported()) {
    log("WebTransport is not supported in this browser.", "error");
    return;
  }
  const hostPk = hexToBytes(HOST_PUBLIC_KEY.value);
  saveHostPublicKey();
  await loadDevCertHash();

  const serverUrl = SERVER_URL.value.trim();
  const serverCertificateHashes = devCertHash ? [`sha-256:${devCertHash}`] : undefined;
  if (serverCertificateHashes) {
    log(`Pinning WebTransport certificate hash: ${serverCertificateHashes[0]}`);
  } else {
    log("No WebTransport certificate hash loaded; relying on browser trust store.", "state");
  }

  try {
    const client = await MTPClient.create({
      url: serverUrl,
      hostPublicKey: hostPk,
      storage: credentialStorage,
      credentialsStorageKey: CREDENTIALS_KEY,
      serverCertificateHashes,
      pings: { intervalMs: 30_000 },
      logger(event) {
        log(renderLoggerEvent(event), event.hint === "error" ? "error" : event.type === "state" ? "state" : "");
      },
    });

    client.subscribe("Pong", (frame: ParsedFrame) => {
      log(`Subscribed Pong: ${formatParsedFrame(frame)}`, "received");
    });

    const activeClientId = await client.auth();
    clientId = activeClientId;
    loadKeys();
    log(`Connected as client ${activeClientId}`);

    log("\nSending typed Ping...");
    await client.send("Ping", {
      Description: "MTP web client send ping",
      Timestamp: BigInt(Date.now()),
    }, { sender: activeClientId });
    log("Typed Ping sent.");

    log("\nRequesting Pong by Ping frame id...");
    const response = await client.request("Ping", {
      Description: "MTP web client request ping",
      Timestamp: BigInt(Date.now()),
    }, { sender: activeClientId, responseType: "Pong" });
    log(`Request response: ${formatParsedFrame(response)}`, "received");

    log("\nClient running. Waiting for incoming messages...");
  } catch (error) {
    log(`[error] ${error}`, "error");
  }
}

GENERATE_KEYPAIR.addEventListener("click", () => {
  try {
    clientId = null;
    localStorage.removeItem(CREDENTIALS_KEY);
    CLIENT_CREDENTIALS.value = "";
    setKeyStatus("Cleared saved credentials. The next connection will generate a new reusable keyring.");
    log("Cleared saved SDK credentials.");
  } catch (e) {
    log(`Credential reset failed: ${e}`, "error");
    console.error(e);
  }
});

CONNECT.addEventListener("click", () => {
  connect().catch((e) => {
    log(`Fatal error: ${e}`, "error");
    log(
      `[fatal context] clientId=${clientId?.toString() ?? "unregistered"}, server=${SERVER_URL.value.trim()}, hostPkChars=${HOST_PUBLIC_KEY.value.replace(/[^0-9a-fA-F]/g, "").length}, hasStoredCredentials=${localStorage.getItem(CREDENTIALS_KEY) ? "yes" : "no"}, certHash=${devCertHash || "none"}`,
      "error",
    );
    console.error(e);
  });
});

CLEAR_KEYS.addEventListener("click", () => {
  clientId = null;
  CLIENT_CREDENTIALS.value = "";
  localStorage.removeItem(CREDENTIALS_KEY);
  localStorage.removeItem(HOST_PUBLIC_KEY_KEY);
  setKeyStatus("No saved SDK credentials.");
  log("Cleared saved SDK credentials and host public key.");
});

HOST_PUBLIC_KEY.addEventListener("change", saveHostPublicKey);

initWasm()
  .then(() => {
    loadKeys();
    return Promise.all([loadHostPublicKey(), loadDevCertHash()]);
  })
  .catch((e) => {
    log(`Fatal error: ${e}`, "error");
    console.error(e);
  });
