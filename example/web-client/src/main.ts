import { MTPClient } from "mtp";
import type {
  MTPCredentialStorage,
  MTPLogEvent,
  MTPPipeReader,
  MTPPipeWriter,
  ParsedFrame,
} from "mtp";

const STATUS = document.getElementById("status")!;
const KEY_STATUS = document.getElementById("key-status")!;
const SERVER_URL = document.getElementById("server-url") as HTMLInputElement;
const HOST_PUBLIC_KEY = document.getElementById(
  "host-public-key",
) as HTMLTextAreaElement;
const CLIENT_CREDENTIALS = document.getElementById(
  "client-credentials",
) as HTMLTextAreaElement;
const GENERATE_KEYPAIR = document.getElementById(
  "generate-keypair",
) as HTMLButtonElement;
const CONNECT = document.getElementById("connect") as HTMLButtonElement;
const CLEAR_KEYS = document.getElementById("clear-keys") as HTMLButtonElement;
const STREAM_MIC = document.getElementById("stream-mic") as HTMLButtonElement;
const STOP_MIC = document.getElementById("stop-mic") as HTMLButtonElement;
const PIPE_STATUS = document.getElementById("pipe-status")!;
const METRICS = document.getElementById("metrics")!;

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
let activeClient: ReturnType<typeof createClient> extends Promise<infer T>
  ? T
  : never;
let micStream: MediaStream | null = null;
let mediaRecorder: MediaRecorder | null = null;
let activePipeWriter: MTPPipeWriter | null = null;
let pipeSendCount = 0;
let pendingPipeReaders: MTPPipeReader[] = [];
let audioContext: AudioContext | null = null;
let micMonitorAudio: HTMLAudioElement | null = null;
let currentPipePingMs: number | null = null;
let lastPipeSendStartedAt = 0;
let currentPipeId: number | null = null;
let currentPipeDescription = "";
let currentPipeState = "idle";
let loopbackPlaybackCount = 0;
let hasPipeRequestHandler = false;

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

function pipeLog(msg: string, cls = "pipe") {
  const line = document.createElement("div");
  line.textContent = msg;
  if (cls) line.className = cls;
  PIPE_STATUS.prepend(line);
}

function setMetric(name: string, value: string) {
  const row = document.querySelector(`[data-metric="${name}"]`);
  if (row) {
    row.querySelector<HTMLElement>(".metric-value")!.textContent = value;
    return;
  }

  const wrapper = document.createElement("div");
  wrapper.dataset.metric = name;
  wrapper.innerHTML = `<span class="metric-name"></span>: <span class="metric-value"></span>`;
  wrapper.querySelector<HTMLElement>(".metric-name")!.textContent = name;
  wrapper.querySelector<HTMLElement>(".metric-value")!.textContent = value;
  METRICS.appendChild(wrapper);
}

function updateMetrics() {
  setMetric(
    "Current Pipe",
    currentPipeId == null ? "none" : String(currentPipeId),
  );
  setMetric("Pipe State", currentPipeState);
  setMetric("Pipe Description", currentPipeDescription || "n/a");
  setMetric(
    "Current Pipe Ping",
    currentPipePingMs == null ? "n/a" : `${currentPipePingMs.toFixed(1)} ms`,
  );
  setMetric("Loopback Playback", String(loopbackPlaybackCount));
  setMetric("Sent Chunks", String(pipeSendCount));
}

function setPipeState(
  state: string,
  details: Partial<{
    pipeId: number | null;
    description: string;
    pingMs: number | null;
  }>,
) {
  if ("pipeId" in details) currentPipeId = details.pipeId ?? null;
  if ("description" in details)
    currentPipeDescription = details.description ?? "";
  if ("pingMs" in details)
    currentPipePingMs = details.pingMs ?? currentPipePingMs;
  currentPipeState = state;
  updateMetrics();
}

function getPipeId(handle: unknown): number | null {
  if (handle && typeof handle === "object") {
    const candidate = handle as Record<string, unknown>;
    const value =
      candidate.pipeId ??
      candidate.pipe_id ??
      candidate["pipe-id"] ??
      candidate.id;
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
  }
  return null;
}

function ensureAudioContext() {
  if (!audioContext) {
    audioContext = new AudioContext();
  }
  return audioContext;
}

async function playLoopbackAudio(chunks: BlobPart[], mimeType: string) {
  if (chunks.length === 0) return;
  const blob = new Blob(chunks, { type: mimeType });
  const url = URL.createObjectURL(blob);
  const audio = new Audio(url);
  audio.autoplay = true;
  audio.onended = () => URL.revokeObjectURL(url);
  audio.onerror = () => URL.revokeObjectURL(url);
  try {
    await ensureAudioContext().resume();
    await audio.play();
    loopbackPlaybackCount += 1;
    updateMetrics();
    pipeLog(`Loopback playback started (${chunks.length} chunks).`);
  } catch (e) {
    URL.revokeObjectURL(url);
    pipeLog(`Loopback playback failed: ${e}`, "error");
  }
}

async function startMicPlayback(stream: MediaStream) {
  if (micMonitorAudio) {
    micMonitorAudio.pause();
    micMonitorAudio.srcObject = null;
    micMonitorAudio = null;
  }

  const audio = new Audio();
  audio.autoplay = true;
  audio.controls = false;
  audio.muted = false;
  audio.srcObject = stream;
  micMonitorAudio = audio;

  try {
    await ensureAudioContext().resume();
    await audio.play();
    pipeLog("Microphone monitoring playback started.");
  } catch (e) {
    pipeLog(`Microphone monitoring playback failed: ${e}`, "error");
  }
}

function stopMicPlayback() {
  if (!micMonitorAudio) return;
  micMonitorAudio.pause();
  micMonitorAudio.srcObject = null;
  micMonitorAudio = null;
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
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function hexToBytes(value: string): Uint8Array {
  const hex = value.replace(/[^0-9a-fA-F]/g, "");
  if (hex.length === 0) throw new Error("host public key is required");
  if (hex.length % 2 !== 0)
    throw new Error("host public key hex has an odd length");

  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function saveHostPublicKey() {
  try {
    localStorage.setItem(
      HOST_PUBLIC_KEY_KEY,
      bytesToHex(hexToBytes(HOST_PUBLIC_KEY.value)),
    );
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
    setKeyStatus(
      "No saved SDK credentials. The next connection will generate and store a reusable keyring.",
    );
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
    const response = await fetch("/host_public_key_bundle.hex", {
      cache: "no-store",
    });
    if (!response.ok) return;

    const hostPublicKey = (await response.text()).trim();
    if (!hostPublicKey || !/^[0-9a-f]+$/i.test(hostPublicKey)) return;

    HOST_PUBLIC_KEY.value = hostPublicKey;
    saveHostPublicKey();
    log(`Loaded host public key bundle (${hostPublicKey.length / 2} bytes).`);
  } catch {
    // Manual paste still works when the server has not exported the file yet.
  }
}

async function loadDevCertHash() {
  try {
    const response = await fetch(`/mtp_dev_cert_hash.txt?t=${Date.now()}`, {
      cache: "no-store",
    });
    if (!response.ok) return;

    const hash = (await response.text()).trim();
    if (/^[0-9a-f]{64}$/i.test(hash)) {
      devCertHash = hash;
      log(`Loaded WebTransport certificate hash: ${devCertHash}`);
    }
  } catch {
    devCertHash = "";
  }
}

async function initWasm() {
  log("Loading WASM module...");
  await MTPClient.create({
    url: SERVER_URL.value,
    storage: credentialStorage,
    credentialsStorageKey: CREDENTIALS_KEY,
  });
  const supported = MTPClient.isSupported();
  log(`WASM loaded. WebTransport supported: ${supported}`);
  CONNECT.disabled = !supported;
}

async function createClient() {
  const hostPk = hexToBytes(HOST_PUBLIC_KEY.value);
  await loadDevCertHash();
  const serverUrl = SERVER_URL.value.trim();
  const serverCertificateHashes = devCertHash ? [devCertHash] : undefined;

  const client = await MTPClient.create({
    url: serverUrl,
    hostPublicKey: hostPk,
    storage: credentialStorage,
    credentialsStorageKey: CREDENTIALS_KEY,
    serverCertificateHashes,
    pings: { intervalMs: 30_000 },
    logger(event) {
      log(
        renderLoggerEvent(event),
        event.hint === "error"
          ? "error"
          : event.type === "state"
            ? "state"
            : "",
      );
    },
  });

  return client;
}

async function connect() {
  STATUS.textContent = "";
  PIPE_STATUS.textContent = "";

  if (!MTPClient.isSupported()) {
    log("WebTransport is not supported in this browser.", "error");
    return;
  }
  const hostPk = hexToBytes(HOST_PUBLIC_KEY.value);
  saveHostPublicKey();
  await loadDevCertHash();

  const serverUrl = SERVER_URL.value.trim();
  const serverCertificateHashes = devCertHash ? [devCertHash] : undefined;
  if (serverCertificateHashes) {
    log(`Pinning WebTransport certificate hash: ${serverCertificateHashes[0]}`);
  } else {
    log(
      "No WebTransport certificate hash loaded; relying on browser trust store.",
      "state",
    );
  }

  try {
    const client = await createClient();
    activeClient = client;

    client.subscribe("Pong", (frame: ParsedFrame) => {
      log(`Subscribed Pong: ${formatParsedFrame(frame)}`, "received");
    });

    const activeClientId = await client.auth();
    clientId = activeClientId;
    loadKeys();
    log(`Connected as client ${activeClientId}`);

    log("\nSending typed Ping...");
    await client.send(
      "Ping",
      {
        Description: "MTP web client send ping",
        Timestamp: BigInt(Date.now()),
      },
      { sender: activeClientId },
    );
    log("Typed Ping sent.");

    log("\nRequesting Pong by Ping frame id...");
    const response = await client.request(
      "Ping",
      {
        Description: "MTP web client request ping",
        Timestamp: BigInt(Date.now()),
      },
      { sender: activeClientId, responseType: "Pong" },
    );
    log(`Request response: ${formatParsedFrame(response)}`, "received");

    log("\nClient running. Waiting for incoming messages...");
    STREAM_MIC.disabled = false;
    log("\nPipe demo ready. Click 'Stream Microphone' to start.", "pipe");
    updateMetrics();
  } catch (error) {
    log(`[error] ${error}`, "error");
  }
}

async function startMicStreaming() {
  if (!activeClient) {
    pipeLog("No active client connection.", "error");
    return;
  }

  try {
    micStream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch (e) {
    pipeLog(`Microphone access denied: ${e}`, "error");
    return;
  }

  STREAM_MIC.disabled = true;
  STOP_MIC.disabled = false;
  setPipeState("creating", { pipeId: null, description: "mic-audio" });
  pipeLog("Microphone acquired. Creating pipe ...");
  await startMicPlayback(micStream);

  if (!hasPipeRequestHandler) {
    activeClient.setOnPipeRequest(async (request) => {
      pipeLog(
        `Incoming return pipe: id=${request.pipeId} desc=${request.description}`,
      );
      try {
        const reader = await activeClient!.acceptPipe(request.pipeId);
        pendingPipeReaders.push(reader);
        pipeLog(
          `Pipe accepted. Streaming return pipe (pipe id=${getPipeId(reader) ?? "unknown"}) ...`,
        );
        readLoopbackPipe(reader);
      } catch (e) {
        pipeLog(`Failed to accept return pipe: ${e}`, "error");
      }
    });
    hasPipeRequestHandler = true;
  }

  const handle = await activeClient.createPipe("mic-audio");
  const pipeId = getPipeId(handle);
  setPipeState("waiting-for-accept", { pipeId, description: "mic-audio" });
  pipeLog(
    `Pipe created (id=${pipeId ?? "unknown"}). Waiting for server to accept ...`,
  );

  const writer = await handle.wait();
  if (!writer) {
    setPipeState("denied", { pipeId, description: "mic-audio" });
    pipeLog("Pipe denied by server.", "error");
    stopMicStreaming();
    return;
  }
  activePipeWriter = writer;

  setPipeState("streaming", {
    pipeId: getPipeId(writer) ?? pipeId,
    description: "mic-audio",
  });
  pipeLog(
    `Pipe accepted. Streaming microphone (pipe id=${getPipeId(writer) ?? pipeId ?? "unknown"}) ...`,
  );

  // Stream microphone audio via MediaRecorder
  const mimeType = MediaRecorder.isTypeSupported("audio/webm;codecs=opus")
    ? "audio/webm;codecs=opus"
    : "audio/webm";
  mediaRecorder = new MediaRecorder(micStream, { mimeType });

  mediaRecorder.ondataavailable = async (event) => {
    if (event.data.size === 0 || !activeClient) return;

    const startTime = performance.now();
    pipeSendCount++;
    const chunkNum = pipeSendCount;

    try {
      lastPipeSendStartedAt = performance.now();
      const buffer = await event.data.arrayBuffer();
      const data = new Uint8Array(buffer);
      await writer.write(data);
      currentPipePingMs = performance.now() - lastPipeSendStartedAt;
      updateMetrics();
    } catch (e) {
      pipeLog(`  [chunk ${chunkNum}] send error: ${e}`, "error");
    }
  };

  mediaRecorder.start(200); // emit data every 200ms
  updateMetrics();
  pipeLog("Streaming started (200ms chunks).");
}

async function readLoopbackPipe(reader: MTPPipeReader) {
  const startTime = performance.now();
  let totalBytes = 0;
  let chunkCount = 0;
  const chunks: BlobPart[] = [];
  const mimeType = MediaRecorder.isTypeSupported("audio/webm;codecs=opus")
    ? "audio/webm;codecs=opus"
    : "audio/webm";

  try {
    while (true) {
      const data = await reader.read();
      if (data == null) break; // EOF
      totalBytes += data.length;
      chunkCount++;
      chunks.push(data.slice().buffer);
    }
  } catch (e) {
    pipeLog(`  Return pipe read error: ${e}`, "error");
    return;
  }

  const elapsed = performance.now() - startTime;
  pipeLog(
    `  Return pipe complete: ${chunkCount} chunks, ${totalBytes} bytes, ` +
      `delay=${elapsed.toFixed(1)}ms`,
  );
  setPipeState("loopback-ready", { pingMs: elapsed });
  await playLoopbackAudio(chunks, mimeType);

  // Clean up the reader from the pending list
  const idx = pendingPipeReaders.indexOf(reader);
  if (idx >= 0) pendingPipeReaders.splice(idx, 1);
}

async function stopMicStreaming() {
  if (mediaRecorder && mediaRecorder.state !== "inactive") {
    mediaRecorder.stop();
    mediaRecorder = null;
  }

  if (activePipeWriter) {
    try {
      await activePipeWriter.close();
    } catch (e) {
      pipeLog(`Pipe close error: ${e}`, "error");
    } finally {
      activePipeWriter = null;
    }
  }

  if (micStream) {
    micStream.getTracks().forEach((track) => track.stop());
    micStream = null;
  }
  stopMicPlayback();

  // Close pending pipe readers
  pendingPipeReaders = [];
  setPipeState("stopped", {
    pipeId: currentPipeId,
    description: currentPipeDescription,
  });

  STREAM_MIC.disabled = false;
  STOP_MIC.disabled = true;
  pipeLog("Microphone streaming stopped.");
}

GENERATE_KEYPAIR.addEventListener("click", () => {
  try {
    clientId = null;
    localStorage.removeItem(CREDENTIALS_KEY);
    CLIENT_CREDENTIALS.value = "";
    setKeyStatus(
      "Cleared saved credentials. The next connection will generate a new reusable keyring.",
    );
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

STREAM_MIC.addEventListener("click", () => {
  startMicStreaming().catch((e) => {
    pipeLog(`Pipe streaming error: ${e}`, "error");
    console.error(e);
  });
});

STOP_MIC.addEventListener("click", () => {
  stopMicStreaming();
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

updateMetrics();
