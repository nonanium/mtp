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
let loopbackAudioContext: AudioContext | null = null;
let micStreamGeneration = 0;
let pipeSendCount = 0;
let pendingPipeReaders: MTPPipeReader[] = [];
let currentPipePingMs: number | null = null;
let lastPipeSendStartedAt = 0;
let currentPipeId: number | null = null;
let currentPipeDescription = "";
let currentPipeState = "idle";
let loopbackPlaybackCount = 0;
let hasPipeRequestHandler = false;

// ===== AUDIO LOOPBACK STATE =====
// We accumulate all chunks into a single Blob, then decode and play it
// when the pipe closes. decodeAudioData needs a complete file, not fragments.
let loopbackBlobParts: BlobPart[] = [];
let loopbackMimeType = "";
let loopbackAudioElement: HTMLAudioElement | null = null;

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
    let value =
      candidate.pipeId ??
      candidate.pipe_id ??
      candidate["pipe-id"] ??
      candidate.id;
    if (typeof value === "function") {
      try {
        value = value.call(handle);
      } catch {
        return null;
      }
    }
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
  }
  return null;
}

// ===== FIXED AUDIO LOOPBACK: accumulate chunks, play as single file =====

function startLoopbackAccumulation(mimeType: string) {
  loopbackBlobParts = [];
  loopbackMimeType = mimeType;
  pipeLog("Loopback: accumulating audio chunks...");
}

function queueLoopbackChunk(data: Uint8Array) {
  loopbackBlobParts.push(data.slice());
}

async function finishLoopbackPlayback() {
  if (loopbackBlobParts.length === 0) {
    pipeLog("Loopback: no chunks received.", "error");
    return;
  }

  // Stop any previous playback
  if (loopbackAudioElement) {
    loopbackAudioElement.pause();
    const src = loopbackAudioElement.src;
    loopbackAudioElement.src = "";
    if (src.startsWith("blob:")) {
      URL.revokeObjectURL(src);
    }
    loopbackAudioElement = null;
  }

  // Concatenate all chunks into one Blob
  const blob = new Blob(loopbackBlobParts, { type: loopbackMimeType });
  loopbackBlobParts = [];

  pipeLog(`Loopback: assembled ${blob.size} bytes, decoding...`);

  try {
    const arrayBuffer = await blob.arrayBuffer();
    const audioContext = new AudioContext();
    const audioBuffer = await audioContext.decodeAudioData(arrayBuffer);

    const source = audioContext.createBufferSource();
    source.buffer = audioBuffer;
    source.connect(audioContext.destination);
    source.start();

    loopbackPlaybackCount += 1;
    updateMetrics();
    pipeLog(`Loopback playback started (${audioBuffer.duration.toFixed(2)}s).`);

    // Clean up audio context when done
    source.onended = () => {
      audioContext.close().catch(() => {});
    };
  } catch (e) {
    pipeLog(`Loopback decode/playback failed: ${e}`, "error");
  }
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
    log(`Connected as authenticated client ${activeClientId}`);

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
  pipeLog(
    "Microphone monitoring is off; playback will use the server loopback.",
  );

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
  const streamGeneration = ++micStreamGeneration;

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
  const recorder = new MediaRecorder(micStream, { mimeType });
  mediaRecorder = recorder;

  recorder.ondataavailable = async (event) => {
    // A final chunk can be queued before recorder.stop(). Do not use the
    // captured writer unless this is still the current active stream.
    if (
      event.data.size === 0 ||
      !activeClient ||
      micStreamGeneration !== streamGeneration ||
      mediaRecorder !== recorder ||
      activePipeWriter !== writer
    ) {
      return;
    }

    pipeSendCount++;
    const chunkNum = pipeSendCount;

    try {
      lastPipeSendStartedAt = performance.now();
      const buffer = await event.data.arrayBuffer();
      const data = new Uint8Array(buffer);
      // arrayBuffer() yields, so shutdown may have happened meanwhile.
      if (
        micStreamGeneration !== streamGeneration ||
        mediaRecorder !== recorder ||
        activePipeWriter !== writer
      ) {
        return;
      }
      await writer.write(data);
      currentPipePingMs = performance.now() - lastPipeSendStartedAt;
      updateMetrics();
    } catch (e) {
      pipeLog(`  [chunk ${chunkNum}] send error: ${e}`, "error");
    }
  };

  recorder.start(200); // emit data every 200ms
  updateMetrics();
  pipeLog("Streaming started (200ms chunks).");
}
async function readLoopbackPipe(reader: MTPPipeReader) {
  const startTime = performance.now();
  let totalBytes = 0;
  let chunkCount = 0;
  const mimeType = MediaRecorder.isTypeSupported("audio/webm;codecs=opus")
    ? "audio/webm;codecs=opus"
    : "audio/webm";

  try {
    loopbackBlobParts = [];
    loopbackMimeType = mimeType;
    pipeLog("Loopback: accumulating chunks...");

    while (true) {
      const data = await reader.read();
      if (data == null) break; // EOF
      totalBytes += data.length;
      chunkCount++;
      loopbackBlobParts.push(data.slice());
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

  // Decode and play the complete recording
  if (loopbackBlobParts.length > 0) {
    try {
      const blob = new Blob(loopbackBlobParts, { type: loopbackMimeType });
      const arrayBuffer = await blob.arrayBuffer();

      if (!loopbackAudioContext) {
        loopbackAudioContext = new AudioContext();
      }
      const audioBuffer =
        await loopbackAudioContext.decodeAudioData(arrayBuffer);

      const source = loopbackAudioContext.createBufferSource();
      source.buffer = audioBuffer;
      source.connect(loopbackAudioContext.destination);
      source.start();

      loopbackPlaybackCount += 1;
      updateMetrics();
      pipeLog(
        `Loopback playback started (${audioBuffer.duration.toFixed(2)}s).`,
      );
    } catch (e) {
      pipeLog(`Loopback decode failed: ${e}`, "error");
    }
  }

  // Clean up the reader from the pending list
  const idx = pendingPipeReaders.indexOf(reader);
  if (idx >= 0) pendingPipeReaders.splice(idx, 1);
}

// ===== CRITICAL FIX: stopMicStreaming must capture the final chunk =====
async function stopMicStreaming() {
  micStreamGeneration++;
  const recorder = mediaRecorder;
  mediaRecorder = null;
  const writer = activePipeWriter;
  activePipeWriter = null;

  // STOPPING STRATEGY:
  // 1. Request a final dataavailable event by calling requestData() if needed,
  //    then stop(). The final event contains the WebM trailer.
  // 2. Wait for that final event to be processed (it writes through the pipe).
  // 3. Only THEN close the pipe writer.

  if (recorder) {
    // Create a promise that resolves when the final dataavailable fires
    const finalChunkPromise = new Promise<void>((resolve) => {
      const originalHandler = recorder.ondataavailable;
      recorder.ondataavailable = async (event) => {
        // Call the original handler first so the chunk gets written to the pipe
        if (originalHandler) {
          await originalHandler.call(recorder, event);
        }
        // The final chunk from stop() has a 'type' but no special marker.
        // MediaRecorder state will be 'inactive' after the final event.
        if (recorder.state === "inactive") {
          resolve();
        }
      };
    });

    if (recorder.state !== "inactive") {
      recorder.stop();
    }

    // Wait up to 1 second for the final chunk to be captured and written
    await Promise.race([
      finalChunkPromise,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("final chunk timeout")), 1000),
      ),
    ]).catch(() => {
      pipeLog("Warning: final chunk may not have been captured", "error");
    });
  }

  if (writer) {
    try {
      await writer.close();
    } catch (e) {
      pipeLog(`Pipe close error: ${e}`, "error");
    }
  }

  if (micStream) {
    micStream.getTracks().forEach((track) => track.stop());
    micStream = null;
  }
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
