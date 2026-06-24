import init, {
  WasmClient,
  ConnectionConfig,
  ConnectionState,
  WasmEd25519Signer,
  ed25519_generate,
  keyring_from_ed25519,
  build_demo_message,
} from 'mtp-wasm';

const STATUS = document.getElementById('status')!;
const STORAGE_KEY = 'mtp-web-client-keys';

function log(msg: string, cls = '') {
  const line = document.createElement('div');
  line.textContent = msg;
  if (cls) line.className = cls;
  STATUS.appendChild(line);
}

function saveKeys(clientId: bigint, keyringBytes: Uint8Array) {
  const data = {
    clientId: clientId.toString(),
    keyring: Array.from(keyringBytes),
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
}

function loadKeys(): { clientId: bigint; keyringBytes: Uint8Array } | null {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  const data = JSON.parse(raw);
  return {
    clientId: BigInt(data.clientId),
    keyringBytes: new Uint8Array(data.keyring),
  };
}

async function initWasm() {
  log('Loading WASM module...');
  await init();
  log(`WASM loaded. WebTransport supported: ${WasmClient.is_supported()}`);
}

function createClient(): WasmClient {
  return new WasmClient(
    (state: number) => log(`[state] ${ConnectionState[state] ?? state}`, 'state'),
    (data: Uint8Array) => {
      const decoder = new TextDecoder();
      log(`[message] ${data.length} bytes: ${decoder.decode(data)}`, 'received');
    },
    (err: any) => log(`[error] ${err}`, 'error'),
  );
}

function generateKeyringBytes(): Uint8Array {
  const gen = ed25519_generate();
  const sk = gen.secretKey as Uint8Array;
  const pk = gen.publicKey as Uint8Array;
  gen.signer.free();
  return keyring_from_ed25519(sk, pk);
}

async function run() {
  await initWasm();

  if (!WasmClient.is_supported()) {
    log('WebTransport is not supported in this browser.', 'error');
    return;
  }

  const serverUrl = 'https://127.0.0.1:8080';
  const saved = loadKeys();

  const client = createClient();
  const config = new ConnectionConfig(serverUrl);

  let clientId: bigint;
  let keyringBytes: Uint8Array;

  if (saved) {
    log(`Found saved client keys (ID: ${saved.clientId})`);
    const hostPk = new Uint8Array(0);
    clientId = await client.auth_connect(config, hostPk, saved.keyringBytes, saved.clientId);
    log(`Authenticated as client ${clientId}`);
    keyringBytes = saved.keyringBytes;
  } else {
    log('No saved keys — registering new client...');
    const hostPk = new Uint8Array(0);
    keyringBytes = generateKeyringBytes();
    clientId = await client.auth_register(config, hostPk, keyringBytes);
    log(`Registered with ID: ${clientId}`);
    saveKeys(clientId, keyringBytes);
    log('Saved client keys to localStorage');
  }

  config.free();

  log('\nSending demo message...');
  const frame = build_demo_message(clientId, keyringBytes);
  await client.send(frame);
  log(`Sent ${frame.length} bytes`);

  log('\nClient running. Waiting for incoming messages...');
}

run().catch((e) => {
  log(`Fatal error: ${e}`, 'error');
  console.error(e);
});
