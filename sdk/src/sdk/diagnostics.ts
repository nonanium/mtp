import { on_usage_diagnostics_checkpoint, usage_diagnostics } from "mtp/raw";
import { initWasmOnce } from "./wasm-init.js";

// Only aggregate measurements cross this boundary; payloads and errors never do.
export async function usageDiagnostics(
  action: "snapshot" | "restore" | "clear" | "enabled" | "event",
  argument = "",
  value = 1,
): Promise<string> {
  await initWasmOnce();
  return usage_diagnostics(action, argument, value);
}

export async function onUsageDiagnosticsCheckpoint(
  callback: () => void,
): Promise<void> {
  await initWasmOnce();
  on_usage_diagnostics_checkpoint(callback);
}
