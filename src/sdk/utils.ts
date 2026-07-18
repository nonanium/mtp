export function utf8Encode(text: string): Uint8Array {
  if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(text);
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(text, "utf-8"));
  const bytes = new Uint8Array(text.length * 4);
  let len = 0;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.codePointAt(i) as number;
    if (code < 0x80) bytes[len++] = code;
    else if (code < 0x800) { bytes[len++] = 0xc0 | (code >> 6); bytes[len++] = 0x80 | (code & 0x3f); }
    else if (code < 0x10000) { bytes[len++] = 0xe0 | (code >> 12); bytes[len++] = 0x80 | ((code >> 6) & 0x3f); bytes[len++] = 0x80 | (code & 0x3f); }
    else { bytes[len++] = 0xf0 | (code >> 18); bytes[len++] = 0x80 | ((code >> 12) & 0x3f); bytes[len++] = 0x80 | ((code >> 6) & 0x3f); bytes[len++] = 0x80 | (code & 0x3f); i += 1; }
  }
  return bytes.subarray(0, len);
}

export function writeU64BE(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) throw new Error("u64 value out of range");
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i -= 1) { out[i] = Number(value & 0xffn); value >>= 8n; }
  return out;
}

export function concatBytes(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
