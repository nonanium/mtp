/**
 * Encrypted secret material persisted for MTP cryptographic facilities.
 *
 * `id` is an opaque, MTP-owned or caller-derived identifier. The provider
 * does not interpret it or infer an identity hierarchy from it.
 */
export interface MTPEncryptedSecretRecord {
  id: string;
  encryptedSecret: Uint8Array;
  formatVersion: number;
  wrappingScheme: string;
  wrappingKeyId?: string;
  createdAt: number;
  updatedAt: number;
}

export interface MTPEncryptedSecretProvider {
  get(id: string): Promise<MTPEncryptedSecretRecord | null>;
  set(record: MTPEncryptedSecretRecord): Promise<void>;
  delete(id: string): Promise<void>;
}

function requireId(id: string): string {
  if (typeof id !== "string" || id.length === 0) {
    throw new TypeError("encrypted secret id must be a non-empty string");
  }
  return id;
}

function validateTimestamp(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative safe integer`);
  }
}

function cloneRecord(record: MTPEncryptedSecretRecord): MTPEncryptedSecretRecord {
  return {
    ...record,
    encryptedSecret: new Uint8Array(record.encryptedSecret),
  };
}

function validateRecord(record: MTPEncryptedSecretRecord): void {
  requireId(record.id);
  if (
    !(record.encryptedSecret instanceof Uint8Array) ||
    record.encryptedSecret.length === 0
  ) {
    throw new TypeError(
      "encrypted secret requires non-empty encryptedSecret bytes",
    );
  }
  if (!Number.isSafeInteger(record.formatVersion) || record.formatVersion < 0) {
    throw new TypeError(
      "encrypted secret formatVersion must be a non-negative safe integer",
    );
  }
  if (typeof record.wrappingScheme !== "string" || !record.wrappingScheme) {
    throw new TypeError("encrypted secret requires wrappingScheme");
  }
  validateTimestamp(record.createdAt, "encrypted secret createdAt");
  validateTimestamp(record.updatedAt, "encrypted secret updatedAt");
  if (
    record.wrappingKeyId !== undefined &&
    (typeof record.wrappingKeyId !== "string" || !record.wrappingKeyId)
  ) {
    throw new TypeError("encrypted secret wrappingKeyId must be non-empty");
  }
}

/** A small reference implementation for callers that need local persistence. */
export class InMemoryEncryptedSecretProvider
  implements MTPEncryptedSecretProvider
{
  private store = new Map<string, MTPEncryptedSecretRecord>();

  async get(id: string): Promise<MTPEncryptedSecretRecord | null> {
    const record = this.store.get(requireId(id));
    return record ? cloneRecord(record) : null;
  }

  async set(record: MTPEncryptedSecretRecord): Promise<void> {
    validateRecord(record);
    this.store.set(record.id, cloneRecord(record));
  }

  async delete(id: string): Promise<void> {
    this.store.delete(requireId(id));
  }
}
