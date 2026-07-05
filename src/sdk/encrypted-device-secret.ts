export interface EncryptedDeviceSecretRecord {
  userId: string;
  deviceId: string;
  secretId: string;
  version: number;
  encryptedSecret: Uint8Array;
  wrappingPublicKeyId?: string;
  wrappingScheme: string;
  createdAt: number;
  updatedAt: number;
}

export interface MTPEncryptedDeviceSecretProvider {
  setEncryptedDeviceSecret(record: EncryptedDeviceSecretRecord): Promise<void>;
  getEncryptedDeviceSecret(query: {
    userId: string;
    deviceId?: string;
    secretId?: string;
  }): Promise<EncryptedDeviceSecretRecord | null>;
}

function keyFor(record: Pick<EncryptedDeviceSecretRecord, "userId" | "deviceId" | "secretId">): string {
  return `${record.userId}\0${record.deviceId}\0${record.secretId}`;
}

function cloneRecord(record: EncryptedDeviceSecretRecord): EncryptedDeviceSecretRecord {
  return {
    ...record,
    encryptedSecret: new Uint8Array(record.encryptedSecret),
  };
}

function validateEncryptedRecord(record: EncryptedDeviceSecretRecord): void {
  if (!record.userId || !record.deviceId || !record.secretId) {
    throw new Error("encrypted device secret requires userId, deviceId, and secretId");
  }
  if (!(record.encryptedSecret instanceof Uint8Array) || record.encryptedSecret.length === 0) {
    throw new Error("encrypted device secret requires non-empty encryptedSecret bytes");
  }
  if (!record.wrappingScheme) {
    throw new Error("encrypted device secret requires wrappingScheme");
  }
}

export class InMemoryEncryptedDeviceSecretProvider implements MTPEncryptedDeviceSecretProvider {
  private store = new Map<string, EncryptedDeviceSecretRecord>();

  async setEncryptedDeviceSecret(record: EncryptedDeviceSecretRecord): Promise<void> {
    validateEncryptedRecord(record);
    const now = Date.now();
    this.store.set(keyFor(record), cloneRecord({ ...record, updatedAt: record.updatedAt || now }));
  }

  async getEncryptedDeviceSecret(query: {
    userId: string;
    deviceId?: string;
    secretId?: string;
  }): Promise<EncryptedDeviceSecretRecord | null> {
    if (!query.userId) {
      throw new Error("userId is required");
    }
    if (query.deviceId && query.secretId) {
      const found = this.store.get(`${query.userId}\0${query.deviceId}\0${query.secretId}`);
      return found ? cloneRecord(found) : null;
    }
    for (const record of this.store.values()) {
      if (record.userId !== query.userId) continue;
      if (query.deviceId && record.deviceId !== query.deviceId) continue;
      if (query.secretId && record.secretId !== query.secretId) continue;
      return cloneRecord(record);
    }
    return null;
  }
}
