/** Versioned wire contracts. Runtime validation remains mandatory for untrusted input. */
export interface PublicP256Jwk {
  [member: string]: unknown;
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
}
export interface PrivateP256Jwk extends PublicP256Jwk {
  d: string;
}
export interface SignedPacket<T = unknown> {
  payload: T;
  signature: string;
  keyId: string;
}
export interface CreationGrant {
  grantId: string;
  userId: string;
  deviceId: string;
  unitId: string;
  missionIds: string[];
  creationEpoch: number;
  policyDigest: string;
  issuedAt: number;
  expiresAt: number;
  maxSensitivity: 'DEMO';
}
export interface ObjectContextBase {
  objectId: string;
  senderUserId: string;
  senderDeviceId: string;
  senderUnitId: string;
  recipientUserId: string;
  recipientDeviceId: string;
  recipientUnitId: string;
  recipientKeyId: string;
  missionId: string;
  classification: 'DEMO';
  action: 'deliver';
  createdAt: number;
  expiresAt: number;
  creationGrant: SignedPacket<CreationGrant>;
  cryptoSuite: 'P256-HKDF-SHA256-AES256GCM';
  keyVersion: 1;
}
export type ObjectContext = ObjectContextBase &
  (
    | { schemaVersion: 1; messagePriority?: never; messageDomain?: never }
    | {
        schemaVersion: 2;
        messagePriority: 'FLASH' | 'IMMEDIATE' | 'PRIORITY' | 'ROUTINE';
        messageDomain: 'GENERAL' | 'INTEL';
      }
  );
export interface WrappedKey {
  ephemeralPublicKey: PublicP256Jwk;
  salt: string;
  iv: string;
  ciphertext: string;
}
export type ObjectEnvelope = ObjectContext & {
  ciphertextHash: string;
  nonce: string;
  wrappedKey: WrappedKey;
};
export interface EncryptedObject {
  envelope: ObjectEnvelope;
  signature: string;
  ciphertext: string;
}
/** Laboratory endpoint contract. Classical browser encrypt/decrypt rejects this version. */
export type PqcLabContext = Omit<ObjectContextBase, 'cryptoSuite'> & {
  schemaVersion: 3;
  messagePriority: 'FLASH' | 'IMMEDIATE' | 'PRIORITY' | 'ROUTINE';
  messageDomain: 'GENERAL' | 'INTEL';
  providerId: 'node-openssl-pqc-lab' | 'noble-xwing-lab';
  cryptoSuite: string;
  suiteVersion: 1;
  senderCryptoKeyId: string;
  suitePolicyRevision: number;
};
export interface ProviderWrappedKey {
  schemaVersion: 1;
  providerId: string;
  suiteId: string;
  recipientKeyId: string;
  encapsulation: { algorithm: string; ciphertext: string };
  salt: string;
  nonce: string;
  ciphertext: string;
}
export type PqcLabEnvelope = PqcLabContext & {
  ciphertextHash: string;
  nonce: string;
  wrappedKey: ProviderWrappedKey;
  providerSignature: string;
};
export type VersionedObjectEnvelope = ObjectEnvelope | PqcLabEnvelope;
export interface Payload {
  kind: 'text' | 'file';
  name: string;
  mime: string;
  data: string;
}
export interface VaultPacket {
  version: number;
  kdf: string;
  iterations: number;
  salt: string;
  iv: string;
  ciphertext: string;
}
export type ChallengeExpectation =
  | { purpose: 'bind'; deviceId: string; operation?: never; requestHash?: never }
  | { purpose: 'enroll'; deviceId?: never; operation?: never; requestHash: string }
  | { purpose: 'operation'; deviceId: string; operation: string; requestHash: string };
export type DeviceChallenge = ChallengeExpectation & {
  domain: 'SIEPMU_DEVICE_PROOF_V1';
  nonce: string;
  sessionId: string;
  expiresAt: number;
};
export interface ReleaseScope {
  eventType: string;
  decision: string;
  actorId: string;
  objectId: string;
  details?: { recipientUserId?: string; recipientDeviceId?: string; action?: string };
}
