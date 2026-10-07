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
export interface ObjectContext {
  schemaVersion: 1;
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
export interface WrappedKey {
  ephemeralPublicKey: PublicP256Jwk;
  salt: string;
  iv: string;
  ciphertext: string;
}
export interface ObjectEnvelope extends ObjectContext {
  ciphertextHash: string;
  nonce: string;
  wrappedKey: WrappedKey;
}
export interface EncryptedObject {
  envelope: ObjectEnvelope;
  signature: string;
  ciphertext: string;
}
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
