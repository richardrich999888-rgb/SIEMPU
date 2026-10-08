import { requestBytes } from '../transport/tls.mjs';
import { canonical } from '../protocol/canonical.mjs';
import { createObjectCryptography } from '../crypto/crypto.mjs';
import { totp } from '../../services/control/primitives.mjs';
import {
  validateDeviceChallenge,
  validateReleaseScope,
} from '../../apps/unit-client/challenge.mjs';

// Synthetic managed endpoint SDK. Authority/recipient public keys are supplied
// by the operator; neither TOFU nor a directory response replaces those pins.
export class IntegrationEndpoint {
  constructor({ url, tls, profile, authorityKey, provider }) {
    if (new URL(url).protocol !== 'https:' || !tls) throw new Error('SDK_TLS_REQUIRED');
    Object.assign(this, { url, tls, profile, authorityKey });
    this.crypto = createObjectCryptography(provider);
    this.token = null;
  }
  async call(method, path, body) {
    const r = await requestBytes(this.url + path, {
      method,
      tls: this.tls,
      headers: {
        'content-type': 'application/json',
        ...(this.token ? { authorization: 'Bearer ' + this.token } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (r.status !== 200) {
      // Error code only; never echo request or response bodies (may carry protected material).
      let code = null;
      try {
        code = JSON.parse(r.body).code ?? null;
      } catch {}
      throw Object.assign(new Error('PLATFORM_REQUEST_REJECTED'), {
        status: r.status,
        method,
        path,
        code,
      });
    }
    return JSON.parse(r.body);
  }
  async signed(path) {
    const result = await this.call('GET', path);
    if (!(await this.crypto.verifyPacket(this.authorityKey, result)))
      throw new Error('AUTHORITY_SIGNATURE');
    return result;
  }
  async authenticate() {
    const login = await this.call('POST', '/api/auth/login', {
      username: this.profile.username,
      password: this.profile.password,
      otp: totp(this.profile.totpSecret),
    });
    this.token = login.token;
    const expected = { purpose: 'bind', deviceId: this.profile.deviceId };
    const reply = await this.call('POST', '/api/auth/challenge', expected);
    await this.call('POST', '/api/auth/bind', {
      deviceId: this.profile.deviceId,
      challengeId: reply.challengeId,
      signature: await this.crypto.sign(
        this.profile.keys.signing.privateKey,
        validateDeviceChallenge(reply, expected),
      ),
    });
  }
  async proof(operation, body = {}) {
    const expected = {
      purpose: 'operation',
      deviceId: this.profile.deviceId,
      operation,
      requestHash: await this.crypto.sha256(canonical(body)),
    };
    const reply = await this.call('POST', '/api/auth/challenge', expected);
    return {
      challengeId: reply.challengeId,
      signature: await this.crypto.sign(
        this.profile.keys.signing.privateKey,
        validateDeviceChallenge(reply, expected),
      ),
    };
  }
  async seal(
    recipient,
    payload,
    { missionId = 'DEMO-MISSION', messagePriority = 'ROUTINE', messageDomain = 'GENERAL' } = {},
  ) {
    const creationGrant = await this.call('POST', '/api/grants', {
      proof: await this.proof('grant'),
    });
    return this.sealUsingGrant(recipient, payload, creationGrant, {
      missionId,
      messagePriority,
      messageDomain,
    });
  }
  async sealUsingGrant(
    recipient,
    payload,
    creationGrant,
    { missionId = 'DEMO-MISSION', messagePriority = 'ROUTINE', messageDomain = 'GENERAL' } = {},
  ) {
    if (!(await this.crypto.verifyPacket(this.authorityKey, creationGrant)))
      throw new Error('GRANT_SIGNATURE');
    const now = Date.now(),
      p = this.profile;
    if (
      creationGrant.payload.expiresAt <= now ||
      creationGrant.payload.issuedAt > now ||
      creationGrant.payload.userId !== p.userId ||
      creationGrant.payload.deviceId !== p.deviceId
    )
      throw new Error('CACHED_GRANT_INVALID');
    const context = {
      schemaVersion: 2,
      objectId: crypto.randomUUID(),
      senderUserId: p.userId,
      senderDeviceId: p.deviceId,
      senderUnitId: p.unitId,
      recipientUserId: recipient.userId,
      recipientDeviceId: recipient.deviceId,
      recipientUnitId: recipient.unitId,
      recipientKeyId: await this.crypto.keyId(recipient.encryptionPublicKey),
      missionId,
      classification: 'DEMO',
      action: 'deliver',
      createdAt: now,
      expiresAt: Math.min(now + 600000, creationGrant.payload.expiresAt),
      creationGrant,
      cryptoSuite: 'P256-HKDF-SHA256-AES256GCM',
      keyVersion: 1,
      messagePriority,
      messageDomain,
    };
    return this.crypto.encryptObject(
      context,
      payload,
      recipient.encryptionPublicKey,
      p.keys.signing.privateKey,
    );
  }
  async submit(sealed) {
    const result = await this.call('POST', '/api/objects', {
      ...sealed,
      proof: await this.proof('submit', sealed),
    });
    if (
      !(await this.crypto.verifyPacket(this.authorityKey, result.receipt)) ||
      result.receipt.payload.objectId !== sealed.envelope.objectId
    )
      throw new Error('SUBMISSION_RECEIPT');
    return result;
  }
  async receive(objectId, senderPublicKey) {
    const control = await this.signed('/api/control');
    if (control.payload.expiresAt <= Date.now()) throw new Error('CONTROL_STALE');
    const body = { expectedEpoch: control.payload.epoch };
    const result = await this.call('POST', `/api/objects/${objectId}/claim`, {
      ...body,
      proof: await this.proof('claim:' + objectId, body),
    });
    if (!(await this.crypto.verifyPacket(this.authorityKey, result.receipt)))
      throw new Error('RELEASE_SIGNATURE');
    validateReleaseScope(result.receipt.payload, {
      objectId,
      userId: this.profile.userId,
      deviceId: this.profile.deviceId,
    });
    return this.crypto.decryptObject(
      result,
      this.profile.keys.encryption.privateKey,
      senderPublicKey,
    );
  }
}
