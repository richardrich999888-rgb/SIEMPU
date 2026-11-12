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
  #fileInspector;
  #renewing = null;
  constructor({
    url,
    tls,
    profile,
    authorityKey,
    provider,
    fileInspector = null,
    sessionRenewal = false,
  }) {
    if (new URL(url).protocol !== 'https:' || !tls) throw new Error('SDK_TLS_REQUIRED');
    Object.assign(this, { url, tls, profile, authorityKey });
    if (fileInspector !== null && typeof fileInspector?.inspect !== 'function')
      throw new Error('FILE_INSPECTION_CONFIG');
    this.#fileInspector = fileInspector;
    this.crypto = createObjectCryptography(provider);
    this.token = null;
    if (typeof sessionRenewal !== 'boolean') throw new Error('SESSION_RENEWAL_CONFIG');
    this.sessionRenewal = sessionRenewal;
    this.expiresAt = 0;
  }
  get fileInspectionMode() {
    return this.#fileInspector ? 'ENDPOINT_REQUIRED' : 'UNSCANNED';
  }
  async call(method, path, body) {
    // Fixed labels only: diagnostics must not serialize credentials, proofs or content.
    const requestStage =
      {
        __proto__: null,
        '/api/auth/login': 'LOGIN',
        '/api/auth/challenge': 'DEVICE_CHALLENGE',
        '/api/auth/bind': 'DEVICE_BIND',
        '/api/auth/renew': 'SESSION_RENEWAL',
        '/api/grants': 'CREATION_GRANT',
        '/api/control': 'CONTROL_STATE',
        '/api/objects': method === 'POST' ? 'OBJECT_SUBMISSION' : 'OBJECT_LIST',
      }[path] ??
      (/^\/api\/objects\/[^/]+\/claim$/.test(path)
        ? 'KEY_RELEASE'
        : /^\/api\/objects\/[^/]+\/ack$/.test(path)
          ? 'DELIVERY_ACK'
          : 'PLATFORM_REQUEST');
    try {
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
    } catch (error) {
      error.requestStage = requestStage;
      throw error;
    }
  }
  async signed(path) {
    await this.ensureSession();
    const result = await this.call('GET', path);
    if (!(await this.crypto.verifyPacket(this.authorityKey, result)))
      throw new Error('AUTHORITY_SIGNATURE');
    return result;
  }
  async authenticate() {
    this.token = null;
    this.expiresAt = 0;
    try {
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
      this.expiresAt = login.expiresAt;
    } catch (error) {
      // Neither an old session nor a partially bound new session survives failure locally.
      this.token = null;
      this.expiresAt = 0;
      throw error;
    }
  }
  async ensureSession() {
    if (!this.sessionRenewal || !this.token) return;
    if (this.expiresAt <= Date.now()) {
      this.token = null;
      this.expiresAt = 0;
      throw Object.assign(new Error('SESSION_INVALID'), { code: 'SESSION_INVALID' });
    }
    if (this.expiresAt - Date.now() <= 120000) await this.renewSession();
  }
  async renewSession() {
    if (this.#renewing) return this.#renewing;
    const pending = (async () => {
      try {
        const body = { otp: totp(this.profile.totpSecret) };
        const expected = {
          purpose: 'operation',
          deviceId: this.profile.deviceId,
          operation: 'renew-session',
          requestHash: await this.crypto.sha256(canonical(body)),
        };
        const challenge = await this.call('POST', '/api/auth/challenge', expected);
        const reply = await this.call('POST', '/api/auth/renew', {
          ...body,
          proof: {
            challengeId: challenge.challengeId,
            signature: await this.crypto.sign(
              this.profile.keys.signing.privateKey,
              validateDeviceChallenge(challenge, expected),
            ),
          },
        });
        if (
          typeof reply.token !== 'string' ||
          !/^[A-Za-z0-9_-]{43}$/.test(reply.token) ||
          reply.user?.id !== this.profile.userId ||
          reply.device?.id !== this.profile.deviceId ||
          !Number.isSafeInteger(reply.expiresAt) ||
          reply.expiresAt <= Date.now() ||
          reply.expiresAt > Date.now() + 900000
        )
          throw new Error('SESSION_RENEWAL_RESPONSE');
        this.token = reply.token;
        this.expiresAt = reply.expiresAt;
      } catch (error) {
        // An ambiguous response can leave a new server session; never try password login
        // automatically or revive the superseded session after a denial/network failure.
        this.token = null;
        this.expiresAt = 0;
        throw error;
      }
    })();
    this.#renewing = pending;
    try {
      return await pending;
    } finally {
      this.#renewing = null;
    }
  }
  async proof(operation, body = {}) {
    await this.ensureSession();
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
    // Copy before obtaining a grant; caller mutation across awaits cannot replace the file.
    payload = structuredClone(payload);
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
    payload = await this.inspectPayload(payload);
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
  async inspectPayload(payload) {
    const snapshot = structuredClone(payload);
    const unpacked = this.crypto.unpackPayload(snapshot);
    if (unpacked.kind === 'file' && this.#fileInspector) {
      // The scanner gets a separate copy, never the object later passed to encryption.
      const expectedHash = await this.crypto.sha256(unpacked.bytes);
      let result;
      try {
        result = await this.#fileInspector.inspect(unpacked.bytes);
      } catch (error) {
        const code = /^FILE_INSPECTION_[A-Z_]+$/.test(error?.code ?? '')
          ? error.code
          : 'FILE_INSPECTION_FAILED';
        throw Object.assign(new Error(code), { code });
      } finally {
        unpacked.bytes.fill(0);
      }
      if (
        result?.version !== 1 ||
        Object.keys(result).sort().join(',') !== 'bytes,sha256,status,version' ||
        result.status !== 'NO_THREAT_DETECTED' ||
        result.sha256 !== expectedHash ||
        result.bytes !== unpacked.bytes.length
      )
        throw Object.assign(new Error('FILE_INSPECTION_RESULT'), {
          code: 'FILE_INSPECTION_RESULT',
        });
    }
    return snapshot;
  }
  async receive(objectId, senderPublicKey) {
    return (await this.receiveWithRelease(objectId, senderPublicKey)).plaintext;
  }
  /**
   * Claims, verifies and decrypts an object, returning the plaintext together with the
   * authority-signed release receipt (needed to acknowledge delivery).
   */
  async receiveWithRelease(objectId, senderPublicKey) {
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
    const plaintext = await this.crypto.decryptObject(
      result,
      this.profile.keys.encryption.privateKey,
      senderPublicKey,
    );
    // A release receipt authorizes access; it is not a malware verdict or delivery ACK.
    const inspected = await this.inspectPayload(plaintext);
    return { plaintext: inspected, release: result.receipt, object: result.object };
  }
  /** Objects visible to this user (as sender or recipient), as reported by the authority. */
  async listObjects() {
    await this.ensureSession();
    return (await this.call('GET', '/api/objects')).objects;
  }
  /**
   * Acknowledges delivery of a released object. Returns the authority-signed DELIVERY_ACK
   * receipt after checking its signature and scope.
   */
  async acknowledge(objectId, release) {
    const body = { receiptId: release.payload.eventId };
    const result = await this.call('POST', `/api/objects/${objectId}/ack`, {
      ...body,
      proof: await this.proof('ack:' + objectId, body),
    });
    if (
      !(await this.crypto.verifyPacket(this.authorityKey, result.receipt)) ||
      result.receipt.payload.objectId !== objectId ||
      result.receipt.payload.eventType !== 'DELIVERY_ACK'
    )
      throw new Error('DELIVERY_RECEIPT');
    return result.receipt;
  }
}
