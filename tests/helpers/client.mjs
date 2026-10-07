// Independent protocol peer for acceptance tests and synthetic demonstrations.
// Intentionally uses Node crypto directly rather than the implementation's crypto helpers.
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  randomUUID,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';

export const b64 = (value) => Buffer.from(value).toString('base64url');
export const unb64 = (value) => Buffer.from(value, 'base64url');
export function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string')
    return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return (
      '{' +
      Object.keys(value)
        .sort()
        .map((key) => JSON.stringify(key) + ':' + canonical(value[key]))
        .join(',') +
      '}'
    );
  }
  throw new TypeError('Unsupported canonical value');
}
export const hash = (value) => createHash('sha256').update(value).digest('hex');
export function keyObject(key, privateKey = false) {
  if (key?.type && typeof key.export === 'function') return key;
  return privateKey
    ? createPrivateKey({ key, format: 'jwk' })
    : createPublicKey({ key, format: 'jwk' });
}
export function sign(value, key) {
  return b64(
    cryptoSign('sha256', Buffer.from(canonical(value)), {
      key: keyObject(key, true),
      dsaEncoding: 'ieee-p1363',
    }),
  );
}
export function verify(value, signature, key) {
  return cryptoVerify(
    'sha256',
    Buffer.from(canonical(value)),
    { key: keyObject(key), dsaEncoding: 'ieee-p1363' },
    unb64(signature),
  );
}
export function pair() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    publicKey: publicKey.export({ format: 'jwk' }),
    privateKey: privateKey.export({ format: 'jwk' }),
  };
}
export const deviceKeys = () => ({ signing: pair(), encryption: pair() });
export function totp(secret, timestamp = Date.now()) {
  let bits = '';
  for (const c of secret.toUpperCase().replace(/=+$/g, '')) {
    const n = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);
    if (n < 0) throw new Error('Invalid base32 secret');
    bits += n.toString(2).padStart(5, '0');
  }
  const key = Buffer.from(bits.match(/.{8}/g)?.map((byte) => parseInt(byte, 2)) || []);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(timestamp / 30000)));
  const digest = createHmac('sha1', key).update(counter).digest();
  const offset = digest.at(-1) & 15;
  return ((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
}
function encrypt(key, iv, bytes, aad) {
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(canonical(aad)));
  return Buffer.concat([cipher.update(bytes), cipher.final(), cipher.getAuthTag()]);
}
function decrypt(key, iv, bytes, aad) {
  const cipher = createDecipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(canonical(aad)));
  cipher.setAuthTag(bytes.subarray(-16));
  return Buffer.concat([cipher.update(bytes.subarray(0, -16)), cipher.final()]);
}
export function createObject(sender, recipient, creationGrant, options = {}) {
  const now = Date.now();
  const context = {
    schemaVersion: 1,
    objectId: randomUUID(),
    senderUserId: sender.userId,
    senderDeviceId: sender.deviceId,
    senderUnitId: sender.unitId,
    recipientUserId: recipient.userId,
    recipientDeviceId: recipient.deviceId,
    recipientUnitId: recipient.unitId,
    recipientKeyId: hash(canonical(recipient.keys.encryption.publicKey)),
    missionId: 'DEMO-MISSION',
    classification: 'DEMO',
    action: 'deliver',
    createdAt: now,
    expiresAt: now + 10 * 60 * 1000,
    creationGrant,
    cryptoSuite: 'P256-HKDF-SHA256-AES256GCM',
    keyVersion: 1,
    ...options.context,
  };
  const data = options.data ?? 'SYNTHETIC: routine logistics message';
  const payload = {
    kind: options.kind ?? 'text',
    name: options.name ?? '',
    mime: options.mime ?? 'text/plain',
    data: b64(Buffer.from(data)),
  };
  const contentKey = randomBytes(32),
    nonce = randomBytes(12);
  const ciphertext = encrypt(contentKey, nonce, Buffer.from(JSON.stringify(payload)), context);
  const ephemeral = pair(),
    salt = randomBytes(32),
    iv = randomBytes(12);
  const shared = diffieHellman({
    privateKey: keyObject(ephemeral.privateKey, true),
    publicKey: keyObject(recipient.keys.encryption.publicKey),
  });
  const wrapKey = Buffer.from(hkdfSync('sha256', shared, salt, Buffer.from('SIEPMU_WRAP_V1'), 32));
  const wrappedKey = {
    ephemeralPublicKey: ephemeral.publicKey,
    salt: b64(salt),
    iv: b64(iv),
    ciphertext: b64(encrypt(wrapKey, iv, contentKey, context)),
  };
  const envelope = { ...context, ciphertextHash: hash(ciphertext), nonce: b64(nonce), wrappedKey };
  return {
    envelope,
    signature: sign(envelope, sender.keys.signing.privateKey),
    ciphertext: b64(ciphertext),
  };
}
export function decryptObject(claim, recipient) {
  const { envelope, ciphertext, signature, senderSigningPublicKey } = claim;
  if (!verify(envelope, signature, senderSigningPublicKey))
    throw new Error('Sender signature invalid');
  if (
    envelope.recipientUserId !== recipient.userId ||
    envelope.recipientDeviceId !== recipient.deviceId
  )
    throw new Error('Wrong recipient');
  if (envelope.recipientKeyId !== hash(canonical(recipient.keys.encryption.publicKey)))
    throw new Error('Wrong recipient key');
  if (hash(unb64(ciphertext)) !== envelope.ciphertextHash)
    throw new Error('Ciphertext digest mismatch');
  const { ciphertextHash, nonce, wrappedKey, ...context } = envelope;
  const shared = diffieHellman({
    privateKey: keyObject(recipient.keys.encryption.privateKey, true),
    publicKey: keyObject(wrappedKey.ephemeralPublicKey),
  });
  const wrapKey = Buffer.from(
    hkdfSync('sha256', shared, unb64(wrappedKey.salt), Buffer.from('SIEPMU_WRAP_V1'), 32),
  );
  const contentKey = decrypt(wrapKey, unb64(wrappedKey.iv), unb64(wrappedKey.ciphertext), context);
  const payload = JSON.parse(
    decrypt(contentKey, unb64(nonce), unb64(ciphertext), context).toString(),
  );
  return { ...payload, bytes: unb64(payload.data) };
}

export class ApiClient {
  constructor(transport, profile) {
    this.transport = transport;
    this.profile = profile;
    this.token = null;
  }
  async request(method, path, body = undefined, options = {}) {
    return this.transport(
      method,
      path,
      body,
      options.token === undefined ? this.token : options.token,
      options,
    );
  }
  async ok(method, path, body, options) {
    const result = await this.request(method, path, body, options);
    if (result.status < 200 || result.status >= 300)
      throw new Error(`${method} ${path}: ${result.status} ${JSON.stringify(result.body)}`);
    return result.body;
  }
  async login() {
    const result = await this.ok('POST', '/api/auth/login', {
      username: this.profile.username,
      password: this.profile.password,
      otp: totp(this.profile.totpSecret),
    });
    this.token = result.token;
    this.user = result.user;
    return result;
  }
  async bind() {
    const challenge = await this.ok('POST', '/api/auth/challenge', {
      purpose: 'bind',
      deviceId: this.profile.deviceId,
    });
    return this.ok('POST', '/api/auth/bind', {
      deviceId: this.profile.deviceId,
      challengeId: challenge.challengeId,
      signature: sign(challenge.challenge, this.profile.keys.signing.privateKey),
    });
  }
  async authenticate() {
    await this.login();
    await this.bind();
    return this;
  }
  async proof(operation, body = {}) {
    const challenge = await this.ok('POST', '/api/auth/challenge', {
      purpose: 'operation',
      deviceId: this.profile.deviceId,
      operation,
      requestHash: hash(canonical(body)),
    });
    return {
      challengeId: challenge.challengeId,
      signature: sign(challenge.challenge, this.profile.keys.signing.privateKey),
    };
  }
  async grant() {
    return this.ok('POST', '/api/grants', { proof: await this.proof('grant') });
  }
  async submit(object) {
    return this.ok('POST', '/api/objects', {
      ...object,
      proof: await this.proof('submit', object),
    });
  }
  async prepare(id) {
    return this.request('POST', `/api/objects/${id}/prepare`, {
      proof: await this.proof('prepare:' + id),
    });
  }
  async claim(id, expectedEpoch) {
    return this.request('POST', `/api/objects/${id}/claim`, {
      expectedEpoch,
      proof: await this.proof('claim:' + id, { expectedEpoch }),
    });
  }
  async admin(method, path, body = {}) {
    return this.request(method, path, {
      ...body,
      proof: await this.proof(`admin:${method}:${path}`, body),
    });
  }
}

export function coreTransport(authority) {
  return async (method, path, body, token, options = {}) => {
    try {
      return await authority.dispatch(method, path, body ?? {}, token, {
        ip: options.ip ?? 'test-local',
      });
    } catch (error) {
      return {
        status: error.status ?? error.statusCode ?? 500,
        body: { error: error.message, code: error.code ?? 'INTERNAL_ERROR' },
      };
    }
  };
}
export function httpTransport(baseUrl) {
  return async (method, path, body, token, options = {}) => {
    const response = await fetch(baseUrl + path, {
      method,
      headers: {
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(token ? { Authorization: 'Bearer ' + token } : {}),
        ...options.headers,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(10000),
    });
    const text = await response.text();
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text;
    }
    return { status: response.status, body: parsed, headers: response.headers };
  };
}

export async function enrollUser(
  admin,
  { username, unitId, role = 'operator', missionIds = ['DEMO-MISSION'] },
) {
  const password = 'Demo-' + b64(randomBytes(18));
  const result = await admin.admin('POST', '/api/admin/users', {
    username,
    password,
    unitId,
    role,
    missionIds,
  });
  if (result.status !== 200 && result.status !== 201)
    throw new Error('User enrollment failed: ' + JSON.stringify(result));
  const profile = {
    username,
    password,
    userId: result.body.user.id,
    unitId,
    totpSecret: result.body.totpSecret,
    keys: deviceKeys(),
  };
  const client = new ApiClient(admin.transport, profile);
  await client.login();
  const enrollment = {
    label: username + '-synthetic-device',
    signingPublicKey: profile.keys.signing.publicKey,
    encryptionPublicKey: profile.keys.encryption.publicKey,
  };
  const challenge = await client.ok('POST', '/api/auth/challenge', {
    purpose: 'enroll',
    requestHash: hash(canonical(enrollment)),
  });
  const enrolled = await client.ok('POST', '/api/devices/enroll', {
    ...enrollment,
    challengeId: challenge.challengeId,
    signature: sign(challenge.challenge, profile.keys.signing.privateKey),
  });
  profile.deviceId = enrolled.device.id;
  const approved = await admin.admin('POST', `/api/admin/devices/${profile.deviceId}/approve`);
  if (approved.status !== 200)
    throw new Error('Device approval failed: ' + JSON.stringify(approved));
  await client.bind();
  return { profile, client };
}
