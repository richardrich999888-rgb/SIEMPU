// Optional managed endpoint provider. Never import into a service or browser bundle.
import { spawn } from 'node:child_process';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEMO_SUITE } from '../../packages/crypto/crypto.mjs';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fail = (code) => Object.assign(new Error(code), { code });
const worker = fileURLToPath(new URL('./worker.py', import.meta.url));
const pathOK = (p) => typeof p === 'string' && isAbsolute(p) && !/[\x00-\x1f\x7f]/.test(p);
const pinHash = (h) => typeof h === 'string' && /^[a-f0-9]{64}$/.test(h);
const exact = (r, keys) => r && Object.keys(r).sort().join() === [...keys].sort().join();
const bytes = (v, size) => {
  if (typeof v !== 'string') throw fail('PKCS11_PROTOCOL');
  const b = Buffer.from(v, 'base64');
  if (b.length !== size || b.toString('base64') !== v) throw fail('PKCS11_PROTOCOL');
  return b;
};

export function createPkcs11Provider({
  python,
  pythonSha256,
  module,
  moduleSha256,
  workerSha256,
  tokenLabel,
  tokenSerial,
  getPin,
  softhsmConfig,
  timeoutMs = 10000,
}) {
  if (
    ![python, module].every(pathOK) ||
    ![pythonSha256, moduleSha256, workerSha256].every(pinHash) ||
    ![tokenLabel, tokenSerial].every(
      (v) => typeof v === 'string' && /^[\x20-\x7e]{1,32}$/.test(v),
    ) ||
    typeof getPin !== 'function' ||
    (softhsmConfig !== undefined && !pathOK(softhsmConfig)) ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 100 ||
    timeoutMs > 30000
  )
    throw fail('PKCS11_CONFIG');
  const id = 'pkcs11-p256-endpoint-v1';
  const handles = new WeakMap(),
    resolved = new WeakMap(),
    ephemeral = new WeakSet();
  let busy = false;
  async function request(operation, keyId, purpose, extra = {}) {
    if (busy) throw fail('PKCS11_BUSY');
    busy = true;
    let input;
    try {
      for (const [path, expected] of [
        [python, pythonSha256],
        [module, moduleSha256],
        [worker, workerSha256],
      ])
        if (hash(await readFile(path)) !== expected) throw fail('PKCS11_COMPONENT_CHANGED');
      const pin = await getPin();
      if (typeof pin !== 'string' || !pin.length || pin.length > 256) throw fail('PKCS11_PIN');
      input = Buffer.from(
        JSON.stringify({
          version: 1,
          operation,
          module,
          tokenLabel,
          tokenSerial,
          pin,
          id: keyId,
          purpose,
          ...extra,
        }),
      );
      if (input.length > 8192) throw fail('PKCS11_REQUEST_LIMIT');
      return await new Promise((resolve, reject) => {
        const child = spawn(python, ['-I', '-B', worker], {
          shell: false,
          stdio: ['pipe', 'pipe', 'pipe'],
          cwd: '/',
          env: {
            LANG: 'C.UTF-8',
            PATH: '/usr/bin:/bin',
            ...(softhsmConfig ? { SOFTHSM2_CONF: softhsmConfig } : {}),
          },
        });
        let output = '',
          count = 0,
          error;
        const stop = (code) => {
          error ??= code;
          child.kill('SIGKILL');
        };
        const timer = setTimeout(() => stop('PKCS11_TIMEOUT'), timeoutMs);
        child.on('error', () => stop('PKCS11_UNAVAILABLE'));
        child.stdin.on('error', () => stop('PKCS11_IO'));
        child.stderr.on('data', () => stop('PKCS11_DIAGNOSTIC'));
        child.stdout.on('data', (chunk) => {
          count += chunk.length;
          if (count > 2048) stop('PKCS11_OUTPUT_LIMIT');
          else output += chunk.toString('utf8');
        });
        child.on('close', (code, signal) => {
          clearTimeout(timer);
          if (error || code !== 0 || signal)
            return reject(fail(error ?? 'PKCS11_OPERATION_FAILED'));
          try {
            const r = JSON.parse(output);
            const field = ['open', 'generate'].includes(operation) ? 'publicKey' : 'data';
            if (!exact(r, ['version', 'ok', field]) || r.version !== 1 || r.ok !== true)
              throw fail('PKCS11_OPERATION_FAILED');
            resolve(r[field]);
          } catch {
            reject(fail('PKCS11_OPERATION_FAILED'));
          }
        });
        child.stdin.end(input);
      });
    } catch (e) {
      throw /^PKCS11_[A-Z_]+$/.test(e?.code ?? '') ? e : fail('PKCS11_UNAVAILABLE');
    } finally {
      input?.fill(0);
      busy = false;
    }
  }
  const entry = (h) => {
    const value = handles.get(h);
    if (!value || !value.active) throw fail('KEY_HANDLE_UNKNOWN_OR_DESTROYED');
    return value;
  };
  async function key(operation, keyId, purpose, expectedPublicKey) {
    const encoded = await request(operation, keyId, purpose);
    const der = bytes(encoded, 91);
    const jwk = createPublicKey({ key: der, format: 'der', type: 'spki' }).export({
      format: 'jwk',
    });
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw fail('PKCS11_PUBLIC_KEY');
    const publicKey = Object.freeze({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y });
    if (
      operation === 'open' &&
      (!expectedPublicKey ||
        Object.keys(publicKey).some((k) => publicKey[k] !== expectedPublicKey[k]) ||
        Object.keys(expectedPublicKey).length !== 4)
    )
      throw fail('PKCS11_KEY_SUBSTITUTED');
    const handle = Object.freeze({
      ...publicKey,
      handleVersion: 1,
      providerId: id,
      handleId: keyId,
    });
    const value = { publicKey, keyId, purpose, publicSha256: hash(der), active: true };
    handles.set(handle, value);
    return { publicKey, privateKey: handle };
  }
  const native = crypto.subtle;
  const subtle = new Proxy(native, {
    get(target, name) {
      if (name === 'importKey')
        return async (format, value, ...args) => {
          if (format === 'pkcs8' || (format === 'jwk' && value?.d))
            throw fail('PKCS11_PRIVATE_IMPORT_DENIED');
          // Public ECDH points must cross the PKCS#11 boundary; private imports remain denied.
          if (format === 'jwk' && value?.kty === 'EC') args[1] = true;
          return target.importKey(format, value, ...args);
        };
      if (name === 'generateKey')
        return async (alg, extractable, usages) => {
          if (
            alg?.name !== 'ECDH' ||
            alg.namedCurve !== 'P-256' ||
            extractable !== false ||
            usages.length !== 1 ||
            usages[0] !== 'deriveBits'
          )
            throw fail('PKCS11_SOFTWARE_KEY_DENIED');
          const pair = await target.generateKey(alg, false, usages);
          ephemeral.add(pair.privateKey);
          return pair;
        };
      if (name === 'sign')
        return async (alg, handle, data) => {
          const v = resolved.get(handle);
          if (!v?.active || v.purpose !== 'sign' || alg?.name !== 'ECDSA' || alg.hash !== 'SHA-256')
            throw fail('PKCS11_KEY_USAGE_DENIED');
          return bytes(
            await request('sign', v.keyId, v.purpose, {
              publicSha256: v.publicSha256,
              data: createHash('sha256').update(Buffer.from(data)).digest('base64'),
            }),
            64,
          );
        };
      if (name === 'deriveBits')
        return async (alg, handle, length) => {
          if (ephemeral.has(handle)) return target.deriveBits(alg, handle, length);
          const v = resolved.get(handle);
          if (!v?.active || v.purpose !== 'deriveBits' || alg?.name !== 'ECDH' || length !== 256)
            throw fail('PKCS11_KEY_USAGE_DENIED');
          const peer = await target.exportKey('raw', alg.public);
          return bytes(
            await request('derive', v.keyId, v.purpose, {
              publicSha256: v.publicSha256,
              data: Buffer.from(peer).toString('base64'),
            }),
            32,
          );
        };
      return typeof target[name] === 'function' ? target[name].bind(target) : target[name];
    },
  });
  return Object.freeze({
    version: 1,
    id,
    suites: Object.freeze([DEMO_SUITE]),
    subtle,
    capabilities: Object.freeze({
      opaquePrivateKeys: true,
      hardwareBacked: false,
      pqc: false,
      sagGraded: false,
      tokenBacked: true,
      softwareContentEncryption: true,
    }),
    random: (b) => crypto.getRandomValues(b),
    isHandle: (h) => !!h && typeof h === 'object' && 'handleVersion' in h,
    publicKey: (h) => entry(h).publicKey,
    resolve: (h, purpose) => {
      const v = entry(h);
      if (v.purpose !== purpose) throw fail('KEY_USAGE_DENIED');
      const key = Object.freeze({});
      resolved.set(key, v);
      return key;
    },
    destroy: (h) => {
      const v = entry(h);
      v.active = false;
      handles.delete(h);
    },
    openKey: (keyId, purpose, expectedPublicKey) => {
      if (!/^[a-f0-9]{32}$/.test(keyId ?? '') || !['sign', 'deriveBits'].includes(purpose))
        throw fail('PKCS11_CONFIG');
      return key('open', keyId, purpose, expectedPublicKey);
    },
    async generateDeviceHandles() {
      return {
        signing: await key('generate', randomBytes(16).toString('hex'), 'sign'),
        encryption: await key('generate', randomBytes(16).toString('hex'), 'deriveBits'),
      };
    },
  });
}
