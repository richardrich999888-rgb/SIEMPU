// Optional endpoint companion. Never load into the authority, relay or browser.
import { join } from 'node:path';
import { createPkcs11Provider } from '../pkcs11/provider.mjs';
import { BubblewrapSandbox } from '../../packages/file-inspection/sandbox.mjs';
import { ClamAvInspector } from '../../packages/file-inspection/clamav.mjs';
import { IntegrationEndpoint } from '../../packages/integration/client.mjs';

const fail = (code) => Object.assign(new Error(code), { code });
const record = (v, required, optional = []) => {
  if (
    !v ||
    typeof v !== 'object' ||
    Array.isArray(v) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(v)) ||
    required.some((k) => !Object.hasOwn(v, k)) ||
    Object.keys(v).some((k) => ![...required, ...optional].includes(k))
  )
    throw fail('MANAGED_ENDPOINT_CONFIG');
};
const publicKey = (v) => {
  record(v, ['kty', 'crv', 'x', 'y']);
  if (
    v.kty !== 'EC' ||
    v.crv !== 'P-256' ||
    ['x', 'y'].some(
      (k) =>
        typeof v[k] !== 'string' ||
        !/^[A-Za-z0-9_-]{43}$/.test(v[k]) ||
        Buffer.from(v[k], 'base64url').toString('base64url') !== v[k],
    )
  )
    throw fail('MANAGED_ENDPOINT_PUBLIC_KEY');
};

/** Public configuration only. Credentials and token PIN callbacks are separate arguments. */
export function validateConfiguration(input) {
  record(input, ['schemaVersion', 'url', 'authorityKey', 'profile', 'pkcs11', 'inspection']);
  let c;
  try {
    c = structuredClone(input);
  } catch {
    throw fail('MANAGED_ENDPOINT_CONFIG');
  }
  if (c.schemaVersion !== 1) throw fail('MANAGED_ENDPOINT_CONFIG');
  let url;
  try {
    url = new URL(c.url);
  } catch {
    throw fail('MANAGED_ENDPOINT_DESTINATION');
  }
  if (url.protocol !== 'https:' || url.origin !== c.url) throw fail('MANAGED_ENDPOINT_DESTINATION');
  publicKey(c.authorityKey);
  record(c.profile, ['username', 'userId', 'deviceId', 'unitId', 'signing', 'encryption']);
  for (const k of ['username', 'userId', 'deviceId', 'unitId'])
    if (typeof c.profile[k] !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(c.profile[k]))
      throw fail('MANAGED_ENDPOINT_CONFIG');
  for (const purpose of ['signing', 'encryption']) {
    record(c.profile[purpose], ['handleId', 'publicKey']);
    if (!/^[a-f0-9]{32}$/.test(c.profile[purpose].handleId ?? ''))
      throw fail('MANAGED_ENDPOINT_CONFIG');
    publicKey(c.profile[purpose].publicKey);
  }
  record(
    c.pkcs11,
    [
      'python',
      'pythonSha256',
      'module',
      'moduleSha256',
      'workerSha256',
      'tokenLabel',
      'tokenSerial',
    ],
    ['softhsmConfig', 'timeoutMs'],
  );
  record(
    c.inspection,
    ['executable', 'executableSha256', 'database', 'tempRoot', 'sandbox'],
    ['maxBytes', 'timeoutMs', 'maxDatabaseAgeDays'],
  );
  record(c.inspection.sandbox, [
    'bwrap',
    'bwrapSha256',
    'prlimit',
    'prlimitSha256',
    'runtimeRoot',
    'files',
  ]);
  if (c.inspection.executable !== join(c.inspection.sandbox.runtimeRoot, 'bin/clamscan'))
    throw fail('MANAGED_ENDPOINT_CONFIG');
  // Reuse each adapter's bounds and path checks, without invoking external programs.
  createPkcs11Provider({ ...c.pkcs11, getPin: async () => '' });
  new ClamAvInspector({ ...c.inspection, sandbox: new BubblewrapSandbox(c.inspection.sandbox) });
  return c;
}

function transport(input) {
  record(input, ['ca'], ['cert', 'key', 'crl', 'minVersion', 'maxVersion', 'rejectUnauthorized']);
  if (
    !!input.cert !== !!input.key ||
    (input.rejectUnauthorized !== undefined && input.rejectUnauthorized !== true) ||
    ['minVersion', 'maxVersion'].some((k) => input[k] !== undefined && input[k] !== 'TLSv1.3')
  )
    throw fail('MANAGED_ENDPOINT_TLS');
  const tls = { minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', rejectUnauthorized: true };
  for (const k of ['ca', 'cert', 'key', 'crl']) {
    if (input[k] === undefined) continue;
    if (
      !(typeof input[k] === 'string' || Buffer.isBuffer(input[k])) ||
      Buffer.byteLength(input[k]) < 1 ||
      Buffer.byteLength(input[k]) > 65536
    )
      throw fail('MANAGED_ENDPOINT_TLS');
    tls[k] = Buffer.from(input[k]);
  }
  return tls;
}

const safeError = (error) => {
  const code = error?.code ?? error?.message;
  return fail(
    typeof code === 'string' && /^[A-Z][A-Z0-9_]{1,79}$/.test(code)
      ? code
      : 'MANAGED_ENDPOINT_OPERATION_FAILED',
  );
};

/** Opens existing, enrolled token keys; does not enroll, approve or authenticate personnel. */
export async function openManagedEndpoint({ config, tls, credentials, getPin }) {
  const c = validateConfiguration(config),
    connection = transport(tls);
  record(credentials, ['password', 'totpSecret']);
  if (
    ['password', 'totpSecret'].some(
      (k) =>
        typeof credentials[k] !== 'string' ||
        !credentials[k].length ||
        credentials[k].length > 1024,
    ) ||
    typeof getPin !== 'function'
  )
    throw fail('MANAGED_ENDPOINT_CREDENTIALS');
  const secrets = { password: credentials.password, totpSecret: credentials.totpSecret };
  const provider = createPkcs11Provider({ ...c.pkcs11, getPin });
  const inspector = new ClamAvInspector({
    ...c.inspection,
    sandbox: new BubblewrapSandbox(c.inspection.sandbox),
  });
  let signing, encryption, endpoint;
  const invalidate = () => {
    for (const key of [signing, encryption]) if (key) provider.destroy(key.privateKey);
    signing = encryption = undefined;
    if (endpoint) {
      endpoint.token = null;
      endpoint.profile.password = endpoint.profile.totpSecret = '';
    }
    secrets.password = secrets.totpSecret = '';
  };
  try {
    // Fail before requesting a PIN or returning a usable client if isolation is unavailable.
    await inspector.inspect(Buffer.from('SIEPMU_MANAGED_ENDPOINT_PREFLIGHT'));
    signing = await provider.openKey(
      c.profile.signing.handleId,
      'sign',
      c.profile.signing.publicKey,
    );
    encryption = await provider.openKey(
      c.profile.encryption.handleId,
      'deriveBits',
      c.profile.encryption.publicKey,
    );
    endpoint = new IntegrationEndpoint({
      url: c.url,
      tls: connection,
      profile: { ...c.profile, ...secrets, keys: { signing, encryption } },
      authorityKey: c.authorityKey,
      provider,
      fileInspector: inspector,
    });
  } catch (error) {
    invalidate();
    throw safeError(error);
  }
  let closed = false,
    busy = false,
    authenticated = false;
  const invoke = async (name, args) => {
    if (closed) throw fail('MANAGED_ENDPOINT_CLOSED');
    if (busy) throw fail('MANAGED_ENDPOINT_BUSY');
    busy = true;
    if (name === 'authenticate') authenticated = false;
    try {
      const snapshot = structuredClone(args);
      const result =
        name === 'send'
          ? await endpoint.submit(await endpoint.seal(...snapshot))
          : await endpoint[name](...snapshot);
      if (name === 'authenticate') authenticated = true;
      return result;
    } catch (error) {
      throw safeError(error);
    } finally {
      busy = false;
    }
  };
  const api = {};
  for (const name of [
    'authenticate',
    'send',
    'receive',
    'receiveWithRelease',
    'listObjects',
    'acknowledge',
  ])
    api[name] = (...args) => invoke(name, args);
  for (const name of ['createTextPayload', 'createFilePayload', 'unpackPayload'])
    api[name] = (...args) => {
      if (closed) throw fail('MANAGED_ENDPOINT_CLOSED');
      return endpoint.crypto[name](...args);
    };
  api.status = () =>
    Object.freeze({
      schemaVersion: 1,
      closed,
      authenticated: !closed && authenticated,
      fileInspection: 'REQUIRED_ISOLATED',
      keyProvider: 'PKCS11_P256',
      hardwareQualified: false,
      sagGrading: 'NOT_ESTABLISHED',
    });
  api.close = () => {
    if (busy) throw fail('MANAGED_ENDPOINT_BUSY');
    if (!closed) {
      closed = true;
      invalidate();
    }
  };
  return Object.freeze(api);
}
