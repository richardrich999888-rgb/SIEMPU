import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { httpFixture } from '../helpers/fixture.mjs';
import {
  canonical,
  createObject,
  decryptObject,
  deviceKeys,
  hash,
  sign,
  verify,
} from '../helpers/client.mjs';

const document = JSON.parse(
  await readFile(new URL('../../docs/api.openapi.json', import.meta.url), 'utf8'),
);
const methods = new Set(['get', 'post', 'put', 'patch', 'delete']);
const uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const slice = new Set([
  'POST /api/auth/login',
  'GET /api/auth/me',
  'POST /api/auth/logout',
  'POST /api/auth/challenge',
  'POST /api/auth/bind',
  'POST /api/devices/enroll',
  'GET /api/control',
  'POST /api/grants',
  'GET /api/objects',
  'POST /api/objects',
  'POST /api/objects/{id}/prepare',
  'POST /api/objects/{id}/claim',
  'POST /api/objects/{id}/ack',
  'PUT /api/admin/policies',
]);
function resolve(reference) {
  assert.ok(reference.startsWith('#/'), 'Contract references must be local');
  let value = document;
  for (const part of reference.slice(2).split('/')) value = value?.[part];
  assert.ok(value, `Unresolved contract reference: ${reference}`);
  return value;
}
function dereference(value) {
  return value.$ref ? resolve(value.$ref) : value;
}

// Intentionally bounded JSON Schema checker for this file's explicit vocabulary.
// Unknown validation keywords fail, rather than silently implying full validator support.
const keywords = new Set([
  '$ref',
  'type',
  'required',
  'properties',
  'additionalProperties',
  'items',
  'oneOf',
  'anyOf',
  'enum',
  'const',
  'pattern',
  'format',
  'minimum',
  'maximum',
  'minLength',
  'maxLength',
  'maxItems',
  'description',
  'writeOnly',
]);
function validate(schema, value, at = '$') {
  for (const keyword of Object.keys(schema))
    assert.ok(keywords.has(keyword), `Unsupported schema keyword ${keyword} at ${at}`);
  if (schema.$ref) return validate(resolve(schema.$ref), value, at);
  for (const union of ['oneOf', 'anyOf']) {
    if (!schema[union]) continue;
    const matches = schema[union].filter((member) => {
      try {
        validate(member, value, at);
        return true;
      } catch {
        return false;
      }
    }).length;
    assert.ok(union === 'oneOf' ? matches === 1 : matches > 0, `${at}: ${union} mismatch`);
  }
  if (schema.enum) assert.ok(schema.enum.includes(value), `${at}: invalid enum value`);
  if (Object.hasOwn(schema, 'const')) assert.deepEqual(value, schema.const, `${at}: constant`);
  if (schema.type) {
    const actual = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
    assert.ok(
      schema.type === 'integer' ? Number.isSafeInteger(value) : actual === schema.type,
      `${at}: expected ${schema.type}, received ${actual}`,
    );
  }
  if (typeof value === 'string') {
    if (schema.minLength !== undefined)
      assert.ok(value.length >= schema.minLength, `${at}: too short`);
    if (schema.maxLength !== undefined)
      assert.ok(value.length <= schema.maxLength, `${at}: too long`);
    if (schema.pattern) assert.match(value, new RegExp(schema.pattern), at);
    if (schema.format) {
      assert.equal(schema.format, 'uuid', 'Only the UUID format is supported here');
      assert.match(value, uuidPattern, at);
    }
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined) assert.ok(value >= schema.minimum, `${at}: below minimum`);
    if (schema.maximum !== undefined) assert.ok(value <= schema.maximum, `${at}: above maximum`);
  }
  if (Array.isArray(value)) {
    if (schema.maxItems !== undefined)
      assert.ok(value.length <= schema.maxItems, `${at}: too many items`);
    if (schema.items) value.forEach((item, i) => validate(schema.items, item, `${at}[${i}]`));
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const key of schema.required ?? [])
      assert.ok(Object.hasOwn(value, key), `${at}: missing ${key}`);
    for (const [key, item] of Object.entries(value)) {
      if (schema.properties?.[key]) validate(schema.properties[key], item, `${at}.${key}`);
      else if (schema.additionalProperties === false) assert.fail(`${at}: unexpected ${key}`);
    }
  }
}
function operation(method, path) {
  for (const [template, item] of Object.entries(document.paths)) {
    if (new RegExp('^' + template.replace('{id}', '[^/]+') + '$').test(path)) {
      const op = item[method.toLowerCase()];
      if (op) return { op, key: `${method} ${template}` };
    }
  }
  assert.fail(`HTTP request has no documented route: ${method} ${path}`);
}
function correlation(result) {
  assert.match(result.headers.get('x-request-id') ?? '', uuidPattern);
  assert.match(result.headers.get('content-type') ?? '', /^application\/json/);
  assert.equal(result.headers.get('cache-control'), 'no-store');
  if (result.status >= 400) assert.equal(result.body.requestId, result.headers.get('x-request-id'));
}
function responseContract(method, path, result) {
  const { op } = operation(method, path);
  const response = op.responses[String(result.status)];
  assert.ok(response, `Undocumented HTTP ${result.status} for ${method} ${path}`);
  const schema = dereference(response).content?.['application/json']?.schema;
  if (schema) validate(schema, result.body);
  correlation(result);
}
function errorCode(result, status, code) {
  assert.equal(result.status, status, JSON.stringify(result.body));
  assert.equal(result.body.code, code);
  assert.ok(!JSON.stringify(result.body).includes('wrappedKey'));
  assert.ok(!Object.hasOwn(result.body, 'ciphertext'));
}
function receipt(packet, key, eventType, objectId) {
  assert.equal(packet.keyId, hash(canonical(key)));
  assert.ok(verify(packet.payload, packet.signature, key));
  assert.equal(packet.payload.eventType, eventType);
  assert.equal(packet.payload.objectId, objectId);
}

test('OpenAPI identifies the bounded HTTP contract slice and resolves every reference', () => {
  const walk = (value) => {
    if (!value || typeof value !== 'object') return;
    if (value.$ref) resolve(value.$ref);
    Object.values(value).forEach(walk);
  };
  walk(document);
  assert.equal(document.openapi, '3.1.0');
  const marked = new Set();
  for (const [path, item] of Object.entries(document.paths)) {
    for (const [method, op] of Object.entries(item)) {
      if (!methods.has(method)) continue;
      const key = `${method.toUpperCase()} ${path}`;
      if (op['x-contract-coverage'] === 'http-request-response-tested') marked.add(key);
      if (!slice.has(key)) continue;
      assert.ok(op.responses['200'].content['application/json'].schema);
      if (method !== 'get') assert.ok(op.requestBody.content['application/json'].schema.$ref);
      const security = op.security ?? document.security;
      assert.deepEqual(security, path === '/api/auth/login' ? [] : [{ BearerSession: [] }]);
      for (const status of ['400', '401', '403', '404', '409', '413', '415', '429', '500'])
        assert.ok(dereference(op.responses[status]).content['application/json'].schema);
    }
  }
  assert.deepEqual(marked, slice);
  for (const path of [
    '/api/grants',
    '/api/objects',
    '/api/objects/{id}/prepare',
    '/api/objects/{id}/claim',
    '/api/objects/{id}/ack',
    '/api/admin/policies',
  ]) {
    const op = document.paths[path][path === '/api/admin/policies' ? 'put' : 'post'];
    assert.equal(op['x-device-binding-required'], true);
    assert.equal(op['x-operation-proof'].bodyField, 'proof');
  }
});

test('contract checker rejects missing fields, malformed proofs and metadata key leakage', () => {
  const error = { error: 'UNAUTHENTICATED', code: 'UNAUTHENTICATED', requestId: randomUUID() };
  validate(document.components.schemas.Error, error);
  assert.throws(() =>
    validate(document.components.schemas.Error, { ...error, requestId: undefined }),
  );
  assert.throws(() =>
    validate(document.components.schemas.Proof, {
      challengeId: randomUUID(),
      signature: 'invalid',
    }),
  );
  assert.throws(() =>
    validate(document.components.schemas.ObjectList, { objects: [], wrappedKey: {} }),
  );
  assert.throws(() => validate({ type: 'number', multipleOf: 2 }, 3));
});

test(
  'real HTTP contracts cover authentication, bound proof, exchange and policy HOLD',
  { timeout: 45000 },
  async (t) => {
    const f = await httpFixture(t);
    const successful = new Set();
    const captured = [];
    const transport = async (method, path, body, token, options) => {
      const result = await f.transport(method, path, body, token, options);
      responseContract(method, path, result);
      const { op, key } = operation(method, path);
      if (result.status < 400 && slice.has(key)) {
        if (op.requestBody) validate(op.requestBody.content['application/json'].schema, body);
        successful.add(key);
      }
      captured.push({ method, path, body, result });
      return result;
    };
    for (const client of Object.values(f.clients)) client.transport = transport;
    const { alice, bob, admin } = f.clients;

    // Every inventoried protected operation must reject a request lacking a session.
    const authGuards = new Set();
    for (const [path, item] of Object.entries(document.paths)) {
      for (const [method, op] of Object.entries(item)) {
        if (!methods.has(method) || !(op.security ?? document.security).length) continue;
        const actualPath = path.replace('{id}', randomUUID());
        const result = await transport(
          method.toUpperCase(),
          actualPath,
          method === 'get' ? undefined : {},
        );
        errorCode(result, 401, 'UNAUTHENTICATED');
        authGuards.add(`${method.toUpperCase()} ${path}`);
      }
    }
    assert.ok(authGuards.size >= 25, 'Protected route inventory unexpectedly shrank');
    errorCode(await alice.request('POST', '/api/auth/login', {}), 400, 'INVALID_INPUT');
    const login = await alice.login();
    assert.equal(login.user.id, f.profiles.alice.userId);
    assert.ok(login.expiresAt > Date.now() && login.expiresAt <= Date.now() + 900000);
    assert.equal((await alice.ok('GET', '/api/auth/me')).device, null);
    errorCode(await alice.request('GET', '/api/objects'), 403, 'DEVICE_UNTRUSTED');
    errorCode(
      await alice.request('POST', '/api/auth/challenge', {
        purpose: 'operation',
        operation: 'submit',
        requestHash: hash('{}'),
      }),
      403,
      'DEVICE_UNTRUSTED',
    );

    const bindChallenge = await alice.ok('POST', '/api/auth/challenge', {
      purpose: 'bind',
      deviceId: f.profiles.alice.deviceId,
    });
    const binding = {
      deviceId: f.profiles.alice.deviceId,
      challengeId: bindChallenge.challengeId,
      signature: sign(bindChallenge.challenge, f.profiles.alice.keys.signing.privateKey),
    };
    errorCode(
      await alice.request('POST', '/api/auth/bind', {
        ...binding,
        signature: Buffer.alloc(64).toString('base64url'),
      }),
      403,
      'INVALID_PROOF',
    );
    assert.equal((await alice.ok('POST', '/api/auth/bind', binding)).device.status, 'approved');
    errorCode(
      await alice.request('POST', '/api/auth/bind', binding),
      403,
      'PROOF_REPLAY_OR_EXPIRED',
    );
    assert.equal((await alice.ok('GET', '/api/auth/me')).device.id, binding.deviceId);
    await bob.authenticate();
    await admin.authenticate();
    errorCode(
      await alice.request('POST', '/api/auth/challenge', {
        purpose: 'operation',
        operation: 'submit',
      }),
      400,
      'INVALID_INPUT',
    );

    const keys = deviceKeys();
    const enrollment = {
      label: 'contract-pending-device',
      signingPublicKey: keys.signing.publicKey,
      encryptionPublicKey: keys.encryption.publicKey,
    };
    const enrollChallenge = await alice.ok('POST', '/api/auth/challenge', {
      purpose: 'enroll',
      requestHash: hash(canonical(enrollment)),
    });
    const enrolled = await alice.ok('POST', '/api/devices/enroll', {
      ...enrollment,
      challengeId: enrollChallenge.challengeId,
      signature: sign(enrollChallenge.challenge, keys.signing.privateKey),
    });
    assert.equal(enrolled.device.status, 'pending');
    assert.equal(enrolled.device.userId, login.user.id);

    const meta = await f.transport('GET', '/api/meta');
    const publicKey = meta.body.serverPublicKey;
    const grant = await alice.grant();
    assert.ok(verify(grant.payload, grant.signature, publicKey));
    const object = createObject(f.profiles.alice, f.profiles.bob, grant, {
      data: 'SYNTHETIC contract payload',
    });
    const id = object.envelope.objectId;
    const invalidEnvelope = {
      ...object,
      envelope: { ...object.envelope, undeclaredField: true },
    };
    errorCode(
      await alice.request('POST', '/api/objects', {
        ...invalidEnvelope,
        proof: await alice.proof('submit', invalidEnvelope),
      }),
      400,
      'ENVELOPE_SCHEMA',
    );
    const proof = await alice.proof('submit', object);
    errorCode(
      await alice.request('POST', '/api/objects', { ...object, ciphertext: 'AA', proof }),
      403,
      'PROOF_BODY_MISMATCH',
    );
    const submitted = await alice.ok('POST', '/api/objects', { ...object, proof });
    assert.equal(submitted.object.state, 'PENDING');
    receipt(submitted.receipt, publicKey, 'SUBMITTED', id);
    errorCode(
      await alice.request('POST', '/api/objects', { ...object, proof }),
      403,
      'PROOF_REPLAY_OR_EXPIRED',
    );
    const listing = await bob.ok('GET', '/api/objects');
    assert.deepEqual(
      listing.objects.map((item) => item.objectId),
      [id],
    );
    assert.ok(!JSON.stringify(listing).includes('wrappedKey'));
    const prepared = await alice.prepare(id);
    assert.equal(prepared.body.object.state, 'READY');
    assert.ok(!JSON.stringify(prepared.body).includes('wrappedKey'));
    receipt(prepared.body.receipt, publicKey, 'ADMISSION', id);
    const current = await bob.ok('GET', '/api/control');
    errorCode(await alice.claim(id, current.payload.epoch), 403, 'RECIPIENT_ONLY');
    errorCode(
      await bob.request('POST', `/api/objects/${id}/claim`, {
        proof: await bob.proof('claim:' + id),
      }),
      400,
      'INVALID_INPUT',
    );
    const staleClaim = await bob.claim(id, current.payload.epoch + 1);
    errorCode(staleClaim, 409, 'EPOCH_MISMATCH');
    receipt(staleClaim.body.receipt, publicKey, 'RELEASE_DENIED', id);
    const claimed = await bob.claim(id, current.payload.epoch);
    assert.equal(claimed.status, 200);
    assert.equal(claimed.body.object.state, 'RELEASED');
    receipt(claimed.body.receipt, publicKey, 'RELEASE_ISSUED', id);
    assert.equal(
      decryptObject(claimed.body, f.profiles.bob).bytes.toString(),
      'SYNTHETIC contract payload',
    );
    const receiptId = claimed.body.receipt.payload.eventId;
    errorCode(
      await bob.request('POST', `/api/objects/${id}/ack`, {
        proof: await bob.proof('ack:' + id),
      }),
      400,
      'RECEIPT_INVALID',
    );
    const ackBody = { receiptId };
    const acknowledged = await bob.ok('POST', `/api/objects/${id}/ack`, {
      ...ackBody,
      proof: await bob.proof('ack:' + id, ackBody),
    });
    assert.equal(acknowledged.object.state, 'DELIVERED');
    receipt(acknowledged.receipt, publicKey, 'DELIVERY_ACK', id);

    const policy = {
      fromUnit: f.profiles.alice.unitId,
      toUnit: f.profiles.bob.unitId,
      missionId: 'DEMO-MISSION',
      allow: false,
    };
    errorCode(await alice.admin('PUT', '/api/admin/policies', policy), 403, 'FORBIDDEN');
    errorCode(
      await admin.request('PUT', '/api/admin/policies', policy),
      403,
      'PROOF_BODY_MISMATCH',
    );
    errorCode(
      await admin.admin('PUT', '/api/admin/policies', { ...policy, allow: 'false' }),
      400,
      'INVALID_INPUT',
    );
    const policyResult = await admin.admin('PUT', '/api/admin/policies', policy);
    assert.equal(policyResult.status, 200);
    assert.deepEqual(policyResult.body.policy, policy);
    const updated = await bob.ok('GET', '/api/control');
    assert.equal(updated.payload.epoch, current.payload.epoch + 1);
    assert.notEqual(updated.payload.policyDigest, current.payload.policyDigest);
    const held = await bob.claim(id, updated.payload.epoch);
    errorCode(held, 409, 'POLICY_DENIED');
    assert.equal(held.body.object.state, 'HELD');
    receipt(held.body.receipt, publicKey, 'RELEASE_DENIED', id);
    assert.equal(held.body.receipt.payload.reason, held.body.code);

    const rawErrors = [
      {
        headers: { 'Content-Type': 'application/json' },
        body: '{',
        code: 'INVALID_JSON',
        status: 400,
      },
      { headers: { 'Content-Type': 'text/plain' }, body: '{}', code: 'CONTENT_TYPE', status: 415 },
      {
        headers: { 'Content-Type': 'application/json', Origin: 'https://invalid.example' },
        body: '{}',
        code: 'ORIGIN_MISMATCH',
        status: 403,
      },
    ];
    for (const item of rawErrors) {
      const raw = await fetch(f.baseUrl + '/api/auth/login', {
        method: 'POST',
        headers: { ...item.headers, 'X-Request-Id': 'caller-controlled' },
        body: item.body,
      });
      const result = { status: raw.status, headers: raw.headers, body: await raw.json() };
      responseContract('POST', '/api/auth/login', result);
      errorCode(result, item.status, item.code);
    }
    assert.deepEqual(await alice.ok('POST', '/api/auth/logout', {}), { ok: true });
    errorCode(await alice.request('GET', '/api/auth/me'), 401, 'SESSION_INVALID');
    assert.deepEqual(
      successful,
      slice,
      'Every marked contract must execute successfully over HTTP',
    );
    const ids = captured.map(({ result }) => result.headers.get('x-request-id'));
    assert.equal(
      new Set(ids).size,
      ids.length,
      'Each HTTP response needs a distinct correlation ID',
    );
  },
);
