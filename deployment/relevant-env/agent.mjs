// Host agent: runs INSIDE one host namespace and holds only that host's state directory.
//
// Usage: ip netns exec <ns> node deployment/relevant-env/agent.mjs <command> '<json-args>'
// Environment: SIEPMU_HOST_STATE (this host's directory), SIEPMU_GATEWAY_URL (https://web:<port>).
// Output: exactly one JSON line. Expected refusals are reported as {ok:false, status, code};
// the exit code is non-zero only for crashes, so the conductor can tell a refusal from a fault.
//
// State layout (written by the conductor's offline provisioning step, public data except the
// host's own profiles):
//   ca.crt, authority-public.json, peers.json (public descriptors by username),
//   profiles/<username>.json (this host's users only), sessions/<username>.json (tokens),
//   queue/<name>.json (sealed objects awaiting submission), grants/<username>.json.

import { mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { IntegrationEndpoint } from '../../packages/integration/client.mjs';
import { ApiClient, enrollUser } from '../../tests/helpers/client.mjs';
import { secureApiTransport } from '../secure/harness.mjs';
import { requestBytes } from '../../packages/transport/tls.mjs';
import { connect } from 'node:net';
import { DocumentOutbox, adapterTransport } from '../../apps/document-system/outbox.mjs';
import { DocumentInbox } from '../../apps/document-system/inbox.mjs';
import { createObjectCryptography } from '../../packages/crypto/crypto.mjs';
import { syntheticBytes } from './payload.mjs';
import { execFileSync } from 'node:child_process';
import { verifyEvidence } from '../../apps/verifier/verify.mjs';

const STATE = process.env.SIEPMU_HOST_STATE;
const GATEWAY = process.env.SIEPMU_GATEWAY_URL;
if (!STATE || !GATEWAY) throw new Error('SIEPMU_HOST_STATE and SIEPMU_GATEWAY_URL are required');

const readJson = (...p) => JSON.parse(readFileSync(join(STATE, ...p), 'utf8'));
const writeJson = (value, ...p) => {
  mkdirSync(join(STATE, ...p.slice(0, -1)), { recursive: true });
  writeFileSync(join(STATE, ...p), JSON.stringify(value), { mode: 0o600 });
};
const tls = () => ({ ca: readFileSync(join(STATE, 'ca.crt')) });
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const ms = (start) => Math.round((performance.now() - start) * 100) / 100;

/** Unit endpoint for a local user, reusing a saved session (one MFA login per run). */
async function unit(username) {
  const endpoint = new IntegrationEndpoint({
    url: GATEWAY,
    tls: tls(),
    profile: readJson('profiles', `${username}.json`),
    authorityKey: readJson('authority-public.json'),
  });
  if (existsSync(join(STATE, 'sessions', `${username}.json`)))
    endpoint.token = readJson('sessions', `${username}.json`).token;
  else {
    await endpoint.authenticate();
    writeJson({ token: endpoint.token }, 'sessions', `${username}.json`);
  }
  return endpoint;
}

/** Administrator client (Host B), reusing a saved session. */
async function administrator(username) {
  const client = new ApiClient(
    secureApiTransport(GATEWAY, tls()),
    readJson('profiles', `${username}.json`),
  );
  if (existsSync(join(STATE, 'sessions', `${username}.json`)))
    client.token = readJson('sessions', `${username}.json`).token;
  else {
    await client.authenticate();
    writeJson({ token: client.token }, 'sessions', `${username}.json`);
  }
  return client;
}

const recipient = (name) => {
  const p = readJson('peers.json')[name];
  if (!p) throw new Error(`Unknown peer ${name}`);
  return p;
};
const refusal = (error) => ({
  ok: false,
  status: error.status ?? null,
  code: error.code ?? error.message ?? 'ERROR',
});

const commands = {
  /** Polls the gateway readiness endpoint (bounded). */
  async ready({ attempts = 200 } = {}) {
    for (let i = 0; i < attempts; i++) {
      try {
        const r = await requestBytes(GATEWAY + '/health/ready', { tls: tls(), timeoutMs: 1000 });
        if (r.status === 200) return { ok: true, attempts: i + 1 };
      } catch {}
      await new Promise((r) => setTimeout(r, 50));
    }
    return { ok: false, code: 'NOT_READY' };
  },

  /** MFA login + device binding for a local user. */
  async login({ user }) {
    const started = performance.now();
    await unit(user);
    return { ok: true, loginMs: ms(started) };
  },

  /** Wrong one-time password: must be refused (401). */
  async loginWrongOtp({ user }) {
    const p = readJson('profiles', `${user}.json`);
    const r = await requestBytes(GATEWAY + '/api/auth/login', {
      method: 'POST',
      tls: tls(),
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: p.username, password: p.password, otp: '000000' }),
    });
    return { ok: r.status === 200, status: r.status };
  },

  /** TLS with a trust root that did not issue the gateway certificate: must fail. */
  async wrongTrustRoot({ caPath }) {
    try {
      await requestBytes(GATEWAY + '/health/ready', {
        tls: { ca: readFileSync(caPath) },
        timeoutMs: 3000,
      });
      return { ok: true, code: 'CONNECTED' };
    } catch (error) {
      return { ok: false, code: error.code ?? error.message };
    }
  },

  /** Seal and submit online; returns timings and the payload digest. */
  async send({ user, to, bytes, seed = 1 }) {
    const endpoint = await unit(user);
    const data = syntheticBytes(bytes, seed);
    const payload = endpoint.crypto.createFilePayload(
      `synthetic-${seed}.bin`,
      'application/octet-stream',
      data,
    );
    const t0 = performance.now();
    try {
      const sealed = await endpoint.seal(recipient(to), payload);
      const t1 = performance.now();
      const result = await endpoint.submit(sealed);
      return {
        ok: true,
        objectId: result.object.id,
        sha256: sha256(data),
        sealMs: Math.round((t1 - t0) * 100) / 100,
        submitMs: ms(t1),
      };
    } catch (error) {
      return refusal(error);
    }
  },

  /** Obtains and caches a creation grant while online (for later offline sealing). */
  async grant({ user }) {
    const endpoint = await unit(user);
    const g = await endpoint.call('POST', '/api/grants', { proof: await endpoint.proof('grant') });
    writeJson(g, 'grants', `${user}.json`);
    return { ok: true, expiresAt: g.payload.expiresAt };
  },

  /** Seals with the cached grant WITHOUT contacting the platform (offline queue). */
  async queue({ user, to, bytes, seed = 1, name }) {
    const endpoint = await unit(user);
    const data = syntheticBytes(bytes, seed);
    const payload = endpoint.crypto.createFilePayload(
      `queued-${seed}.bin`,
      'application/octet-stream',
      data,
    );
    const sealed = await endpoint.sealUsingGrant(
      recipient(to),
      payload,
      readJson('grants', `${user}.json`),
    );
    writeJson(sealed, 'queue', `${name}.json`);
    return { ok: true, objectId: sealed.envelope.objectId, sha256: sha256(data) };
  },

  /** Submits a queued object (after reconnection). */
  async submitQueued({ user, name }) {
    const endpoint = await unit(user);
    const started = performance.now();
    try {
      const result = await endpoint.submit(readJson('queue', `${name}.json`));
      return { ok: true, objectId: result.object.id, submitMs: ms(started) };
    } catch (error) {
      return refusal(error);
    }
  },

  /** Claims, decrypts and acknowledges; returns the plaintext digest and signed receipts. */
  async receive({ user, objectId, from, ack = true }) {
    const endpoint = await unit(user);
    const started = performance.now();
    try {
      const delivered = await endpoint.receiveWithRelease(
        objectId,
        recipient(from).signingPublicKey,
      );
      const plain = endpoint.crypto.unpackPayload(delivered.plaintext);
      const receiveMs = ms(started);
      const acknowledgement = ack ? await endpoint.acknowledge(objectId, delivered.release) : null;
      return {
        ok: true,
        sha256: sha256(plain.bytes),
        bytes: plain.bytes.length,
        receiveMs,
        releaseEventId: delivered.release.payload.eventId,
        ackEventId: acknowledgement?.payload.eventId ?? null,
      };
    } catch (error) {
      return refusal(error);
    }
  },

  /** Administrator call through the gateway (Host B operator position). */
  async admin({ user, method, path, body = {} }) {
    const client = await administrator(user);
    const r = await client.admin(method, path, body);
    return { ok: r.status === 200, status: r.status, body: r.body };
  },

  /**
   * Administrator enrols synthetic users and approves their devices. Lab provisioning only: the
   * device keys are generated here and handed to the target host by the conductor; in a
   * deployment they are generated on the device itself.
   */
  async enroll({ user, users }) {
    const client = await administrator(user);
    const profiles = [];
    // enrollUser already logged the new user in (consuming its current TOTP code); the bound
    // session token is handed over too, so the target host does not replay that code.
    for (const u of users) {
      const enrolled = await enrollUser(client, u);
      profiles.push({ profile: enrolled.profile, token: enrolled.client.token });
    }
    return { ok: true, profiles };
  },

  /** Exports the signed evidence chain to a file in this host's state. */
  async exportEvidence({ user, file }) {
    const client = await administrator(user);
    const evidence = await client.ok('GET', '/api/evidence/export');
    writeJson(evidence, file);
    return { ok: true, records: evidence.records.length };
  },

  /**
   * Concurrent load: each listed user runs `workers` sequential send loops for `seconds`.
   * Returns per-operation latencies (ms) and counts; refusals are counted, never hidden.
   */
  async loadSend({ users, to, seconds, bytes, workers = 1 }) {
    const endpoints = await Promise.all(users.map((u) => unit(u)));
    const deadline = Date.now() + seconds * 1000;
    const latencies = [];
    const sent = [];
    let refused = 0;
    let seed = 1000;
    await Promise.all(
      endpoints.flatMap((endpoint, i) =>
        Array.from({ length: workers }, async () => {
          while (Date.now() < deadline) {
            const s = seed++;
            const data = syntheticBytes(bytes, s);
            const payload = endpoint.crypto.createFilePayload(
              `load-${s}.bin`,
              'application/octet-stream',
              data,
            );
            const t0 = performance.now();
            try {
              const sealed = await endpoint.seal(recipient(to[i % to.length]), payload);
              const result = await endpoint.submit(sealed);
              latencies.push(ms(t0));
              sent.push({
                objectId: result.object.id,
                to: to[i % to.length],
                sha256: sha256(data),
              });
            } catch {
              refused++;
            }
          }
        }),
      ),
    );
    writeJson(sent, 'load-sent.json');
    return { ok: true, sent: sent.length, refused, latencies };
  },

  /** Drains every pending object for the listed local users; verifies digests against a manifest. */
  async loadReceive({ users, from, manifest }) {
    const expected = new Map(readJson(manifest).map((m) => [m.objectId, m]));
    const endpoints = new Map(await Promise.all(users.map(async (u) => [u, await unit(u)])));
    const latencies = [];
    let delivered = 0;
    let mismatched = 0;
    let failed = 0;
    await Promise.all(
      [...endpoints.entries()].map(async ([user, endpoint]) => {
        const pending = (await endpoint.listObjects()).filter(
          (o) =>
            o.recipientUserId === endpoint.profile.userId && ['PENDING', 'READY'].includes(o.state),
        );
        for (const object of pending) {
          const t0 = performance.now();
          try {
            const d = await endpoint.receiveWithRelease(
              object.id,
              recipient(from[object.senderUserId] ?? from._).signingPublicKey,
            );
            await endpoint.acknowledge(object.id, d.release);
            latencies.push(ms(t0));
            const digest = sha256(endpoint.crypto.unpackPayload(d.plaintext).bytes);
            if (expected.get(object.id)?.sha256 === digest) delivered++;
            else mismatched++;
          } catch {
            failed++;
          }
        }
        void user;
      }),
    );
    return { ok: mismatched === 0 && failed === 0, delivered, mismatched, failed, latencies };
  },

  /** Claims with an explicitly stale epoch: the authority must fence it. */
  async claimStale({ user, objectId, epoch }) {
    const endpoint = await unit(user);
    const body = { expectedEpoch: epoch };
    try {
      await endpoint.call('POST', `/api/objects/${objectId}/claim`, {
        ...body,
        proof: await endpoint.proof('claim:' + objectId, body),
      });
      return { ok: true };
    } catch (error) {
      return refusal(error);
    }
  },

  /** Current signed control epoch as seen by a unit. */
  async epoch({ user }) {
    try {
      const endpoint = await unit(user);
      return { ok: true, epoch: (await endpoint.signed('/api/control')).payload.epoch };
    } catch (error) {
      return refusal(error);
    }
  },

  /** Submits a synthetic document through the local adapter with a named client identity. */
  async dmsSubmit({ document, identity, adapterUrl }) {
    const outbox = new DocumentOutbox({
      database: join(STATE, `dms-${identity}.sqlite`),
      createFilePayload: createObjectCryptography().createFilePayload,
      send: adapterTransport(adapterUrl, {
        ca: readFileSync(join(STATE, 'ca.crt')),
        cert: readFileSync(join(STATE, 'tls', `${identity}.crt`)),
        key: readFileSync(join(STATE, 'tls', `${identity}.key`)),
      }),
    });
    try {
      return { ok: true, ...(await outbox.submit(document)) };
    } catch (error) {
      return refusal(error);
    } finally {
      outbox.close();
    }
  },

  /** Delivery state of a submitted document, via the adapter. */
  async dmsStatus({ documentId, identity, adapterUrl }) {
    const outbox = new DocumentOutbox({
      database: join(STATE, `dms-${identity}.sqlite`),
      createFilePayload: createObjectCryptography().createFilePayload,
      send: adapterTransport(adapterUrl, {
        ca: readFileSync(join(STATE, 'ca.crt')),
        cert: readFileSync(join(STATE, 'tls', `${identity}.crt`)),
        key: readFileSync(join(STATE, 'tls', `${identity}.key`)),
      }),
    });
    try {
      return { ok: true, ...(await outbox.status(documentId)) };
    } catch (error) {
      return refusal(error);
    } finally {
      outbox.close();
    }
  },

  /** Destination document system: claims, validates and acknowledges pending documents. */
  async dmsReceive({ user, senders }) {
    const endpoint = await unit(user);
    const peers = readJson('peers.json');
    const inbox = new DocumentInbox({
      endpoint,
      senders: new Map(senders.map((n) => [peers[n].userId, peers[n].signingPublicKey])),
    });
    const outcomes = await inbox.poll();
    return {
      ok: true,
      outcomes: outcomes.map((o) => ({
        objectId: o.objectId,
        outcome: o.outcome,
        code: o.code ?? null,
        documentId: o.document?.documentId ?? null,
        ackEventId: o.acknowledgement?.payload.eventId ?? null,
      })),
    };
  },

  /** Attempts a TCP connection to an address outside the enclave (sovereignty check). */
  async external({ host, port }) {
    return await new Promise((resolve) => {
      const socket = connect({ host, port, timeout: 3000 });
      socket.on('connect', () => {
        socket.destroy();
        resolve({ ok: true, code: 'CONNECTED' });
      });
      socket.on('timeout', () => {
        socket.destroy();
        resolve({ ok: false, code: 'TIMEOUT' });
      });
      socket.on('error', (error) => resolve({ ok: false, code: error.code }));
    });
  },

  /** A unit calling an administrative route: must be refused (403). */
  async forbidden({ user }) {
    const endpoint = await unit(user);
    try {
      await endpoint.call('GET', '/api/admin/overview');
      return { ok: true };
    } catch (error) {
      return refusal(error);
    }
  },

  /** Number of objects this user can see (to prove nothing half-written appears). */
  async count({ user }) {
    try {
      const endpoint = await unit(user);
      return { ok: true, objects: (await endpoint.listObjects()).length };
    } catch (error) {
      return refusal(error);
    }
  },

  /** Operator view of the independent collector (Host B), with a named client identity. */
  async collector({ identity, action = 'list', eventId, port }) {
    const material = {
      ca: readFileSync(join(STATE, 'ca.crt')),
      cert: readFileSync(join(STATE, 'tls', `${identity}.crt`)),
      key: readFileSync(join(STATE, 'tls', `${identity}.key`)),
    };
    const base = `https://127.0.0.1:${port}`;
    const r =
      action === 'ack'
        ? await requestBytes(base + '/v1/ack', {
            method: 'POST',
            tls: material,
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ eventId, disposition: 'INVESTIGATING' }),
          })
        : await requestBytes(base + '/v1/events', { tls: material });
    let body = null;
    try {
      body = JSON.parse(r.body);
    } catch {}
    return {
      ok: r.status === 200,
      status: r.status,
      events: action === 'list' ? (body?.events ?? []) : undefined,
    };
  },

  /** Offline evidence verification on this host: Node verifier and, if built, the Rust verifier. */
  async verify({ file, rustBinary }) {
    const evidence = readJson(file);
    const key = readJson('authority-public.json');
    const tampered = structuredClone(evidence);
    tampered.records[Math.floor(tampered.records.length / 2)].payload.decision = 'TAMPERED';
    writeJson(tampered, 'evidence-tampered.json');
    let node = 'ACCEPT';
    try {
      await verifyEvidence(evidence, key);
    } catch {
      node = 'REJECT';
    }
    let nodeTampered = 'ACCEPT';
    try {
      await verifyEvidence(tampered, key);
    } catch {
      nodeTampered = 'REJECT';
    }
    const rust = (path) => {
      if (!rustBinary || !existsSync(rustBinary)) return 'NOT_BUILT';
      try {
        execFileSync(rustBinary, [join(STATE, path), join(STATE, 'authority-public.json')], {
          stdio: 'pipe',
        });
        return 'ACCEPT';
      } catch {
        return 'REJECT';
      }
    };
    return {
      ok: true,
      records: evidence.records.length,
      node,
      nodeTampered,
      rust: rust(file),
      rustTampered: rust('evidence-tampered.json'),
    };
  },

  /** Replays a stored adapter request with an altered payload under the same request ID. */
  async dmsReplayAltered({ documentId, identity, adapterUrl }) {
    const { DatabaseSync } = await import('node:sqlite');
    const db = new DatabaseSync(join(STATE, `dms-${identity}.sqlite`));
    const row = db.prepare('SELECT request FROM outbox WHERE document_id=?').get(documentId);
    db.close();
    const request = JSON.parse(String(row.request));
    const send = adapterTransport(adapterUrl, {
      ca: readFileSync(join(STATE, 'ca.crt')),
      cert: readFileSync(join(STATE, 'tls', `${identity}.crt`)),
      key: readFileSync(join(STATE, 'tls', `${identity}.key`)),
    });
    const r = await send('POST', '/v1/messages', {
      ...request,
      payload: createObjectCryptography().createTextPayload('ALTERED'),
    });
    return { ok: r.status === 200, status: r.status };
  },

  /** Lists files in this host's state (for the isolation audit; names only). */
  async inventory() {
    const walk = (dir, prefix = '') =>
      readdirSync(join(STATE, dir), { withFileTypes: true }).flatMap((e) =>
        e.isDirectory() ? walk(join(dir, e.name), prefix + e.name + '/') : [prefix + e.name],
      );
    return { ok: true, files: walk('.') };
  },
};

const [command, rawArgs = '{}'] = process.argv.slice(2);
if (!Object.hasOwn(commands, command)) throw new Error(`Unknown command ${command}`);
const result = await commands[command](JSON.parse(rawArgs));
process.stdout.write(JSON.stringify(result) + '\n');
