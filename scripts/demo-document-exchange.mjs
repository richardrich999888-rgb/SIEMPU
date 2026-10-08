// HPSC Demo 3 — existing-system integration (synthetic).
//
// A separate synthetic document-management system (apps/document-system) hands a document to
// the SIEPMU integration adapter (its own process, mTLS-pinned source identity). The adapter's
// managed endpoint seals and submits; the authority decides release; the destination system
// claims, decrypts at its endpoint, validates and acknowledges with a signed receipt. Duplicate,
// replay, unauthorised-destination and unauthenticated-source cases are refused.
//
// This is NOT an AFNET, e-Office or IAF interface. Synthetic data only. Output:
// artifacts/demo-document-exchange/{report.json,report.md,evidence.json,public-key.json}.
// Reset: remove that directory. Every run uses fresh temporary identities and PKI.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { provision } from '../tests/helpers/fixture.mjs';
import { ApiClient } from '../tests/helpers/client.mjs';
import { startSecureStack, secureApiTransport } from '../deployment/secure/harness.mjs';
import { startLabAdapter } from '../deployment/secure/adapter-process.mjs';
import { IntegrationEndpoint } from '../packages/integration/client.mjs';
import { createObjectCryptography } from '../packages/crypto/crypto.mjs';
import { DocumentOutbox, adapterTransport } from '../apps/document-system/outbox.mjs';
import { DocumentInbox } from '../apps/document-system/inbox.mjs';
import { SYNTHETIC_MARKING } from '../apps/document-system/document.mjs';
import { verifyEvidence } from '../apps/verifier/verify.mjs';
import { createDemoReport, writeDemoReport } from './lib/demo-report.mjs';

const OUTPUT = resolve(process.env.SIEPMU_EVIDENCE_DIR || 'artifacts/demo-document-exchange');
const RUST_VERIFIER = resolve('native/target/release/siepmu-evidence-verify');
const CANARY = 'SYNTHETIC_DMS_CANARY';

/** Runs the Rust reference verifier if built; returns null when the binary is absent. */
function rustVerify(evidencePath, keyPath) {
  if (!existsSync(RUST_VERIFIER)) return null;
  try {
    execFileSync(RUST_VERIFIER, [evidencePath, keyPath], { stdio: 'pipe' });
    return 'ACCEPT';
  } catch {
    return 'REJECT';
  }
}

export async function runDocumentExchangeDemo() {
  const { report, step } = createDemoReport({
    kind: 'demo-document-exchange',
    title: 'Demo 3 — synthetic existing-system integration through the adapter',
    configuration: {
      sourceSystem: 'apps/document-system (synthetic document-management emulator)',
      adapter:
        'services/integration/server.mjs, separate process, mTLS with pinned source identity',
      platform: 'five-process secure stack (TLS 1.3 gateway; mTLS between services)',
      documentMarking: SYNTHETIC_MARKING,
    },
    limitations: [
      'Synthetic document contract invented for the laboratory; no AFNET, e-Office or IAF interface is modelled or connected.',
      'Single host; all processes share one kernel and clock.',
      'The adapter holds a managed endpoint profile (software device keys) for the sending unit; no hardware custody.',
      'DELIVERY_ACK means the destination client processed the object, not that a person read it.',
      'Classical endpoint suite; no SAG grading.',
    ],
  });
  const crypto = createObjectCryptography();
  const f = await provision();
  const work = mkdtempSync(join(tmpdir(), 'siepmu-demo3-'));
  let stack, adapter, outbox, impostor;
  try {
    const { alice, bob, eve } = f.profiles;
    const destination = (p) => ({
      userId: p.userId,
      deviceId: p.deviceId,
      unitId: p.unitId,
      encryptionPublicKey: p.keys.encryption.publicKey,
    });
    const document = {
      version: 1,
      documentId: randomUUID(),
      reference: 'SYN/LOG/2026/013',
      title: 'Synthetic stores transfer note',
      marking: SYNTHETIC_MARKING,
      body: `${CANARY}: transfer two synthetic pallets to Unit B.`,
      originatorUserId: alice.userId,
      destinationUserId: bob.userId,
    };
    let accepted, outcome;

    await step('Start secure stack and the adapter as a separate process', async () => {
      stack = await startSecureStack(f.dir);
      adapter = await startLabAdapter({
        stack,
        dir: work,
        profile: alice,
        destinations: [destination(bob)],
      });
      outbox = new DocumentOutbox({
        database: join(work, 'dms-outbox.sqlite'),
        createFilePayload: crypto.createFilePayload,
        send: adapterTransport(adapter.url, adapter.sourceTls),
      });
      return { adapterUrl: adapter.url };
    });

    await step('Source system submits an authorised synthetic document', async () => {
      accepted = await outbox.submit(document);
      assert.match(accepted.objectId, /^[0-9a-f-]{36}$/);
      const state = (await outbox.status(document.documentId)).state;
      assert.equal(state, 'PENDING');
      return { objectId: accepted.objectId, state };
    });

    await step('Duplicate submission returns the same object (idempotent)', async () => {
      assert.deepEqual(await outbox.submit(document), accepted);
    });

    await step('Replay of the request with altered content is refused', async () => {
      const stored = JSON.parse(
        /** @type {string} */ (
          outbox.db
            .prepare('SELECT request FROM outbox WHERE document_id=?')
            .get(document.documentId).request
        ),
      );
      const r = await adapterTransport(adapter.url, adapter.sourceTls)('POST', '/v1/messages', {
        ...stored,
        payload: crypto.createTextPayload('altered'),
      });
      assert.equal(r.status, 409);
      return { httpStatus: r.status };
    });

    await step('Document for an unauthorised destination is refused', async () => {
      await assert.rejects(
        outbox.submit({ ...document, documentId: randomUUID(), destinationUserId: eve.userId }),
        { code: 'ADAPTER_REJECTED' },
      );
    });

    await step('Source presenting an unpinned client certificate is refused', async () => {
      impostor = new DocumentOutbox({
        database: join(work, 'impostor.sqlite'),
        createFilePayload: crypto.createFilePayload,
        send: adapterTransport(adapter.url, stack.pki.material('unit-denied')),
      });
      await assert.rejects(impostor.submit({ ...document, documentId: randomUUID() }), {
        code: 'SOURCE_NOT_AUTHENTICATED',
      });
    });

    await step('Destination system claims, decrypts, validates and acknowledges', async () => {
      const endpoint = new IntegrationEndpoint({
        url: stack.baseUrl,
        tls: stack.tls,
        profile: bob,
        authorityKey: f.provisioned.serverPublicKey,
      });
      await endpoint.authenticate();
      const inbox = new DocumentInbox({
        endpoint,
        senders: new Map([[alice.userId, alice.keys.signing.publicKey]]),
      });
      const outcomes = await inbox.poll();
      assert.equal(outcomes.length, 1);
      [outcome] = outcomes;
      assert.equal(outcome.outcome, 'DELIVERED');
      assert.deepEqual(outcome.document, document);
      assert.equal(
        await endpoint.crypto.verifyPacket(f.provisioned.serverPublicKey, outcome.acknowledgement),
        true,
      );
      return {
        releaseEventId: outcome.release.payload.eventId,
        acknowledgementEventId: outcome.acknowledgement.payload.eventId,
      };
    });

    await step('Source system observes delivery through the adapter', async () => {
      const state = (await outbox.status(document.documentId)).state;
      assert.equal(state, 'DELIVERED');
      return { state };
    });

    await step('Signed evidence verifies independently; a tampered copy is rejected', async () => {
      const admin = new ApiClient(secureApiTransport(stack.baseUrl, stack.tls), f.profiles.admin);
      await admin.authenticate();
      const evidence = await admin.ok('GET', '/api/evidence/export');
      const forObject = (type) =>
        evidence.records.filter(
          (r) => r.payload.objectId === accepted.objectId && r.payload.eventType === type,
        ).length;
      const counts = Object.fromEntries(
        ['SUBMITTED', 'RELEASE_ISSUED', 'DELIVERY_ACK'].map((t) => [t, forObject(t)]),
      );
      assert.deepEqual(counts, { SUBMITTED: 1, RELEASE_ISSUED: 1, DELIVERY_ACK: 1 });
      const chain = await verifyEvidence(evidence, f.provisioned.serverPublicKey);
      mkdirSync(OUTPUT, { recursive: true });
      const evidencePath = join(OUTPUT, 'evidence.json');
      const keyPath = join(OUTPUT, 'public-key.json');
      writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));
      writeFileSync(keyPath, JSON.stringify(f.provisioned.serverPublicKey, null, 2));
      const tampered = structuredClone(evidence);
      tampered.records[0].payload.decision = 'TAMPERED';
      await assert.rejects(verifyEvidence(tampered, f.provisioned.serverPublicKey));
      const tamperedPath = join(work, 'tampered.json');
      writeFileSync(tamperedPath, JSON.stringify(tampered));
      const rust = rustVerify(evidencePath, keyPath);
      const rustTampered = rustVerify(tamperedPath, keyPath);
      if (rust !== null) {
        assert.equal(rust, 'ACCEPT');
        assert.equal(rustTampered, 'REJECT');
      }
      return {
        eventCounts: counts,
        nodeVerifier: { records: chain.records ?? evidence.records.length, tampered: 'REJECT' },
        rustVerifier: rust === null ? 'NOT_BUILT' : { genuine: rust, tampered: rustTampered },
      };
    });

    await step('No document plaintext in the adapter store or adapter logs', async () => {
      assert.equal(readFileSync(join(work, 'adapter.sqlite')).includes(CANARY), false);
      assert.equal(adapter.logs().includes(CANARY), false);
    });
    report.outcome = 'PASS';
  } catch {
    report.outcome = 'FAIL';
  } finally {
    outbox?.close();
    impostor?.close();
    await adapter?.stop();
    await stack?.stop();
    rmSync(work, { recursive: true, force: true });
    rmSync(f.dir, { recursive: true, force: true });
    await writeDemoReport(OUTPUT, report);
  }
  return report;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const report = await runDocumentExchangeDemo();
  console.log(`Demo 3 ${report.outcome}: ${join(OUTPUT, 'report.json')}`);
  if (report.outcome !== 'PASS') process.exitCode = 1;
}
