import test from 'node:test';
import assert from 'node:assert/strict';
import { commitEncryptedVault, commitEncryptedVaultLocked } from './vault-store.mjs';

function memoryStore() {
  const map = new Map();
  return { getItem: (key) => map.get(key) ?? null, setItem: (key, value) => map.set(key, value) };
}
test('stale browser tab cannot overwrite a newer encrypted outbox snapshot', () => {
  const storage = memoryStore();
  const original = commitEncryptedVault(storage, 'vault', null, {
    ciphertext: 'first-sealed-snapshot',
  });
  const newer = commitEncryptedVault(storage, 'vault', original, {
    ciphertext: 'newer-sealed-snapshot',
  });
  assert.throws(
    () => commitEncryptedVault(storage, 'vault', original, { ciphertext: 'stale-tab-snapshot' }),
    /another tab/,
  );
  assert.equal(storage.getItem('vault'), newer);
});
test('blocked durable storage is reported without reporting success', () => {
  const storage = {
    getItem: () => null,
    setItem: () => {
      throw new Error('QuotaExceededError');
    },
  };
  assert.throws(
    () => commitEncryptedVault(storage, 'vault', null, { ciphertext: 'sealed' }),
    /storage is full or blocked/,
  );
});

test('cooperating simultaneous vault writes are serialized and stale one is rejected', async () => {
  const storage = memoryStore();
  let queue = Promise.resolve();
  const locks = {
    request: (_name, _options, callback) => {
      const result = queue.then(callback);
      queue = result.catch(() => {});
      return result;
    },
  };
  const results = await Promise.allSettled([
    commitEncryptedVaultLocked(storage, locks, 'vault', null, { ciphertext: 'first' }),
    commitEncryptedVaultLocked(storage, locks, 'vault', null, { ciphertext: 'second' }),
  ]);
  assert.deepEqual(
    results.map((r) => r.status),
    ['fulfilled', 'rejected'],
  );
  assert.equal(storage.getItem('vault'), JSON.stringify({ ciphertext: 'first' }));
});
test('vault writes fail closed when cooperative Web Locks are unavailable', async () => {
  const storage = memoryStore();
  await assert.rejects(
    commitEncryptedVaultLocked(storage, undefined, 'vault', null, { ciphertext: 'sealed' }),
    /Web Locks/,
  );
  assert.equal(storage.getItem('vault'), null);
});
