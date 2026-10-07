import test from 'node:test';
import assert from 'node:assert/strict';
import { commitEncryptedVault } from './vault-store.mjs';

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
