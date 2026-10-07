/** Must be called under the shared Web Lock when used by browser tabs. */
export function commitEncryptedVault(storage, key, expected, encryptedPacket) {
  if (storage.getItem(key) !== expected)
    throw new Error(
      'This vault changed in another tab. Export pending local work, then lock and unlock the latest vault before writing.',
    );
  const encoded = JSON.stringify(encryptedPacket);
  try {
    storage.setItem(key, encoded);
  } catch {
    throw new Error(
      'Encrypted vault storage is full or blocked. Export the vault and free storage before continuing.',
    );
  }
  return encoded;
}

export async function commitEncryptedVaultLocked(storage, locks, key, expected, encryptedPacket) {
  if (!locks || typeof locks.request !== 'function')
    throw new Error(
      'This browser cannot coordinate safe vault writes. A browser with Web Locks support is required.',
    );
  return locks.request(`siepmu-vault:${key}`, { mode: 'exclusive' }, () =>
    commitEncryptedVault(storage, key, expected, encryptedPacket),
  );
}
