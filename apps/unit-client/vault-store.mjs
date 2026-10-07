/** Compare before synchronous write so stale tabs cannot overwrite newer local work. */
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
