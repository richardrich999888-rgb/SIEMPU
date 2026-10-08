import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { authorityPublicJwk } from './authority-pin.mjs';

test('authority pin accepts exact public coordinates and rejects private or unrelated fields', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicCoordinates = publicKey.export({ format: 'jwk' });
  assert.deepEqual(authorityPublicJwk(publicCoordinates), publicCoordinates);
  assert.throws(
    () => authorityPublicJwk(privateKey.export({ format: 'jwk' })),
    /no private or extra/,
  );
  assert.throws(() => authorityPublicJwk({ ...publicCoordinates, d: '' }), /no private or extra/);
  assert.throws(() => authorityPublicJwk({ ...publicCoordinates, x: 'bad' }), /size|base64/i);
  const imported = { ...publicCoordinates, password: 'synthetic-unrelated-credential' };
  assert.throws(() => authorityPublicJwk(imported), /no private or extra/);
});
