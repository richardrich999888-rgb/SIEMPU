import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { authorityPublicJwk } from './authority-pin.mjs';

test('authority pin rejects private material and retains only validated public coordinates', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicCoordinates = publicKey.export({ format: 'jwk' });
  assert.deepEqual(authorityPublicJwk(publicCoordinates), publicCoordinates);
  assert.throws(() => authorityPublicJwk(privateKey.export({ format: 'jwk' })), /only public/);
  assert.throws(() => authorityPublicJwk({ ...publicCoordinates, d: '' }), /only public/);
  assert.throws(() => authorityPublicJwk({ ...publicCoordinates, x: 'bad' }), /size|base64/i);
  const imported = { ...publicCoordinates, password: 'synthetic-unrelated-credential' };
  assert.deepEqual(authorityPublicJwk(imported), publicCoordinates);
  assert.equal(JSON.stringify(authorityPublicJwk(imported)).includes('credential'), false);
});
