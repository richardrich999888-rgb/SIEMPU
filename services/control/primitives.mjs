import {
  createHash,
  randomBytes,
  scryptSync,
  timingSafeEqual,
  createCipheriv,
  createDecipheriv,
  createHmac,
  sign as ecSign,
  verify as ecVerify,
  createPrivateKey,
  createPublicKey,
} from 'node:crypto';
import { canonical } from '../../packages/protocol/canonical.mjs';
export { canonical };
export const hash = (value) => createHash('sha256').update(value).digest('hex');
export const encode = (v) => Buffer.from(v).toString('base64url');
export const decode = (v) => {
  if (typeof v !== 'string' || !/^[A-Za-z0-9_-]+$/.test(v)) throw new Error('Invalid encoding');
  const bytes = Buffer.from(v, 'base64url');
  if (bytes.toString('base64url') !== v) throw new Error('Noncanonical encoding');
  return bytes;
};
export const publicJwk = (k) => ({ kty: 'EC', crv: 'P-256', x: k.x, y: k.y });
export function validateKey(k, privateAllowed = false) {
  if (
    !k ||
    k.kty !== 'EC' ||
    k.crv !== 'P-256' ||
    (!privateAllowed && Object.hasOwn(k, 'd')) ||
    decode(k.x).length !== 32 ||
    decode(k.y).length !== 32
  )
    throw new Error('Invalid P256 key');
  createPublicKey({ key: publicJwk(k), format: 'jwk' });
  return publicJwk(k);
}
export const keyId = (k) => hash(canonical(publicJwk(k)));
export const sign = (key, value) =>
  ecSign('sha256', Buffer.from(canonical(value)), {
    key: createPrivateKey({ key, format: 'jwk' }),
    dsaEncoding: 'ieee-p1363',
  }).toString('base64url');
export function verify(key, value, sig) {
  try {
    return (
      decode(sig).length === 64 &&
      ecVerify(
        'sha256',
        Buffer.from(canonical(value)),
        {
          key: createPublicKey({ key: validateKey(key), format: 'jwk' }),
          dsaEncoding: 'ieee-p1363',
        },
        decode(sig),
      )
    );
  } catch {
    return false;
  }
}
export const packet = (key, payload) => ({
  payload,
  signature: sign(key, payload),
  keyId: keyId(key),
});
export const verifyPacket = (key, p) =>
  !!p && p.keyId === keyId(key) && verify(key, p.payload, p.signature);
export function passwordHash(password) {
  const salt = randomBytes(16);
  const result = scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 });
  return salt.toString('hex') + ':' + result.toString('hex');
}
export function passwordCheck(password, stored) {
  try {
    const [s, h] = stored.split(':');
    const result = scryptSync(password, Buffer.from(s, 'hex'), 32, { N: 16384, r: 8, p: 1 });
    return timingSafeEqual(result, Buffer.from(h, 'hex'));
  } catch {
    return false;
  }
}
export function seal(value, key) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  return JSON.stringify({
    iv: encode(iv),
    data: encode(Buffer.concat([c.update(value, 'utf8'), c.final()])),
    tag: encode(c.getAuthTag()),
  });
}
export function unseal(value, key) {
  const p = JSON.parse(value);
  const d = createDecipheriv('aes-256-gcm', key, decode(p.iv));
  d.setAuthTag(decode(p.tag));
  return Buffer.concat([d.update(decode(p.data)), d.final()]).toString();
}
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32(bytes) {
  let bits = 0,
    value = 0,
    out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
export function fromBase32(s) {
  let bits = 0,
    value = 0,
    out = [];
  for (const c of s) {
    const x = alphabet.indexOf(c);
    if (x < 0) throw new Error('Base32');
    value = (value << 5) | x;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}
export function totp(secret, time = Date.now()) {
  const count = Buffer.alloc(8);
  count.writeBigUInt64BE(BigInt(Math.floor(time / 30000)));
  const mac = createHmac('sha1', fromBase32(secret)).update(count).digest();
  const o = mac[mac.length - 1] & 15;
  return String((mac.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
}
export function totpCounter(secret, code, floor, time = Date.now()) {
  if (!/^\d{6}$/.test(code || '')) return -1;
  for (const delta of [-1, 0, 1]) {
    const t = time + delta * 30000,
      c = Math.floor(t / 30000);
    if (c > floor && timingSafeEqual(Buffer.from(totp(secret, t)), Buffer.from(code))) return c;
  }
  return -1;
}
