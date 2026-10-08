import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  readdirSync,
  lstatSync,
  chmodSync,
  renameSync,
  rmSync,
  existsSync,
  openSync,
  closeSync,
  fsyncSync,
  constants,
} from 'node:fs';
import { join, resolve, dirname, relative, sep } from 'node:path';
import { randomUUID } from 'node:crypto';
import { canonical, hash, packet, verifyPacket } from '../../services/control/primitives.mjs';

const validPath = (p) =>
  typeof p === 'string' &&
  p.length < 300 &&
  /^[A-Za-z0-9_./-]+$/.test(p) &&
  !p.startsWith('/') &&
  p.split('/').every((x) => x && x !== '.' && x !== '..');
function files(root, prefix = '') {
  const out = [];
  for (const name of readdirSync(join(root, prefix)).sort()) {
    const path = prefix ? prefix + '/' + name : name,
      st = lstatSync(join(root, path));
    if (st.isSymbolicLink() || !validPath(path)) throw new Error('PACKAGE_UNSAFE_PATH');
    if (st.isDirectory()) out.push(...files(root, path));
    else if (st.isFile()) out.push(path);
    else throw new Error('PACKAGE_SPECIAL_FILE');
  }
  return out;
}
function readBounded(path, limit) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    if (lstatSync(path).size > limit) throw new Error('PACKAGE_SIZE_LIMIT');
    const data = readFileSync(fd);
    if (data.length > limit) throw new Error('PACKAGE_SIZE_LIMIT');
    return data;
  } finally {
    closeSync(fd);
  }
}
function durableWrite(path, content, mode = 0o600) {
  const fd = openSync(path, 'wx', mode);
  try {
    writeFileSync(fd, content);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
function syncDirectory(path) {
  const fd = openSync(path, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

export function buildOfflineBundle({
  source,
  destination,
  signingKey,
  version,
  revision,
  runtime = process.execPath,
}) {
  if (!Number.isSafeInteger(version) || version < 1 || !/^[a-f0-9]{40}$/.test(revision))
    throw new Error('RELEASE_IDENTITY');
  source = resolve(source);
  destination = resolve(destination);
  if (existsSync(destination)) throw new Error('PACKAGE_DESTINATION_EXISTS');
  mkdirSync(join(destination, 'files'), { recursive: true, mode: 0o700 });
  const entries = [];
  const add = (from, path, mode = 0o644) => {
    const data = readBounded(from, 180 * 1024 * 1024);
    mkdirSync(dirname(join(destination, 'files', path)), { recursive: true, mode: 0o700 });
    durableWrite(join(destination, 'files', path), data, mode);
    entries.push({ path, size: data.length, sha256: hash(data), mode });
  };
  for (const folder of ['apps', 'services', 'packages', 'database', 'scripts', 'deployment'])
    for (const name of files(join(source, folder))) {
      if (!/\.(mjs|js|json|css|html|sql|md|yaml|yml|sh|svg|txt|ts)$/.test(name)) continue;
      add(join(source, folder, name), 'app/' + folder + '/' + name);
    }
  for (const name of ['package.json', 'package-lock.json', 'LICENSE'])
    if (existsSync(join(source, name))) add(join(source, name), 'app/' + name);
  add(runtime, 'runtime/node', 0o755);
  const manifest = packet(signingKey, {
    format: 'SIEPMU_OFFLINE_RELEASE_V1',
    version,
    revision,
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    createdAt: Date.now(),
    files: entries.sort((a, b) => a.path.localeCompare(b.path)),
    limitations: [
      'Laboratory software keys; no SAG or deployment approval',
      'Runtime requires compatible OS shared libraries; OS image not included',
      'Operator provisions identity, PKI, checkpoints and independent signing trust locally',
    ],
  });
  durableWrite(join(destination, 'manifest.json'), canonical(manifest));
  syncDirectory(destination);
  return manifest;
}
export function installOfflineBundle(options) {
  const lock = resolve(options.ledger) + '.lock';
  mkdirSync(dirname(lock), { recursive: true, mode: 0o700 });
  mkdirSync(lock, { mode: 0o700 });
  try {
    return installLocked(options);
  } finally {
    rmSync(lock, { recursive: true, force: true });
  }
}
function installLocked({
  bundle,
  destination,
  ledger,
  trustedKey,
  initialize = false,
  rollbackAuthorization,
  recoveryKey,
  fault,
}) {
  bundle = resolve(bundle);
  destination = resolve(destination);
  ledger = resolve(ledger);
  if (ledger === destination || ledger.startsWith(destination + sep))
    throw new Error('LEDGER_MUST_BE_INDEPENDENT');
  const signed = JSON.parse(readBounded(join(bundle, 'manifest.json'), 8 * 1024 * 1024));
  if (!verifyPacket(trustedKey, signed)) throw new Error('RELEASE_SIGNATURE');
  const m = signed.payload,
    digest = hash(canonical(signed));
  if (
    m.format !== 'SIEPMU_OFFLINE_RELEASE_V1' ||
    m.platform !== process.platform ||
    m.arch !== process.arch ||
    !Number.isSafeInteger(m.version) ||
    m.version < 1 ||
    !Array.isArray(m.files) ||
    m.files.length < 1 ||
    m.files.length > 10000
  )
    throw new Error('RELEASE_MANIFEST');
  const names = m.files.map((f) => f.path);
  if (
    new Set(names).size !== names.length ||
    names.some((p) => !validPath(p) || !['app/', 'runtime/'].some((prefix) => p.startsWith(prefix)))
  )
    throw new Error('RELEASE_PATH');
  if (files(join(bundle, 'files')).sort().join('\n') !== [...names].sort().join('\n'))
    throw new Error('RELEASE_INVENTORY');
  const exists = existsSync(ledger);
  if (!exists && (!initialize || existsSync(destination)))
    throw new Error('RELEASE_LEDGER_MISSING');
  const old = exists
    ? JSON.parse(readBounded(ledger, 1024 * 1024))
    : { floor: 0, digest: null, used: [], trustId: signed.keyId };
  if (old.trustId !== signed.keyId) throw new Error('RELEASE_TRUST_CHANGED');
  let used = old.used;
  if (m.version <= old.floor && old.digest !== digest) {
    const auth = rollbackAuthorization?.payload,
      now = Date.now();
    if (
      !recoveryKey ||
      !verifyPacket(recoveryKey, rollbackAuthorization) ||
      auth.action !== 'AUTHORIZE_LAB_ROLLBACK' ||
      auth.fromDigest !== old.digest ||
      auth.toDigest !== digest ||
      auth.floor !== old.floor ||
      !Number.isSafeInteger(auth.expiresAt) ||
      auth.expiresAt <= now ||
      auth.expiresAt > now + 300000 ||
      typeof auth.nonce !== 'string' ||
      used.includes(auth.nonce)
    )
      throw new Error('RELEASE_ROLLBACK_DENIED');
    used = [...used, auth.nonce];
  }
  // Hash every file even on idempotent re-install; never trust the manifest alone.
  let total = 0;
  for (const f of m.files) {
    if (
      ![0o644, 0o755].includes(f.mode) ||
      !Number.isSafeInteger(f.size) ||
      f.size < 0 ||
      f.size > 180 * 1024 * 1024 ||
      !/^[a-f0-9]{64}$/.test(f.sha256)
    )
      throw new Error('RELEASE_FILE_SCHEMA');
    total += f.size;
  }
  if (total > 256 * 1024 * 1024) throw new Error('RELEASE_SIZE_LIMIT');
  const stage = destination + '.stage-' + randomUUID();
  mkdirSync(stage, { recursive: true, mode: 0o700 });
  try {
    for (const f of m.files) {
      const data = readBounded(join(bundle, 'files', f.path), f.size);
      if (data.length !== f.size || hash(data) !== f.sha256) throw new Error('RELEASE_DIGEST');
      const path = join(stage, f.path);
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      durableWrite(path, data, f.mode);
      chmodSync(path, f.mode);
    }
    durableWrite(join(stage, 'manifest.json'), canonical(signed));
    fault?.('before-promote');
    mkdirSync(destination, { recursive: true, mode: 0o700 });
    const release = join(destination, digest);
    if (!existsSync(release)) renameSync(stage, release);
    else {
      if (lstatSync(release).isSymbolicLink()) throw new Error('RELEASE_UNSAFE_INSTALLATION');
      for (const f of m.files)
        if (hash(readBounded(join(release, f.path), f.size)) !== f.sha256)
          throw new Error('INSTALLED_RELEASE_CORRUPT');
      rmSync(stage, { recursive: true });
    }
    syncDirectory(destination);
    fault?.('before-activate');
    mkdirSync(dirname(ledger), { recursive: true, mode: 0o700 });
    const next = {
      floor: Math.max(old.floor, m.version),
      digest,
      used,
      trustId: signed.keyId,
      active: relative(dirname(ledger), release),
      activatedAt: Date.now(),
    };
    const tmp = ledger + '.tmp-' + randomUUID();
    durableWrite(tmp, canonical(next));
    renameSync(tmp, ledger);
    syncDirectory(dirname(ledger));
    return { status: 'INSTALLED', version: m.version, digest, release, ledger };
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
}
