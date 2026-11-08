// Explicit Linux managed-endpoint profile. Requires an administrator-provisioned runtime image.
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readdir, statfs } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
const fail = (code) => Object.assign(new Error(code), { code });
const pathOK = (p) =>
  typeof p === 'string' && isAbsolute(p) && p !== '/' && !/[\x00-\x1f\x7f]/.test(p);
const hashOK = (h) => typeof h === 'string' && /^[a-f0-9]{64}$/.test(h);
async function hash(path) {
  const result = createHash('sha256');
  for await (const chunk of createReadStream(path)) result.update(chunk);
  return result.digest('hex');
}

export class BubblewrapSandbox {
  #config;
  constructor({ bwrap, bwrapSha256, prlimit, prlimitSha256, runtimeRoot, files }) {
    if (
      ![bwrap, prlimit, runtimeRoot].every(pathOK) ||
      ![bwrapSha256, prlimitSha256].every(hashOK) ||
      !files ||
      Array.isArray(files) ||
      Object.keys(files).length > 128 ||
      !files['bin/clamscan'] ||
      Object.entries(files).some(
        ([p, h]) =>
          !/^(bin|lib|lib64|usr\/lib|etc\/certs)\/[a-zA-Z0-9_+./-]+$/.test(p) ||
          p.split('/').some((v) => v === '..' || v === '.' || !v) ||
          !hashOK(h),
      )
    )
      throw fail('FILE_INSPECTION_SANDBOX_CONFIG');
    this.#config = Object.freeze({
      bwrap,
      bwrapSha256,
      prlimit,
      prlimitSha256,
      runtimeRoot,
      files: Object.freeze({ ...files }),
    });
  }
  async prepare(args, { executable, database, directory, timeoutMs }) {
    const o = this.#config;
    if (process.platform !== 'linux' || executable !== join(o.runtimeRoot, 'bin/clamscan'))
      throw fail('FILE_INSPECTION_SANDBOX_CONFIG');
    for (const [path, expected] of [
      [o.bwrap, o.bwrapSha256],
      [o.prlimit, o.prlimitSha256],
    ]) {
      const info = await lstat(path);
      if (!info.isFile() || info.mode & 0o6022 || (await hash(path)) !== expected)
        throw fail('FILE_INSPECTION_SANDBOX_CHANGED');
    }
    const temp = await lstat(directory);
    if (
      !temp.isDirectory() ||
      temp.uid !== process.getuid() ||
      (temp.mode & 0o7777) !== 0o700 ||
      Number((await statfs(directory)).type) !== 0x01021994
    )
      throw fail('FILE_INSPECTION_SANDBOX_TEMP');
    const seen = [];
    async function walk(path, relative = '') {
      const info = await lstat(path);
      if (info.isSymbolicLink() || info.mode & 0o6022)
        throw fail('FILE_INSPECTION_SANDBOX_CHANGED');
      if (info.isDirectory()) {
        for (const name of await readdir(path))
          await walk(join(path, name), relative ? relative + '/' + name : name);
      } else {
        if (
          !info.isFile() ||
          !Object.hasOwn(o.files, relative) ||
          info.size > 300 * 1024 * 1024 ||
          (await hash(path)) !== o.files[relative]
        )
          throw fail('FILE_INSPECTION_SANDBOX_CHANGED');
        seen.push(relative);
      }
    }
    await walk(o.runtimeRoot);
    if (seen.length !== Object.keys(o.files).length) throw fail('FILE_INSPECTION_SANDBOX_CHANGED');
    const db = await lstat(database);
    if (!db.isDirectory() || db.isSymbolicLink()) throw fail('FILE_INSPECTION_SANDBOX_DATABASE');
    const flags = args.map((a) =>
      a.startsWith('--database=')
        ? '--database=/signatures'
        : a.startsWith('--tempdir=')
          ? '--tempdir=/tmp'
          : a,
    );
    return {
      executable: o.prlimit,
      args: [
        '--as=4294967296',
        '--cpu=' + Math.ceil(timeoutMs / 1000),
        '--nofile=128',
        '--core=0',
        '--fsize=16777216',
        '--',
        o.bwrap,
        '--unshare-all',
        '--unshare-user',
        '--disable-userns',
        '--assert-userns-disabled',
        '--die-with-parent',
        '--new-session',
        '--cap-drop',
        'ALL',
        '--clearenv',
        '--ro-bind',
        o.runtimeRoot,
        '/',
        '--proc',
        '/proc',
        '--dev',
        '/dev',
        '--size',
        '16777216',
        '--tmpfs',
        '/tmp',
        '--ro-bind',
        database,
        '/signatures',
        '--setenv',
        'LANG',
        'C',
        '--setenv',
        'LC_ALL',
        'C',
        '--setenv',
        'TMPDIR',
        '/tmp',
        '--setenv',
        'LD_LIBRARY_PATH',
        '/lib',
        '--setenv',
        'CVD_CERTS_DIR',
        '/etc/certs',
        '--chdir',
        '/tmp',
        '--',
        '/bin/clamscan',
        ...flags,
      ],
    };
  }
}
