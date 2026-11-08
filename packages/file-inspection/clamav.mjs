// Managed endpoint only. Never import this into a relay, authority or connector.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';

const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const reject = (code) => Object.assign(new Error(code), { code });
const bounded = (n, min, max) => Number.isSafeInteger(n) && n >= min && n <= max;

/**
 * Optional local-process adapter; executable and its libraries are trusted deployment inputs.
 * ClamAV is separately installed, not bundled or downloaded by the application.
 * The operator must provision a private, memory-backed tempRoot on the endpoint.
 */
export class ClamAvInspector {
  #options;
  #busy = false;
  constructor({
    executable,
    executableSha256,
    database,
    tempRoot,
    maxBytes = 512 * 1024,
    timeoutMs = 30000,
    maxDatabaseAgeDays = 2,
  }) {
    if (
      ![executable, database, tempRoot].every(
        (v) => typeof v === 'string' && isAbsolute(v) && !/[\x00-\x1f\x7f]/.test(v),
      ) ||
      !/^[a-f0-9]{64}$/.test(executableSha256 ?? '') ||
      !bounded(maxBytes, 1, 512 * 1024) ||
      !bounded(timeoutMs, 100, 120000) ||
      !bounded(maxDatabaseAgeDays, 1, 7)
    )
      throw reject('FILE_INSPECTION_CONFIG');
    this.#options = Object.freeze({
      executable,
      executableSha256,
      database,
      tempRoot,
      maxBytes,
      timeoutMs,
      maxDatabaseAgeDays,
    });
  }

  async inspect(input) {
    const o = this.#options;
    if (!(input instanceof Uint8Array) || !bounded(input.byteLength, 1, o.maxBytes))
      throw reject('FILE_INSPECTION_SIZE');
    if (this.#busy) throw reject('FILE_INSPECTION_BUSY');
    this.#busy = true;
    // Snapshot before the first await: later caller mutation cannot change the scanned bytes.
    const bytes = Buffer.from(input);
    let directory, result, failure;
    try {
      if (digest(await readFile(o.executable)) !== o.executableSha256)
        throw reject('FILE_INSPECTION_ENGINE_CHANGED');
      directory = await mkdtemp(join(o.tempRoot, 'siepmu-scan-'));
      const args = [
        '--stdout',
        '--no-summary',
        '--database=' + o.database,
        '--official-db-only=yes',
        '--fail-if-cvd-older-than=' + o.maxDatabaseAgeDays,
        '--tempdir=' + directory,
        '--leave-temps=no',
        '--force-to-disk=no',
        '--heuristic-alerts=yes',
        '--alert-exceeds-max=yes',
        '--alert-encrypted=yes',
        '--alert-macros=yes',
        '--alert-broken=yes',
        '--alert-broken-media=yes',
        '--max-filesize=' + o.maxBytes,
        '--max-scansize=8M',
        '--max-files=100',
        '--max-recursion=8',
        '--max-scantime=' + o.timeoutMs,
        '--disable-cache',
        '-',
      ];
      await new Promise((resolve, fail) => {
        const child = spawn(o.executable, args, {
          shell: false,
          cwd: directory,
          stdio: ['pipe', 'pipe', 'pipe'],
          // No inherited loader overrides, credentials, proxy or content-bearing environment.
          env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin', TMPDIR: directory },
        });
        let stdout = '',
          size = 0,
          failure;
        const stop = (code) => {
          failure ??= code;
          child.kill('SIGKILL');
        };
        const timer = setTimeout(() => stop('FILE_INSPECTION_TIMEOUT'), o.timeoutMs);
        child.on('error', () => stop('FILE_INSPECTION_UNAVAILABLE'));
        child.stdin.on('error', () => stop('FILE_INSPECTION_IO'));
        for (const [stream, output] of [
          [child.stdout, true],
          [child.stderr, false],
        ]) {
          stream.on('data', (chunk) => {
            size += chunk.length;
            if (size > 16384) stop('FILE_INSPECTION_OUTPUT_LIMIT');
            else if (!output) stop('FILE_INSPECTION_DIAGNOSTIC');
            else stdout += chunk.toString('utf8');
          });
        }
        child.on('close', (code, signal) => {
          clearTimeout(timer);
          // Never return raw diagnostics, signature names, temporary paths or content.
          if (failure) fail(reject(failure));
          else if (code === 1) fail(reject('FILE_INSPECTION_DETECTED'));
          else if (code !== 0 || signal || stdout.trim() !== 'stdin: OK')
            fail(reject('FILE_INSPECTION_INCOMPLETE'));
          else resolve();
        });
        child.stdin.end(bytes);
      });
      result = Object.freeze({
        version: 1,
        status: 'NO_THREAT_DETECTED',
        sha256: digest(bytes),
        bytes: bytes.length,
      });
    } catch (error) {
      failure = /^FILE_INSPECTION_[A-Z_]+$/.test(error?.code ?? '')
        ? error
        : reject('FILE_INSPECTION_UNAVAILABLE');
    } finally {
      bytes.fill(0);
      try {
        if (directory) await rm(directory, { recursive: true, force: true });
      } catch {
        failure = reject('FILE_INSPECTION_CLEANUP');
      } finally {
        this.#busy = false;
      }
    }
    if (failure) throw failure;
    return result;
  }
}
