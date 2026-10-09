// Orchestration: loads vector sets (IO), executes them through the adapter (implementation under
// test), aggregates verdicts (core) and renders the report. Dependencies are injected so the
// plumbing can be tested without real vectors.
//
// CLI: node assurance/kat/run.mjs [--report docs/assurance/kat-conformance.md] [--json out.json]
// Exit status 1 if any vector case or failure-mode check FAILs. NOT-RUN never fails the run and
// never counts as a pass.

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ALGORITHMS, VENDORED, USER_VECTORS, STRUCTURAL_NOT_RUN } from './core/catalog.mjs';
import { STATUS, setStatus, algorithmStatus } from './core/verdict.mjs';
import { renderMarkdown } from './core/report.mjs';
import { platform } from './adapters/platform.mjs';
import * as io from './io/sources.mjs';
import * as suites from './suites.mjs';
import { aesGcmFailureModes, ecdsaFailureModes, xwingFailureModes } from './failure-modes.mjs';

/** Builds one set row from an executor result. */
function row(set, implementation, file, source, version, result) {
  const status = setStatus(result.cases, result.notRunReason);
  return {
    set,
    implementation,
    status,
    cases: result.cases.length,
    passed: result.cases.filter((c) => c.pass).length,
    skipped: result.skipped,
    source,
    version,
    fileSha256: file?.sha256 ?? null,
    reason: result.notRunReason,
    failures: result.failures,
  };
}
const notRun = (set, reason, source = null) => ({
  set,
  implementation: '—',
  status: STATUS.NOT_RUN,
  cases: 0,
  passed: 0,
  skipped: 0,
  source,
  version: null,
  fileSha256: null,
  reason,
  failures: [],
});

/** CAVP version line from an .rsp header (e.g. "CAVS 11.0"), if present. */
const cavsVersion = (text) => (text.match(/^#\s*(CAVS [^\n\r]*)/m)?.[1] ?? 'no CAVS header').trim();

/**
 * Runs operator-supplied files for one algorithm; NOT-RUN when none are present.
 * @returns {Promise<any[]>}
 */
async function userSets(deps, spec, pattern, implementations, execute) {
  const files = deps.listFiles(deps.root, spec.dir, pattern);
  if (files.length === 0)
    return [notRun(`${spec.dir}/*`, `no vector files present; accepts ${spec.accepts}`)];
  const rows = [];
  for (const file of files)
    for (const [implName, fn] of implementations) {
      const result = await execute(file.text, fn);
      rows.push(
        row(
          file.path,
          implName,
          file,
          result.source ?? `operator-supplied ${file.path}`,
          result.version ?? cavsVersion(file.text),
          result,
        ),
      );
    }
  return rows;
}

/**
 * Executes the KAT campaign.
 * @param {{root: string, adapter?: any, listFiles?: Function, readFile?: Function,
 *   loadHybrid?: Function}} deps
 */
export async function runKat(deps) {
  const d = {
    adapter: platform,
    listFiles: io.listVectorFiles,
    readFile: io.readVectorFile,
    loadHybrid: io.loadLabHybrid,
    ...deps,
  };
  const A = d.adapter;
  const vendored = (key) => {
    const file = d.readFile(d.root, VENDORED[key].file);
    return { file, vectors: JSON.parse(file.text) };
  };
  const hybrid = await d.loadHybrid(d.root);
  const sets = {
    sha256: await userSets(
      d,
      USER_VECTORS.sha256,
      /\.rsp$/,
      [
        ['node:crypto createHash', A.sha256Node],
        ['WebCrypto digest', A.sha256Web],
      ],
      suites.sha256Rsp,
    ),
    aes256gcm: await userSets(
      d,
      USER_VECTORS.aesGcm,
      /\.rsp$/,
      [['WebCrypto AES-GCM', A]],
      suites.aesGcmRsp,
    ),
    hkdf: await userSets(
      d,
      USER_VECTORS.hkdf,
      /\.json$/,
      [['WebCrypto HKDF', A.hkdfSha256]],
      suites.hkdfJson,
    ),
    ecdsa: await userSets(
      d,
      USER_VECTORS.ecdsa,
      /\.rsp$/,
      [
        ['WebCrypto ECDSA', A.ecdsaVerifyWeb],
        ['node:crypto verify (P1363)', A.ecdsaVerifyNode],
      ],
      suites.ecdsaSigVerRsp,
    ),
  };
  const kem = vendored('mlkemKeygen');
  for (const [id, set] of [
    ['mlkem768', 'ML-KEM-768'],
    ['mlkem1024', 'ML-KEM-1024'],
  ])
    sets[id] = [
      row(
        'keyGen (vendored)',
        'node:crypto raw-seed',
        kem.file,
        VENDORED.mlkemKeygen.source,
        VENDORED.mlkemKeygen.version,
        await suites.mlkemKeygen(kem.vectors, set, A.mlkemKeygen),
      ),
      notRun('encapDecap', STRUCTURAL_NOT_RUN[`${id}:encapDecap`]),
    ];
  const dsa = vendored('mldsaKeygen');
  sets.mldsa65 = [
    row(
      'keyGen (vendored)',
      'node:crypto raw-seed',
      dsa.file,
      VENDORED.mldsaKeygen.source,
      VENDORED.mldsaKeygen.version,
      await suites.mldsaKeygen(dsa.vectors, A.mldsa65Keygen),
    ),
    notRun('sigGen / sigVer', STRUCTURAL_NOT_RUN['mldsa65:sigGenSigVer']),
  ];
  const xw = vendored('xwing');
  sets.xwing = hybrid.module
    ? [
        row(
          'author KAT (vendored)',
          `@noble/post-quantum ${hybrid.version} ml_kem768_x25519`,
          xw.file,
          VENDORED.xwing.source,
          VENDORED.xwing.version,
          await suites.xwing(xw.vectors, hybrid.module.ml_kem768_x25519),
        ),
      ]
    : [notRun('author KAT (vendored)', hybrid.reason, VENDORED.xwing.source)];
  sets.overlay = [notRun('combiner', STRUCTURAL_NOT_RUN['overlay:combiner'])];

  const algorithms = ALGORITHMS.map((a) => ({
    ...a,
    sets: sets[a.id],
    status: algorithmStatus(sets[a.id].map((s) => s.status)),
  }));
  const failureModes = [
    ...(await aesGcmFailureModes(A)),
    ...(await ecdsaFailureModes(A)),
    ...(hybrid.module ? xwingFailureModes(hybrid.module.ml_kem768_x25519, xw.vectors[0]) : []),
  ];
  const all = algorithms.flatMap((a) => a.sets);
  const summary = {
    casesRun: all.reduce((n, s) => n + s.cases, 0),
    casesPassed: all.reduce((n, s) => n + s.passed, 0),
    failureModes: failureModes.length,
    failureModesPassed: failureModes.filter((f) => f.status === STATUS.PASS).length,
  };
  summary.outcome =
    summary.casesPassed === summary.casesRun && summary.failureModesPassed === summary.failureModes
      ? STATUS.PASS
      : STATUS.FAIL;
  return { algorithms, failureModes, summary };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  const opt = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : null);
  const root = resolve('.');
  const startedAt = new Date().toISOString();
  const result = await runKat({ root });
  const { getVersion } = await import('./io/runtime.mjs');
  const run = {
    ...result,
    revision: io.gitRevision(root),
    command: `node assurance/kat/run.mjs ${args.join(' ')}`.trim(),
    startedAt,
    runtime: getVersion(),
  };
  for (const a of run.algorithms)
    for (const s of a.sets)
      console.log(
        `${s.status.padEnd(7)} ${a.name} / ${s.set} / ${s.implementation}${s.status === 'NOT-RUN' ? '' : ` ${s.passed}/${s.cases}`}`,
      );
  for (const f of run.failureModes)
    console.log(`${f.status.padEnd(7)} failure-mode ${f.algorithm}: ${f.check}`);
  console.log(
    `KAT ${run.summary.outcome}: ${run.summary.casesPassed}/${run.summary.casesRun} cases, ${run.summary.failureModesPassed}/${run.summary.failureModes} failure-mode checks (commit ${run.revision.commit}${run.revision.dirty ? ', dirty' : ''})`,
  );
  if (opt('--report')) writeFileSync(opt('--report'), renderMarkdown(run));
  if (opt('--json')) writeFileSync(opt('--json'), JSON.stringify(run, null, 2) + '\n');
  if (run.summary.outcome !== STATUS.PASS) process.exitCode = 1;
}
