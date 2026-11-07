// Applicant laboratory campaign. Passing this runner never assigns a TRL or approval.
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync, lstatSync } from 'node:fs';
import { resolve, relative, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { snapshot } from '../sag/package.mjs';
import { encode, sha256, fingerprint, safePath, insist, members } from '../sag/format.mjs';

const FAMILIES = Array.from({ length: 9 }, (_, i) => `ADV-0${i + 1}`);
const REQUIREMENTS = Array.from({ length: 12 }, (_, i) => `R${i + 1}`);
const STATUSES = new Set([
  'EXTERNAL_INPUT_REQUIRED',
  'PARTIAL_LAB',
  'OPEN_DESIGN_BLOCKER',
  'IMPLEMENTATION_PENDING',
  'ROOT_CAUSE_OPEN',
]);
const text = (s) => typeof s === 'string' && s.trim().length > 0 && s.length <= 4000;
export function validatePlan(plan, sourcePaths) {
  members(plan, [
    'schemaVersion',
    'kind',
    'targetTrl',
    'currentAssessment',
    'qualification',
    'sourceBaseline',
    'scope',
    'families',
    'gaps',
  ]);
  insist(
    plan.schemaVersion === 1 &&
      plan.kind === 'IAF_QUALIFICATION_PREPARATION' &&
      plan.targetTrl === 8 &&
      plan.currentAssessment === 'PROVISIONAL_TRL4_UNCHANGED' &&
      plan.qualification === 'NOT_ESTABLISHED',
    'UNSUPPORTED_QUALIFICATION_CLAIM',
  );
  insist(/^[a-f0-9]{40}$/.test(plan.sourceBaseline) && text(plan.scope), 'PLAN_SCOPE');
  const familyIds = new Set(),
    covered = new Set(),
    testPaths = new Set();
  const requirements = (ids) => {
    insist(
      Array.isArray(ids) &&
        ids.length > 0 &&
        new Set(ids).size === ids.length &&
        ids.every((id) => REQUIREMENTS.includes(id)),
      'REQUIREMENT_MAPPING',
    );
    ids.forEach((id) => covered.add(id));
  };
  insist(
    Array.isArray(plan.families) && plan.families.length === FAMILIES.length,
    'CAMPAIGN_INCOMPLETE',
  );
  for (const f of plan.families) {
    members(f, ['id', 'title', 'requirements', 'tests', 'oracle']);
    insist(
      FAMILIES.includes(f.id) && !familyIds.has(f.id) && text(f.title) && text(f.oracle),
      'FAMILY_SCHEMA',
    );
    familyIds.add(f.id);
    requirements(f.requirements);
    insist(Array.isArray(f.tests) && f.tests.length > 0, 'MISSING_TESTS');
    for (const path of f.tests) {
      insist(
        safePath(path) &&
          /^(?:tests|apps|services|scripts)\//.test(path) &&
          path.endsWith('.test.mjs') &&
          sourcePaths.has(path) &&
          !testPaths.has(path),
        'TEST_PATH',
      );
      testPaths.add(path);
    }
  }
  insist(covered.size === REQUIREMENTS.length, 'REQUIREMENT_COVERAGE');
  insist(Array.isArray(plan.gaps) && plan.gaps.length >= 19, 'GAP_REGISTER_INCOMPLETE');
  const gapIds = new Set();
  for (const g of plan.gaps) {
    members(g, [
      'id',
      'priority',
      'status',
      'requirements',
      'owner',
      'title',
      'current',
      'implementationNeeded',
      'sponsorInputs',
      'exitEvidence',
      'source',
    ]);
    insist(
      /^IAF-G\d{2}$/.test(g.id) &&
        !gapIds.has(g.id) &&
        ['P0', 'P1'].includes(g.priority) &&
        STATUSES.has(g.status),
      'GAP_SCHEMA',
    );
    gapIds.add(g.id);
    requirements(g.requirements);
    for (const field of [
      'owner',
      'title',
      'current',
      'implementationNeeded',
      'sponsorInputs',
      'exitEvidence',
    ])
      insist(text(g[field]), 'GAP_EVIDENCE_REQUIRED');
    insist(safePath(g.source) && sourcePaths.has(g.source), 'GAP_SOURCE');
  }
  insist(gapIds.has('IAF-G05') && gapIds.has('IAF-G18') && gapIds.has('IAF-G19'), 'MANDATORY_GAPS');
  return plan;
}
export function tapOutcome(stdout, exitCode, terminated = false) {
  const counts = {};
  for (const name of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
    const matches = [...stdout.matchAll(new RegExp(`^# ${name} (\\d+)\\r?$`, 'gm'))];
    counts[name] = matches.length === 1 ? Number(matches[0][1]) : null;
  }
  const passed =
    exitCode === 0 &&
    !terminated &&
    Number.isSafeInteger(counts.tests) &&
    counts.tests > 0 &&
    counts.pass === counts.tests &&
    ['fail', 'cancelled', 'skipped', 'todo'].every((k) => counts[k] === 0);
  return { outcome: passed ? 'PASS' : 'FAIL', counts };
}
export function redact(log) {
  return log
    .replace(/otpauth:\/\/\S+/gi, '[REDACTED_OTP_URI]')
    .replace(/(authorization\s*[:=]\s*|bearer\s+)\S+/gi, '$1[REDACTED]')
    .replace(
      /((?:password|totpSecret|privateKey|token|secret)\s*["']?\s*[:=]\s*["']?)[^\s,"'}]+/gi,
      '$1[REDACTED]',
    );
}
export async function executeFamily(root, tests) {
  const command = ['--test', '--test-concurrency=1', '--test-reporter=tap', ...tests];
  return new Promise((resolveResult) => {
    const environment = Object.fromEntries(
      Object.entries(process.env).filter(([k]) => !k.startsWith('NODE_TEST_')),
    );
    const child = spawn(process.execPath, command, {
      cwd: root,
      env: environment,
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '',
      stderr = '',
      bytes = 0,
      terminated = false,
      killer;
    const signal = (s) => {
      try {
        if (process.platform !== 'win32') process.kill(-child.pid, s);
        else child.kill(s);
      } catch {}
    };
    const terminate = () => {
      if (terminated) return;
      terminated = true;
      signal('SIGTERM');
      killer = setTimeout(() => signal('SIGKILL'), 1000);
    };
    const timer = setTimeout(terminate, 180000);
    const capture = (stream) => (b) => {
      bytes += b.length;
      if (bytes > 1024 * 1024) {
        terminate();
        return;
      }
      if (stream === 'stdout') stdout += b.toString();
      else stderr += b.toString();
    };
    child.stdout.on('data', capture('stdout'));
    child.stderr.on('data', capture('stderr'));
    child.on('error', () => {
      terminated = true;
    });
    child.on('close', (exitCode) => {
      clearTimeout(timer);
      clearTimeout(killer);
      resolveResult({
        command: [process.execPath, ...command],
        exitCode,
        terminated,
        ...tapOutcome(stdout, exitCode, terminated),
        log: redact(stdout + '\n' + stderr),
      });
    });
  });
}
export async function runCampaign(root, destination) {
  root = resolve(root);
  destination = resolve(root, destination);
  const rel = relative(root, destination).replaceAll('\\', '/');
  insist(
    safePath(rel) && rel.startsWith('artifacts/') && !existsSync(destination),
    'NEW_ARTIFACT_DIRECTORY_REQUIRED',
  );
  let parent = root;
  for (const part of rel.split('/').slice(0, -1)) {
    parent = join(parent, part);
    if (existsSync(parent))
      insist(
        lstatSync(parent).isDirectory() && !lstatSync(parent).isSymbolicLink(),
        'UNSAFE_ARTIFACT_DIRECTORY',
      );
    else mkdirSync(parent, { mode: 0o700 });
  }
  const before = snapshot(root);
  const plan = validatePlan(
    JSON.parse(before.source.get('assurance/iaf/plan.json')),
    new Set(before.source.keys()),
  );
  mkdirSync(destination, { mode: 0o700 });
  const report = {
    schemaVersion: 1,
    kind: 'IAF_ADVERSARIAL_LAB_CAMPAIGN',
    gitCommit: before.commit,
    gitTree: before.tree,
    sourceFingerprint: fingerprint(before.index),
    planSha256: sha256(before.source.get('assurance/iaf/plan.json')),
    startedAt: new Date().toISOString(),
    runtime: { node: process.version, platform: process.platform, architecture: process.arch },
    scope: plan.scope,
    targetTrl: 8,
    qualification: 'NOT_ESTABLISHED',
    assignedTrl: null,
    externalAssessment: 'NOT_ESTABLISHED',
    results: [],
    openGaps: plan.gaps,
  };
  for (const family of plan.families) {
    const startedAt = new Date().toISOString();
    const { log, ...execution } = await executeFamily(root, family.tests);
    const file = family.id + '.tap';
    writeFileSync(join(destination, file), log, { mode: 0o600, flag: 'wx' });
    report.results.push({
      id: family.id,
      title: family.title,
      requirements: family.requirements,
      oracle: family.oracle,
      startedAt,
      finishedAt: new Date().toISOString(),
      ...execution,
      evidence: { path: file, sha256: sha256(log) },
    });
    console.log(
      `${family.id}: ${execution.outcome} (${execution.counts.tests ?? 'unknown'} tests)`,
    );
  }
  report.sourceUnchanged = false;
  try {
    const after = snapshot(root);
    report.sourceUnchanged =
      before.commit === after.commit &&
      before.tree === after.tree &&
      fingerprint(before.index) === fingerprint(after.index);
  } catch {}
  report.finishedAt = new Date().toISOString();
  report.outcome =
    report.sourceUnchanged && report.results.every((r) => r.outcome === 'PASS') ? 'PASS' : 'FAIL';
  report.limitations = [
    'Applicant-authored laboratory evidence; no independent attestation or operational qualification.',
    'A passing adapter boundary observation confirms plaintext exposure inside the synthetic managed endpoint; it does not close IAF-G05.',
    'Browser, container, Rust/NEXORA, full network matrix and external assessments require their separate exact-candidate evidence.',
    'Queue limits are proposed laboratory defaults; aggregate connection limits, service renewal, HA and capacity qualification remain open.',
  ];
  writeFileSync(join(destination, 'report.json'), encode(report), { mode: 0o600, flag: 'wx' });
  return report;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    insist(process.argv.length === 3, 'Usage: run.mjs artifacts/NEW_DIRECTORY');
    const report = await runCampaign(process.cwd(), process.argv[2]);
    console.log(
      JSON.stringify({
        outcome: report.outcome,
        gitCommit: report.gitCommit,
        families: report.results.length,
        tests: report.results.reduce((n, r) => n + (r.counts.tests ?? 0), 0),
        qualification: report.qualification,
        openGaps: report.openGaps.length,
      }),
    );
    if (report.outcome !== 'PASS') process.exitCode = 1;
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
