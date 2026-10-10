// Claims audit: finds assurance-sensitive terms in tracked text and source files and classifies
// each hit. Classification is rule-based and explainable; anything the rules cannot settle is
// marked REVIEW and must carry a manual verdict in MANUAL_VERDICTS (keyed by file and a
// fragment of the line) before the report is regenerated. Output: docs/assurance/claims-audit.md.
//
// Usage: node scripts/claims-audit.mjs [--write docs/assurance/claims-audit.md]
// Exit 1 if any hit remains REVIEW without a manual verdict, or any manual verdict is stale.

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

/** Terms from the audit request. SAG and FIPS are case-sensitive acronyms. */
export const TERMS = Object.freeze([
  { term: 'FIPS', re: /\bFIPS\b/ },
  { term: 'SAG', re: /\bSAG\b/ },
  { term: 'validated', re: /\bvalidated\b/i },
  { term: 'certified', re: /\bcertified\b/i },
  { term: 'approved', re: /\bapproved\b/i },
  { term: 'quantum-proof', re: /\bquantum-proof\b/i },
  { term: 'quantum-safe', re: /\bquantum-safe\b/i },
  { term: 'production-ready', re: /\bproduction[- ]ready\b/i },
  { term: 'TRL 5', re: /\bTRL 5\b/ },
]);

/** Words that make a hit a statement of absence or a prohibition. */
export const NEGATION =
  /\b(?:not|no|never|none|without|nor|neither|cannot|isn't|aren't|don't|doesn't|unless|absent|pending|outstanding|lacks?|missing|disallow\w*|forbid\w*|prohibit\w*|avoid|refus\w*|until|before|exclude\w*|non-approved|unapproved|unvalidated|uncertified|candidate|roadmap|planned|proposed|future|gate|gates|blocked|do not use|nothing|neither)\b|n't\b|\bNOT[_ ]|NOT_SUPPORTED|Not claimed|NOT DEFINED/i;

/** Standards references (accurate citations of a published document). */
const STANDARD_REF =
  /\bFIPS\s?(?:140-3|180-4|186-[45]|197|198-1|202|203|204|205)\b|\bSP 800-|\bRFC \d/;

/** Application domain senses of approved/validated (not certification claims). */
const DOMAIN_SENSE =
  /\b(?:device|devices|FLASH|approval|approve|approver|approvals|admin|operator|dual|policy|policies|crypto policy|suite|suites|schema|input|envelope|request|grant|records?|checkpoint|lease|signature|mission|duty|enrol\w*|registry|newSuites|status|state|pending|approved_by|approvedBy|isApproved|APPROVED|validatedBy|validatedAt|research record|research records)\b/i;

const CODE_FILE = /\.(?:mjs|rs|ts)$/;
const TEST_FILE = /(?:^tests\/|\.test\.mjs$|\.check\.mjs$|\/tests\/)/;

/**
 * Manual verdicts for hits the rules cannot settle. Key: `${file}::${fragment}` where fragment
 * is a substring of the line. Value: [verdict, proposed wording or null].
 */
export const MANUAL_VERDICTS = new Map([
  [
    '.claude/skills/siepmu-architecture/SKILL.md::re-validated at every decision',
    ['accurate', null],
  ],
  ['.claude/skills/siepmu-crypto-agility/SKILL.md::re-validated at release', ['accurate', null]],
  ['.claude/skills/siepmu-crypto-agility/SKILL.md::SAG pathway:', ['accurate', null]],
  [
    '.claude/skills/siepmu-defence-integration/SKILL.md::validated metadata through',
    ['accurate', null],
  ],
  ['.claude/skills/siepmu-project-context/SKILL.md::SAG-graded encryption)', ['accurate', null]],
  ['.claude/skills/siepmu-project-context/SKILL.md::**SAG grading**', ['accurate', null]],
  [
    '.claude/skills/siepmu-project-context/SKILL.md::validated by `research/trl56/validate.py`',
    ['accurate', null],
  ],
  [
    '.claude/skills/siepmu-trl-readiness/SKILL.md::validated in a relevant environment',
    ['accurate', null],
  ],
  [
    '.claude/skills/siepmu-trl-readiness/SKILL.md::SAG cryptographic grading (external',
    ['accurate', null],
  ],
  [
    '.claude/skills/siepmu-trl-readiness/SKILL.md::CTE-03/04/05/06 are TRL 5',
    [
      'inaccurate',
      'system provisional TRL 4; CTE-03/04/05 are TRL 5 candidates; CTE-06 (evidence custody) also needs the D-T5-01 scaling fix (docs/trl5/PERFORMANCE_REPORT.md)',
    ],
  ],
  [
    'CLAIMS_REGISTER.yaml::SAG graded, IAF approved or defence certified operation.',
    ['accurate', null],
  ],
  [
    'CLAIMS_REGISTER.yaml::four elements identified as TRL 5 validation candidates',
    [
      'inaccurate',
      'Provisional TRL 4 by internal self-assessment; TRL 5 advancement tests completed (C23); release, relay and offline queue are TRL 5 validation candidates, evidence custody pending the D-T5-01 fix.',
    ],
  ],
  ['CLAIMS_REGISTER.yaml::maturation plan toward TRL 5 validation', ['accurate', null]],
  ['CLAIMS_REGISTER.yaml::Formal TRL 5 or 6 achieved', ['accurate', null]],
  ['CLAUDE.md::SAG-graded, independently assessed or operationally deployed.', ['accurate', null]],
  ['CLAUDE.md::TRL 5 advancement matrix (root', ['accurate', null]],
  ['CLAUDE.md::sponsor acceptance, SAG grading,', ['accurate', null]],
  ['CLAUDE.md::"military-grade", "certified".', ['accurate', null]],
  ['docs/EXECUTION_CHECKLIST.md::SAG/live integration/QA remain external', ['accurate', null]],
  ['docs/application/DELIVERY_TRACKER.md::SAG guidance', ['accurate', null]],
  [
    'docs/decisions/ADR-012-rust-reference-components.md::AWS-LC offers a FIPS-mode build',
    ['accurate', null],
  ],
  [
    'docs/assurance/fips-sag-gap-analysis.md::# Cryptographic module boundary and FIPS 140-3 / SAG gap analysis',
    ['accurate', null],
  ],
  [
    'docs/assurance/fips-sag-gap-analysis.md::M1 TRL 5 preparation, M2 TRL 5 validation',
    ['accurate', null],
  ],
  ['docs/assurance/fips-sag-gap-analysis.md::**Revision examined:**', ['accurate', null]],
  [
    'docs/assurance/fips-sag-gap-analysis.md::wrapping a module that is itself validated or under',
    ['accurate', null],
  ],
  [
    "docs/assurance/fips-sag-gap-analysis.md::The sponsor's SAG evaluation route, criteria and approved algorithm list",
    ['accurate', null],
  ],
  [
    'docs/assurance/fips-sag-gap-analysis.md::Absence of FIPS mode and self-tests:',
    ['accurate', null],
  ],
  ['docs/engineering/CURRENT_STATE.md::## TRL 5 advancement sprint', ['accurate', null]],
  ['docs/engineering/CURRENT_STATE.md::SAG grading, IAF identity/PKI', ['accurate', null]],
  [
    'docs/engineering/RECONCILIATION_MATRIX.md::validated crypto evidence',
    ['inaccurate', "PR #15 + crypto evidence checks ('cfdaae1')"],
  ],
  [
    'docs/engineering/TRUST_BEFORE_RELEASE.md::sponsor acceptance, SAG grading or TRL',
    ['accurate', null],
  ],
  [
    'docs/engineering/WORK_PACKAGE_REGISTER.md::SAG evaluation and provider dossier',
    ['accurate', null],
  ],
  ['docs/hpsc/EXECUTIVE_SUMMARY.md::are TRL 5 validation', ['accurate', null]],
  [
    'docs/hpsc/EXECUTIVE_SUMMARY.md::SAG-graded encryption, depend on sponsor decisions',
    ['accurate', null],
  ],
  ['docs/hpsc/EXECUTIVE_SUMMARY.md::toward TRL 5 validation and a TRL 6', ['accurate', null]],
  ['docs/hpsc/EXECUTIVE_SUMMARY.md::Guidance on the SAG grading route', ['accurate', null]],
  ['docs/hpsc/FUNDING_PLAN.md::M1 TRL 5 preparation', ['accurate', null]],
  ['docs/hpsc/FUNDING_PLAN.md::M2 TRL 5 validation', ['accurate', null]],
  [
    'docs/hpsc/FUNDING_PLAN.md::SAG evaluation dossier for the selected provider configuration',
    ['accurate', null],
  ],
  ['docs/hpsc/FUNDING_PLAN.md::The sponsor controls entry to M2', ['accurate', null]],
  ['docs/hpsc/HPSC_DECK.md::8. SAG-graded encryption', ['accurate', null]],
  [
    'docs/hpsc/HPSC_DECK.md::Live demonstration and validated results',
    ['inaccurate', '## Slide 6: Live demonstration and tested results'],
  ],
  ['docs/hpsc/HPSC_DECK.md::TRL 5 advancement tests completed:', ['accurate', null]],
  ['docs/hpsc/HPSC_DECK.md::TRL 5 validation candidates:', ['accurate', null]],
  ['docs/hpsc/HPSC_DECK.md::M1 TRL 5 preparation', ['accurate', null]],
  ['docs/hpsc/HPSC_DECK.md::M2 TRL 5 validation', ['accurate', null]],
  ['docs/hpsc/HPSC_DECK.md::SAG evaluation dossier for the selected provider', ['accurate', null]],
  ['docs/hpsc/HPSC_DECK.md::the relevant environment (M2) and SAG (M5)', ['accurate', null]],
  ['docs/hpsc/HPSC_DECK.md::Guidance on the SAG grading route', ['accurate', null]],
  ['docs/hpsc/evaluation.md::SAG/integration/QA route is unclear', ['accurate', null]],
  ['docs/hpsc/evaluator-questions.md::with TRL 5 advancement tests completed', ['accurate', null]],
  ['docs/hpsc/story.md::SAG/QA route remain external', ['accurate', null]],
  ["docs/threat-model/README.md::the sponsor's SAG/QA route", ['accurate', null]],
  ['docs/trl/TRL_ASSESSMENT.md::sponsor decision or SAG grading', ['accurate', null]],
  [
    'docs/trl/TRL_ASSESSMENT.md::validated with automated and scripted evidence',
    ['accurate', null],
  ],
  [
    'docs/trl/TRL_ASSESSMENT.md::CTE-06 evidence custody. They need',
    [
      'inaccurate',
      '| TRL 5 candidates | CTE-03 release, CTE-04 relay, CTE-05 offline queue. CTE-06 evidence custody also needs the D-T5-01 scaling fix. All need a sponsor-defined relevant environment. |',
    ],
  ],
  ['docs/trl/TRL_ASSESSMENT.md::TRL 5 requires validation', ['accurate', null]],
  ['docs/trl/TRL_ASSESSMENT.md::The TRL 5 advancement', ['accurate', null]],
  ['docs/trl/TRL_ASSESSMENT.md::### TRL 5 advancement campaign', ['accurate', null]],
  ['docs/trl/TRL_ASSESSMENT.md::Planning detail for TRL 5 and 6', ['accurate', null]],
  ['docs/trl5/ENVIRONMENT.md::# TRL 5 advancement environment', ['accurate', null]],
  ['docs/trl5/EXECUTION_REPORT.md::# TRL 5 advancement execution report', ['accurate', null]],
  ['docs/trl5/PERFORMANCE_REPORT.md::# TRL 5 advancement performance report', ['accurate', null]],
  ['docs/trl5/SECURITY_REPORT.md::# TRL 5 advancement security report', ['accurate', null]],
  ['docs/trl5/READINESS_DECISION.md::TRL 4: validated laboratory prototype', ['accurate', null]],
  [
    'docs/trl5/READINESS_DECISION.md::SAG grading, independent assessment, certification',
    ['accurate', null],
  ],
  ['docs/trl5/READINESS_DECISION.md::TRL 5 nevertheless requires', ['accurate', null]],
  ['docs/trl5/READINESS_DECISION.md::make a TRL 5 claim indefensible', ['accurate', null]],
  ['docs/trl5/READINESS_DECISION.md::"SAG-graded", "certified".', ['accurate', null]],
  ['native/DEPENDENCIES.md::is an external (SAG) decision', ['accurate', null]],
  ['packages/object-format/README.md::validated strings.', ['accurate', null]],
  [
    'research/cryptographic-standards/INDEPENDENT_REVIEW.md::Exact FIPS revisions',
    ['accurate', null],
  ],
  ['research/cryptographic-standards/V3_COMPOSITION.md::validated v3 context', ['accurate', null]],
  ['research/hpsc/indian-crypto-providers.md::validated modules was found.', ['accurate', null]],
  ['research/hpsc/indian-crypto-providers.md::the SAG process, stay external', ['accurate', null]],
  [
    'research/trl56/02-defence-software-ecosystem.md::TRL 5/6 Defence Ecosystem Research',
    ['accurate', null],
  ],
  [
    'research/trl56/03-external-hardware-and-security-addons.md::TRL 5/6 Defence Ecosystem Research',
    ['accurate', null],
  ],
  [
    'research/trl56/03-external-hardware-and-security-addons.md::YubiKey 5 series',
    ['accurate', null],
  ],
  [
    'research/trl56/03-external-hardware-and-security-addons.md::Isolated test nodes',
    ['accurate', null],
  ],
  ['research/trl56/03-external-hardware-and-security-addons.md::Power/network', ['accurate', null]],
  [
    'research/trl56/03-external-hardware-and-security-addons.md::Independent evidence',
    ['accurate', null],
  ],
  [
    'research/trl56/03-external-hardware-and-security-addons.md::Manufacturer legal name/model',
    ['accurate', null],
  ],
  [
    'research/trl56/04-sag-crypto-integration-pathway.md::TRL 5/6 Defence Ecosystem Research',
    ['accurate', null],
  ],
  ['research/trl56/04-sag-crypto-integration-pathway.md::| SAG-0', ['accurate', null]],
  [
    'research/trl56/05-iaf-interoperability-readiness.md::TRL 5/6 Defence Ecosystem Research',
    ['accurate', null],
  ],
  [
    'research/trl56/06-defence-relevant-testbed-design.md::TRL 5/6 Defence Ecosystem Research',
    ['accurate', null],
  ],
  [
    'research/trl56/06-defence-relevant-testbed-design.md::Minimum TRL 5 relevant environment proposal',
    ['accurate', null],
  ],
  [
    'research/trl56/07-trl5-validation-master-plan.md::TRL 5/6 Defence Ecosystem Research',
    ['accurate', null],
  ],
  [
    'research/trl56/08-trl5-verification-matrix.md::# TRL 5/6 verification matrix',
    ['accurate', null],
  ],
  ['research/trl56/08-trl5-verification-matrix.md::| SAG-01 | R9', ['accurate', null]],
  ['research/trl56/08-trl5-verification-matrix.md::## SAG-01', ['accurate', null]],
  ['research/trl56/08-trl5-verification-matrix.md::SoftHSM', ['accurate', null]],
  [
    'research/trl56/13-bill-of-materials-and-budget.md::IAF/SAG process and quote unknow',
    ['accurate', null],
  ],
  ['research/trl56/15-implementation-roadmap.md::CTE/SAG questions', ['accurate', null]],
  ['research/trl56/18-work-packages.md::| WP11 | SAG evaluation', ['accurate', null]],
  ['research/trl56/18-work-packages.md::tests SAG-01 T5-13', ['accurate', null]],
  ['research/trl56/18-work-packages.md::## WP11', ['accurate', null]],
  ['research/trl56/18-work-packages.md::Traceability: R9 R12; tests SAG-01', ['accurate', null]],
  ['research/trl56/18-work-packages.md::tests T5-08 SAG-01', ['accurate', null]],
  ['research/trl56/20-q-agile-execution.md::Q10 \u2014 external assurance', ['accurate', null]],
  [
    'research/trl56/20-q-agile-execution.md::## TRL 5 and TRL 6 exit boundaries',
    ['accurate', null],
  ],
  ['research/trl56/README.md::# SIEPMU TRL 5/6 research', ['accurate', null]],
  ['research/trl56/historical-baseline.md::TRL 5/6 Defence Ecosystem Research', ['accurate', null]],
  ['research/trl56/historical-baseline.md::Additional TRL 5 neede', ['accurate', null]],
  ['scripts/audit-claims.mjs::SAG (?:graded|certified)', ['accurate', null]],
  ['scripts/mission-workflow.mjs::SAG grading or TRL decision', ['accurate', null]],
  ["scripts/record-engineering-evidence.mjs::'SAG-01',", ['accurate', null]],
  ['scripts/trl5-validation.mjs::// TRL 5 advancement validation', ['accurate', null]],
  ['scripts/trl5-validation.mjs::`TRL 5 advancement validation', ['accurate', null]],
]);

/**
 * Classifies one hit (pure).
 * @param {{file: string, text: string, term: string}} hit
 * @returns {{category: string, accurate: boolean|null, note: string, proposed: string|null}}
 */
export function classify(hit) {
  for (const [key, [verdict, proposed]] of MANUAL_VERDICTS) {
    const [file, fragment] = key.split('::');
    if (file === hit.file && hit.text.includes(fragment))
      return {
        category: 'MANUAL',
        accurate: verdict === 'accurate',
        note:
          verdict === 'accurate'
            ? 'Reviewed: accurate statement of status'
            : 'Reviewed: inaccurate or overstated',
        proposed,
      };
  }
  if (NEGATION.test(hit.text))
    return {
      category: 'NEGATED',
      accurate: true,
      note: 'States absence, a limitation or a prohibition',
      proposed: null,
    };
  if (
    (hit.term === 'FIPS' || hit.term === 'SAG') &&
    STANDARD_REF.test(hit.text) &&
    hit.term === 'FIPS'
  )
    return {
      category: 'STANDARD',
      accurate: true,
      note: 'Cites a published standard by number',
      proposed: null,
    };
  if ((hit.term === 'approved' || hit.term === 'validated') && DOMAIN_SENSE.test(hit.text))
    return {
      category: 'DOMAIN',
      accurate: true,
      note: `Application sense of "${hit.term}" (approval workflow, input/schema validation)`,
      proposed: null,
    };
  if (TEST_FILE.test(hit.file))
    return {
      category: 'TEST',
      accurate: true,
      note: 'Test name or assertion text',
      proposed: null,
    };
  if (CODE_FILE.test(hit.file) && (hit.term === 'approved' || hit.term === 'validated'))
    return {
      category: 'DOMAIN',
      accurate: true,
      note: 'Code identifier or message in application sense',
      proposed: null,
    };
  return { category: 'REVIEW', accurate: null, note: 'Needs manual verdict', proposed: null };
}

/** Lists tracked files in scope (IO). */
export function trackedFiles(root) {
  return (
    execFileSync('git', ['ls-files', '*.md', '*.mjs', '*.rs', '*.ts', '*.yaml'], {
      cwd: root,
      encoding: 'utf8',
    })
      .split('\n')
      .filter(Boolean)
      // Frozen evidence and this audit's own outputs and pattern definitions are excluded.
      .filter((f) => !f.startsWith('docs/trl5/evidence/'))
      .filter((f) => f !== 'docs/assurance/claims-audit.md')
      .filter((f) => f !== 'scripts/claims-audit.mjs')
  );
}

/** Finds all hits (IO for reading; matching is pure). */
export function findHits(root, files) {
  const hits = [];
  for (const file of files) {
    const lines = readFileSync(resolve(root, file), 'utf8').split('\n');
    lines.forEach((line, i) => {
      for (const { term, re } of TERMS)
        if (re.test(line)) hits.push({ file, line: i + 1, term, text: line.trim() });
    });
  }
  return hits;
}

const cell = (s) =>
  String(s ?? '')
    .replaceAll('|', '\\|')
    .replaceAll('`', "'")
    .slice(0, 220);

/** Corrections applied on this branch (recorded so the audit shows what changed and why). */
export const APPLIED_CORRECTIONS = Object.freeze([
  {
    file: 'docs/decisions/ADR-012-rust-reference-components.md',
    before: 'evaluate aws-lc-rs (AWS-LC, assembly, FIPS-validated module family)',
    after:
      'evaluate aws-lc-rs (AWS-LC, assembly; AWS-LC offers a FIPS-mode build whose CMVP certificate and operational environment must be confirmed before relying on it)',
    reason: 'Unverified third-party validation claim; it would also fail scripts/check-claims.sh',
  },
]);

/** Renders the audit (pure). */
export function render({ commit, hits }) {
  const rows = hits.map((h) => ({ ...h, ...classify(h) }));
  const count = (pred) => rows.filter(pred).length;
  const out = [
    '# Claims audit',
    '',
    '<!-- GENERATED by scripts/claims-audit.mjs. Re-run: node scripts/claims-audit.mjs --write docs/assurance/claims-audit.md -->',
    '',
    `**Revision:** \`${commit}\`. **Scope:** tracked \`*.md\`, \`*.mjs\`, \`*.rs\`, \`*.ts\`, \`*.yaml\` files (frozen evidence logs excluded). **Terms:** ${TERMS.map((t) => `"${t.term}"`).join(', ')} (FIPS and SAG case-sensitive, word-bounded).`,
    '',
    'Categories are rule-based (`scripts/claims-audit.mjs` `classify`): NEGATED (states absence or a prohibition), STANDARD (cites a standard by number), DOMAIN (application sense: device/FLASH approval, schema or input validation), TEST (test name or assertion), MANUAL (reviewed individually; verdict and proposed wording below). Rule categories are heuristics; the MANUAL table is the reviewed set.',
    '',
    '## Summary',
    '',
    '| Term | Hits | NEGATED | STANDARD | DOMAIN | TEST | MANUAL accurate | MANUAL inaccurate | REVIEW (unresolved) |',
    '| --- | --- | --- | --- | --- | --- | --- | --- | --- |',
  ];
  for (const { term } of TERMS) {
    const t = (pred) => count((r) => r.term === term && pred(r));
    out.push(
      `| ${term} | ${t(() => true)} | ${t((r) => r.category === 'NEGATED')} | ${t((r) => r.category === 'STANDARD')} | ${t((r) => r.category === 'DOMAIN')} | ${t((r) => r.category === 'TEST')} | ${t((r) => r.category === 'MANUAL' && r.accurate)} | ${t((r) => r.category === 'MANUAL' && !r.accurate)} | ${t((r) => r.category === 'REVIEW')} |`,
    );
  }
  out.push('', '## Corrections applied on this branch', '');
  out.push('| File | Before | After | Reason |');
  out.push('| --- | --- | --- | --- |');
  for (const c of APPLIED_CORRECTIONS)
    out.push(`| \`${cell(c.file)}\` | ${cell(c.before)} | ${cell(c.after)} | ${cell(c.reason)} |`);
  out.push(
    '',
    'Every other item marked **No** below is a **proposal only**; those files are unchanged pending owner review.',
  );
  const manual = rows.filter((r) => r.category === 'MANUAL' || r.category === 'REVIEW');
  out.push('', '## Individually reviewed hits', '');
  out.push('| File:line | Term | Text | Accurate? | Proposed corrected wording |');
  out.push('| --- | --- | --- | --- | --- |');
  for (const r of manual)
    out.push(
      `| \`${cell(r.file)}:${r.line}\` | ${r.term} | ${cell(r.text)} | ${r.category === 'REVIEW' ? '**UNRESOLVED**' : r.accurate ? 'Yes' : '**No**'} | ${cell(r.proposed ?? '—')} |`,
    );
  out.push('', '## All hits (rule-classified)', '');
  out.push('| File:line | Term | Category | Text |');
  out.push('| --- | --- | --- | --- |');
  for (const r of rows.filter((x) => x.category !== 'MANUAL' && x.category !== 'REVIEW'))
    out.push(`| \`${cell(r.file)}:${r.line}\` | ${r.term} | ${r.category} | ${cell(r.text)} |`);
  out.push('');
  return { markdown: out.join('\n'), unresolved: manual.filter((r) => r.category === 'REVIEW') };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const root = resolve('.');
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  const hits = findHits(root, trackedFiles(root));
  const { markdown, unresolved } = render({ commit, hits });
  const used = new Set();
  for (const h of hits)
    for (const key of MANUAL_VERDICTS.keys()) {
      const [file, fragment] = key.split('::');
      if (file === h.file && h.text.includes(fragment)) used.add(key);
    }
  const stale = [...MANUAL_VERDICTS.keys()].filter((k) => !used.has(k));
  const args = process.argv.slice(2);
  if (args.includes('--write')) writeFileSync(args[args.indexOf('--write') + 1], markdown);
  console.log(
    `hits ${hits.length}; unresolved ${unresolved.length}; stale manual verdicts ${stale.length}`,
  );
  for (const u of unresolved)
    console.log(`REVIEW ${u.file}:${u.line} [${u.term}] ${u.text.slice(0, 160)}`);
  for (const s of stale) console.log(`STALE ${s}`);
  if (unresolved.length || stale.length) process.exitCode = 1;
}
