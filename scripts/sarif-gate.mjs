import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

/** Reject high/critical or ungraded error/security findings. Suppressions do not waive this gate. */
export function evaluateSarif(document) {
  if (document?.version !== '2.1.0' || !Array.isArray(document.runs) || !document.runs.length)
    throw new Error('A nonempty SARIF 2.1.0 CodeQL run is required');
  const blocked = [];
  let findings = 0;
  for (const run of document.runs) {
    if (
      run.tool?.driver?.name !== 'CodeQL' ||
      !Array.isArray(run.tool.driver.rules) ||
      !Array.isArray(run.results)
    )
      throw new Error('Invalid CodeQL SARIF structure');
    const rules = run.tool.driver.rules;
    for (const result of run.results) {
      if (['pass', 'notApplicable'].includes(result.kind)) continue;
      const rule = Number.isInteger(result.ruleIndex)
        ? rules[result.ruleIndex]
        : rules.find((candidate) => candidate.id === result.ruleId);
      if (!rule || (result.ruleId && result.ruleId !== rule.id))
        throw new Error('Finding does not resolve to an unambiguous rule');
      const rawScore = rule.properties?.['security-severity'];
      if (
        rawScore !== undefined &&
        ((typeof rawScore !== 'string' && typeof rawScore !== 'number') ||
          (typeof rawScore === 'string' && !/^\d+(?:\.\d+)?$/.test(rawScore)))
      )
        throw new Error('Invalid security severity type');
      const score = rawScore === undefined ? null : Number(rawScore);
      if (score !== null && (!Number.isFinite(score) || score < 0 || score > 10))
        throw new Error('Invalid security severity');
      const level = result.level || rule.defaultConfiguration?.level || 'warning';
      const securityTagged = rule.properties?.tags?.includes('security') === true;
      findings++;
      if (
        (score !== null && score >= 7) ||
        level === 'error' ||
        (securityTagged && score === null)
      ) {
        blocked.push({
          ruleId: rule.id,
          securitySeverity: score,
          level,
          reason:
            score !== null && score >= 7
              ? 'HIGH_OR_CRITICAL_SECURITY'
              : level === 'error'
                ? 'ERROR_LEVEL_FINDING'
                : 'UNRATED_SECURITY_FINDING',
        });
      }
    }
  }
  return {
    policy:
      'CodeQL severity >=7, any error-level finding, or unrated security finding blocks; no suppression waiver',
    status: blocked.length ? 'FAIL' : 'PASS',
    findings,
    blocked,
  };
}

export async function gateDirectory(directory) {
  const names = (await readdir(directory)).filter((name) => name.endsWith('.sarif')).sort();
  if (!names.length) throw new Error('No CodeQL SARIF outputs found; refusing a vacuous pass');
  const reports = [];
  for (const name of names)
    reports.push({
      file: name,
      ...evaluateSarif(JSON.parse(await readFile(join(directory, name), 'utf8'))),
    });
  const summary = {
    status: reports.some((report) => report.status !== 'PASS') ? 'FAIL' : 'PASS',
    reports,
  };
  await writeFile(join(directory, 'gate.json'), JSON.stringify(summary, null, 2) + '\n');
  return summary;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const report = await gateDirectory(resolve(process.argv[2] || 'artifacts/codeql'));
    console.log(JSON.stringify(report, null, 2));
    if (report.status !== 'PASS') process.exitCode = 1;
  } catch (error) {
    console.error(`SAST gate failed: ${error.message}`);
    process.exitCode = 1;
  }
}
