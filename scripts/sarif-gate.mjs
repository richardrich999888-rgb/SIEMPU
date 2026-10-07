import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// SARIF 2.1.0 permits query-pack rules in tool.extensions. Their indices are local
// to the referenced component, not indices into tool.driver.rules.
function resolveRule(run, result) {
  const reference = result.rule;
  if (
    reference !== undefined &&
    (!reference || typeof reference !== 'object' || Array.isArray(reference))
  )
    throw new Error('Invalid rule reference');
  const extensions = run.tool.extensions ?? [];
  const componentReference = reference?.toolComponent;
  let component = run.tool.driver;
  if (componentReference !== undefined) {
    if (
      !componentReference ||
      typeof componentReference !== 'object' ||
      Array.isArray(componentReference)
    )
      throw new Error('Invalid tool component reference');
    if (componentReference.index !== undefined) {
      if (!Number.isInteger(componentReference.index) || componentReference.index < 0)
        throw new Error('Invalid tool component index');
      component = extensions[componentReference.index];
    } else {
      if (componentReference.name === undefined && componentReference.guid === undefined)
        throw new Error('Empty tool component reference');
      const matches = [run.tool.driver, ...extensions].filter(
        (candidate) =>
          (componentReference.name === undefined || candidate.name === componentReference.name) &&
          (componentReference.guid === undefined || candidate.guid === componentReference.guid),
      );
      if (matches.length !== 1) throw new Error('Ambiguous tool component reference');
      [component] = matches;
    }
    if (
      !component ||
      (componentReference.name !== undefined && component.name !== componentReference.name) ||
      (componentReference.guid !== undefined && component.guid !== componentReference.guid)
    )
      throw new Error('Unresolved or conflicting tool component reference');
  }
  const rules = component.rules ?? [];
  if (!Array.isArray(rules)) throw new Error('Invalid component rules');
  const indices = [reference?.index, result.ruleIndex].filter((value) => value !== undefined);
  if (indices.some((value) => !Number.isInteger(value) || value < 0) || new Set(indices).size > 1)
    throw new Error('Invalid or conflicting rule indices');
  const ids = [reference?.id, result.ruleId].filter((value) => value !== undefined);
  if (ids.some((value) => typeof value !== 'string' || !value) || new Set(ids).size > 1)
    throw new Error('Invalid or conflicting rule identifiers');
  let matches = indices.length
    ? [rules[indices[0]]].filter(Boolean)
    : rules.filter((rule) => rule.id === ids[0]);
  if (reference?.guid !== undefined)
    matches = matches.filter((rule) => rule.guid === reference.guid);
  if (
    matches.length !== 1 ||
    typeof matches[0].id !== 'string' ||
    (ids.length && matches[0].id !== ids[0])
  )
    throw new Error('Finding does not resolve to an unambiguous rule');
  return matches[0];
}

/** Reject high/critical or ungraded error/security findings. Suppressions do not waive this gate. */
export function evaluateSarif(document) {
  if (document?.version !== '2.1.0' || !Array.isArray(document.runs) || !document.runs.length)
    throw new Error('A nonempty SARIF 2.1.0 CodeQL run is required');
  const blocked = [];
  let findings = 0;
  for (const run of document.runs) {
    if (
      run.tool?.driver?.name !== 'CodeQL' ||
      (run.tool.driver.rules !== undefined && !Array.isArray(run.tool.driver.rules)) ||
      (run.tool.extensions !== undefined && !Array.isArray(run.tool.extensions)) ||
      !Array.isArray(run.results)
    )
      throw new Error('Invalid CodeQL SARIF structure');
    if (run.invocations?.some((invocation) => invocation.executionSuccessful === false))
      throw new Error('CodeQL reported an unsuccessful invocation');
    for (const result of run.results) {
      if (['pass', 'notApplicable'].includes(result.kind)) continue;
      const rule = resolveRule(run, result);
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
  for (const name of names) {
    try {
      reports.push({
        file: name,
        ...evaluateSarif(JSON.parse(await readFile(join(directory, name), 'utf8'))),
      });
    } catch (error) {
      reports.push({ file: name, status: 'FAIL', error: error.message });
    }
  }
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
