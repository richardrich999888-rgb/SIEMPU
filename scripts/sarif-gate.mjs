import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const present = (value, key) => Object.hasOwn(value, key);
const indexValue = (value) => Number.isSafeInteger(value) && value >= 0;
const identifier = (value) => typeof value === 'string' && value.length > 0;

// SARIF 2.1.0 sections 3.27.7, 3.52 and 3.54: component indexes address
// tool.extensions, whereas rule indexes address that selected component's rules.
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
function resolveRule(run, result) {
  if (!object(result) || (present(result, 'rule') && !object(result.rule)))
    throw new Error('Invalid SARIF rule reference');
  const reference = result.rule ?? {};
  const componentReference = reference.toolComponent ?? {};
  if (
    !object(componentReference) ||
    (present(reference, 'toolComponent') && reference.toolComponent === null)
  )
    throw new Error('Invalid SARIF component reference');
  const extensions = run.tool.extensions ?? [];
  let component = run.tool.driver;
  if (present(componentReference, 'index')) {
    if (!indexValue(componentReference.index)) throw new Error('Invalid component index');
    component = extensions[componentReference.index];
  }
  if (present(componentReference, 'guid')) {
    if (!identifier(componentReference.guid)) throw new Error('Invalid component GUID');
    const matches = [run.tool.driver, ...extensions].filter(
      (candidate) => candidate.guid === componentReference.guid,
    );
    if (matches.length !== 1 || (present(componentReference, 'index') && matches[0] !== component))
      throw new Error('Component reference is missing, conflicting or ambiguous');
    component = matches[0];
  }
  if (
    !object(component) ||
    !identifier(component.name) ||
    (component.rules !== undefined && !Array.isArray(component.rules))
  )
    throw new Error('Unresolved SARIF tool component');
  if (present(componentReference, 'name') && componentReference.name !== component.name)
    throw new Error('Conflicting component name');
  for (const [flat, nested] of [
    ['ruleIndex', 'index'],
    ['ruleId', 'id'],
  ]) {
    if (present(result, flat) && present(reference, nested) && result[flat] !== reference[nested])
      throw new Error('Conflicting result and nested rule reference');
  }
  const ruleIndex = present(reference, 'index') ? reference.index : result.ruleIndex;
  const ruleId = present(reference, 'id') ? reference.id : result.ruleId;
  const rules = component.rules ?? [];
  let rule;
  if (ruleIndex !== undefined) {
    if (!indexValue(ruleIndex)) throw new Error('Invalid rule index');
    rule = rules[ruleIndex];
  }
  if (present(reference, 'guid')) {
    if (!identifier(reference.guid)) throw new Error('Invalid rule GUID');
    const matches = rules.filter((candidate) => candidate.guid === reference.guid);
    if (matches.length !== 1 || (ruleIndex !== undefined && matches[0] !== rule))
      throw new Error('Rule GUID reference is missing, conflicting or ambiguous');
    rule = matches[0];
  }
  // Metadata-bearing SARIF references require index or GUID. Never guess a
  // same-named rule in another component or silently use the first duplicate.
  if (!object(rule) || !identifier(rule.id))
    throw new Error('Finding does not resolve to an unambiguous rule');
  if (ruleId !== undefined) {
    const suffix =
      typeof ruleId === 'string' && ruleId.startsWith(rule.id + '/')
        ? ruleId.slice(rule.id.length + 1)
        : null;
    if (!identifier(ruleId) || (ruleId !== rule.id && (!suffix || suffix.includes('/'))))
      throw new Error('Rule identifier does not match selected descriptor');
  }
  return { rule, component };
}

function resultLocations(run, result) {
  if (result.locations !== undefined && !Array.isArray(result.locations))
    throw new Error('Invalid result locations');
  return (result.locations ?? []).map((location) => {
    const physical = location.physicalLocation ?? {};
    const artifact = physical.artifactLocation ?? {};
    let uri = artifact.uri;
    if (artifact.index !== undefined) {
      if (!indexValue(artifact.index) || !run.artifacts?.[artifact.index])
        throw new Error('Unresolved artifact location index');
      const indexedUri = run.artifacts[artifact.index].location?.uri;
      if (uri !== undefined && indexedUri !== undefined && uri !== indexedUri)
        throw new Error('Conflicting artifact locations');
      uri ??= indexedUri;
    }
    if (uri !== undefined && !identifier(uri)) throw new Error('Invalid artifact URI');
    const line = physical.region?.startLine;
    if (line !== undefined && (!Number.isSafeInteger(line) || line < 1))
      throw new Error('Invalid source line');
    return { path: uri ?? null, line: line ?? null };
  });
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
      (run.tool.extensions !== undefined &&
        (!Array.isArray(run.tool.extensions) ||
          run.tool.extensions.some((component) => !object(component)))) ||
      !Array.isArray(run.results)
    )
      throw new Error('Invalid CodeQL SARIF structure');
    for (const result of run.results) {
      if (['pass', 'notApplicable'].includes(result.kind)) continue;
      const { rule, component } = resolveRule(run, result);
      const locations = resultLocations(run, result);
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
      const level = result.level ?? rule.defaultConfiguration?.level ?? 'warning';
      if (!['none', 'note', 'warning', 'error'].includes(level))
        throw new Error('Invalid result severity level');
      if (
        rule.properties?.tags !== undefined &&
        (!Array.isArray(rule.properties.tags) ||
          rule.properties.tags.some((tag) => typeof tag !== 'string'))
      )
        throw new Error('Invalid rule tags');
      const securityTagged = rule.properties?.tags?.includes('security') === true;
      findings++;
      if (
        (score !== null && score >= 7) ||
        level === 'error' ||
        (securityTagged && score === null)
      ) {
        blocked.push({
          ruleId: rule.id,
          toolComponent: component.name,
          path: locations[0]?.path ?? null,
          line: locations[0]?.line ?? null,
          locations,
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
