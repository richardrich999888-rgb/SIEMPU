/** Informational operator-supplied build identifiers; never a code-attestation result.
 * @param {NodeJS.ProcessEnv} [env]
 */
export function buildInfo(env = process.env) {
  const revision = /^[a-f0-9]{40}$/i.test(env.SIEPMU_BUILD_REVISION || '')
    ? (env.SIEPMU_BUILD_REVISION || '').toLowerCase()
    : null;
  const timestamp = env.SIEPMU_BUILD_TIMESTAMP || '';
  const validDate =
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(timestamp) &&
    Number.isFinite(Date.parse(timestamp)) &&
    new Date(timestamp).toISOString().replace('.000Z', 'Z') === timestamp.replace('.000Z', 'Z');
  return {
    revision,
    builtAt: validDate ? new Date(timestamp).toISOString() : null,
    provenance: 'Operator-supplied metadata; not code attestation or proof of an approved build',
  };
}
