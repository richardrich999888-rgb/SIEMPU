// Stable, bounded operational observations; never serialize an upstream exception or body.
const STAGES = new Set(['CONFIGURE', 'AUTHENTICATE', 'DATABASE', 'LISTEN']);
const CODES = new Set([
  'LOGIN_DENIED',
  'MFA_REPLAY',
  'RATE_LIMITED',
  'UNAUTHORIZED',
  'DEVICE_REVOKED',
  'DEVICE_NOT_APPROVED',
  'FORBIDDEN',
  'RECOVERY_REQUIRED',
  'EADDRINUSE',
  'EACCES',
]);
export function startupDiagnostic(error) {
  return {
    event: 'ADAPTER_STARTUP_FAILED',
    stage: STAGES.has(error?.adapterStage) ? error.adapterStage : 'UNKNOWN',
    code: CODES.has(error?.code) ? error.code : 'STARTUP_FAILURE',
    status:
      Number.isInteger(error?.status) && error.status >= 400 && error.status <= 599
        ? error.status
        : null,
  };
}
export function isAdapterReady(response) {
  try {
    const r = JSON.parse(response.body);
    return (
      response.status === 200 &&
      r.service === 'synthetic-adapter' &&
      r.ready === true &&
      r.checks?.database === true &&
      r.checks?.capacity === true &&
      r.checks?.authority === true
    );
  } catch {
    return false;
  }
}
