// The wire contract lives in packages/crypto/crypto.mjs (see the invariant there).
// Server modules import it through this stable path.
export {
  CLASSICAL_SCHEMA_VERSIONS,
  PROVIDER_SCHEMA_VERSION,
  contextFields,
  envelopeFieldsFor,
  hasEnvelopeShape,
  hasMissionLabels,
  validEnvelopeVersion,
} from '../crypto/crypto.mjs';
