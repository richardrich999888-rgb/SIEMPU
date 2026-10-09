// IO: runtime identification for the report (process metadata only).

/** Versions of the runtime and its cryptographic library. */
export function getVersion() {
  return {
    'Node.js': process.version,
    OpenSSL: process.versions.openssl,
    Platform: `${process.platform}-${process.arch}`,
  };
}
