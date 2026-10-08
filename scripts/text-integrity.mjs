// Source-text integrity gate. Commit a4abc80 (Q-agile branch) was published with
// base64-decoded tool output spliced into five text files; the damage surfaced only
// indirectly as lint, format and syntax failures. This check names the defect directly.

/** File extensions treated as UTF-8 source text. Everything else is ignored. */
export const TEXT_EXTENSIONS = Object.freeze([
  '.mjs',
  '.js',
  '.cjs',
  '.ts',
  '.json',
  '.md',
  '.yml',
  '.yaml',
  '.sql',
  '.txt',
  '.css',
  '.html',
]);

const decoder = new TextDecoder('utf-8', { fatal: true });
const REPLACEMENT_CHARACTER = '\uFFFD';
// C0 controls other than TAB (0x09), LF (0x0A) and CR (0x0D), plus DEL (0x7F).
const FORBIDDEN_CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;

/**
 * Returns null for clean text, otherwise a short reason code.
 * @param {Uint8Array} bytes raw file contents
 * @returns {null | 'INVALID_UTF8' | 'CONTROL_CHARACTER' | 'REPLACEMENT_CHARACTER'}
 */
export function textIntegrityViolation(bytes) {
  let text;
  try {
    text = decoder.decode(bytes);
  } catch {
    return 'INVALID_UTF8';
  }
  if (FORBIDDEN_CONTROL.test(text)) return 'CONTROL_CHARACTER';
  // A lossy decoder elsewhere would turn the same damage into U+FFFD; reject that too.
  if (text.includes(REPLACEMENT_CHARACTER)) return 'REPLACEMENT_CHARACTER';
  return null;
}

/** @param {string} path */
export function isTextPath(path) {
  return TEXT_EXTENSIONS.some((extension) => path.endsWith(extension));
}
