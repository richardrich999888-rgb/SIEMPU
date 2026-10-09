// Pure parser for NIST CAVP response (.rsp) files. No IO.
//
// Format (CAVP test vector files, e.g. SHA256ShortMsg.rsp, gcmEncryptExtIV256.rsp, SigVer.rsp):
//   - lines starting with '#' are comments; the leading comment block names the CAVS version
//   - '[Name = Value]' or '[Label]' lines set section parameters for the records that follow
//   - records are blank-line-separated groups of 'Name = Value' lines; a bare token line
//     (e.g. 'FAIL' in gcmDecrypt files) is recorded as a flag on its record
// Unknown structure fails closed: a line that is none of the above throws.

const HEADER = /^\[(.+)\]$/;
const FIELD = /^([A-Za-z][A-Za-z0-9_ ]*?)\s*=\s*(.*)$/;
const FLAG = /^[A-Z]+$/;

/**
 * Parses CAVP .rsp text.
 * @param {string} text file contents
 * @returns {{comments: string[], records: Array<{section: Record<string,string>, fields: Record<string,string>, flags: string[]}>}}
 */
export function parseRsp(text) {
  if (typeof text !== 'string') throw new TypeError('rsp text must be a string');
  const comments = [];
  const records = [];
  let section = {};
  let sectionUsed = false;
  let current = null;
  const flush = () => {
    if (current) records.push(current);
    current = null;
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '') {
      flush();
      continue;
    }
    if (line.startsWith('#')) {
      comments.push(line.slice(1).trim());
      continue;
    }
    const header = HEADER.exec(line);
    if (header) {
      flush();
      // A header after records starts a new section; consecutive headers accumulate.
      if (sectionUsed) {
        section = {};
        sectionUsed = false;
      }
      const inner = header[1];
      const eq = inner.indexOf('=');
      if (eq === -1) section = { ...section, label: inner.trim() };
      else section = { ...section, [inner.slice(0, eq).trim()]: inner.slice(eq + 1).trim() };
      continue;
    }
    const field = FIELD.exec(line);
    if (field) {
      if (!current) {
        current = { section, fields: {}, flags: [] };
        sectionUsed = true;
      }
      if (Object.hasOwn(current.fields, field[1])) throw new Error(`Duplicate field ${field[1]}`);
      current.fields[field[1]] = field[2].trim();
      continue;
    }
    if (FLAG.test(line) && current) {
      current.flags.push(line);
      continue;
    }
    throw new Error(`Unrecognised rsp line: ${line.slice(0, 40)}`);
  }
  flush();
  return { comments, records };
}
