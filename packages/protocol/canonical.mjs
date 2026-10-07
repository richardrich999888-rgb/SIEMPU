/** SIEPMU-CJSON-v1: sorted JSON member names, preserved array order, safe integers.
 * This is a project encoding, not an implementation claim for RFC 8785.
 */
export function canonical(value) {
  const ancestors = new Set();
  function encode(v, depth) {
    if (depth > 64) throw new TypeError('Canonical value exceeds depth limit');
    if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
    if (typeof v === 'number') {
      if (!Number.isSafeInteger(v) || Object.is(v, -0))
        throw new TypeError('Canonical numbers must be safe integers');
      return JSON.stringify(v);
    }
    if (typeof v !== 'object') throw new TypeError('Unsupported canonical value');
    if (ancestors.has(v)) throw new TypeError('Cyclic canonical value');
    ancestors.add(v);
    try {
      if (Array.isArray(v)) {
        if (Object.getOwnPropertySymbols(v).length)
          throw new TypeError('Symbol keys are unsupported');
        if (Object.keys(v).length !== v.length)
          throw new TypeError('Sparse or extended arrays are unsupported');
        const items = [];
        for (let index = 0; index < v.length; index++) {
          const d = Object.getOwnPropertyDescriptor(v, String(index));
          if (!d || !('value' in d))
            throw new TypeError('Sparse arrays and accessors are unsupported');
          items.push(encode(d.value, depth + 1));
        }
        return '[' + items.join(',') + ']';
      }
      if (![Object.prototype, null].includes(Object.getPrototypeOf(v)))
        throw new TypeError('Canonical objects must be plain objects');
      if (Object.getOwnPropertySymbols(v).length)
        throw new TypeError('Symbol keys are unsupported');
      return (
        '{' +
        Object.keys(v)
          .sort()
          .map((k) => {
            const d = Object.getOwnPropertyDescriptor(v, k);
            if (!d || !('value' in d)) throw new TypeError('Accessors are unsupported');
            return JSON.stringify(k) + ':' + encode(d.value, depth + 1);
          })
          .join(',') +
        '}'
      );
    } finally {
      ancestors.delete(v);
    }
  }
  return encode(value, 0);
}
