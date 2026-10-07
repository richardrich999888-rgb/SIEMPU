/** DOM creation only: protected content is never interpreted as HTML. */
export function element(tag, properties = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(properties)) {
    if (name.startsWith('on') && typeof value === 'function')
      node.addEventListener(name.slice(2).toLowerCase(), value);
    else if (name === 'className') node.className = value;
    else if (name === 'dataset') Object.assign(node.dataset, value);
    else if (name in node) node[name] = value;
    else if (value !== undefined && value !== false) node.setAttribute(name, String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}
export const field = (text, input) => element('label', {}, text, input);
export const button = (text, onClick, className = '') =>
  element('button', { type: 'button', className, onClick }, text);
export const badge = (text) =>
  element('span', { className: `badge ${String(text).toLowerCase()}` }, text);
export const hint = (text) => element('p', { className: 'hint' }, text);
export function panel(title, description, ...children) {
  return element(
    'section',
    { className: 'panel' },
    element(
      'div',
      { className: 'panel-heading' },
      element('div', {}, element('h2', {}, title), description ? hint(description) : null),
    ),
    children,
  );
}
export function table(headers, rows) {
  return element(
    'div',
    { className: 'table-wrap' },
    element(
      'table',
      {},
      element(
        'thead',
        {},
        element(
          'tr',
          {},
          headers.map((x) => element('th', {}, x)),
        ),
      ),
      element(
        'tbody',
        {},
        rows.map((row) =>
          element(
            'tr',
            {},
            row.map((x) => element('td', {}, x)),
          ),
        ),
      ),
    ),
  );
}
export function download(value, filename, mime = 'application/json') {
  const blob =
    value instanceof Blob
      ? value
      : new Blob([typeof value === 'string' ? value : JSON.stringify(value, null, 2)], {
          type: mime,
        });
  const url = URL.createObjectURL(blob);
  const a = element('a', { href: url, download: filename, rel: 'noopener' });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function safeName(name) {
  return (
    String(name || 'attachment')
      .replace(/[\\/\x00-\x1f\x7f<>:"|?*]/g, '_')
      .slice(0, 120) || 'attachment'
  );
}
