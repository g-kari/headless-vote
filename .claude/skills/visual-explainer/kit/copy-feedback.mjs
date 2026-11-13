import { esc, find, parseHtml, serialize } from './html.mjs';

// Compatibility only, not a trust boundary: the host independently ignores stdout.
// Existing rendered pages may still have the old Send to agent opt-in marker.
export function copyOnlyFeedback(html) {
  const doc = parseHtml(html);
  for (const node of find(doc, n => Object.hasOwn(n.attrs, 'data-send-back'))) {
    delete node.attrs['data-send-back'];
    const attrs = Object.entries(node.attrs).map(([key, value]) => ` ${key}="${esc(value)}"`).join('');
    node.openRaw = `<${node.name}${attrs}${node.selfClose ? ' /' : ''}>`;
  }
  return serialize(doc);
}
