(function(root, factory) {
  const api = factory();
  root.BackToolsDomain = Object.assign(root.BackToolsDomain || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function() {
  function parseUrl(u) {
    try {
      const x = new URL(u);
      return {
        host: x.host,
        path: x.pathname + (x.search || ''),
        scheme: x.protocol.replace(':', '')
      };
    } catch {
      return { host: null, path: u || 'unknown', scheme: null };
    }
  }

  function parseDataUrl(url) {
    const m = /^data:([^,]*?),(.*)$/s.exec(url || '');
    if (!m) return null;
    const meta = m[1] || '';
    const payload = m[2] || '';
    const parts = meta.split(';').filter(Boolean);
    const mime = parts[0] && parts[0].includes('/') ? parts[0] : 'text/plain';
    const base64 = parts.includes('base64');
    return { mimeType: mime, base64, payload };
  }

  function base64ToBytes(value) {
    if (typeof atob === 'function') {
      return Uint8Array.from(atob(value), c => c.charCodeAt(0));
    }
    if (typeof Buffer !== 'undefined') {
      return Uint8Array.from(Buffer.from(value, 'base64'));
    }
    throw new Error('base64 decoder unavailable');
  }

  function decodeDataUrl(url) {
    const parsed = parseDataUrl(url);
    if (!parsed) return { ok: false, reason: 'DATA_URL_DECODE_FAILED' };
    try {
      if (parsed.base64) {
        const clean = parsed.payload.replace(/\s/g, '');
        const bytes = base64ToBytes(clean);
        return {
          ok: true,
          bytes,
          mimeType: parsed.mimeType,
          contentKind: 'binary_base64'
        };
      }
      const decoded = decodeURIComponent(parsed.payload);
      return {
        ok: true,
        bytes: new TextEncoder().encode(decoded),
        mimeType: parsed.mimeType,
        contentKind: 'text_utf8'
      };
    } catch {
      return { ok: false, reason: 'DATA_URL_DECODE_FAILED' };
    }
  }

  return { parseUrl, parseDataUrl, decodeDataUrl };
});

