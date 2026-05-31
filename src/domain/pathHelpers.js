(function(root, factory) {
  const api = factory(root);
  root.BackToolsDomain = Object.assign(root.BackToolsDomain || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  let domain = root.BackToolsDomain || {};
  if (typeof require === 'function') {
    try { domain = Object.assign({}, require('./normalize.js'), require('./classify.js'), domain); } catch {}
  }

  async function sha1Hex(value) {
    const input = new TextEncoder().encode(value);
    if (root.crypto?.subtle) {
      return Array.from(new Uint8Array(await root.crypto.subtle.digest('SHA-1', input)))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
        .slice(0, 10);
    }
    if (typeof require === 'function') {
      const crypto = require('crypto');
      return crypto.createHash('sha1').update(value).digest('hex').slice(0, 10);
    }
    throw new Error('SHA-1 unavailable');
  }

  function buildCurrentSourceZipPath(resource) {
    const pu = domain.parseUrl(resource.url || '');
    const host = pu.host || 'unknown-host';
    const safe = (pu.path || resource.id).replace(/^\//, '').replace(/[<>:"|?*]/g, '_');
    return `sources/${host}/${safe || 'index'}`;
  }

  async function buildCurrentDataUrlZipPath(resource, index, mimeType) {
    const hash = await sha1Hex(resource.url || resource.id);
    const ext = domain.mapDataExt(mimeType);
    return `data-urls/data-url-${index + 1}-${hash}.${ext}`;
  }

  return { sha1Hex, buildCurrentSourceZipPath, buildCurrentDataUrlZipPath };
});

