(function(root, factory) {
  const api = factory();
  root.BackToolsDomain = Object.assign(root.BackToolsDomain || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function() {
  function inferType(url, mime) {
    const u = (url || '').toLowerCase();
    const m = (mime || '').toLowerCase();
    if (m.includes('javascript') || u.endsWith('.js')) return 'script';
    if (m.includes('css') || u.endsWith('.css')) return 'stylesheet';
    if (m.includes('html')) return 'document';
    if (m.includes('image')) return 'image';
    if (m.includes('json') || u.endsWith('.json')) return 'json';
    return 'other';
  }

  function mapDataExt(mime) {
    const m = (mime || '').toLowerCase();
    if (m === 'image/svg+xml') return 'svg';
    if (m === 'image/png') return 'png';
    if (m === 'image/jpeg') return 'jpg';
    if (m === 'image/gif') return 'gif';
    if (m === 'text/html') return 'html';
    if (m === 'text/css') return 'css';
    if (m === 'application/json') return 'json';
    if (m === 'text/plain') return 'txt';
    return 'bin';
  }

  function summarizeResources(rows) {
    const s = { total: rows.length, readable: 0, metadataOnly: 0, unavailable: 0, exportable: 0 };
    rows.forEach(r => {
      const bodyStatus = r.bodyCaptureStatus || r.bodyStatus || r.status;
      if (r.status === 'readable' || bodyStatus === 'body_captured') s.readable++;
      if (r.status === 'metadata_only' || bodyStatus === 'metadata_only') s.metadataOnly++;
      if (r.status === 'unavailable' || bodyStatus === 'platform_unavailable') s.unavailable++;
      if (r.exportable) s.exportable++;
    });
    return s;
  }

  function buildReasonGroups(rows) {
    const g = {};
    rows.forEach(r => {
      if (r.reason) g[r.reason] = (g[r.reason] || 0) + 1;
    });
    return g;
  }

  return { inferType, mapDataExt, summarizeResources, buildReasonGroups };
});
