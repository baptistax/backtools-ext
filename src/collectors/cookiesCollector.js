(function(root, factory) {
  const api = factory(root);
  root.BackToolsCollectors = Object.assign(root.BackToolsCollectors || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  let domain = root.BackToolsDomain || {};
  if (typeof require === 'function') {
    try { domain = Object.assign({}, require('../domain/normalize.js'), require('../domain/cookies.js'), domain); } catch {}
  }

  function collectCookieMetadata(entries, targetUrl) {
    return domain.analyzeCookies(entries, targetUrl);
  }

  return { collectCookieMetadata };
});

