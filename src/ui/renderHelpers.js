(function(root, factory) {
  const api = factory();
  root.BackToolsUI = Object.assign(root.BackToolsUI || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function() {
  function escapeHtml(v) {
    return String(v ?? '').replace(/[&<>"']/g, m => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[m]));
  }

  function escapeAttr(v) {
    return escapeHtml(v).replace(/`/g, '&#96;');
  }

  function safeText(v) {
    return escapeHtml(v);
  }

  function safeUrlForDisplay(v) {
    const text = String(v ?? '');
    return escapeHtml(text.replace(/[\u0000-\u001f\u007f]/g, ''));
  }

  return { escapeHtml, escapeAttr, safeText, safeUrlForDisplay };
});
