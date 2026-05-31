(function(root, factory) {
  const api = factory();
  root.BackToolsUI = Object.assign(root.BackToolsUI || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function() {
  function startTargetUrlPolling({ evalUrl, state, resetCookieSessionState, syncState, q, onTargetUrlChange, intervalMs = 1500 }) {
    return setInterval(async () => {
      const prev = state.target.currentUrl;
      const next = await evalUrl();
      if (typeof onTargetUrlChange === 'function') {
        onTargetUrlChange(next, 'inspected_window_eval_location_href');
      } else {
        state.target.currentUrl = next;
      }
      if (prev !== state.target.currentUrl) {
        resetCookieSessionState();
      }
      syncState();
      q('targetUrl').textContent = state.target.currentUrl || 'Unavailable';
    }, intervalMs);
  }

  return { startTargetUrlPolling };
});
