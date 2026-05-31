(function(root, factory) {
  const api = factory(root);
  root.BackToolsPlatform = Object.assign(root.BackToolsPlatform || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  function isRuntimeAvailable() {
    return !!root.chrome?.runtime;
  }

  return { isRuntimeAvailable };
});

