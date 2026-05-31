(function(root, factory) {
  const api = factory(root);
  root.BackToolsPlatform = Object.assign(root.BackToolsPlatform || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  function getHar() {
    return new Promise(resolve => {
      try {
        const network = root.chrome?.devtools?.network;
        if (!network || typeof network.getHAR !== 'function') {
          resolve({ entries: [], unavailable: true, reason: 'network_har_unavailable' });
          return;
        }
        network.getHAR(har => resolve(har || { entries: [] }));
      } catch {
        resolve({ entries: [], unavailable: true, reason: 'network_har_unavailable' });
      }
    });
  }

  function addRequestFinishedListener(listener) {
    const event = root.chrome?.devtools?.network?.onRequestFinished;
    if (!event || typeof event.addListener !== 'function') return () => {};
    event.addListener(listener);
    return () => {
      if (typeof event.removeListener === 'function') event.removeListener(listener);
    };
  }

  function addNavigatedListener(listener) {
    const event = root.chrome?.devtools?.network?.onNavigated;
    if (!event || typeof event.addListener !== 'function') return () => {};
    event.addListener(listener);
    return () => {
      if (typeof event.removeListener === 'function') event.removeListener(listener);
    };
  }

  function getRequestContent(request, options = {}) {
    const timeoutMs = options.timeoutMs || 3000;
    return new Promise((resolve, reject) => {
      if (!request || typeof request.getContent !== 'function') {
        resolve({
          ok: false,
          status: 'platform_unavailable',
          reason: 'GET_CONTENT_UNAVAILABLE'
        });
        return;
      }
      let done = false;
      const timer = setTimeout(() => {
        if (done) return;
        done = true;
        reject(new Error('GET_CONTENT_TIMEOUT'));
      }, timeoutMs);
      try {
        request.getContent((content, encoding) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          resolve({
            ok: true,
            content,
            encoding: encoding || ''
          });
        });
      } catch (error) {
        if (done) return;
        done = true;
        clearTimeout(timer);
        reject(error);
      }
    });
  }

  return { getHar, addRequestFinishedListener, addNavigatedListener, getRequestContent };
});
