(function(root, factory) {
  const api = factory(root);
  root.BackToolsPlatform = Object.assign(root.BackToolsPlatform || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  function evalInspectedUrl() {
    return new Promise(resolve => {
      try {
        const inspectedWindow = root.chrome?.devtools?.inspectedWindow;
        if (!inspectedWindow || typeof inspectedWindow.eval !== 'function') {
          resolve(null);
          return;
        }
        inspectedWindow.eval('location.href', (res, exc) => {
          resolve((exc && (exc.isException || exc.isError)) ? null : res || null);
        });
      } catch {
        resolve(null);
      }
    });
  }

  function evalInInspectedWindow(expression, options = {}) {
    return new Promise(resolve => {
      const callback = (result, exception) => {
        const failed = !!(exception && (exception.isException || exception.isError));
        resolve({
          ok: !failed,
          result: failed ? null : result,
          exception: exception || null,
          error: failed ? exception?.description || exception?.value || 'Inspected window eval failed.' : null
        });
      };
      try {
        const inspectedWindow = root.chrome?.devtools?.inspectedWindow;
        if (!inspectedWindow || typeof inspectedWindow.eval !== 'function') {
          resolve({
            ok: false,
            result: null,
            exception: null,
            error: 'inspected_window_eval_unavailable'
          });
          return;
        }
        if (options && Object.keys(options).length) {
          inspectedWindow.eval(expression, options, callback);
        } else {
          inspectedWindow.eval(expression, callback);
        }
      } catch (error) {
        resolve({
          ok: false,
          result: null,
          exception: null,
          error: 'inspected_window_eval_unavailable'
        });
      }
    });
  }

  function getResources() {
    return new Promise(resolve => {
      try {
        const inspectedWindow = root.chrome?.devtools?.inspectedWindow;
        if (!inspectedWindow || typeof inspectedWindow.getResources !== 'function') {
          resolve([]);
          return;
        }
        inspectedWindow.getResources(resources => {
          resolve(Array.isArray(resources) ? resources : []);
        });
      } catch {
        resolve([]);
      }
    });
  }

  function getResourceContent(resource) {
    return new Promise(resolve => {
      try {
        if (!resource || typeof resource.getContent !== 'function') {
          resolve({ content: null, encoding: null, error: 'resource_content_unavailable' });
          return;
        }
        resource.getContent((content, encoding) => {
          resolve({ content, encoding, error: root.chrome?.runtime?.lastError?.message || null });
        });
      } catch {
        resolve({ content: null, encoding: null, error: 'resource_content_unavailable' });
      }
    });
  }

  function reloadInspectedWindow(options) {
    root.chrome?.devtools?.inspectedWindow?.reload(options);
  }

  return { evalInspectedUrl, evalInInspectedWindow, getResources, getResourceContent, reloadInspectedWindow };
});
