(function(root, factory) {
  const api = factory(root);
  root.BackToolsCollectors = Object.assign(root.BackToolsCollectors || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  let domain = root.BackToolsDomain || {};
  if (typeof require === 'function') {
    try {
      domain = Object.assign(
        {},
        require('../domain/application.js'),
        require('../domain/targetClassification.js'),
        domain
      );
    } catch {}
  }

  const DEFAULT_APPLICATION_COLLECTOR_POLICY = {
    timeoutMs: 1800,
    pollIntervalMs: 60,
    indexedDbStoreCountLimit: 80,
    cacheRequestLimit: 500
  };

  async function collectApplicationMetadata(adapters = {}, targetUrl, options = {}) {
    const policy = normalizeApplicationCollectorPolicy(options.policy);
    const target = options.target || safeClassifyTarget(targetUrl);
    if (target && target.isNormalWebTarget === false) {
      return buildUnavailableApplication(targetUrl, target, controlledReasonForTarget(target));
    }
    const evalInInspectedWindow = adapters.evalInInspectedWindow || adapters.eval;
    if (typeof evalInInspectedWindow !== 'function') {
      return buildUnavailableApplication(targetUrl, target, 'inspected_window_eval_unavailable');
    }

    const token = `bt-app-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const start = await safeEval(evalInInspectedWindow, buildApplicationSnapshotExpression(token, policy));
    if (!start.ok) {
      await cleanupApplicationSnapshot(evalInInspectedWindow, token);
      return buildUnavailableApplication(targetUrl, target, start.reason || 'inspected_window_eval_unavailable');
    }

    const deadlineAt = Date.now() + policy.timeoutMs;
    let lastResult = null;
    let finalReason = null;
    try {
      while (Date.now() <= deadlineAt) {
        await sleep(Math.min(policy.pollIntervalMs, Math.max(0, deadlineAt - Date.now())));
        const poll = await safeEval(evalInInspectedWindow, buildApplicationSnapshotPollExpression(token));
        if (!poll.ok) {
          finalReason = 'application_poll_failed';
          lastResult = {
            status: 'error',
            reason: finalReason,
            error: diagnosticMessageForReason(finalReason)
          };
          break;
        }
        lastResult = poll.result || null;
        if (lastResult?.status === 'done' || lastResult?.status === 'error') break;
      }
    } finally {
      await cleanupApplicationSnapshot(evalInInspectedWindow, token);
    }

    if (lastResult?.status === 'done') {
      return domain.analyzeApplicationSnapshot(lastResult.snapshot || {}, targetUrl);
    }

    if (!finalReason) {
      finalReason = lastResult?.reason || (lastResult?.status === 'error' ? 'application_snapshot_failed' : 'application_collection_timeout');
    }
    return domain.analyzeApplicationSnapshot({
      status: 'partial',
      pageUrl: targetUrl || null,
      origin: getOrigin(targetUrl),
      reason: finalReason,
      error: lastResult?.error || diagnosticMessageForReason(finalReason)
    }, targetUrl);
  }

  async function safeEval(evalInInspectedWindow, expression, options) {
    try {
      const response = await evalInInspectedWindow(expression, options || {});
      if (response && typeof response === 'object' && Object.prototype.hasOwnProperty.call(response, 'ok')) {
        if (response.ok === false) {
          return {
            ok: false,
            reason: 'inspected_window_eval_unavailable',
            error: 'inspected_window_eval_unavailable'
          };
        }
        return { ok: true, result: response.result };
      }
      return { ok: true, result: response };
    } catch (error) {
      return { ok: false, reason: 'inspected_window_eval_unavailable', error: 'inspected_window_eval_unavailable' };
    }
  }

  async function cleanupApplicationSnapshot(evalInInspectedWindow, token) {
    await safeEval(evalInInspectedWindow, buildApplicationSnapshotCleanupExpression(token));
  }

  function normalizeApplicationCollectorPolicy(policy = {}) {
    return {
      timeoutMs: normalizeLimit(policy.timeoutMs, DEFAULT_APPLICATION_COLLECTOR_POLICY.timeoutMs),
      pollIntervalMs: normalizeLimit(policy.pollIntervalMs, DEFAULT_APPLICATION_COLLECTOR_POLICY.pollIntervalMs),
      indexedDbStoreCountLimit: normalizeLimit(policy.indexedDbStoreCountLimit, DEFAULT_APPLICATION_COLLECTOR_POLICY.indexedDbStoreCountLimit),
      cacheRequestLimit: normalizeLimit(policy.cacheRequestLimit, DEFAULT_APPLICATION_COLLECTOR_POLICY.cacheRequestLimit)
    };
  }

  function normalizeLimit(value, fallback) {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0
      ? Math.floor(value)
      : fallback;
  }

  function diagnosticMessageForReason(reason) {
    if (reason === 'application_poll_failed') return 'Application collector polling failed before storage inventory completed.';
    if (reason === 'application_snapshot_failed') return 'Application collector failed before storage inventory completed.';
    return 'Application collector timed out before storage inventory completed.';
  }

  function buildUnavailableApplication(targetUrl, target, reason) {
    const message = applicationUnavailableMessage(target, reason);
    return domain.analyzeApplicationSnapshot({
      status: 'platform_unavailable',
      pageUrl: target?.targetUrl || targetUrl || null,
      origin: getOrigin(target?.targetUrl || targetUrl),
      error: message,
      reason,
      localStorage: unavailableStorageArea('localStorage', target, reason, message),
      sessionStorage: unavailableStorageArea('sessionStorage', target, reason, message),
      indexedDB: unavailableInventory('indexedDB', target, reason, message, { databases: [] }),
      cacheStorage: unavailableInventory('cacheStorage', target, reason, message, { caches: [] }),
      serviceWorkers: unavailableInventory('serviceWorkers', target, reason, message, { registrations: [] }),
      manifest: unavailableInventory('manifest', target, reason, message, {})
    }, target?.targetUrl || targetUrl);
  }

  function unavailableStorageArea(name, target, reason, message) {
    return {
      status: 'unavailable',
      available: false,
      origin: getOrigin(target?.targetUrl),
      frameUrl: target?.targetUrl || null,
      itemCount: 0,
      entries: [],
      reason,
      error: message
    };
  }

  function unavailableInventory(name, target, reason, message, extra) {
    return {
      status: 'unavailable',
      available: false,
      origin: getOrigin(target?.targetUrl),
      reason,
      error: message,
      ...extra
    };
  }

  function controlledReasonForTarget(target) {
    if (typeof domain.moduleReasonForTarget === 'function') {
      return domain.moduleReasonForTarget(target, 'application');
    }
    return 'application_storage_unavailable';
  }

  function applicationUnavailableMessage(target, reason) {
    if (reason === 'no_http_origin') return 'Application storage is unavailable because this target has no normal HTTP origin.';
    if (reason === 'inspected_window_eval_unavailable') return 'Application storage is unavailable because page evaluation is not available for this target.';
    if (target?.isLimitedTarget) return 'Application storage is unavailable for this limited target.';
    return 'Application storage is unavailable for this target.';
  }

  function safeClassifyTarget(targetUrl) {
    if (typeof domain.classifyTargetUrl === 'function') {
      return domain.classifyTargetUrl(targetUrl, { urlSource: 'inspected_window_eval_location_href' });
    }
    return { isNormalWebTarget: /^https?:/i.test(String(targetUrl || '')), isLimitedTarget: !/^https?:/i.test(String(targetUrl || '')), targetUrl };
  }

  function buildApplicationSnapshotExpression(token, policy) {
    return `(() => {
const token = ${JSON.stringify(token)};
const policy = ${JSON.stringify(policy)};
const asError = error => String(error && (error.message || error.name) || error || 'Unknown error');
const write = payload => { window.__BackToolsApplicationSnapshot = Object.assign({ token }, payload); };
const storageArea = (name, storage) => {
  try {
    if (storage && storage.__backToolsStorageError) {
      return { status: 'unavailable', available: false, origin: location.origin, frameUrl: location.href, itemCount: 0, entries: [], error: storage.__backToolsStorageError };
    }
    const entries = [];
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      if (key === null || key === undefined) continue;
      const value = storage.getItem(key);
      entries.push({
        key: String(key),
        value: value === null || value === undefined ? '' : String(value),
        valueLength: value === null || value === undefined ? 0 : String(value).length,
        rawAvailable: value !== null && value !== undefined
      });
    }
    return { status: 'collected', available: true, origin: location.origin, frameUrl: location.href, itemCount: entries.length, entries };
  } catch (error) {
    return { status: 'unavailable', available: false, origin: location.origin, frameUrl: location.href, itemCount: 0, entries: [], error: asError(error) };
  }
};
const getStorageObject = name => {
  try {
    return window[name];
  } catch (error) {
    return { __backToolsStorageError: asError(error) };
  }
};
const requestResult = request => new Promise(resolve => {
  request.onsuccess = () => resolve({ ok: true, value: request.result });
  request.onerror = () => resolve({ ok: false, error: asError(request.error) });
});
const openDatabase = info => new Promise(resolve => {
  try {
    if (!info || !info.name) {
      resolve({ ok: false, error: 'Database name is not available.' });
      return;
    }
    const request = indexedDB.open(info.name);
    const timer = setTimeout(() => resolve({ ok: false, error: 'IndexedDB open timed out.' }), 700);
    request.onsuccess = () => {
      clearTimeout(timer);
      resolve({ ok: true, db: request.result });
    };
    request.onerror = () => {
      clearTimeout(timer);
      resolve({ ok: false, error: asError(request.error) });
    };
    request.onblocked = () => {
      clearTimeout(timer);
      resolve({ ok: false, error: 'IndexedDB open was blocked.' });
    };
  } catch (error) {
    resolve({ ok: false, error: asError(error) });
  }
});
const collectIndexedDB = async () => {
  if (!('indexedDB' in window)) return { status: 'platform_unavailable', available: false, origin: location.origin, databases: [], error: 'indexedDB is not available.' };
  if (typeof indexedDB.databases !== 'function') return { status: 'platform_unavailable', available: false, origin: location.origin, databases: [], error: 'indexedDB.databases is not available.' };
  try {
    const infos = await indexedDB.databases();
    const databases = [];
    for (const info of infos || []) {
      const database = { name: info.name || null, version: info.version ?? null, objectStores: [] };
      const opened = await openDatabase(info);
      if (!opened.ok) {
        database.error = opened.error;
        databases.push(database);
        continue;
      }
      const db = opened.db;
      try {
        const names = Array.from(db.objectStoreNames || []);
        for (const storeName of names.slice(0, policy.indexedDbStoreCountLimit)) {
          const storeRecord = { name: storeName, indexes: [], count: null, countStatus: 'not_collected' };
          try {
            const tx = db.transaction(storeName, 'readonly');
            const store = tx.objectStore(storeName);
            storeRecord.keyPath = store.keyPath ?? null;
            storeRecord.autoIncrement = store.autoIncrement ?? null;
            storeRecord.indexes = Array.from(store.indexNames || []).map(indexName => {
              const index = store.index(indexName);
              return { name: index.name, keyPath: index.keyPath ?? null, unique: index.unique, multiEntry: index.multiEntry };
            });
            const count = await requestResult(store.count());
            if (count.ok) {
              storeRecord.count = count.value;
              storeRecord.countStatus = 'collected';
            } else {
              storeRecord.countStatus = 'failed';
              storeRecord.error = count.error;
            }
          } catch (error) {
            storeRecord.countStatus = 'failed';
            storeRecord.error = asError(error);
          }
          database.objectStores.push(storeRecord);
        }
        if (names.length > policy.indexedDbStoreCountLimit) database.error = 'Object store inventory was truncated by policy.';
      } finally {
        db.close();
      }
      databases.push(database);
    }
    return { status: 'collected', available: true, origin: location.origin, databases };
  } catch (error) {
    return { status: 'unavailable', available: false, origin: location.origin, databases: [], error: asError(error) };
  }
};
const collectCacheStorage = async () => {
  if (!('caches' in window)) return { status: 'platform_unavailable', available: false, origin: location.origin, caches: [], error: 'Cache Storage is not available.' };
  try {
    const names = await caches.keys();
    const rows = [];
    for (const name of names || []) {
      const row = { name, requests: [] };
      try {
        const cache = await caches.open(name);
        const requests = await cache.keys();
        row.requests = (requests || []).slice(0, policy.cacheRequestLimit).map(request => ({
          url: request.url,
          method: request.method || 'GET',
          mode: request.mode || null,
          destination: request.destination || null
        }));
        if ((requests || []).length > policy.cacheRequestLimit) row.error = 'Cache request inventory was truncated by policy.';
      } catch (error) {
        row.error = asError(error);
      }
      rows.push(row);
    }
    return { status: 'collected', available: true, origin: location.origin, caches: rows };
  } catch (error) {
    return { status: 'unavailable', available: false, origin: location.origin, caches: [], error: asError(error) };
  }
};
const collectServiceWorkers = async () => {
  if (!navigator.serviceWorker || typeof navigator.serviceWorker.getRegistrations !== 'function') {
    return { status: 'platform_unavailable', available: false, origin: location.origin, registrations: [], note: 'Service worker registrations are not available in this context.' };
  }
  try {
    const registrations = await navigator.serviceWorker.getRegistrations();
    return {
      status: 'collected',
      available: true,
      origin: location.origin,
      registrations: (registrations || []).map(registration => ({
        scope: registration.scope || null,
        activeState: registration.active?.state || null,
        activeScriptUrl: registration.active?.scriptURL || null,
        waitingState: registration.waiting?.state || null,
        waitingScriptUrl: registration.waiting?.scriptURL || null,
        installingState: registration.installing?.state || null,
        installingScriptUrl: registration.installing?.scriptURL || null,
        updateViaCache: registration.updateViaCache || null
      }))
    };
  } catch (error) {
    return { status: 'unavailable', available: false, origin: location.origin, registrations: [], error: asError(error) };
  }
};
const collectManifest = () => {
  try {
    const link = document.querySelector('link[rel~="manifest"]');
    if (!link) return { status: 'not_found', available: false, origin: location.origin, note: 'No web app manifest link was found.' };
    return {
      status: 'link_found',
      available: true,
      origin: location.origin,
      href: link.href || link.getAttribute('href') || null,
      rel: link.getAttribute('rel') || null,
      crossorigin: link.getAttribute('crossorigin') || null,
      note: 'Manifest link collected; manifest body is not fetched by the MVP collector.'
    };
  } catch (error) {
    return { status: 'unavailable', available: false, origin: location.origin, error: asError(error) };
  }
};
write({ status: 'pending' });
(async () => {
  const snapshot = {
    status: 'collected',
    collectedAt: new Date().toISOString(),
    pageUrl: location.href,
    frameUrl: location.href,
    origin: location.origin,
    localStorage: storageArea('localStorage', getStorageObject('localStorage')),
    sessionStorage: storageArea('sessionStorage', getStorageObject('sessionStorage')),
    indexedDB: await collectIndexedDB(),
    cacheStorage: await collectCacheStorage(),
    serviceWorkers: await collectServiceWorkers(),
    manifest: collectManifest()
  };
  write({ status: 'done', snapshot });
})().catch(error => write({ status: 'error', error: asError(error), snapshot: { status: 'partial', pageUrl: location.href, frameUrl: location.href, origin: location.origin, error: asError(error) } }));
return { status: 'started', token };
})()`;
  }

  function buildApplicationSnapshotPollExpression(token) {
    return `(() => {
const box = window.__BackToolsApplicationSnapshot;
if (!box || box.token !== ${JSON.stringify(token)}) return { status: 'missing' };
return box;
})()`;
  }

  function buildApplicationSnapshotCleanupExpression(token) {
    return `(() => {
const box = window.__BackToolsApplicationSnapshot;
if (box && box.token === ${JSON.stringify(token)}) delete window.__BackToolsApplicationSnapshot;
return true;
})()`;
  }

  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  function getOrigin(url) {
    try {
      return new URL(url || '').origin;
    } catch {
      return null;
    }
  }

  return {
    DEFAULT_APPLICATION_COLLECTOR_POLICY,
    collectApplicationMetadata,
    buildApplicationSnapshotExpression,
    buildApplicationSnapshotPollExpression,
    buildApplicationSnapshotCleanupExpression
  };
});
