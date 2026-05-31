(function(root, factory) {
  const api = factory(root);
  root.BackToolsDomain = Object.assign(root.BackToolsDomain || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  let domain = root.BackToolsDomain || {};
  if (typeof require === 'function') {
    try {
      domain = Object.assign(
        {},
        require('./redaction.js'),
        require('./cookies.js'),
        domain
      );
    } catch {}
  }

  const APPLICATION_SCHEMA_VERSION = 'backtools.application.v1';
  const APPLICATION_STORAGE_RAW_SCHEMA_VERSION = 'backtools.application.storage.raw.v1';
  const SENSITIVE_STORAGE_TERMS = [
    'session',
    'token',
    'auth',
    'jwt',
    'csrf',
    'xsrf',
    'bearer',
    'secret',
    'password',
    'credential',
    'sid',
    'sess',
    'id_token',
    'access_token',
    'refresh_token',
    'api_key',
    'apikey',
    'private_key'
  ];

  function normalizeStorageType(type) {
    return type === 'sessionStorage' ? 'sessionStorage' : 'localStorage';
  }

  function normalizeText(value, fallback = '') {
    if (value === undefined || value === null) return fallback;
    return String(value);
  }

  function isPossibleJwt(value) {
    if (domain.isPossibleJwt) return domain.isPossibleJwt(value);
    return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(String(value || ''));
  }

  function isSensitiveStorageKey(key) {
    const normalized = normalizeText(key).toLowerCase();
    if (!normalized) return false;
    if (domain.isSensitiveQueryKey && domain.isSensitiveQueryKey(normalized)) return true;
    return SENSITIVE_STORAGE_TERMS.some(term => normalized.includes(term));
  }

  function hasSensitiveStorageValue(value) {
    const text = normalizeText(value).toLowerCase();
    if (!text) return false;
    if (isPossibleJwt(value)) return true;
    if (/bearer\s+[a-z0-9._-]+/i.test(text)) return true;
    return SENSITIVE_STORAGE_TERMS.some(term => text.includes(term)) && text.length >= 16;
  }

  function classifyStorageItem(key, value) {
    const name = normalizeText(key).toLowerCase();
    if (isPossibleJwt(value)) return 'jwt_like';
    if (/(password|secret|credential|private_key|api_key|apikey)/.test(name)) return 'secret_like';
    if (/(session|sess|sid|auth|token|access|refresh|jwt|bearer|id_token)/.test(name)) return 'auth_like';
    if (/(csrf|xsrf)/.test(name)) return 'csrf_like';
    if (hasSensitiveStorageValue(value)) return 'sensitive_value_like';
    if (/(theme|locale|lang|layout|feature|flag|pref|setting)/.test(name)) return 'preference_like';
    return 'general';
  }

  function isSensitiveStorageItem(key, value) {
    const classification = classifyStorageItem(key, value);
    return ['jwt_like', 'secret_like', 'auth_like', 'csrf_like', 'sensitive_value_like'].includes(classification);
  }

  function deterministicMiddle(value) {
    const raw = normalizeText(value);
    if (raw.length < 16) return '';
    const start = Math.max(4, Math.floor((raw.length - 3) / 2));
    return raw.slice(start, start + 3);
  }

  function buildStorageFingerprint(value) {
    if (value === undefined || value === null) return null;
    if (domain.buildCookieFingerprint) return domain.buildCookieFingerprint(value);
    return {
      algorithm: 'stable-hash',
      version: 'v1',
      truncatedBits: 32,
      value: stableId(value),
      warning: 'Not suitable for low-entropy value proof against brute force'
    };
  }

  function maskStorageValue(rawValue, item = {}) {
    if (rawValue === undefined || rawValue === null) {
      return {
        rawAvailable: false,
        rawIncluded: false,
        masked: 'not_available',
        length: null,
        visibleRawChars: 0,
        fingerprint: null,
        fingerprintAlgorithm: null,
        maskPolicy: 'not_available',
        redactionReason: 'Raw value is not available from the current collector.'
      };
    }
    const raw = normalizeText(rawValue);
    const length = raw.length;
    const sensitive = isSensitiveStorageItem(item.key || item.name, raw);
    if (length === 0) {
      return {
        rawAvailable: true,
        rawIncluded: false,
        masked: '[empty]',
        length,
        visibleRawChars: 0,
        fingerprint: buildStorageFingerprint(raw),
        fingerprintAlgorithm: 'SHA-256',
        maskPolicy: 'empty_value',
        redactionReason: 'Empty storage value.'
      };
    }
    let masked;
    let maskPolicy;
    let visibleRawChars = 0;
    if (sensitive) {
      masked = '#'.repeat(Math.min(Math.max(length, 8), 24));
      maskPolicy = 'sensitive_full_mask';
    } else if (length <= 8) {
      masked = '#'.repeat(length);
      maskPolicy = 'full_mask_when_short';
    } else if (length <= 15) {
      masked = `${raw.slice(0, 4)}${'#'.repeat(Math.max(4, length - 4))}`;
      maskPolicy = 'prefix4_when_medium';
      visibleRawChars = 4;
    } else {
      masked = `${raw.slice(0, 4)}########${deterministicMiddle(raw)}########`;
      maskPolicy = 'prefix4_middle3_when_long';
      visibleRawChars = 7;
    }
    const fingerprint = buildStorageFingerprint(raw);
    return {
      rawAvailable: true,
      rawIncluded: false,
      masked,
      length,
      visibleRawChars,
      fingerprint,
      fingerprintAlgorithm: fingerprint?.algorithm || null,
      maskPolicy,
      redactionReason: sensitive ? 'Sensitive storage value masked by policy.' : 'Storage value masked by default.'
    };
  }

  function serializeStorageEntries(storageType, storageSnapshot = {}, context = {}) {
    const type = normalizeStorageType(storageType);
    const origin = storageSnapshot.origin || context.origin || getOrigin(context.analyzedUrl || context.pageUrl);
    const frameUrl = storageSnapshot.frameUrl || context.frameUrl || context.pageUrl || context.analyzedUrl || null;
    const status = storageSnapshot.status || (storageSnapshot.available === false ? 'unavailable' : 'collected');
    const entries = Array.isArray(storageSnapshot.entries) ? storageSnapshot.entries : [];
    const serialized = entries.map((entry, index) => serializeStorageEntry(type, entry, {
      origin,
      frameUrl,
      index
    }));
    return {
      type,
      status,
      available: status === 'collected' && storageSnapshot.available !== false,
      origin,
      frameUrl,
      itemCount: serialized.length,
      rawAvailableItems: serialized.filter(item => item.value.rawAvailable).length,
      sensitiveItems: serialized.filter(item => item.sensitive).length,
      entries: serialized,
      reason: storageSnapshot.reason || null,
      error: storageSnapshot.error || null
    };
  }

  function serializeStorageEntry(storageType, entry = {}, context = {}) {
    const key = normalizeText(entry.key);
    const rawAvailable = entry.rawAvailable !== false && Object.prototype.hasOwnProperty.call(entry, 'value');
    const rawValue = rawAvailable ? normalizeText(entry.value) : null;
    const value = maskStorageValue(rawValue, { key });
    const classification = classifyStorageItem(key, rawValue);
    const sensitive = isSensitiveStorageItem(key, rawValue);
    const origin = context.origin || entry.origin || null;
    const frameUrl = context.frameUrl || entry.frameUrl || null;
    const id = `app:${storageType}:${stableId([storageType, origin, frameUrl, key, context.index].join('|'))}`;
    return {
      id,
      kind: 'application_storage',
      storageType,
      type: storageType,
      origin,
      frameUrl,
      key,
      classification,
      sensitive,
      sensitivityReasons: buildStorageSensitivityReasons(key, rawValue),
      value,
      valueLength: value.length,
      rawAvailable: value.rawAvailable,
      rawValue,
      rawIncluded: false
    };
  }

  function buildStorageSensitivityReasons(key, value) {
    const reasons = [];
    if (isSensitiveStorageKey(key)) reasons.push('sensitive_key');
    if (isPossibleJwt(value)) reasons.push('possible_jwt');
    if (/bearer\s+/i.test(normalizeText(value))) reasons.push('possible_bearer_token');
    if (hasSensitiveStorageValue(value)) reasons.push('sensitive_value');
    return reasons;
  }

  function serializeIndexedDbInventory(indexedDBSnapshot = {}, context = {}) {
    const origin = indexedDBSnapshot.origin || context.origin || getOrigin(context.analyzedUrl || context.pageUrl);
    const databases = (indexedDBSnapshot.databases || []).map((database, index) => {
      const objectStores = (database.objectStores || []).map(store => ({
        name: normalizeText(store.name),
        keyPath: store.keyPath ?? null,
        autoIncrement: store.autoIncrement ?? null,
        count: Number.isFinite(Number(store.count)) ? Number(store.count) : null,
        countStatus: store.countStatus || (store.count == null ? 'not_collected' : 'collected'),
        indexes: (store.indexes || []).map(indexRecord => ({
          name: normalizeText(indexRecord.name),
          keyPath: indexRecord.keyPath ?? null,
          unique: indexRecord.unique ?? null,
          multiEntry: indexRecord.multiEntry ?? null
        })),
        error: store.error || null
      }));
      return {
        id: `app:indexedDB:${stableId([origin, database.name, database.version, index].join('|'))}`,
        kind: 'application_indexeddb',
        type: 'indexedDB',
        origin,
        name: database.name || null,
        version: database.version ?? null,
        objectStoreCount: objectStores.length,
        totalRecordCount: objectStores.reduce((sum, store) => sum + (store.count || 0), 0),
        objectStores,
        error: database.error || null
      };
    });
    return {
      type: 'indexedDB',
      status: indexedDBSnapshot.status || (indexedDBSnapshot.available === false ? 'platform_unavailable' : 'collected'),
      available: indexedDBSnapshot.available !== false,
      origin,
      databaseCount: databases.length,
      objectStoreCount: databases.reduce((sum, database) => sum + database.objectStoreCount, 0),
      databases,
      reason: indexedDBSnapshot.reason || null,
      error: indexedDBSnapshot.error || null
    };
  }

  function serializeCacheStorageInventory(cacheSnapshot = {}, context = {}) {
    const origin = cacheSnapshot.origin || context.origin || getOrigin(context.analyzedUrl || context.pageUrl);
    const caches = (cacheSnapshot.caches || []).map((cache, index) => {
      const requests = (cache.requests || []).map(request => {
        const redacted = redactUrlWithMetadata(request.url || '');
        return {
          url: redacted.value,
          urlRedacted: redacted.value,
          urlHash: redacted.hash,
          method: request.method || 'GET',
          mode: request.mode || null,
          destination: request.destination || null
        };
      });
      return {
        id: `app:cacheStorage:${stableId([origin, cache.name, index].join('|'))}`,
        kind: 'application_cache_storage',
        type: 'cacheStorage',
        origin,
        name: cache.name || null,
        requestCount: requests.length,
        requests,
        error: cache.error || null
      };
    });
    return {
      type: 'cacheStorage',
      status: cacheSnapshot.status || (cacheSnapshot.available === false ? 'platform_unavailable' : 'collected'),
      available: cacheSnapshot.available !== false,
      origin,
      cacheCount: caches.length,
      requestCount: caches.reduce((sum, cache) => sum + cache.requestCount, 0),
      caches,
      reason: cacheSnapshot.reason || null,
      error: cacheSnapshot.error || null
    };
  }

  function serializeServiceWorkers(serviceWorkerSnapshot = {}, context = {}) {
    const origin = serviceWorkerSnapshot.origin || context.origin || getOrigin(context.analyzedUrl || context.pageUrl);
    const registrations = (serviceWorkerSnapshot.registrations || []).map((registration, index) => {
      const scope = redactUrlWithMetadata(registration.scope || '');
      const activeScript = redactUrlWithMetadata(registration.activeScriptUrl || '');
      const waitingScript = redactUrlWithMetadata(registration.waitingScriptUrl || '');
      const installingScript = redactUrlWithMetadata(registration.installingScriptUrl || '');
      return {
        id: `app:serviceWorker:${stableId([origin, registration.scope, index].join('|'))}`,
        kind: 'application_service_worker',
        type: 'serviceWorker',
        origin,
        scope: scope.value || null,
        scopeHash: scope.hash,
        activeState: registration.activeState || null,
        activeScriptUrl: activeScript.value || null,
        activeScriptUrlHash: activeScript.hash,
        waitingState: registration.waitingState || null,
        waitingScriptUrl: waitingScript.value || null,
        waitingScriptUrlHash: waitingScript.hash,
        installingState: registration.installingState || null,
        installingScriptUrl: installingScript.value || null,
        installingScriptUrlHash: installingScript.hash,
        updateViaCache: registration.updateViaCache || null
      };
    });
    return {
      type: 'serviceWorker',
      status: serviceWorkerSnapshot.status || (serviceWorkerSnapshot.available === false ? 'platform_unavailable' : 'collected'),
      available: serviceWorkerSnapshot.available !== false,
      origin,
      registrationCount: registrations.length,
      registrations,
      reason: serviceWorkerSnapshot.reason || null,
      error: serviceWorkerSnapshot.error || null,
      note: serviceWorkerSnapshot.note || null
    };
  }

  function serializeManifestMetadata(manifestSnapshot = {}, context = {}) {
    const origin = manifestSnapshot.origin || context.origin || getOrigin(context.analyzedUrl || context.pageUrl);
    const href = manifestSnapshot.href ? redactUrlWithMetadata(manifestSnapshot.href) : { value: null, hash: null };
    return {
      id: `app:manifest:${stableId([origin, manifestSnapshot.href || 'none'].join('|'))}`,
      kind: 'application_manifest',
      type: 'manifest',
      status: manifestSnapshot.status || (manifestSnapshot.href ? 'link_found' : 'not_found'),
      available: !!manifestSnapshot.href,
      origin,
      href: href.value,
      hrefHash: href.hash,
      rel: manifestSnapshot.rel || null,
      crossorigin: manifestSnapshot.crossorigin || null,
      note: manifestSnapshot.note || null,
      reason: manifestSnapshot.reason || null,
      error: manifestSnapshot.error || null
    };
  }

  function analyzeApplicationSnapshot(rawSnapshot = {}, analyzedUrl) {
    const raw = rawSnapshot || {};
    const pageUrl = raw.pageUrl || analyzedUrl || null;
    const origin = raw.origin || getOrigin(pageUrl);
    const context = { analyzedUrl, pageUrl, origin, frameUrl: raw.frameUrl || pageUrl };
    const localStorage = serializeStorageEntries('localStorage', raw.localStorage || { status: 'not_collected', available: false }, context);
    const sessionStorage = serializeStorageEntries('sessionStorage', raw.sessionStorage || { status: 'not_collected', available: false }, context);
    const indexedDB = serializeIndexedDbInventory(raw.indexedDB || { status: 'not_collected', available: false }, context);
    const cacheStorage = serializeCacheStorageInventory(raw.cacheStorage || { status: 'not_collected', available: false }, context);
    const serviceWorkers = serializeServiceWorkers(raw.serviceWorkers || { status: 'planned', available: false, note: 'Service worker inventory was not collected.' }, context);
    const manifest = serializeManifestMetadata(raw.manifest || { status: 'not_found' }, context);
    const errors = collectApplicationErrors({ localStorage, sessionStorage, indexedDB, cacheStorage, serviceWorkers, manifest }, raw.error, raw.reason);
    const summary = buildApplicationSummary({ localStorage, sessionStorage, indexedDB, cacheStorage, serviceWorkers, manifest, errors });
    const inspected = redactUrlWithMetadata(pageUrl || '');
    const status = raw.status === 'platform_unavailable'
      ? 'platform_unavailable'
      : errors.length > 0
        ? 'partial'
        : 'collected';
    return {
      schemaVersion: APPLICATION_SCHEMA_VERSION,
      status,
      collectedAt: raw.collectedAt || new Date().toISOString(),
      inspectedUrl: inspected.value || null,
      inspectedUrlRedacted: inspected.value || null,
      inspectedUrlHash: inspected.hash,
      targetOrigin: origin,
      frameUrl: redactUrlWithMetadata(raw.frameUrl || pageUrl || '').value || null,
      localStorage,
      sessionStorage,
      indexedDB,
      cacheStorage,
      serviceWorkers,
      manifest,
      summary,
      observations: errors
    };
  }

  function buildApplicationSummary(parts) {
    const localEntries = parts.localStorage?.entries || [];
    const sessionEntries = parts.sessionStorage?.entries || [];
    const storageEntries = [...localEntries, ...sessionEntries];
    return {
      localStorageItems: localEntries.length,
      sessionStorageItems: sessionEntries.length,
      storageItems: storageEntries.length,
      rawAvailableStorageItems: storageEntries.filter(entry => entry.value?.rawAvailable).length,
      sensitiveStorageItems: storageEntries.filter(entry => entry.sensitive).length,
      indexedDbDatabases: parts.indexedDB?.databaseCount || 0,
      indexedDbObjectStores: parts.indexedDB?.objectStoreCount || 0,
      cacheStorageCaches: parts.cacheStorage?.cacheCount || 0,
      cacheStorageRequests: parts.cacheStorage?.requestCount || 0,
      serviceWorkerRegistrations: parts.serviceWorkers?.registrationCount || 0,
      manifestLinks: parts.manifest?.href ? 1 : 0,
      errors: (parts.errors || []).length,
      totalInventoryItems: storageEntries.length + (parts.indexedDB?.databaseCount || 0) + (parts.cacheStorage?.cacheCount || 0) + (parts.serviceWorkers?.registrationCount || 0) + (parts.manifest?.href ? 1 : 0)
    };
  }

  function collectApplicationErrors(parts, topLevelError, topLevelReason) {
    const errors = [];
    if (topLevelError) errors.push({ section: 'application', status: 'error', reason: topLevelReason || null, message: normalizeText(topLevelError) });
    Object.entries(parts || {}).forEach(([section, value]) => {
      if (!value || typeof value !== 'object') return;
      if (value.error) errors.push({ section, status: value.status || 'error', reason: value.reason || null, message: normalizeText(value.error) });
    });
  return errors;
  }

  function buildSanitizedStorageEntry(entry) {
    const out = {
      ...(entry || {}),
      value: {
        ...(entry?.value || {}),
        rawIncluded: false
      },
      rawIncluded: false
    };
    delete out.rawValue;
    if (out.value) delete out.value.rawValue;
    return out;
  }

  function buildSanitizedStorageArea(area) {
    return {
      ...(area || {}),
      entries: (area?.entries || []).map(buildSanitizedStorageEntry)
    };
  }

  function sanitizeApplicationModel(application = {}) {
    const app = application || {};
    return {
      schemaVersion: APPLICATION_SCHEMA_VERSION,
      status: app.status || 'not_collected',
      collectedAt: app.collectedAt || null,
      inspectedUrl: app.inspectedUrl || null,
      inspectedUrlRedacted: app.inspectedUrlRedacted || app.inspectedUrl || null,
      inspectedUrlHash: app.inspectedUrlHash || null,
      targetOrigin: app.targetOrigin || null,
      frameUrl: app.frameUrl || null,
      containsRawApplicationData: false,
      summary: app.summary || {},
      localStorage: buildSanitizedStorageArea(app.localStorage),
      sessionStorage: buildSanitizedStorageArea(app.sessionStorage),
      indexedDB: app.indexedDB || { databases: [] },
      cacheStorage: app.cacheStorage || { caches: [] },
      serviceWorkers: app.serviceWorkers || { registrations: [] },
      manifest: app.manifest || {},
      observations: app.observations || []
    };
  }

  function buildApplicationSanitizedJson({ generatedAt, analyzedUrl, application }) {
    const sanitized = sanitizeApplicationModel(application);
    return {
      schemaVersion: 'backtools.application.storage.sanitized.v1',
      generatedAt,
      inspectedUrl: redactUrlWithMetadata(analyzedUrl || sanitized.inspectedUrl || '').value || null,
      containsRawApplicationData: false,
      summary: sanitized.summary,
      localStorage: sanitized.localStorage,
      sessionStorage: sanitized.sessionStorage
    };
  }

  function buildIndexedDbInventoryJson({ generatedAt, analyzedUrl, application }) {
    const sanitized = sanitizeApplicationModel(application);
    return {
      schemaVersion: 'backtools.application.indexeddb.inventory.v1',
      generatedAt,
      inspectedUrl: redactUrlWithMetadata(analyzedUrl || sanitized.inspectedUrl || '').value || null,
      containsRawApplicationData: false,
      summary: {
        databases: sanitized.summary.indexedDbDatabases || 0,
        objectStores: sanitized.summary.indexedDbObjectStores || 0
      },
      indexedDB: sanitized.indexedDB
    };
  }

  function buildCacheStorageInventoryJson({ generatedAt, analyzedUrl, application }) {
    const sanitized = sanitizeApplicationModel(application);
    return {
      schemaVersion: 'backtools.application.cache-storage.inventory.v1',
      generatedAt,
      inspectedUrl: redactUrlWithMetadata(analyzedUrl || sanitized.inspectedUrl || '').value || null,
      containsRawApplicationData: false,
      summary: {
        caches: sanitized.summary.cacheStorageCaches || 0,
        requests: sanitized.summary.cacheStorageRequests || 0
      },
      cacheStorage: sanitized.cacheStorage
    };
  }

  function buildApplicationReport({ generatedAt, analyzedUrl, application, cookiesSummary }) {
    const sanitized = sanitizeApplicationModel(application);
    return {
      schemaVersion: APPLICATION_SCHEMA_VERSION,
      generatedAt,
      inspectedUrl: redactUrlWithMetadata(analyzedUrl || sanitized.inspectedUrl || '').value || null,
      containsRawApplicationData: false,
      summary: sanitized.summary,
      cookies: {
        linkedModule: 'cookies',
        observedCookies: cookiesSummary?.observedCookies || 0,
        findings: cookiesSummary?.findings || 0,
        reportPath: 'cookies/COOKIES_REPORT.json'
      },
      localStorage: sanitized.localStorage,
      sessionStorage: sanitized.sessionStorage,
      indexedDB: sanitized.indexedDB,
      cacheStorage: sanitized.cacheStorage,
      serviceWorkers: sanitized.serviceWorkers,
      manifest: sanitized.manifest,
      observations: sanitized.observations
    };
  }

  function summarizeRawApplicationScope(application = {}) {
    const entries = rawStorageEntries(application);
    return {
      rawStorageItemCount: entries.length,
      origins: unique(entries.map(entry => entry.origin || 'unknown')).sort(),
      storageTypes: unique(entries.map(entry => entry.storageType || entry.type || 'unknown')).sort()
    };
  }

  function buildApplicationRawStorageJson({ generatedAt, analyzedUrl, application, confirmedAt, scope }) {
    const entries = rawStorageEntries(application);
    return {
      schemaVersion: APPLICATION_STORAGE_RAW_SCHEMA_VERSION,
      generatedAt,
      inspectedUrl: redactUrlWithMetadata(analyzedUrl || application?.inspectedUrl || '').value || null,
      containsRawApplicationData: entries.length > 0,
      rawApplicationExportConfirmedAt: confirmedAt || null,
      rawApplicationExportScope: scope || summarizeRawApplicationScope(application),
      storage: entries.map(entry => ({
        ...buildSanitizedStorageEntry(entry),
        value: {
          ...(entry.value || {}),
          rawIncluded: true,
          rawValue: normalizeText(entry.rawValue)
        }
      }))
    };
  }

  function rawStorageEntries(application = {}) {
    return [
      ...(application.localStorage?.entries || []),
      ...(application.sessionStorage?.entries || [])
    ].filter(entry => entry?.value?.rawAvailable && entry.rawValue !== undefined && entry.rawValue !== null);
  }

  function revealStorageValue(entry, confirmation = {}) {
    if (!entry?.value?.rawAvailable || entry.rawValue === undefined || entry.rawValue === null) {
      return { ok: false, reason: 'Raw value is not available from the current collector.' };
    }
    if (confirmation.confirmed !== true) {
      return { ok: false, reason: 'Reveal requires explicit confirmation.' };
    }
    return {
      ok: true,
      rawValue: normalizeText(entry.rawValue),
      key: entry.key || null,
      storageType: entry.storageType || entry.type || null
    };
  }

  function redactUrlWithMetadata(url) {
    if (domain.redactUrlWithMetadata) return domain.redactUrlWithMetadata(url || '');
    return { value: url || null, hash: stableId(url || ''), redacted: false };
  }

  function getOrigin(url) {
    try {
      return new URL(url || '').origin;
    } catch {
      return null;
    }
  }

  function stableId(value) {
    if (domain.hashSensitiveValue) return domain.hashSensitiveValue(value);
    let hash = 0x811c9dc5;
    const text = normalizeText(value);
    for (let i = 0; i < text.length; i++) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, '0');
  }

  function unique(values) {
    return [...new Set((values || []).filter(value => value !== undefined && value !== null && value !== ''))];
  }

  return {
    APPLICATION_SCHEMA_VERSION,
    APPLICATION_STORAGE_RAW_SCHEMA_VERSION,
    SENSITIVE_STORAGE_TERMS,
    isSensitiveStorageKey,
    hasSensitiveStorageValue,
    classifyStorageItem,
    isSensitiveStorageItem,
    buildStorageFingerprint,
    maskStorageValue,
    serializeStorageEntries,
    serializeStorageEntry,
    serializeIndexedDbInventory,
    serializeCacheStorageInventory,
    serializeServiceWorkers,
    serializeManifestMetadata,
    analyzeApplicationSnapshot,
    buildSanitizedStorageEntry,
    sanitizeApplicationModel,
    buildApplicationReport,
    buildApplicationSanitizedJson,
    buildIndexedDbInventoryJson,
    buildCacheStorageInventoryJson,
    summarizeRawApplicationScope,
    buildApplicationRawStorageJson,
    revealStorageValue
  };
});
