(function(root, factory) {
  const api = factory(root);
  root.BackToolsExport = Object.assign(root.BackToolsExport || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  let domain = root.BackToolsDomain || {};
  if (typeof require === 'function') {
    try { domain = Object.assign({}, require('../domain/redaction.js'), require('../domain/cookies.js'), require('../domain/application.js'), domain); } catch {}
  }

  const COOKIE_REPORT_LIMITS = {
    maxCookieRecords: 500,
    maxRawRecordsInDefaultReport: 0,
    maxHarRequestCookieRecordsInDefaultReport: 0,
    maxSourceUrlSamplesPerCookie: 10,
    maxObservedInSamplesPerCookie: 10,
    maxFindings: 500,
    maxEvidenceUrlsPerFinding: 10
  };

  const NETWORK_REPORT_LIMITS = {
    maxCompactEntries: 500,
    maxDetailsEntries: 2000,
    maxExampleEntriesPerReason: 10,
    maxTopHosts: 20,
    maxTopMimeTypes: 20
  };

  function buildCurrentCookiesReport({
    generatedAt,
    analyzedUrl,
    policy,
    summary,
    observedCookies,
    findings,
    rawRecords,
    rawExport = {}
  }) {
    const cookies = observedCookies || [];
    const safeFindings = findings || [];
    const rawRecordCount = (rawRecords || []).length;
    const exportContainsRawCookies = rawExport.included === true;
    const cookieRows = cookies.slice(0, COOKIE_REPORT_LIMITS.maxCookieRecords).map(cookie => compactCookieRecord(cookie, rawExport));
    const findingRows = safeFindings.slice(0, COOKIE_REPORT_LIMITS.maxFindings).map(compactCookieFinding);

    return {
      schemaVersion: 'backtools.cookies.report.v1',
      reportProfile: 'compact_human_readable',
      generatedAt,
      inspectedUrl: redactUrlValue(analyzedUrl || ''),
      containsRawCookies: false,
      containsReplayableCookieJar: false,
      exportContainsRawCookies,
      mode: exportContainsRawCookies ? 'dump_export_safe_report' : 'safe',
      message: exportContainsRawCookies
        ? 'This report is compact and protected. Raw replayable cookies, if present, are stored only in cookies/cookies.raw.json and cookies/cookies.raw.netscape.txt.'
        : 'This report is compact and protected. Raw cookie values are not included.',
      rawDataPath: exportContainsRawCookies ? 'cookies/cookies.raw.json' : null,
      rawNetscapePath: exportContainsRawCookies ? 'cookies/cookies.raw.netscape.txt' : null,
      detailsPath: 'cookies/cookies.sanitized.json',
      policy: compactCookiePolicy(policy),
      limits: COOKIE_REPORT_LIMITS,
      summary: summarizeCookiesForHumans(summary, cookies, safeFindings, rawRecordCount, rawExport),
      cookies: cookieRows,
      findings: findingRows,
      truncation: {
        cookiesTotal: cookies.length,
        cookiesIncluded: cookieRows.length,
        cookiesTruncated: cookies.length > cookieRows.length,
        findingsTotal: safeFindings.length,
        findingsIncluded: findingRows.length,
        findingsTruncated: safeFindings.length > findingRows.length,
        rawRecordsTotal: rawRecordCount,
        rawRecordsIncluded: 0,
        rawRecordsExcludedByDefault: rawRecordCount > 0
      }
    };
  }

  function buildCurrentCookiesHtml({ generatedAt, analyzedUrl, summary, observedCookies }) {
    if (domain.buildCookiesHtml) {
      return domain.buildCookiesHtml({ generatedAt, analyzedUrl, summary, cookies: observedCookies });
    }
    return '';
  }

  function buildCurrentCookiesSanitizedJson({ generatedAt, analyzedUrl, summary, observedCookies, findings }) {
    if (domain.buildCookiesSanitizedJson) {
      return domain.buildCookiesSanitizedJson({ generatedAt, analyzedUrl, summary, cookies: observedCookies, findings });
    }
    return {
      schemaVersion: 'backtools.cookies.v1',
      generatedAt,
      inspectedUrl: redactUrlValue(analyzedUrl || ''),
      containsRawCookies: false,
      containsReplayableCookieJar: false,
      summary,
      cookies: (observedCookies || []).map(cookie => redactCookieUrls(domain.redactCookieRecord ? domain.redactCookieRecord(cookie) : cookie)),
      findings: (findings || []).map(redactFindingUrls)
    };
  }

  function buildCurrentNetscapeSanitized({ observedCookies }) {
    return domain.buildNetscapeSanitized ? domain.buildNetscapeSanitized(observedCookies || []) : '';
  }

  function buildCurrentRawCookiesJson({ generatedAt, analyzedUrl, observedCookies, confirmedAt, scope }) {
    if (domain.buildCookiesRawJson) {
      return domain.buildCookiesRawJson({ generatedAt, analyzedUrl, cookies: observedCookies, confirmedAt, scope });
    }
    return {
      schemaVersion: 'backtools.cookies.raw.v1',
      generatedAt,
      inspectedUrl: redactUrlValue(analyzedUrl || ''),
      containsRawCookies: false,
      containsReplayableCookieJar: false,
      rawCookieExportConfirmedAt: confirmedAt || null,
      rawCookieExportScope: scope || {},
      cookies: []
    };
  }

  function buildCurrentRawNetscapeCookies({ observedCookies }) {
    return domain.buildNetscapeRaw ? domain.buildNetscapeRaw(observedCookies || []) : '';
  }

  function buildDiagnosticsDownloadPayload(logs, reasons, objectDump = {}) {
    return {
      metadata: {
        objectDump: normalizeObjectDumpMetadata(objectDump)
      },
      logs: (logs || []).map(redactLog),
      reasons
    };
  }

  function normalizeObjectDumpMetadata(objectDump = {}) {
    const enabled = objectDump.dumpObjectsEnabled === true;
    return {
      dumpObjectsEnabled: enabled,
      cookieValueMode: objectDump.cookieValueMode === 'raw' ? 'raw' : 'protected',
      applicationValueMode: objectDump.applicationValueMode === 'raw' ? 'raw' : 'protected',
      cookiesTotal: Number(objectDump.cookiesTotal || 0),
      cookiesRawVisible: enabled ? Number(objectDump.cookiesRawVisible || 0) : 0,
      applicationItemsTotal: Number(objectDump.applicationItemsTotal || 0),
      applicationRawVisible: enabled ? Number(objectDump.applicationRawVisible || 0) : 0
    };
  }

  function buildCurrentNetworkReport({ generatedAt, analyzedUrl, policy, entries }) {
    const rows = entries || [];
    const limitedRows = rows.slice(0, NETWORK_REPORT_LIMITS.maxCompactEntries);
    return {
      schemaVersion: 'backtools.network.report.v1',
      reportProfile: 'compact_human_readable',
      generatedAt,
      inspectedUrl: redactUrlValue(analyzedUrl || ''),
      message: 'Compact network overview. Redacted per-request headers and verbose fields are stored in network/NETWORK_DETAILS.json.',
      detailsPath: 'network/NETWORK_DETAILS.json',
      policy: sanitizeNetworkPolicy(policy),
      totals: summarizeNetworkRows(rows),
      highlights: buildNetworkHighlights(rows),
      reasonGroups: buildNetworkReasonGroups(rows),
      entriesTotal: rows.length,
      entriesIncluded: limitedRows.length,
      entriesTruncated: rows.length > limitedRows.length,
      entries: limitedRows.map(compactNetworkEntry)
    };
  }

  function buildCurrentNetworkDetailsReport({ generatedAt, analyzedUrl, policy, entries }) {
    const rows = entries || [];
    const limitedRows = rows.slice(0, NETWORK_REPORT_LIMITS.maxDetailsEntries);
    return {
      schemaVersion: 'backtools.network.details.v1',
      reportProfile: 'redacted_machine_details',
      generatedAt,
      inspectedUrl: redactUrlValue(analyzedUrl || ''),
      message: 'Verbose redacted network details. This file is intended for tooling/debugging, not first-pass reading.',
      policy: sanitizeNetworkPolicy(policy),
      totals: summarizeNetworkRows(rows),
      entriesTotal: rows.length,
      entriesIncluded: limitedRows.length,
      entriesTruncated: rows.length > limitedRows.length,
      entries: limitedRows.map(redactNetworkEntry)
    };
  }

  function buildCurrentApplicationReport({
    generatedAt,
    analyzedUrl,
    application,
    cookiesSummary,
    rawExport = {}
  }) {
    const sanitized = domain.sanitizeApplicationModel
      ? domain.sanitizeApplicationModel(application || {})
      : sanitizeApplicationFallback(application || {});
    const exportContainsRawApplicationData = rawExport.included === true;

    return {
      schemaVersion: 'backtools.application.report.v1',
      reportProfile: 'compact_human_readable',
      generatedAt,
      inspectedUrl: redactUrlValue(analyzedUrl || sanitized.inspectedUrl || ''),
      containsRawApplicationData: false,
      exportContainsRawApplicationData,
      mode: exportContainsRawApplicationData ? 'dump_export_safe_report' : 'safe',
      message: exportContainsRawApplicationData
        ? 'This report is compact and protected. Raw storage values, if present, are stored only in application/storage.raw.json.'
        : 'This report is compact and protected. Raw storage values are not included.',
      rawDataPath: exportContainsRawApplicationData ? 'application/storage.raw.json' : null,
      details: {
        storageSanitizedPath: 'application/storage.sanitized.json',
        indexedDbInventoryPath: 'application/indexeddb.inventory.json',
        cacheStorageInventoryPath: 'application/cache-storage.inventory.json'
      },
      summary: sanitized.summary || {},
      cookies: {
        linkedModule: 'cookies',
        observedCookies: cookiesSummary?.observedCookies || 0,
        findings: cookiesSummary?.findings || 0,
        reportPath: 'cookies/COOKIES_REPORT.json'
      },
      storage: buildStorageOverview(sanitized, rawExport),
      indexedDB: buildIndexedDbOverview(sanitized.indexedDB),
      cacheStorage: buildCacheStorageOverview(sanitized.cacheStorage),
      serviceWorkers: buildServiceWorkerOverview(sanitized.serviceWorkers),
      manifest: buildManifestOverview(sanitized.manifest),
      observations: sanitized.observations || []
    };
  }

  function buildCurrentApplicationStorageSanitizedJson({ generatedAt, analyzedUrl, application }) {
    if (domain.buildApplicationSanitizedJson) {
      return domain.buildApplicationSanitizedJson({ generatedAt, analyzedUrl, application });
    }
    return {
      schemaVersion: 'backtools.application.storage.sanitized.v1',
      generatedAt,
      inspectedUrl: redactUrlValue(analyzedUrl || ''),
      containsRawApplicationData: false,
      summary: application?.summary || {},
      localStorage: application?.localStorage || {},
      sessionStorage: application?.sessionStorage || {}
    };
  }

  function buildCurrentApplicationIndexedDbInventoryJson({ generatedAt, analyzedUrl, application }) {
    if (domain.buildIndexedDbInventoryJson) {
      return domain.buildIndexedDbInventoryJson({ generatedAt, analyzedUrl, application });
    }
    return {
      schemaVersion: 'backtools.application.indexeddb.inventory.v1',
      generatedAt,
      inspectedUrl: redactUrlValue(analyzedUrl || ''),
      containsRawApplicationData: false,
      indexedDB: application?.indexedDB || { databases: [] }
    };
  }

  function buildCurrentApplicationCacheStorageInventoryJson({ generatedAt, analyzedUrl, application }) {
    if (domain.buildCacheStorageInventoryJson) {
      return domain.buildCacheStorageInventoryJson({ generatedAt, analyzedUrl, application });
    }
    return {
      schemaVersion: 'backtools.application.cache-storage.inventory.v1',
      generatedAt,
      inspectedUrl: redactUrlValue(analyzedUrl || ''),
      containsRawApplicationData: false,
      cacheStorage: application?.cacheStorage || { caches: [] }
    };
  }

  function buildCurrentApplicationRawStorageJson({ generatedAt, analyzedUrl, application, confirmedAt, scope }) {
    if (domain.buildApplicationRawStorageJson) {
      return domain.buildApplicationRawStorageJson({ generatedAt, analyzedUrl, application, confirmedAt, scope });
    }
    return {
      schemaVersion: 'backtools.application.storage.raw.v1',
      generatedAt,
      inspectedUrl: redactUrlValue(analyzedUrl || ''),
      containsRawApplicationData: false,
      rawApplicationExportConfirmedAt: confirmedAt || null,
      rawApplicationExportScope: scope || {},
      storage: []
    };
  }

  function buildCurrentCaptureSummary({
    generatedAt,
    analyzedUrl,
    manifest,
    networkReport,
    cookiesReport,
    applicationReport,
    objectDump
  }) {
    const lines = [];
    const target = manifest?.inspectedUrl || redactUrlValue(analyzedUrl || '');
    const totals = manifest?.totals || {};
    const networkTotals = networkReport?.totals || {};
    const cookieSummary = cookiesReport?.summary || {};
    const appSummary = applicationReport?.summary || {};
    const raw = normalizeObjectDumpMetadata(objectDump || {});

    lines.push('# BackTools Capture Summary');
    lines.push('');
    lines.push(`Generated: ${generatedAt || 'unknown'}`);
    lines.push(`Target: ${target || 'unknown'}`);
    lines.push(`Profile: code-rich bounded export`);
    lines.push(`Raw object dump: ${raw.dumpObjectsEnabled ? 'enabled' : 'disabled'}`);
    lines.push('');
    lines.push('## At a glance');
    lines.push('');
    lines.push(`- Exported files: ${numberText(totals.writtenFiles ?? totals.written ?? 0)} of ${numberText(totals.discovered ?? 0)} observed resources.`);
    lines.push(`- Network bodies captured: ${numberText(networkTotals.bodyCaptured || 0)}; metadata-only/skipped: ${numberText((networkTotals.metadataOnly || 0) + (networkTotals.platformUnavailable || 0) + (networkTotals.mimeBlocked || 0) + (networkTotals.sizeLimitExceeded || 0) + (networkTotals.policyBlocked || 0))}.`);
    lines.push(`- Cookies observed: ${numberText(cookieSummary.observedCookies || 0)}; findings: ${numberText(cookieSummary.findings || 0)}.`);
    lines.push(`- Application storage items: ${numberText(appSummary.storageItems || 0)}; IndexedDB databases: ${numberText(appSummary.indexedDbDatabases || 0)}; Cache Storage caches: ${numberText(appSummary.cacheStorageCaches || 0)}.`);
    lines.push('');
    lines.push('## Read this first');
    lines.push('');
    lines.push('- `MANIFEST.json` lists what was written, skipped, or kept as metadata.');
    lines.push('- `NETWORK_REPORT.json`, `cookies/COOKIES_REPORT.json`, and `application/APPLICATION_REPORT.json` are compact first-pass reports.');
    lines.push('- Verbose network details live in `network/NETWORK_DETAILS.json`.');
    lines.push('- Sanitized storage/cookie details live in `application/storage.sanitized.json` and `cookies/cookies.sanitized.json`.');
    if (cookiesReport?.exportContainsRawCookies) lines.push('- Raw cookies were explicitly included in `cookies/cookies.raw.json` and `cookies/cookies.raw.netscape.txt`.');
    if (applicationReport?.exportContainsRawApplicationData) lines.push('- Raw application storage was explicitly included in `application/storage.raw.json`.');
    lines.push('');
    lines.push('## Network');
    lines.push('');
    lines.push(networkHumanSentence(networkReport));
    lines.push('');
    lines.push('Top hosts:');
    for (const item of (networkReport?.highlights?.topHosts || []).slice(0, 8)) {
      lines.push(`- ${item.host}: ${numberText(item.requests)} requests`);
    }
    if (!(networkReport?.highlights?.topHosts || []).length) lines.push('- none');
    lines.push('');
    lines.push('## Cookies');
    lines.push('');
    lines.push(cookieHumanSentence(cookiesReport));
    for (const item of (cookiesReport?.findings || []).slice(0, 5)) {
      lines.push(`- ${item.severity || 'info'}: ${item.message || item.ruleId || 'cookie finding'}`);
    }
    if (!(cookiesReport?.findings || []).length) lines.push('- No cookie findings.');
    lines.push('');
    lines.push('## Application');
    lines.push('');
    lines.push(applicationHumanSentence(applicationReport));
    lines.push('');
    lines.push('## Main files');
    lines.push('');
    lines.push('- `MANIFEST.json`');
    lines.push('- `NETWORK_REPORT.json`');
    lines.push('- `network/NETWORK_DETAILS.json`');
    lines.push('- `cookies/COOKIES_REPORT.json`');
    lines.push('- `cookies/cookies.sanitized.json`');
    lines.push('- `application/APPLICATION_REPORT.json`');
    lines.push('- `application/storage.sanitized.json`');
    lines.push('- `application/indexeddb.inventory.json`');
    lines.push('- `application/cache-storage.inventory.json`');
    return `${lines.join('\n')}\n`;
  }

  function sanitizeNetworkPolicy(policy = {}) {
    return {
      captureBodies: policy.captureBodies !== false,
      captureHiddenBodies: !!policy.captureHiddenBodies,
      maxBodyBytes: policy.maxBodyBytes,
      maxTotalBodyBytes: policy.maxTotalBodyBytes,
      maxBodyRenderBytes: policy.maxBodyRenderBytes,
      maxWasmBodyBytes: policy.maxWasmBodyBytes,
      maxSmallBinaryBytes: policy.maxSmallBinaryBytes,
      includeSmallBinaryBodies: !!policy.includeSmallBinaryBodies,
      allowedMimeTypes: Array.isArray(policy.allowedMimeTypes)
        ? policy.allowedMimeTypes
        : Array.from(policy.allowedMimeTypes || [])
    };
  }

  function summarizeNetworkRows(rows) {
    const totals = {
      requests: rows.length,
      bodyCaptured: 0,
      metadataOnly: 0,
      mimeBlocked: 0,
      sizeLimitExceeded: 0,
      policyBlocked: 0,
      platformUnavailable: 0,
      readFailed: 0,
      encodingUnsupported: 0,
      hiddenByDefault: 0,
      capturedBytes: 0,
      exportedBodies: 0
    };
    rows.forEach(row => {
      const status = row.bodyCaptureStatus || row.status;
      if (status === 'body_captured') totals.bodyCaptured++;
      if (status === 'metadata_only') totals.metadataOnly++;
      if (status === 'mime_blocked') totals.mimeBlocked++;
      if (status === 'size_limit_exceeded') totals.sizeLimitExceeded++;
      if (status === 'policy_blocked') totals.policyBlocked++;
      if (status === 'platform_unavailable') totals.platformUnavailable++;
      if (status === 'read_failed') totals.readFailed++;
      if (status === 'encoding_unsupported') totals.encodingUnsupported++;
      if (status === 'hidden_by_default' || row.visibleByDefault === false) totals.hiddenByDefault++;
      if (row.zipPath || row.bodyPath) totals.exportedBodies++;
      totals.capturedBytes += row.bodyCapturedBytes || 0;
    });
    return totals;
  }

  function buildNetworkHighlights(rows) {
    return {
      topHosts: topCounts(rows.map(row => row.host || hostFromUrl(row.url) || 'unknown'), NETWORK_REPORT_LIMITS.maxTopHosts, 'host'),
      topMimeTypes: topCounts(rows.map(row => row.mimeType || 'unknown'), NETWORK_REPORT_LIMITS.maxTopMimeTypes, 'mimeType'),
      exportedByType: topCounts(rows.filter(row => row.zipPath || row.bodyPath).map(row => row.type || row.resourceType || 'unknown'), 20, 'type')
    };
  }

  function buildNetworkReasonGroups(rows) {
    const groups = {};
    rows.forEach(row => {
      const status = row.bodyCaptureStatus || row.status || 'metadata_only';
      const reason = row.bodyCaptureReason || row.reason || status;
      const key = normalizeReasonKey(status, reason);
      if (!groups[key]) groups[key] = { count: 0, examples: [] };
      groups[key].count++;
      if (groups[key].examples.length < NETWORK_REPORT_LIMITS.maxExampleEntriesPerReason) {
        groups[key].examples.push({
          id: row.id || null,
          host: row.host || hostFromUrl(row.url) || null,
          url: compactDisplayUrl(row.urlRedacted || redactUrlValue(row.url || '')),
          fullUrlRedacted: String(row.urlRedacted || redactUrlValue(row.url || '')).length > 240 ? (row.urlRedacted || redactUrlValue(row.url || '')) : undefined,
          mimeType: row.mimeType || null,
          statusCode: row.statusCode ?? null
        });
      }
    });
    return groups;
  }

  function compactNetworkEntry(row) {
    const fullUrlRedacted = row.urlRedacted || redactUrlValue(row.url || '');
    const url = compactDisplayUrl(fullUrlRedacted);
    const status = row.bodyCaptureStatus || row.status || 'metadata_only';
    const reason = row.bodyCaptureReason || row.reason || null;
    const bodyPath = row.zipPath || row.bodyPath || null;
    const capturedBytes = row.bodyCapturedBytes || 0;
    return {
      id: row.id,
      request: `${row.method || 'GET'} ${url}`,
      url,
      fullUrlRedacted: fullUrlRedacted.length > url.length ? fullUrlRedacted : undefined,
      urlHash: row.urlHash || null,
      host: row.host || hostFromUrl(row.url) || null,
      method: row.method || null,
      statusCode: row.statusCode ?? null,
      mimeType: row.mimeType || null,
      type: row.type || null,
      category: row.resourceCategory || null,
      bodyCaptureStatus: status,
      bodyCaptureReason: reason,
      bodyCapturedBytes: capturedBytes,
      bodyPath,
      exported: !!bodyPath,
      message: networkEntryMessage({ status, reason, capturedBytes, bodyPath })
    };
  }

  function redactNetworkEntry(row) {
    const urlRedacted = row.urlRedacted || redactUrlValue(row.url);
    return {
      id: row.id,
      url: urlRedacted,
      urlRedacted,
      urlHash: row.urlHash || null,
      method: row.method || null,
      statusCode: row.statusCode ?? null,
      mimeType: row.mimeType || null,
      type: row.type || null,
      host: row.host || null,
      startedDateTime: row.startedDateTime || null,
      size: row.size ?? null,
      bodySize: row.bodySize ?? null,
      bodyCaptureStatus: row.bodyCaptureStatus || row.status || 'metadata_only',
      bodyCaptureReason: row.bodyCaptureReason || row.reason || null,
      bodyCapturedBytes: row.bodyCapturedBytes || 0,
      bodySizeBytes: row.bodySizeBytes ?? row.bodyCapturedBytes ?? 0,
      bodyEncoding: row.bodyEncoding || row.encoding || null,
      bodyRenderStatus: row.bodyRenderStatus || null,
      bodyExportStatus: row.bodyExportStatus || null,
      bodyRedactionApplied: !!row.bodyRedactionApplied,
      bodyPath: row.zipPath || row.bodyPath || null,
      resourceCategory: row.resourceCategory || null,
      visibleByDefault: row.visibleByDefault !== false,
      hiddenByDefaultReason: row.hiddenByDefaultReason || null,
      redactionApplied: !!row.redactionApplied,
      redactedFields: row.redactedFields || [],
      requestHeaders: row.requestHeadersRedacted || undefined,
      responseHeaders: row.responseHeadersRedacted || undefined
    };
  }

  function compactCookieRecord(cookie, rawExport = {}) {
    const protectedCookie = domain.buildSanitizedCookie ? domain.buildSanitizedCookie(cookie) : cookie;
    const sourceUrls = (protectedCookie.sourceUrls || []).map(redactUrlValue);
    const observedIn = (protectedCookie.observedIn || []).map(item => ({
      source: item.source || null,
      method: item.method || null,
      url: item.urlRedacted || redactUrlValue(item.url || ''),
      urlHash: item.urlHash || null,
      status: item.status ?? item.statusCode ?? null,
      timestamp: item.timestamp || item.startedDateTime || null
    }));
    return {
      id: protectedCookie.id || null,
      name: protectedCookie.name || null,
      domain: protectedCookie.domain || null,
      path: protectedCookie.path || null,
      flags: {
        secure: protectedCookie.secure ?? 'unknown',
        httpOnly: protectedCookie.httpOnly ?? 'unknown',
        sameSite: protectedCookie.sameSite || 'unknown',
        session: protectedCookie.session ?? null,
        hostOnly: protectedCookie.hostOnly ?? null
      },
      source: protectedCookie.source || null,
      sources: protectedCookie.sources || [],
      classification: protectedCookie.classification || 'unknown',
      risk: protectedCookie.risk || [],
      value: compactProtectedValue(protectedCookie.value, rawExport),
      firstSeen: protectedCookie.firstSeen || firstTimestamp(observedIn),
      lastSeen: protectedCookie.lastSeen || lastTimestamp(observedIn),
      sourceUrlCount: sourceUrls.length,
      sourceUrlsTruncated: sourceUrls.length > COOKIE_REPORT_LIMITS.maxSourceUrlSamplesPerCookie,
      sampleSourceUrls: sourceUrls.slice(0, COOKIE_REPORT_LIMITS.maxSourceUrlSamplesPerCookie),
      observedInCount: observedIn.length,
      observedInTruncated: observedIn.length > COOKIE_REPORT_LIMITS.maxObservedInSamplesPerCookie,
      sampleObservedIn: observedIn.slice(0, COOKIE_REPORT_LIMITS.maxObservedInSamplesPerCookie),
      findingCount: (protectedCookie.findings || []).length
    };
  }

  function compactProtectedValue(value = {}, rawExport = {}) {
    const rawAvailable = !!value.rawAvailable;
    const rawIncludedInRawExport = rawAvailable && rawExport.included === true;
    return {
      rawAvailable,
      rawIncluded: rawIncludedInRawExport,
      rawIncludedInReport: false,
      rawIncludedInRawExport,
      rawExportPath: rawIncludedInRawExport ? 'cookies/cookies.raw.json' : null,
      length: value.length ?? null,
      masked: value.masked || null,
      fingerprint: value.fingerprint || null,
      maskPolicy: value.maskPolicy || null
    };
  }

  function compactCookieFinding(finding) {
    const urls = (finding.sourceUrls || []).map(redactUrlValue);
    return {
      id: finding.id || null,
      ruleId: finding.ruleId || null,
      severity: finding.severity || 'info',
      category: finding.category || 'cookies',
      cookieName: finding.cookieName || null,
      message: finding.evidence || finding.message || finding.ruleId || 'Cookie finding',
      recommendation: finding.recommendation || null,
      confidence: finding.confidence || null,
      targetUrl: redactUrlValue(finding.targetUrl || ''),
      evidenceUrlCount: urls.length,
      evidenceUrlsTruncated: urls.length > COOKIE_REPORT_LIMITS.maxEvidenceUrlsPerFinding,
      sampleEvidenceUrls: urls.slice(0, COOKIE_REPORT_LIMITS.maxEvidenceUrlsPerFinding)
    };
  }

  function compactCookiePolicy(policy = {}) {
    return {
      mode: policy.mode || 'safe',
      rawRecordsIncludedByDefault: false,
      rawHarCookieRecordsIncludedByDefault: false
    };
  }

  function summarizeCookiesForHumans(summary = {}, cookies, findings, rawRecordCount, rawExport = {}) {
    const severities = {};
    (findings || []).forEach(finding => {
      const key = finding.severity || 'info';
      severities[key] = (severities[key] || 0) + 1;
    });
    return {
      ...summary,
      observedCookies: summary.observedCookies ?? cookies.length,
      findings: summary.findings ?? findings.length,
      rawRecordsObserved: rawRecordCount,
      rawRecordsIncludedInReport: 0,
      rawCookieValuesIncludedInRawExport: rawExport.included === true ? Number(rawExport.scope?.rawCookieCount || 0) : 0,
      rawExportPath: rawExport.included === true ? 'cookies/cookies.raw.json' : null,
      findingSeverities: severities
    };
  }

  function buildStorageOverview(sanitized = {}, rawExport = {}) {
    return {
      localStorage: compactStorageArea(sanitized.localStorage, rawExport),
      sessionStorage: compactStorageArea(sanitized.sessionStorage, rawExport)
    };
  }

  function compactStorageArea(area = {}, rawExport = {}) {
    const entries = area.entries || [];
    return {
      status: area.status || null,
      available: area.available !== false,
      origin: area.origin || null,
      frameUrl: redactUrlValue(area.frameUrl || ''),
      itemCount: area.itemCount ?? entries.length,
      rawAvailableItems: area.rawAvailableItems || entries.filter(entry => entry?.value?.rawAvailable).length,
      sensitiveItems: area.sensitiveItems || entries.filter(entry => entry?.sensitive).length,
      sampleKeys: entries.slice(0, 20).map(entry => {
        const rawAvailable = !!entry.value?.rawAvailable;
        const rawIncludedInRawExport = rawAvailable && rawExport.included === true;
        return {
          key: entry.key || null,
          classification: entry.classification || 'unknown',
          sensitive: !!entry.sensitive,
          valueLength: entry.valueLength ?? entry.value?.length ?? null,
          rawAvailable,
          rawIncluded: rawIncludedInRawExport,
          rawIncludedInReport: false,
          rawIncludedInRawExport,
          rawExportPath: rawIncludedInRawExport ? 'application/storage.raw.json' : null
        };
      }),
      keysTruncated: entries.length > 20
    };
  }

  function buildIndexedDbOverview(indexedDB = {}) {
    const databases = indexedDB.databases || [];
    return {
      status: indexedDB.status || null,
      available: indexedDB.available !== false,
      databaseCount: indexedDB.databaseCount ?? databases.length,
      objectStoreCount: databases.reduce((total, db) => total + ((db.objectStores || []).length), 0),
      sampleDatabases: databases.slice(0, 10).map(db => ({
        name: db.name || null,
        version: db.version ?? null,
        objectStoreCount: (db.objectStores || []).length,
        sampleObjectStores: (db.objectStores || []).slice(0, 10).map(store => ({
          name: store.name || null,
          count: store.count ?? null,
          countStatus: store.countStatus || null,
          indexCount: (store.indexes || []).length
        }))
      })),
      databasesTruncated: databases.length > 10
    };
  }

  function buildCacheStorageOverview(cacheStorage = {}) {
    const caches = cacheStorage.caches || [];
    return {
      status: cacheStorage.status || null,
      available: cacheStorage.available !== false,
      cacheCount: cacheStorage.cacheCount ?? caches.length,
      requestCount: caches.reduce((total, cache) => total + ((cache.requests || []).length), 0),
      sampleCaches: caches.slice(0, 10).map(cache => ({
        name: cache.name || null,
        requestCount: cache.requestCount ?? (cache.requests || []).length,
        sampleRequests: (cache.requests || []).slice(0, 5).map(request => ({
          method: request.method || null,
          url: redactUrlValue(request.url || ''),
          destination: request.destination || null
        }))
      })),
      cachesTruncated: caches.length > 10
    };
  }

  function buildServiceWorkerOverview(serviceWorkers = {}) {
    const registrations = serviceWorkers.registrations || [];
    return {
      status: serviceWorkers.status || null,
      available: serviceWorkers.available !== false,
      registrationCount: serviceWorkers.registrationCount ?? registrations.length,
      sampleRegistrations: registrations.slice(0, 10).map(registration => ({
        scope: redactUrlValue(registration.scope || ''),
        activeScriptURL: redactUrlValue(registration.activeScriptURL || registration.activeScriptUrl || '')
      })),
      registrationsTruncated: registrations.length > 10
    };
  }

  function buildManifestOverview(manifest = {}) {
    return {
      status: manifest.status || null,
      available: manifest.available !== false,
      href: redactUrlValue(manifest.href || manifest.url || ''),
      id: manifest.id || null,
      name: manifest.name || null,
      shortName: manifest.shortName || manifest.short_name || null
    };
  }

  function sanitizeApplicationFallback(application = {}) {
    return {
      summary: application.summary || {},
      localStorage: application.localStorage || {},
      sessionStorage: application.sessionStorage || {},
      indexedDB: application.indexedDB || {},
      cacheStorage: application.cacheStorage || {},
      serviceWorkers: application.serviceWorkers || {},
      manifest: application.manifest || {},
      observations: application.observations || []
    };
  }

  function redactUrlValue(url) {
    return domain.redactUrl ? domain.redactUrl(url || '') : url;
  }

  function compactDisplayUrl(url, maxLength = 240) {
    const value = String(url || '');
    if (value.length <= maxLength) {
      return value;
    }
    const head = value.slice(0, Math.max(40, maxLength - 64));
    const tail = value.slice(-32);
    return `${head}…${tail}`;
  }

  function redactCookieUrls(cookie) {
    return {
      ...cookie,
      sourceUrls: (cookie.sourceUrls || []).map(redactUrlValue)
    };
  }

  function redactFindingUrls(finding) {
    return {
      ...finding,
      targetUrl: redactUrlValue(finding.targetUrl),
      sourceUrls: (finding.sourceUrls || []).map(redactUrlValue)
    };
  }

  function redactRawRecordUrls(record) {
    const out = {
      ...record,
      targetUrl: redactUrlValue(record.targetUrl),
      requestUrl: redactUrlValue(record.requestUrl),
      valueRepresentation: 'protected'
    };
    delete out.rawValue;
    if (out.value && typeof out.value === 'object') {
      out.value = { ...out.value, rawIncluded: false };
      delete out.value.rawValue;
    }
    return out;
  }

  function redactLog(log) {
    return {
      ...log,
      detail: redactUrlValue(log.detail)
    };
  }

  function topCounts(values, max, label) {
    const counts = new Map();
    values.forEach(value => {
      const key = value || 'unknown';
      counts.set(key, (counts.get(key) || 0) + 1);
    });
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
      .slice(0, max)
      .map(([value, count]) => ({ [label]: value, requests: count, count }));
  }

  function normalizeReasonKey(status, reason) {
    if (reason) return String(reason).toUpperCase();
    return String(status || 'UNKNOWN').toUpperCase();
  }

  function hostFromUrl(url) {
    try {
      return new URL(url || '').host || null;
    } catch {
      return null;
    }
  }

  function networkEntryMessage({ status, reason, capturedBytes, bodyPath }) {
    if (bodyPath) return `Captured ${formatBytes(capturedBytes)} and exported to ${bodyPath}.`;
    if (status === 'body_captured') return `Body captured (${formatBytes(capturedBytes)}) but no ZIP path was attached.`;
    if (reason) return `Body not exported: ${reason}.`;
    return `Body not exported: ${status}.`;
  }

  function firstTimestamp(items) {
    return (items || []).map(item => item.timestamp).filter(Boolean).sort()[0] || null;
  }

  function lastTimestamp(items) {
    return (items || []).map(item => item.timestamp).filter(Boolean).sort().at(-1) || null;
  }

  function numberText(value) {
    return Number(value || 0).toLocaleString('en-US');
  }

  function formatBytes(bytes) {
    const value = Number(bytes || 0);
    if (value < 1024) return `${value} B`;
    if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
    return `${(value / 1024 / 1024).toFixed(1)} MB`;
  }

  function networkHumanSentence(networkReport) {
    const totals = networkReport?.totals || {};
    const exported = totals.exportedBodies || 0;
    const captured = totals.bodyCaptured || 0;
    const skipped = (totals.mimeBlocked || 0) + (totals.sizeLimitExceeded || 0) + (totals.policyBlocked || 0) + (totals.platformUnavailable || 0);
    return `${numberText(networkReport?.totals?.requests || 0)} requests observed. ${numberText(captured)} bodies captured, ${numberText(exported)} exported as files, ${numberText(skipped)} skipped or unavailable.`;
  }

  function cookieHumanSentence(cookiesReport) {
    const summary = cookiesReport?.summary || {};
    const rawText = cookiesReport?.exportContainsRawCookies ? 'Raw cookie export was explicitly enabled; this report remains protected.' : 'Raw cookie export is not included in this report.';
    return `${numberText(summary.observedCookies || 0)} cookies observed with ${numberText(summary.findings || 0)} findings. ${rawText}`;
  }

  function applicationHumanSentence(applicationReport) {
    const summary = applicationReport?.summary || {};
    const rawText = applicationReport?.exportContainsRawApplicationData ? 'Raw application storage export was explicitly enabled; this report remains protected.' : 'Raw application storage is not included in this report.';
    return `${numberText(summary.storageItems || 0)} storage items, ${numberText(summary.indexedDbDatabases || 0)} IndexedDB databases, and ${numberText(summary.cacheStorageCaches || 0)} Cache Storage caches observed. ${rawText}`;
  }

  return {
    COOKIE_REPORT_LIMITS,
    buildCurrentCookiesReport,
    buildCurrentCookiesSanitizedJson,
    buildCurrentCookiesHtml,
    buildCurrentNetscapeSanitized,
    buildCurrentRawCookiesJson,
    buildCurrentRawNetscapeCookies,
    buildDiagnosticsDownloadPayload,
    buildCurrentNetworkReport,
    buildCurrentNetworkDetailsReport,
    buildCurrentApplicationReport,
    buildCurrentApplicationStorageSanitizedJson,
    buildCurrentApplicationIndexedDbInventoryJson,
    buildCurrentApplicationCacheStorageInventoryJson,
    buildCurrentApplicationRawStorageJson,
    buildCurrentCaptureSummary
  };
});
