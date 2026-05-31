(function(root, factory) {
  const api = factory(root);
  root.BackToolsExport = Object.assign(root.BackToolsExport || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  let domain = root.BackToolsDomain || {};
  if (typeof require === 'function') {
    try {
      domain = Object.assign(
        {},
        require('../domain/targetClassification.js'),
        require('../domain/redaction.js'),
        require('../domain/resourceClassification.js'),
        domain
      );
    } catch {}
  }

  const SOURCE_LABELS = {
    sources: 'sources',
    application: 'application',
    network: 'network',
    cookies: 'cookies',
    report: 'report'
  };

  const MANIFEST_COMPACT_LIMITS = {
    maxResourceExamples: 25,
    maxExportedFileExamples: 50,
    maxReasonExamplesPerGroup: 10,
    maxFailedExamples: 50,
    maxMimeTypes: 25,
    maxTypes: 25,
    maxHosts: 25
  };

  function buildCurrentTotals(plan, written) {
    const resources = plan.resources || [];
    const hiddenByDefault = resources.filter(r => r.visibleByDefault === false).length;
    const redacted = [
      ...resources,
      ...written,
      ...plan.manifestOnlyResources,
      ...plan.skippedResources,
      ...plan.failedResources
    ].filter(r => r.redactionApplied).length;
    return {
      discovered: resources.length || written.length + plan.manifestOnlyResources.length + plan.skippedResources.length + plan.failedResources.length,
      visibleByDefault: resources.length ? resources.length - hiddenByDefault : 0,
      hiddenByDefault,
      written: written.length,
      metadataOnly: plan.manifestOnlyResources.filter(r => r.exportStatus !== 'hidden_by_default').length,
      skipped: plan.skippedResources.length,
      failed: plan.failedResources.length,
      redacted,
      plannedFiles: plan.plannedFiles.length,
      writtenFiles: written.length,
      manifestOnlyEntries: plan.manifestOnlyResources.length,
      skippedEntries: plan.skippedResources.length,
      failedEntries: plan.failedResources.length
    };
  }

  function buildReasonGroupsForExport(plan) {
    const reasonGroups = {};
    [...plan.manifestOnlyResources, ...plan.skippedResources, ...plan.failedResources].forEach(r => {
      reasonGroups[r.reason] = (reasonGroups[r.reason] || 0) + 1;
    });
    return reasonGroups;
  }

  function buildCurrentManifest({
    generatedAt,
    analyzedUrl,
    exportOptions,
    plan,
    written,
    cookiesSummary = {},
    includeCookiesReport,
    cookieExport,
    networkSummary,
    includeNetworkReport,
    applicationSummary,
    includeApplicationReport,
    applicationExport,
    objectDump,
    target,
    moduleStatuses,
    networkEntries = [],
    sourcesResources = [],
    application,
    includeDiagnostics = false,
    includeFailedReport = false,
    includeLogsJson = false,
    includeCookieHtmlReport = false
  }) {
    const totals = buildCurrentTotals(plan, written);
    const inspected = domain.redactUrlWithMetadata
      ? domain.redactUrlWithMetadata(analyzedUrl || '')
      : { value: analyzedUrl, redacted: false, hash: null };
    const resources = buildResourceEntries(plan, written);
    const objectDumpMetadata = normalizeObjectDumpMetadata(objectDump);
    const targetMetadata = buildTargetMetadata(target, analyzedUrl);
    const moduleSummary = typeof domain.summarizeModuleStatuses === 'function'
      ? domain.summarizeModuleStatuses(moduleStatuses || {})
      : { modules: [], unavailableModules: [], emptySections: [], warnings: [] };
    const manifestItems = buildManifestItems({
      generatedAt,
      analyzedUrl,
      targetMetadata,
      plan,
      written,
      resources,
      networkEntries,
      sourcesResources,
      application,
      includeCookiesReport,
      cookieExport,
      cookiesSummary,
      includeNetworkReport,
      networkSummary,
      includeApplicationReport,
      applicationSummary,
      applicationExport,
      includeDiagnostics,
      includeFailedReport,
      includeLogsJson,
      includeCookieHtmlReport,
      includeManifestDetails: exportOptions?.includeManifestDetails !== false
    });
    const coverage = buildManifestCoverageSummary(manifestItems);
    const validation = validateManifestConsistency({
      items: manifestItems,
      coverage,
      written,
      resources,
      networkEntries,
      includeCookiesReport,
      includeNetworkReport,
      includeApplicationReport,
      includeDiagnostics,
      includeFailedReport,
      includeLogsJson,
      includeCookieHtmlReport,
      includeManifestDetails: exportOptions?.includeManifestDetails !== false
    });
    const includeManifestDetails = exportOptions?.includeManifestDetails !== false;
    const detailsPath = includeManifestDetails ? 'MANIFEST_DETAILS.json' : null;

    return {
      schemaVersion: 'backtools.capture.v1',
      reportProfile: 'compact_human_readable',
      generatedAt,
      inspectedUrl: inspected.value,
      inspectedUrlRedacted: inspected.value,
      inspectedUrlHash: inspected.hash,
      targetOrigin: getOrigin(analyzedUrl),
      targetUrl: inspected.value,
      normalizedTargetUrl: domain.redactUrl ? domain.redactUrl(targetMetadata.normalizedUrl || '') : targetMetadata.normalizedUrl,
      targetType: targetMetadata.targetType,
      targetScheme: targetMetadata.scheme,
      isNormalWebTarget: targetMetadata.isNormalWebTarget,
      isLimitedTarget: targetMetadata.isLimitedTarget,
      captureMode: targetMetadata.captureMode,
      targetClassificationReason: targetMetadata.classificationReason,
      urlSource: targetMetadata.urlSource,
      readerGuide: buildManifestReaderGuide({ detailsPath, includeNetworkReport, includeCookiesReport, includeApplicationReport }),
      detailsPath,
      modules: moduleSummary.modules,
      emptySections: moduleSummary.emptySections,
      unavailableModules: moduleSummary.unavailableModules,
      warnings: moduleSummary.warnings,
      exportOptions,
      objectDump: objectDumpMetadata,
      totals,
      categoryTotals: domain.buildCategoryTotals ? domain.buildCategoryTotals(plan.resources || []) : {},
      resources: summarizeResourceCollection(resources),
      exportedFiles: summarizeWrittenFiles(written),
      manifestOnlyResources: summarizeReasonResources(plan.manifestOnlyResources, { maxExamplesPerReason: MANIFEST_COMPACT_LIMITS.maxReasonExamplesPerGroup }),
      skippedResources: summarizeReasonResources(plan.skippedResources, { maxExamplesPerReason: MANIFEST_COMPACT_LIMITS.maxReasonExamplesPerGroup }),
      failedResources: summarizeReasonResources(plan.failedResources, {
        maxExamplesPerReason: MANIFEST_COMPACT_LIMITS.maxFailedExamples,
        maxTotalExamples: MANIFEST_COMPACT_LIMITS.maxFailedExamples
      }),
      reasonGroups: buildReasonGroupsForExport(plan),
      coverage,
      items: manifestItems,
      itemSummary: summarizeManifestItems(manifestItems),
      validation,
      cookies: {
        included: !!includeCookiesReport,
        mode: 'safe',
        reportPath: includeCookiesReport ? 'cookies/COOKIES_REPORT.json' : null,
        sanitizedJsonPath: includeCookiesReport ? 'cookies/cookies.sanitized.json' : null,
        htmlPath: includeCookiesReport && includeCookieHtmlReport ? 'cookies/cookies.html' : null,
        netscapeSanitizedPath: includeCookiesReport ? 'cookies/cookies.netscape.sanitized.txt' : null,
        observedCookies: cookiesSummary.observedCookies || 0,
        rawAvailableCookies: cookiesSummary.rawAvailableCookies || 0,
        rawUnavailableCookies: cookiesSummary.rawUnavailableCookies || 0,
        findings: cookiesSummary.findings || 0,
        valueMode: objectDumpMetadata.cookieValueMode,
        containsRawCookies: !!cookieExport?.containsRawCookies,
        containsReplayableCookieJar: !!cookieExport?.containsReplayableCookieJar,
        rawCookieExportConfirmedAt: cookieExport?.rawCookieExportConfirmedAt || null,
        rawCookieExportScope: cookieExport?.rawCookieExportScope || { rawCookieCount: 0, domains: [] },
        rawJsonPath: cookieExport?.containsRawCookies ? 'cookies/cookies.raw.json' : null,
        rawNetscapePath: cookieExport?.containsReplayableCookieJar ? 'cookies/cookies.raw.netscape.txt' : null
      },
      network: {
        included: !!includeNetworkReport,
        reportPath: includeNetworkReport ? 'NETWORK_REPORT.json' : null,
        detailsPath: includeNetworkReport ? 'network/NETWORK_DETAILS.json' : null,
        summary: networkSummary || null
      },
      application: {
        included: !!includeApplicationReport,
        reportPath: includeApplicationReport ? 'application/APPLICATION_REPORT.json' : null,
        storageSanitizedPath: includeApplicationReport ? 'application/storage.sanitized.json' : null,
        indexedDbInventoryPath: includeApplicationReport ? 'application/indexeddb.inventory.json' : null,
        cacheStorageInventoryPath: includeApplicationReport ? 'application/cache-storage.inventory.json' : null,
        rawStoragePath: applicationExport?.containsRawApplicationData ? 'application/storage.raw.json' : null,
        containsRawApplicationData: !!applicationExport?.containsRawApplicationData,
        rawApplicationExportConfirmedAt: applicationExport?.rawApplicationExportConfirmedAt || null,
        rawApplicationExportScope: applicationExport?.rawApplicationExportScope || { rawStorageItemCount: 0, origins: [], storageTypes: [] },
        valueMode: objectDumpMetadata.applicationValueMode,
        summary: applicationSummary || null
      }
    };
  }

  function normalizeObjectDumpMetadata(objectDump = {}) {
    const enabled = objectDump.dumpObjectsEnabled === true;
    return {
      dumpObjectsEnabled: enabled,
      cookieValueMode: objectDump.cookieValueMode === 'raw' ? 'raw' : 'protected',
      applicationValueMode: objectDump.applicationValueMode === 'raw' ? 'raw' : 'protected'
    };
  }

  function buildTargetMetadata(target, analyzedUrl) {
    if (target && typeof target === 'object' && target.targetType) {
      return target;
    }
    if (typeof domain.classifyTargetUrl === 'function') {
      return domain.classifyTargetUrl(analyzedUrl || null, { urlSource: 'initial_unknown' });
    }
    return {
      targetType: analyzedUrl ? 'unknown' : 'unknown',
      targetUrl: analyzedUrl || null,
      normalizedUrl: analyzedUrl || null,
      scheme: null,
      isNormalWebTarget: /^https?:/i.test(String(analyzedUrl || '')),
      isLimitedTarget: !/^https?:/i.test(String(analyzedUrl || '')),
      captureMode: /^https?:/i.test(String(analyzedUrl || '')) ? 'web_full_available' : 'unknown_target_report_only',
      classificationReason: null,
      urlSource: 'initial_unknown'
    };
  }

  function sanitizeResourceList(resources) {
    return (resources || []).map(resource => {
      const redacted = resource.urlRedacted || (domain.redactUrl ? domain.redactUrl(resource.url || '') : resource.url);
      const out = {
        ...resource,
        url: redacted,
        urlRedacted: redacted
      };
      delete out.originalUrlRaw;
      return out;
    });
  }

  function buildManifestReaderGuide({ detailsPath, includeNetworkReport, includeCookiesReport, includeApplicationReport }) {
    const relatedReports = [];
    if (includeNetworkReport) relatedReports.push('NETWORK_REPORT.json');
    if (includeCookiesReport) relatedReports.push('cookies/COOKIES_REPORT.json');
    if (includeApplicationReport) relatedReports.push('application/APPLICATION_REPORT.json');
    return {
      openFirst: 'CAPTURE_SUMMARY.md',
      purpose: 'Compact export index for quick human review.',
      howToRead: [
        'Use totals, coverage, reasonGroups, and itemSummary to understand what was captured, exported, skipped, or kept as metadata.',
        'Use items as the compact per-file index.',
        detailsPath ? `Use ${detailsPath} only when you need verbose machine-readable resource arrays.` : 'Verbose manifest details were disabled for this export.'
      ],
      relatedReports
    };
  }

  function buildCurrentManifestDetails({
    generatedAt,
    analyzedUrl,
    manifest,
    plan = {},
    written = [],
    networkEntries = [],
    sourcesResources = []
  }) {
    const inspected = domain.redactUrlWithMetadata
      ? domain.redactUrlWithMetadata(analyzedUrl || manifest?.targetUrl || '')
      : { value: analyzedUrl || manifest?.targetUrl || null, redacted: false, hash: null };
    const resources = buildResourceEntries(plan, written);
    return {
      schemaVersion: 'backtools.manifest.details.v1',
      reportProfile: 'verbose_machine_readable',
      generatedAt: generatedAt || manifest?.generatedAt || new Date().toISOString(),
      compactManifestPath: 'MANIFEST.json',
      message: 'Verbose companion for MANIFEST.json. This file keeps full resource arrays out of the compact manifest.',
      inspectedUrl: inspected.value,
      inspectedUrlRedacted: inspected.value,
      inspectedUrlHash: inspected.hash,
      totals: manifest?.totals || buildCurrentTotals(plan, written),
      coverage: manifest?.coverage || null,
      resources,
      exportedFiles: sanitizeResourceList(written),
      manifestOnlyResources: sanitizeResourceList(plan.manifestOnlyResources || []),
      skippedResources: sanitizeResourceList(plan.skippedResources || []),
      failedResources: sanitizeResourceList(plan.failedResources || []),
      items: manifest?.items || [],
      validation: manifest?.validation || null,
      sourceInventory: {
        total: (sourcesResources || []).length,
        examples: (sourcesResources || []).slice(0, MANIFEST_COMPACT_LIMITS.maxResourceExamples).map(compactResourceExample),
        examplesTruncated: (sourcesResources || []).length > MANIFEST_COMPACT_LIMITS.maxResourceExamples
      },
      networkInventory: {
        total: (networkEntries || []).length,
        examples: (networkEntries || []).slice(0, MANIFEST_COMPACT_LIMITS.maxResourceExamples).map(compactResourceExample),
        examplesTruncated: (networkEntries || []).length > MANIFEST_COMPACT_LIMITS.maxResourceExamples
      }
    };
  }

  function summarizeResourceCollection(resources) {
    const rows = resources || [];
    return {
      total: rows.length,
      visibleByDefault: rows.filter(row => row.visibleByDefault !== false).length,
      hiddenByDefault: rows.filter(row => row.visibleByDefault === false).length,
      byCollector: countBy(rows, row => row.collector || 'unknown'),
      byType: topCounts(countBy(rows, row => row.type || 'unknown'), MANIFEST_COMPACT_LIMITS.maxTypes),
      byMimeType: topCounts(countBy(rows, row => row.mimeType || 'unknown'), MANIFEST_COMPACT_LIMITS.maxMimeTypes),
      byHost: topCounts(countBy(rows, row => getHostname(row.urlRedacted || row.url || row.originalUrlRedacted || row.originalUrl) || 'unknown'), MANIFEST_COMPACT_LIMITS.maxHosts),
      examples: rows.slice(0, MANIFEST_COMPACT_LIMITS.maxResourceExamples).map(compactResourceExample),
      examplesTruncated: rows.length > MANIFEST_COMPACT_LIMITS.maxResourceExamples,
      detailsPath: 'MANIFEST_DETAILS.json#resources'
    };
  }

  function summarizeWrittenFiles(written) {
    const rows = written || [];
    return {
      total: rows.length,
      totalBytes: rows.reduce((sum, row) => sum + safeNumber(row.size), 0),
      byCollector: countBy(rows, row => row.collector || 'unknown'),
      byContentKind: countBy(rows, row => row.contentKind || 'unknown'),
      byMimeType: topCounts(countBy(rows, row => row.mimeType || 'unknown'), MANIFEST_COMPACT_LIMITS.maxMimeTypes),
      examples: rows.slice(0, MANIFEST_COMPACT_LIMITS.maxExportedFileExamples).map(compactResourceExample),
      examplesTruncated: rows.length > MANIFEST_COMPACT_LIMITS.maxExportedFileExamples,
      detailsPath: 'MANIFEST_DETAILS.json#exportedFiles'
    };
  }

  function summarizeReasonResources(resources, options = {}) {
    const rows = resources || [];
    const maxExamplesPerReason = options.maxExamplesPerReason || MANIFEST_COMPACT_LIMITS.maxReasonExamplesPerGroup;
    const maxTotalExamples = options.maxTotalExamples || Infinity;
    const byReason = {};
    const examplesByReason = {};
    let exampleCount = 0;

    for (const row of rows) {
      const reason = row.reason || row.bodyCaptureReason || row.exportStatus || 'UNKNOWN';
      byReason[reason] = (byReason[reason] || 0) + 1;
      if (!examplesByReason[reason]) examplesByReason[reason] = [];
      if (examplesByReason[reason].length < maxExamplesPerReason && exampleCount < maxTotalExamples) {
        examplesByReason[reason].push(compactResourceExample(row));
        exampleCount++;
      }
    }

    const truncatedReasons = {};
    Object.keys(byReason).forEach(reason => {
      truncatedReasons[reason] = byReason[reason] > (examplesByReason[reason] || []).length;
    });

    return {
      total: rows.length,
      byReason,
      examplesByReason,
      examplesTruncated: rows.length > exampleCount,
      truncatedReasons,
      detailsPath: rows.length ? 'MANIFEST_DETAILS.json' : null
    };
  }

  function summarizeManifestItems(items) {
    const rows = items || [];
    return {
      total: rows.length,
      bySource: countBy(rows, item => item.source || 'unknown'),
      byExportState: countBy(rows, item => item.exportState || 'unknown'),
      bySkipReason: countBy(rows, item => item.skipReason || 'UNKNOWN'),
      generatedReports: rows
        .filter(item => item.source === SOURCE_LABELS.report || item.type === 'Report' || item.exportState === 'generated')
        .map(item => ({
          id: item.id,
          displayName: item.displayName,
          exportPath: item.exportPath,
          source: item.source,
          exportState: item.exportState
        }))
    };
  }

  function compactResourceExample(resource) {
    const out = {
      id: resource.id || null
    };
    optionalField(out, 'collector', resource.collector);
    optionalField(out, 'type', resource.type);
    optionalField(out, 'mimeType', resource.mimeType);
    optionalField(out, 'method', resource.method);
    if (resource.statusCode != null) out.statusCode = resource.statusCode;
    optionalField(out, 'url', resource.urlRedacted || resource.originalUrlRedacted || resource.url || resource.originalUrl);
    optionalField(out, 'urlHash', resource.urlHash);
    optionalField(out, 'zipPath', resource.zipPath || resource.bodyPath);
    optionalField(out, 'reason', resource.reason || resource.bodyCaptureReason);
    optionalField(out, 'exportStatus', resource.exportStatus);
    if (resource.size != null) out.size = resource.size;
    if (resource.bodyCapturedBytes != null) out.bodyCapturedBytes = resource.bodyCapturedBytes;
    if (resource.bodySizeBytes != null) out.bodySizeBytes = resource.bodySizeBytes;
    if (resource.visibleByDefault === false) out.visibleByDefault = false;
    return out;
  }

  function countBy(rows, getKey) {
    const counts = {};
    (rows || []).forEach(row => {
      const key = String(getKey(row) || 'unknown');
      counts[key] = (counts[key] || 0) + 1;
    });
    return counts;
  }

  function topCounts(counts, maxItems) {
    const entries = Object.entries(counts || {})
      .sort((left, right) => right[1] - left[1])
      .slice(0, maxItems);
    return Object.fromEntries(entries);
  }

  function safeNumber(value) {
    return typeof value === 'number' && Number.isFinite(value) ? value : 0;
  }

  function getOrigin(url) {
    try {
      return new URL(url || '').origin;
    } catch {
      return null;
    }
  }

  function getHostname(url) {
    try {
      return new URL(url || '').hostname || null;
    } catch {
      return null;
    }
  }

  function getPathname(url) {
    try {
      return new URL(url || '').pathname || null;
    } catch {
      return null;
    }
  }

  function basename(value, fallback = 'item') {
    const parts = String(value || '').split('/').filter(Boolean);
    return parts.length ? parts[parts.length - 1] : fallback;
  }

  function buildResourceEntries(plan, written) {
    const byId = new Map();
    (plan.resources || []).forEach(resource => {
      byId.set(resource.id, {
        id: resource.id,
        collector: resource.collector,
        url: resource.urlRedacted || resource.url,
        urlRedacted: resource.urlRedacted || resource.url,
        urlHash: resource.urlHash || null,
        resourceCategory: resource.resourceCategory || 'unknown',
        visibleByDefault: resource.visibleByDefault !== false,
        hiddenByDefaultReason: resource.hiddenByDefaultReason || null,
        userIncludedAdvanced: false,
        exportStatus: resource.visibleByDefault === false ? 'hidden_by_default' : 'metadata_only',
        redactionApplied: !!resource.redactionApplied,
        redactedFields: resource.redactedFields || [],
        bodyCaptureStatus: resource.bodyCaptureStatus || undefined,
        bodyCaptureReason: resource.bodyCaptureReason || undefined,
        bodyCapturedBytes: resource.bodyCapturedBytes || 0,
        bodySizeBytes: resource.bodySizeBytes ?? resource.bodyCapturedBytes ?? 0,
        bodyEncoding: resource.bodyEncoding || undefined,
        bodyRenderStatus: resource.bodyRenderStatus || undefined,
        bodyExportStatus: resource.bodyExportStatus || undefined
      });
    });
    const apply = (resource, status) => {
      const current = byId.get(resource.id) || {};
      byId.set(resource.id, {
        ...current,
        id: resource.id,
        collector: resource.collector || current.collector || null,
        url: resource.urlRedacted || resource.originalUrlRedacted || resource.originalUrl || current.url || null,
        urlRedacted: resource.urlRedacted || resource.originalUrlRedacted || resource.originalUrl || current.urlRedacted || null,
        urlHash: resource.urlHash || current.urlHash || null,
        resourceCategory: resource.resourceCategory || current.resourceCategory || 'unknown',
        visibleByDefault: resource.visibleByDefault !== false,
        hiddenByDefaultReason: resource.hiddenByDefaultReason || current.hiddenByDefaultReason || null,
        userIncludedAdvanced: !!resource.userIncludedAdvanced,
        exportStatus: resource.exportStatus || status,
        redactionApplied: !!(resource.redactionApplied || current.redactionApplied),
        redactedFields: resource.redactedFields || current.redactedFields || [],
        zipPath: resource.zipPath || current.zipPath || null,
        reason: resource.reason || current.reason || null,
        method: resource.method || current.method || null,
        statusCode: resource.statusCode ?? current.statusCode ?? null,
        mimeType: resource.mimeType || current.mimeType || null,
        type: resource.type || current.type || null,
        size: resource.size ?? current.size ?? null,
        startedDateTime: resource.startedDateTime || current.startedDateTime || null,
        collectedAt: resource.collectedAt || current.collectedAt || null,
        bodyCaptureStatus: resource.bodyCaptureStatus || current.bodyCaptureStatus || undefined,
        bodyCaptureReason: resource.bodyCaptureReason || current.bodyCaptureReason || undefined,
        bodyCapturedBytes: resource.bodyCapturedBytes || current.bodyCapturedBytes || 0,
        bodySizeBytes: resource.bodySizeBytes ?? current.bodySizeBytes ?? resource.bodyCapturedBytes ?? current.bodyCapturedBytes ?? 0,
        bodyEncoding: resource.bodyEncoding || current.bodyEncoding || undefined,
        bodyRenderStatus: resource.bodyRenderStatus || current.bodyRenderStatus || undefined,
        bodyExportStatus: resource.bodyExportStatus || current.bodyExportStatus || undefined,
        bodyRedactionApplied: !!(resource.bodyRedactionApplied || current.bodyRedactionApplied)
      });
    };
    written.forEach(resource => apply(resource, 'written'));
    plan.manifestOnlyResources.forEach(resource => apply(resource, resource.exportStatus || 'metadata_only'));
    plan.skippedResources.forEach(resource => apply(resource, 'skipped'));
    plan.failedResources.forEach(resource => apply(resource, 'failed'));
    return [...byId.values()];
  }

  function buildManifestItems(context) {
    const items = [];
    const targetHostname = getHostname(context.analyzedUrl || context.targetMetadata?.normalizedUrl || '');
    const resourceItems = buildObservedResourceManifestItems(context.resources || [], context, targetHostname);
    items.push(...resourceItems);
    items.push(...buildCookiesManifestItems(context, targetHostname));
    items.push(...buildApplicationManifestItems(context, targetHostname));
    items.push(...buildGeneratedReportItems(context, targetHostname));
    return items;
  }

  function buildObservedResourceManifestItems(resources, context, targetHostname) {
    const sourceLookup = new Map((context.sourcesResources || []).map(resource => [resource.id, resource]));
    const networkLookup = new Map((context.networkEntries || []).map(resource => [resource.id, resource]));
    return resources.map(resource => {
      const source = getEvidenceSourceFromCollector(resource.collector, resource.id);
      const extra = source === SOURCE_LABELS.network
        ? (networkLookup.get(resource.id) || {})
        : (sourceLookup.get(resource.id) || {});
      const url = resource.urlRedacted || extra.urlRedacted || extra.url || resource.url || null;
      const domainName = getHostname(url);
      const exportPath = resource.zipPath || null;
      const reason = normalizeManifestReason(source, resource.reason || resource.bodyCaptureReason || resource.exportStatus, resource);
      const exportState = normalizeManifestExportState(source, resource, reason);
      return compactManifestItem({
        id: resource.id,
        source,
        exportState,
        skipReason: exportState === 'exported' ? 'NONE' : reason,
        displayName: buildDisplayName({ exportPath, url, fallback: resource.id }),
        type: normalizeManifestType({
          source,
          path: exportPath || getPathname(url),
          mimeType: extra.mimeType || resource.mimeType,
          rawType: extra.type || resource.type,
          displayName: buildDisplayName({ exportPath, url, fallback: resource.id })
        }),
        url,
        domain: domainName,
        path: getPathname(url),
        exportPath,
        method: extra.method || undefined,
        statusCode: extra.statusCode ?? undefined,
        mimeType: extra.mimeType || resource.mimeType || undefined,
        sizeBytes: numberOrUndefined(extra.size ?? resource.size),
        bodySizeBytes: numberOrUndefined(resource.bodySizeBytes),
        bodyExported: exportState === 'exported',
        metadataOnly: exportState === 'metadata-only',
        isFirstParty: classifyFirstParty(domainName, targetHostname),
        capturedAt: parseTimestampNumber(extra.startedDateTime),
        collectedAt: parseTimestampNumber(extra.collectedAt || resource.collectedAt),
        notes: buildResourceNotes(source, resource, exportState)
      });
    });
  }

  function buildCookiesManifestItems(context, targetHostname) {
    if (!context.includeCookiesReport) {
      return [];
    }
    const items = [];
    const domainName = getHostname(context.analyzedUrl);
    items.push(compactManifestItem({
      id: 'cookies:report',
      source: SOURCE_LABELS.cookies,
      exportState: 'generated',
      skipReason: 'NONE',
      displayName: 'COOKIES_REPORT.json',
      type: 'Report',
      domain: domainName,
      exportPath: 'cookies/COOKIES_REPORT.json',
      bodyExported: true,
      isFirstParty: classifyFirstParty(domainName, targetHostname),
      collectedAt: parseTimestampNumber(context.generatedAt)
    }));
    items.push(compactManifestItem({
      id: 'cookies:sanitized:json',
      source: SOURCE_LABELS.cookies,
      exportState: 'sanitized',
      skipReason: 'SANITIZED_ONLY',
      displayName: 'cookies.sanitized.json',
      type: 'Cookie',
      domain: domainName,
      exportPath: 'cookies/cookies.sanitized.json',
      bodyExported: true,
      isFirstParty: classifyFirstParty(domainName, targetHostname),
      collectedAt: parseTimestampNumber(context.generatedAt)
    }));
    if (context.includeCookieHtmlReport) {
      items.push(compactManifestItem({
        id: 'cookies:html',
        source: SOURCE_LABELS.cookies,
        exportState: 'generated',
        skipReason: 'NONE',
        displayName: 'cookies.html',
        type: 'Report',
        domain: domainName,
        exportPath: 'cookies/cookies.html',
        bodyExported: true,
        isFirstParty: classifyFirstParty(domainName, targetHostname),
        collectedAt: parseTimestampNumber(context.generatedAt)
      }));
    }
    items.push(compactManifestItem({
      id: 'cookies:netscape:sanitized',
      source: SOURCE_LABELS.cookies,
      exportState: 'sanitized',
      skipReason: 'SANITIZED_ONLY',
      displayName: 'cookies.netscape.sanitized.txt',
      type: 'Cookie',
      domain: domainName,
      exportPath: 'cookies/cookies.netscape.sanitized.txt',
      bodyExported: true,
      isFirstParty: classifyFirstParty(domainName, targetHostname),
      collectedAt: parseTimestampNumber(context.generatedAt)
    }));
    const rawCookieCount = Number(context.cookieExport?.rawCookieExportScope?.rawCookieCount || 0);
    if (context.cookieExport?.containsRawCookies) {
      items.push(compactManifestItem({
        id: 'cookies:raw:json',
        source: SOURCE_LABELS.cookies,
        exportState: 'raw',
        skipReason: 'NONE',
        displayName: 'cookies.raw.json',
        type: 'Cookie',
        domain: domainName,
        exportPath: 'cookies/cookies.raw.json',
        bodyExported: true,
        isFirstParty: classifyFirstParty(domainName, targetHostname),
        collectedAt: parseTimestampNumber(context.cookieExport?.rawCookieExportConfirmedAt || context.generatedAt)
      }));
      items.push(compactManifestItem({
        id: 'cookies:raw:netscape',
        source: SOURCE_LABELS.cookies,
        exportState: 'raw',
        skipReason: 'NONE',
        displayName: 'cookies.raw.netscape.txt',
        type: 'Cookie',
        domain: domainName,
        exportPath: 'cookies/cookies.raw.netscape.txt',
        bodyExported: true,
        isFirstParty: classifyFirstParty(domainName, targetHostname),
        collectedAt: parseTimestampNumber(context.cookieExport?.rawCookieExportConfirmedAt || context.generatedAt)
      }));
    } else if (rawCookieCount > 0) {
      items.push(compactManifestItem({
        id: 'cookies:raw:json',
        source: SOURCE_LABELS.cookies,
        exportState: 'skipped',
        skipReason: 'RAW_DISABLED',
        displayName: 'cookies.raw.json',
        type: 'Cookie',
        domain: domainName,
        exportPath: null,
        bodyExported: false,
        isFirstParty: classifyFirstParty(domainName, targetHostname),
        collectedAt: parseTimestampNumber(context.generatedAt)
      }));
    }
    return items;
  }

  function buildApplicationManifestItems(context, targetHostname) {
    if (!context.includeApplicationReport) {
      return [];
    }
    const items = [];
    const application = context.application || {};
    const collectedAt = application.collectedAt || context.generatedAt;
    const origin = application.targetOrigin || getOrigin(context.analyzedUrl);
    const domainName = getHostname(origin);
    items.push(compactManifestItem({
      id: 'application:report',
      source: SOURCE_LABELS.application,
      exportState: 'generated',
      skipReason: 'NONE',
      displayName: 'APPLICATION_REPORT.json',
      type: 'Report',
      domain: domainName,
      exportPath: 'application/APPLICATION_REPORT.json',
      bodyExported: true,
      isFirstParty: classifyFirstParty(domainName, targetHostname),
      collectedAt: parseTimestampNumber(collectedAt)
    }));
    items.push(compactManifestItem({
      id: 'application:storage:sanitized',
      source: SOURCE_LABELS.application,
      exportState: 'sanitized',
      skipReason: 'SANITIZED_ONLY',
      displayName: 'storage.sanitized.json',
      type: 'Storage',
      domain: domainName,
      exportPath: 'application/storage.sanitized.json',
      bodyExported: true,
      isFirstParty: classifyFirstParty(domainName, targetHostname),
      collectedAt: parseTimestampNumber(collectedAt)
    }));
    items.push(compactManifestItem({
      id: 'application:indexeddb:inventory',
      source: SOURCE_LABELS.application,
      exportState: 'inventory-only',
      skipReason: 'APPLICATION_INVENTORY_ONLY',
      displayName: 'indexeddb.inventory.json',
      type: 'IndexedDB',
      domain: domainName,
      exportPath: 'application/indexeddb.inventory.json',
      bodyExported: true,
      isFirstParty: classifyFirstParty(domainName, targetHostname),
      collectedAt: parseTimestampNumber(collectedAt)
    }));
    items.push(compactManifestItem({
      id: 'application:cache-storage:inventory',
      source: SOURCE_LABELS.application,
      exportState: 'inventory-only',
      skipReason: 'APPLICATION_INVENTORY_ONLY',
      displayName: 'cache-storage.inventory.json',
      type: 'Cache Storage',
      domain: domainName,
      exportPath: 'application/cache-storage.inventory.json',
      bodyExported: true,
      isFirstParty: classifyFirstParty(domainName, targetHostname),
      collectedAt: parseTimestampNumber(collectedAt)
    }));

    if (application.serviceWorkers && (application.serviceWorkers.registrationCount > 0 || application.serviceWorkers.available)) {
      items.push(compactManifestItem({
        id: application.serviceWorkers.id || 'application:service-workers',
        source: SOURCE_LABELS.application,
        exportState: 'inventory-only',
        skipReason: 'APPLICATION_INVENTORY_ONLY',
        displayName: 'service-workers',
        type: 'Service Worker',
        domain: getHostname(application.serviceWorkers.origin || origin),
        exportPath: null,
        bodyExported: false,
        isFirstParty: classifyFirstParty(getHostname(application.serviceWorkers.origin || origin), targetHostname),
        collectedAt: parseTimestampNumber(collectedAt),
        notes: ['Observed by Application collector; no standalone v1 export file.']
      }));
    }

    if (application.manifest && (application.manifest.available || application.manifest.href)) {
      items.push(compactManifestItem({
        id: application.manifest.id || 'application:manifest',
        source: SOURCE_LABELS.application,
        exportState: 'metadata-only',
        skipReason: 'APPLICATION_INVENTORY_ONLY',
        displayName: basename(getPathname(application.manifest.href) || 'manifest.webmanifest', 'manifest.webmanifest'),
        type: 'Manifest',
        url: application.manifest.href || null,
        domain: getHostname(application.manifest.href || origin),
        path: getPathname(application.manifest.href || null),
        exportPath: null,
        bodyExported: false,
        metadataOnly: true,
        isFirstParty: classifyFirstParty(getHostname(application.manifest.href || origin), targetHostname),
        collectedAt: parseTimestampNumber(collectedAt),
        notes: ['Observed as Application manifest metadata; no standalone v1 export file.']
      }));
    }

    const rawCount = Number(context.applicationExport?.rawApplicationExportScope?.rawStorageItemCount || 0);
    if (context.applicationExport?.containsRawApplicationData) {
      items.push(compactManifestItem({
        id: 'application:storage:raw',
        source: SOURCE_LABELS.application,
        exportState: 'raw',
        skipReason: 'NONE',
        displayName: 'storage.raw.json',
        type: 'Storage',
        domain: domainName,
        exportPath: 'application/storage.raw.json',
        bodyExported: true,
        isFirstParty: classifyFirstParty(domainName, targetHostname),
        collectedAt: parseTimestampNumber(context.applicationExport?.rawApplicationExportConfirmedAt || collectedAt)
      }));
    } else if (rawCount > 0) {
      items.push(compactManifestItem({
        id: 'application:storage:raw',
        source: SOURCE_LABELS.application,
        exportState: 'skipped',
        skipReason: 'RAW_DISABLED',
        displayName: 'storage.raw.json',
        type: 'Storage',
        domain: domainName,
        exportPath: null,
        bodyExported: false,
        isFirstParty: classifyFirstParty(domainName, targetHostname),
        collectedAt: parseTimestampNumber(collectedAt)
      }));
    }
    return items;
  }

  function buildGeneratedReportItems(context, targetHostname) {
    const items = [];
    const domainName = getHostname(context.analyzedUrl);
    items.push(compactManifestItem({
      id: 'report:manifest',
      source: SOURCE_LABELS.report,
      exportState: 'generated',
      skipReason: 'NONE',
      displayName: 'MANIFEST.json',
      type: 'Manifest',
      domain: domainName,
      exportPath: 'MANIFEST.json',
      bodyExported: true,
      isFirstParty: classifyFirstParty(domainName, targetHostname),
      collectedAt: parseTimestampNumber(context.generatedAt)
    }));
    if (context.includeManifestDetails !== false) {
      items.push(compactManifestItem({
        id: 'report:manifest-details',
        source: SOURCE_LABELS.report,
        exportState: 'generated',
        skipReason: 'NONE',
        displayName: 'MANIFEST_DETAILS.json',
        type: 'Manifest Details',
        domain: domainName,
        exportPath: 'MANIFEST_DETAILS.json',
        bodyExported: true,
        isFirstParty: classifyFirstParty(domainName, targetHostname),
        collectedAt: parseTimestampNumber(context.generatedAt)
      }));
    }
    if (context.includeFailedReport && (context.plan.failedResources || []).length > 0) {
      items.push(compactManifestItem({
        id: 'report:failed-resources',
        source: SOURCE_LABELS.report,
        exportState: 'generated',
        skipReason: 'NONE',
        displayName: 'FAILED_RESOURCES.json',
        type: 'Report',
        domain: domainName,
        exportPath: 'FAILED_RESOURCES.json',
        bodyExported: true,
        isFirstParty: classifyFirstParty(domainName, targetHostname),
        collectedAt: parseTimestampNumber(context.generatedAt)
      }));
    }
    if (context.includeDiagnostics && context.includeLogsJson) {
      items.push(compactManifestItem({
        id: 'report:logs',
        source: SOURCE_LABELS.report,
        exportState: 'generated',
        skipReason: 'NONE',
        displayName: 'logs.json',
        type: 'Report',
        domain: domainName,
        exportPath: 'logs.json',
        bodyExported: true,
        isFirstParty: classifyFirstParty(domainName, targetHostname),
        collectedAt: parseTimestampNumber(context.generatedAt)
      }));
    }
    if (context.includeDiagnostics) {
      items.push(compactManifestItem({
        id: 'report:diagnostics:target',
        source: SOURCE_LABELS.report,
        exportState: 'generated',
        skipReason: 'NONE',
        displayName: 'target.json',
        type: 'Report',
        domain: domainName,
        exportPath: 'diagnostics/target.json',
        bodyExported: true,
        isFirstParty: classifyFirstParty(domainName, targetHostname),
        collectedAt: parseTimestampNumber(context.generatedAt)
      }));
      items.push(compactManifestItem({
        id: 'report:diagnostics:modules',
        source: SOURCE_LABELS.report,
        exportState: 'generated',
        skipReason: 'NONE',
        displayName: 'modules.json',
        type: 'Report',
        domain: domainName,
        exportPath: 'diagnostics/modules.json',
        bodyExported: true,
        isFirstParty: classifyFirstParty(domainName, targetHostname),
        collectedAt: parseTimestampNumber(context.generatedAt)
      }));
    }
    if (context.includeNetworkReport) {
      items.push(compactManifestItem({
        id: 'network:report',
        source: SOURCE_LABELS.network,
        exportState: 'generated',
        skipReason: 'NONE',
        displayName: 'NETWORK_REPORT.json',
        type: 'Report',
        domain: domainName,
        exportPath: 'NETWORK_REPORT.json',
        bodyExported: true,
        isFirstParty: classifyFirstParty(domainName, targetHostname),
        collectedAt: parseTimestampNumber(context.generatedAt)
      }));
    }
    return items;
  }

  function buildManifestCoverageSummary(items) {
    const coverage = {
      totalObserved: items.length,
      totalExportedFiles: 0,
      totalMetadataOnly: 0,
      totalSkipped: 0,
      totalFailed: 0,
      bySource: {},
      byReason: {}
    };
    items.forEach(item => {
      const source = item.source || 'report';
      if (!coverage.bySource[source]) {
        coverage.bySource[source] = {
          observed: 0,
          exported: 0,
          metadataOnly: 0,
          inventoryOnly: 0,
          sanitized: 0,
          skipped: 0,
          failed: 0
        };
      }
      const bucket = coverage.bySource[source];
      bucket.observed++;
      coverage.byReason[item.skipReason || 'UNKNOWN'] = (coverage.byReason[item.skipReason || 'UNKNOWN'] || 0) + 1;

      if (item.exportPath && item.exportState !== 'metadata-only' && item.exportState !== 'skipped' && item.exportState !== 'failed') {
        coverage.totalExportedFiles++;
        bucket.exported++;
      }
      if (item.exportState === 'metadata-only') {
        coverage.totalMetadataOnly++;
        bucket.metadataOnly++;
      }
      if (item.exportState === 'inventory-only') {
        bucket.inventoryOnly++;
      }
      if (item.exportState === 'sanitized') {
        bucket.sanitized++;
      }
      if (item.exportState === 'skipped') {
        coverage.totalSkipped++;
        bucket.skipped++;
      }
      if (item.exportState === 'failed') {
        coverage.totalFailed++;
        bucket.failed++;
      }
    });
    return coverage;
  }

  function validateManifestConsistency({
    items,
    coverage,
    written,
    resources,
    networkEntries,
    includeCookiesReport,
    includeNetworkReport,
    includeApplicationReport,
    includeDiagnostics,
    includeFailedReport,
    includeLogsJson,
    includeCookieHtmlReport = false,
    includeManifestDetails = true
  }) {
    const errors = [];
    const warnings = [];
    const itemById = new Map(items.map(item => [item.id, item]));
    const paths = new Set(items.filter(item => item.exportPath).map(item => item.exportPath));

    written.forEach(file => {
      if (!items.some(item => item.exportPath === file.zipPath)) {
        errors.push(`Missing manifest item for written file ${file.zipPath}`);
      }
    });

    items.forEach(item => {
      if (item.exportState === 'exported' && !item.exportPath) {
        errors.push(`Exported item missing exportPath: ${item.id}`);
      }
      if (item.bodyExported === true && !item.exportPath) {
        errors.push(`bodyExported item missing exportPath: ${item.id}`);
      }
      if (!item.exportPath && item.skipReason === 'NONE' && item.exportState !== 'generated') {
        errors.push(`Non-generated item without exportPath must not use NONE: ${item.id}`);
      }
    });

    (resources || []).forEach(resource => {
      if (!itemById.has(resource.id)) {
        errors.push(`Observed resource missing manifest item: ${resource.id}`);
      }
    });

    (networkEntries || []).forEach(entry => {
      const item = itemById.get(entry.id);
      if (!item) {
        errors.push(`Network entry missing manifest item: ${entry.id}`);
        return;
      }
      if (item.source !== SOURCE_LABELS.network) {
        errors.push(`Network entry manifest source mismatch: ${entry.id}`);
      }
      if ((entry.zipPath || null) !== (item.exportPath || null) && !(entry.zipPath == null && item.exportPath == null)) {
        errors.push(`Network entry exportPath mismatch: ${entry.id}`);
      }
      if (entry.zipPath && item.exportState !== 'exported') {
        errors.push(`Network entry with bodyPath must be exported: ${entry.id}`);
      }
      if (!entry.zipPath && item.exportState === 'exported') {
        errors.push(`Network entry without bodyPath must not be exported: ${entry.id}`);
      }
    });

    const expectedReportPaths = new Set(['MANIFEST.json']);
    if (includeManifestDetails !== false) expectedReportPaths.add('MANIFEST_DETAILS.json');
    if (includeFailedReport) expectedReportPaths.add('FAILED_RESOURCES.json');
    if (includeDiagnostics && includeLogsJson) expectedReportPaths.add('logs.json');
    if (includeDiagnostics) {
      expectedReportPaths.add('diagnostics/target.json');
      expectedReportPaths.add('diagnostics/modules.json');
    }
    if (includeNetworkReport) expectedReportPaths.add('NETWORK_REPORT.json');
    if (includeCookiesReport) {
      expectedReportPaths.add('cookies/COOKIES_REPORT.json');
      expectedReportPaths.add('cookies/cookies.sanitized.json');
      if (includeCookieHtmlReport) expectedReportPaths.add('cookies/cookies.html');
      expectedReportPaths.add('cookies/cookies.netscape.sanitized.txt');
    }
    if (includeApplicationReport) {
      expectedReportPaths.add('application/APPLICATION_REPORT.json');
      expectedReportPaths.add('application/storage.sanitized.json');
      expectedReportPaths.add('application/indexeddb.inventory.json');
      expectedReportPaths.add('application/cache-storage.inventory.json');
    }
    expectedReportPaths.forEach(path => {
      if (!paths.has(path)) {
        warnings.push(`Expected generated exportPath is not represented in manifest items: ${path}`);
      }
    });

    const computedCoverage = buildManifestCoverageSummary(items);
    if (JSON.stringify(computedCoverage) !== JSON.stringify(coverage)) {
      errors.push('Coverage summary does not match manifest item counts.');
    }

    return {
      ok: errors.length === 0,
      errors,
      warnings
    };
  }

  function compactManifestItem(item) {
    const output = {
      id: item.id,
      source: item.source,
      exportState: item.exportState,
      skipReason: item.skipReason,
      displayName: item.displayName
    };
    optionalField(output, 'type', item.type);
    optionalField(output, 'url', item.url);
    optionalField(output, 'domain', item.domain);
    optionalField(output, 'path', item.path);
    output.exportPath = item.exportPath ?? null;
    optionalField(output, 'method', item.method);
    if (item.statusCode != null) output.statusCode = item.statusCode;
    optionalField(output, 'mimeType', item.mimeType);
    if (item.sizeBytes != null) output.sizeBytes = item.sizeBytes;
    if (item.bodySizeBytes != null) output.bodySizeBytes = item.bodySizeBytes;
    if (typeof item.bodyExported === 'boolean') output.bodyExported = item.bodyExported;
    if (typeof item.metadataOnly === 'boolean') output.metadataOnly = item.metadataOnly;
    if (typeof item.isFirstParty === 'boolean') output.isFirstParty = item.isFirstParty;
    if (item.capturedAt != null) output.capturedAt = item.capturedAt;
    if (item.collectedAt != null) output.collectedAt = item.collectedAt;
    if (Array.isArray(item.notes) && item.notes.length) output.notes = item.notes;
    return output;
  }

  function optionalField(target, key, value) {
    if (value !== undefined && value !== null && value !== '') {
      target[key] = value;
    }
  }

  function buildDisplayName({ exportPath, url, fallback }) {
    if (exportPath) {
      return basename(exportPath, fallback || 'item');
    }
    const pathname = getPathname(url);
    if (pathname) {
      return basename(pathname, fallback || 'item');
    }
    return fallback || 'item';
  }

  function getEvidenceSourceFromCollector(collector, id) {
    const value = String(collector || '').toLowerCase();
    const itemId = String(id || '').toLowerCase();
    if (value.includes('source')) return SOURCE_LABELS.sources;
    if (value.includes('network')) return SOURCE_LABELS.network;
    if (itemId.startsWith('src:')) return SOURCE_LABELS.sources;
    return SOURCE_LABELS.network;
  }

  function normalizeManifestExportState(source, resource, reason) {
    if (resource.exportStatus === 'written') return 'exported';
    if (resource.exportStatus === 'failed') return 'failed';
    if (resource.exportStatus === 'hidden_by_default') return 'skipped';
    if (resource.exportStatus === 'skipped') return 'skipped';
    if (source === SOURCE_LABELS.network) {
      if (reason === 'NO_RESPONSE_BODY' || reason === 'REDIRECT_NO_BODY' || reason === 'REQUEST_NOT_FINISHED') {
        return 'metadata-only';
      }
      if (reason === 'GET_CONTENT_FAILED' || reason === 'GET_CONTENT_TIMEOUT') {
        return resource.exportStatus === 'failed' ? 'failed' : 'failed';
      }
      if (reason === 'NONE') return 'exported';
      return 'skipped';
    }
    if (source === SOURCE_LABELS.sources) {
      if (reason === 'SOURCE_CONTENT_UNAVAILABLE') return 'metadata-only';
      if (reason === 'NONE') return 'exported';
      return resource.exportStatus === 'failed' ? 'failed' : 'skipped';
    }
    return 'metadata-only';
  }

  function normalizeManifestReason(source, rawReason, resource = {}) {
    if (rawReason == null || rawReason === '' || rawReason === 'written') return 'NONE';
    const value = String(rawReason).toUpperCase();
    const status = String(resource.bodyCaptureStatus || resource.exportStatus || '').toUpperCase();

    if (source === SOURCE_LABELS.network) {
      const map = {
        NONE: 'NONE',
        METADATA_ONLY: 'NO_RESPONSE_BODY',
        HAR_BODY_UNAVAILABLE: 'NO_RESPONSE_BODY',
        NO_RESPONSE_BODY: 'NO_RESPONSE_BODY',
        REDIRECT_NO_BODY: 'REDIRECT_NO_BODY',
        REQUEST_NOT_FINISHED: 'REQUEST_NOT_FINISHED',
        REQUEST_AFTER_STOP: 'REQUEST_AFTER_STOP',
        MIME_BLOCKED: 'MIME_NOT_ALLOWED',
        MIME_NOT_ALLOWED: 'MIME_NOT_ALLOWED',
        SIZE_LIMIT_EXCEEDED: 'SIZE_LIMIT_EXCEEDED',
        EXPORT_FILE_LIMIT_EXCEEDED: 'EXPORT_FILE_LIMIT_EXCEEDED',
        EXPORT_TOTAL_SIZE_LIMIT_EXCEEDED: 'EXPORT_TOTAL_SIZE_LIMIT_EXCEEDED',
        NETWORK_BODY_FILE_LIMIT_EXCEEDED: 'NETWORK_BODY_FILE_LIMIT_EXCEEDED',
        NETWORK_TOTAL_BODY_LIMIT_EXCEEDED: 'NETWORK_TOTAL_BODY_LIMIT_EXCEEDED',
        POLICY_BLOCKED: 'HIDDEN_BY_POLICY',
        HIDDEN_BY_DEFAULT_EXPORT_DISABLED: 'HIDDEN_BY_POLICY',
        HIDDEN_BY_POLICY: 'HIDDEN_BY_POLICY',
        PLATFORM_UNAVAILABLE: 'UNKNOWN',
        READ_FAILED: 'GET_CONTENT_FAILED',
        GET_CONTENT_FAILED: 'GET_CONTENT_FAILED',
        GET_CONTENT_TIMEOUT: 'GET_CONTENT_TIMEOUT',
        ENCODING_UNSUPPORTED: 'BINARY_BLOCKED',
        BINARY_BLOCKED: 'BINARY_BLOCKED',
        NETWORK_CAPTURED_BODY_MISSING: 'GET_CONTENT_FAILED',
        ZIP_WRITE_FAILED: 'UNKNOWN',
        UNKNOWN: 'UNKNOWN',
        METADATA_ONLY_NOT_WRITTEN: 'NO_RESPONSE_BODY'
      };
      return map[value] || map[status] || 'UNKNOWN';
    }

    if (source === SOURCE_LABELS.sources) {
      const map = {
        NONE: 'NONE',
        EMPTY_CONTENT: 'SOURCE_CONTENT_UNAVAILABLE',
        NOT_EXPORTABLE: 'SOURCE_CONTENT_UNAVAILABLE',
        EXPORTABLE_CONTENT_MISSING: 'SOURCE_CONTENT_UNAVAILABLE',
        SOURCE_CONTENT_UNAVAILABLE: 'SOURCE_CONTENT_UNAVAILABLE',
        HIDDEN_BY_DEFAULT_EXPORT_DISABLED: 'HIDDEN_BY_POLICY',
        HIDDEN_BY_POLICY: 'HIDDEN_BY_POLICY',
        STATIC_ASSET_DISABLED_BY_DEFAULT: 'STATIC_ASSET_DISABLED_BY_DEFAULT',
        MIME_NOT_ALLOWED: 'MIME_NOT_ALLOWED',
        SIZE_LIMIT_EXCEEDED: 'SIZE_LIMIT_EXCEEDED',
        EXPORT_FILE_LIMIT_EXCEEDED: 'EXPORT_FILE_LIMIT_EXCEEDED',
        EXPORT_TOTAL_SIZE_LIMIT_EXCEEDED: 'EXPORT_TOTAL_SIZE_LIMIT_EXCEEDED',
        SOURCE_FILE_LIMIT_EXCEEDED: 'SOURCE_FILE_LIMIT_EXCEEDED',
        SOURCE_TOTAL_SIZE_LIMIT_EXCEEDED: 'SOURCE_TOTAL_SIZE_LIMIT_EXCEEDED',
        DATA_URL_EXPORT_DISABLED: 'HIDDEN_BY_POLICY',
        DATA_URL_DECODE_FAILED: 'UNKNOWN',
        ZIP_WRITE_FAILED: 'UNKNOWN',
        UNKNOWN: 'UNKNOWN'
      };
      return map[value] || 'UNKNOWN';
    }

    return value || 'UNKNOWN';
  }

  function buildResourceNotes(source, resource, exportState) {
    const notes = [];
    if (resource.detail) notes.push(String(resource.detail));
    if (source === SOURCE_LABELS.network && exportState === 'metadata-only') {
      notes.push('Observed in Network, but no response body file was exported.');
    }
    if (source === SOURCE_LABELS.sources && exportState === 'metadata-only') {
      notes.push('Observed in Sources, but source content was unavailable for export.');
    }
    if (source === SOURCE_LABELS.sources && resource.reason === 'STATIC_ASSET_DISABLED_BY_DEFAULT') {
      notes.push('Static asset export is disabled by default in public v1.');
    }
    return notes;
  }

  function normalizeManifestType({ source, path, mimeType, rawType, displayName }) {
    const lowerPath = String(path || '').toLowerCase();
    const lowerMime = String(mimeType || '').toLowerCase();
    const lowerType = String(rawType || '').toLowerCase();
    const lowerName = String(displayName || '').toLowerCase();

    if (source === SOURCE_LABELS.report && lowerName === 'manifest.json') return 'Manifest';
    if (lowerPath.includes('indexeddb') || lowerName.includes('indexeddb')) return 'IndexedDB';
    if (lowerPath.includes('cache-storage') || lowerName.includes('cache-storage')) return 'Cache Storage';
    if (lowerPath.includes('service-worker') || lowerType.includes('serviceworker')) return 'Service Worker';
    if (lowerPath.includes('manifest') || lowerName.includes('manifest')) return 'Manifest';
    if (lowerPath.includes('_report.json') || lowerName.endsWith('_report.json') || lowerPath.endsWith('logs.json') || source === SOURCE_LABELS.report) return 'Report';
    if (lowerPath.includes('storage') || lowerType.includes('storage')) return 'Storage';
    if (lowerPath.includes('cookie') || lowerType.includes('cookie') || source === SOURCE_LABELS.cookies) return 'Cookie';
    if (lowerMime.includes('text/html') || lowerType === 'document') return 'Document';
    if (lowerMime.includes('javascript') || lowerMime.includes('ecmascript') || lowerType.includes('script') || lowerName.endsWith('.js')) return 'JavaScript';
    if (lowerMime.includes('text/css') || lowerName.endsWith('.css')) return 'Stylesheet';
    if (lowerMime.startsWith('image/')) return 'Image';
    if (lowerMime.startsWith('font/') || lowerMime.includes('woff') || lowerMime.includes('font')) return 'Font';
    if (lowerType.includes('xhr') || lowerType.includes('fetch')) return 'Fetch/XHR';
    return 'Other';
  }

  function classifyFirstParty(domainName, targetHostname) {
    const left = baseDomain(domainName);
    const right = baseDomain(targetHostname);
    if (!left || !right) return undefined;
    return left === right;
  }

  function baseDomain(hostname) {
    const value = String(hostname || '').toLowerCase().replace(/^\.+|\.+$/g, '');
    if (!value) return '';
    const parts = value.split('.').filter(Boolean);
    if (parts.length <= 2) return value;
    const last = parts[parts.length - 1];
    const second = parts[parts.length - 2];
    if (last.length === 2 && second.length <= 3 && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  function parseTimestampNumber(value) {
    if (!value) return undefined;
    const num = Date.parse(value);
    return Number.isFinite(num) ? num : undefined;
  }

  function numberOrUndefined(value) {
    return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
  }

  return {
    buildCurrentTotals,
    buildReasonGroupsForExport,
    buildCurrentManifest,
    buildCurrentManifestDetails,
    buildManifestCoverageSummary,
    validateManifestConsistency
  };
});
