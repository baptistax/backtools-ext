(function(root, factory) {
  const api = factory(root);
  root.BackToolsExport = Object.assign(root.BackToolsExport || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  let domain = root.BackToolsDomain || {};
  let exportApi = root.BackToolsExport || {};
  if (typeof require === 'function') {
    try {
      domain = Object.assign(
        {},
        require('../domain/pathHelpers.js'),
        require('../domain/pathPlanner.js'),
        require('../domain/redaction.js'),
        require('../domain/cookies.js'),
        require('../domain/application.js'),
        require('../domain/resourceClassification.js'),
        domain
      );
      exportApi = Object.assign(
        {},
        require('./zipWriterAdapter.js'),
        require('./manifestBuilder.js'),
        require('./reportBuilder.js'),
        exportApi
      );
    } catch {}
  }

  function isRawCookieExportEnabled(state) {
    const mode = state?.export?.options?.cookieExportMode;
    return state?.dumpObjectsEnabled === true && (mode === 'raw' || mode === 'raw_confirmed');
  }

  function isRawApplicationExportEnabled(_state) {
    return false;
  }

  function estimateSerializedBytes(value) {
    const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
    if (typeof TextEncoder === 'function') {
      return new TextEncoder().encode(text).length;
    }
    if (typeof Buffer !== 'undefined') {
      return Buffer.byteLength(text, 'utf8');
    }
    return text.length;
  }

  function replaceOversizedEntries(payload, maxBytes, notice) {
    if (!payload || !Array.isArray(payload.entries) || !maxBytes || maxBytes <= 0) {
      return payload;
    }
    const basePayload = {
      ...payload,
      entries: [],
      entriesIncluded: 0,
      entriesTruncated: Array.isArray(payload.entries) && payload.entries.length > 0,
      truncation: notice
    };
    if (estimateSerializedBytes(basePayload) > maxBytes) {
      return basePayload;
    }
    let low = 0;
    let high = payload.entries.length;
    while (low < high) {
      const mid = Math.ceil((low + high) / 2);
      const candidate = {
        ...basePayload,
        entries: payload.entries.slice(0, mid),
        entriesIncluded: mid,
        entriesTruncated: mid < payload.entries.length
      };
      if (estimateSerializedBytes(candidate) <= maxBytes) {
        low = mid;
      } else {
        high = mid - 1;
      }
    }
    return {
      ...basePayload,
      entries: payload.entries.slice(0, low),
      entriesIncluded: low,
      entriesTruncated: low < payload.entries.length
    };
  }

  function enforceJsonArtifactBudget(payload, { filePath, maxBytes, log, fallbackMode = 'truncate_entries' }) {
    if (!payload || !maxBytes || maxBytes <= 0) {
      return payload;
    }
    const currentBytes = estimateSerializedBytes(payload);
    if (currentBytes <= maxBytes) {
      return payload;
    }
    const notice = {
      warning: 'artifact_budget_exceeded',
      filePath,
      originalBytes: currentBytes,
      maxBytes
    };
    if (fallbackMode === 'truncate_entries' && Array.isArray(payload.entries)) {
      const truncated = replaceOversizedEntries(payload, maxBytes, notice);
      const nextBytes = estimateSerializedBytes(truncated);
      if (nextBytes <= maxBytes) {
        try {
          log('WARN', 'Artifact truncated to fit budget', `${filePath} ${currentBytes} -> ${nextBytes} bytes`);
        } catch {}
        return truncated;
      }
    }
    const fallback = {
      schemaVersion: payload.schemaVersion || 'backtools.artifact.notice.v1',
      reportProfile: payload.reportProfile || 'compact_notice',
      generatedAt: payload.generatedAt || new Date().toISOString(),
      inspectedUrl: payload.inspectedUrl || null,
      truncated: true,
      truncation: notice,
      message: `Artifact exceeded configured size budget and was compacted: ${filePath}`,
      summary: payload.totals || payload.summary || null
    };
    try {
      log('WARN', 'Artifact replaced with compact notice', `${filePath} ${currentBytes} -> ${estimateSerializedBytes(fallback)} bytes`);
    } catch {}
    return fallback;
  }

  function warnIfArtifactExceedsBytes(payload, { filePath, maxBytes, log }) {
    if (!payload || !maxBytes || maxBytes <= 0) {
      return;
    }
    const bytes = estimateSerializedBytes(payload);
    if (bytes > maxBytes) {
      try {
        log('WARN', 'Artifact exceeds recommended size', `${filePath} ${bytes} bytes > ${maxBytes} bytes`);
      } catch {}
    }
  }


  async function writeCurrentCaptureZip({ plan, state, log, ZipCtor, onProgress }) {
    const zip = new exportApi.ZipWriterAdapter(ZipCtor ? { JSZip: ZipCtor } : {});
    const written = [];
    const includeHumanSummary = state?.export?.options?.includeHumanSummary !== false;
    const includeNetworkReport = !!(state?.export?.options?.includeNetwork && state?.export?.options?.includeNetworkSummary !== false);
    const includeManifestDetails = state?.export?.options?.includeManifestDetails !== false;
    const budgets = plan?.budgets || {};
    const rawCookieScope = domain.summarizeRawCookieScope
      ? domain.summarizeRawCookieScope(state.cookies.observedCookies || [])
      : { rawCookieCount: 0, domains: [] };
    const includeRawCookieExport = isRawCookieExportEnabled(state)
      && rawCookieScope.rawCookieCount > 0;
    const rawApplicationScope = domain.summarizeRawApplicationScope
      ? domain.summarizeRawApplicationScope(state.application || {})
      : { rawStorageItemCount: 0, origins: [], storageTypes: [] };
    const includeRawApplicationExport = isRawApplicationExportEnabled(state)
      && rawApplicationScope.rawStorageItemCount > 0;
    const totalPlannedWrites = (plan?.plannedFiles?.length || 0)
      + (state?.export?.options?.includeCookiesReport ? (state?.export?.options?.includeCookieHtmlReport ? 4 : 3) : 0)
      + (includeRawCookieExport ? 2 : 0)
      + (includeNetworkReport ? 2 : 0)
      + (state?.export?.options?.includeApplication ? 4 : 0)
      + (includeRawApplicationExport ? 1 : 0)
      + 1
      + (includeManifestDetails ? 1 : 0)
      + (includeHumanSummary ? 1 : 0)
      + (state?.export?.options?.includeDiagnostics ? ((state?.export?.options?.includeLogsJson ? 1 : 0) + 2) : 0)
      + (state?.export?.options?.includeFailedReport && (plan?.failedResources?.length || 0) ? 1 : 0);
    let writeCount = 0;

    function reportProgress(phase, label, current = writeCount, total = totalPlannedWrites) {
      if (typeof onProgress === 'function') {
        try {
          onProgress({ phase, label, current, total });
        } catch {}
      }
    }

    reportProgress('Preparing export plan', 'Preparing export plan', 0, totalPlannedWrites);
    for (let i = 0; i < plan.plannedFiles.length; i++) {
      const p = plan.plannedFiles[i];
      try {
        if (p.isDataUrl) {
          p.zipPath = domain.buildSafeDataUrlZipPath
            ? domain.buildSafeDataUrlZipPath(p.resource, i, p.mimeType)
            : await domain.buildCurrentDataUrlZipPath(p.resource, i, p.mimeType);
          await zip.add(p.zipPath, exportApi.bytesInput(p.bytes), { mimeType: p.mimeType || undefined });
        } else {
          p.zipPath = p.isNetworkBody && domain.buildSafeZipPath
            ? domain.buildSafeZipPath(p.resource, { mimeType: p.mimeType || p.resource.mimeType })
            : domain.buildSafeSourceZipPath
              ? domain.buildSafeSourceZipPath(p.resource)
            : domain.buildCurrentSourceZipPath(p.resource);
          if (p.encoding === 'base64') await zip.add(p.zipPath, exportApi.base64Input(p.content), { mimeType: p.mimeType || undefined });
          else await zip.add(p.zipPath, exportApi.textInput(p.content), { mimeType: p.mimeType || undefined });
        }
        const urlInfo = domain.redactUrlWithMetadata
          ? domain.redactUrlWithMetadata(p.resource.url || '')
          : { value: p.resource.url, redacted: false, hash: null };
        written.push({
          id: p.resource.id,
          originalUrl: urlInfo.value,
          originalUrlRedacted: urlInfo.value,
          urlHash: p.resource.urlHash || urlInfo.hash,
          zipPath: p.zipPath,
          type: p.resource.type,
          mimeType: p.mimeType || null,
          size: p.resource.bodyCapturedBytes || p.resource.size || p.bytes?.length || 0,
          collector: p.resource.collector,
          contentKind: p.contentKind,
          resourceCategory: p.resource.resourceCategory || null,
          visibleByDefault: p.resource.visibleByDefault !== false,
          hiddenByDefaultReason: p.resource.hiddenByDefaultReason || null,
          userIncludedAdvanced: domain.getResourceUserIncludedAdvanced
            ? domain.getResourceUserIncludedAdvanced(p.resource, state.export.options)
            : false,
          exportStatus: 'written',
          redactionApplied: !!(p.resource.redactionApplied || urlInfo.redacted),
          redactedFields: p.resource.redactedFields || (urlInfo.redacted ? ['url.query'] : []),
          bodyCaptureStatus: p.resource.bodyCaptureStatus || undefined,
          bodyCapturedBytes: p.resource.bodyCapturedBytes || 0,
          bodySizeBytes: p.resource.bodySizeBytes ?? p.resource.bodyCapturedBytes ?? 0,
          bodyEncoding: p.resource.bodyEncoding || p.resource.encoding || undefined,
          bodyRenderStatus: p.resource.bodyRenderStatus || undefined,
          bodyExportStatus: p.resource.bodyExportStatus || undefined,
          bodyRedactionApplied: !!p.resource.bodyRedactionApplied
        });
        writeCount++;
        reportProgress(
          p.isNetworkBody ? 'Writing network files' : 'Writing source files',
          `Writing ${writeCount}/${totalPlannedWrites} files`,
          writeCount,
          totalPlannedWrites
        );
        log('INFO', 'Export file written', `${p.zipPath}`);
      } catch (e) {
        plan.failedResources.push({
          id: p.resource.id,
          url: p.resource.url,
          collector: p.resource.collector,
          reason: 'ZIP_WRITE_FAILED',
          detail: String(e)
        });
        log('ERROR', 'Export file failed', `${domain.redactUrl ? domain.redactUrl(p.resource.url || '') : p.resource.url} ZIP_WRITE_FAILED`);
      }
    }

    const generatedAt = new Date().toISOString();
    const targetMetadata = state.target?.analyzed || state.target?.current || null;
    const moduleStatuses = state.target?.moduleStatuses || {};
    const includeApplicationReport = !!state.export.options.includeApplication;
    const objectDumpEnabled = state.dumpObjectsEnabled === true;
    const objectDumpMetadata = {
      dumpObjectsEnabled: objectDumpEnabled,
      cookieValueMode: isRawCookieExportEnabled(state) ? 'raw' : 'protected',
      applicationValueMode: isRawApplicationExportEnabled(state) ? 'raw' : 'protected',
      cookiesTotal: state.cookies.summary?.observedCookies || 0,
      cookiesRawVisible: isRawCookieExportEnabled(state) ? rawCookieScope.rawCookieCount : 0,
      applicationItemsTotal: state.application.summary?.storageItems || 0,
      applicationRawVisible: 0
    };
    objectDumpMetadata.applicationRawVisible = isRawApplicationExportEnabled(state) ? rawApplicationScope.rawStorageItemCount : 0;
    const writtenNetworkBodyById = indexWrittenNetworkBodies(written);
    const networkEntriesForReport = (state.network.entries || []).map(row => {
      const bodyFile = writtenNetworkBodyById.get(row.id);
      return compactNetworkEntryForReports(row, bodyFile?.zipPath || null);
    });
    const networkReportInput = {
      generatedAt,
      analyzedUrl: state.target.analyzedUrl,
      policy: state.network.policy || {},
      entries: networkEntriesForReport
    };
    const networkReport = includeNetworkReport
      ? enforceJsonArtifactBudget(exportApi.buildCurrentNetworkReport(networkReportInput), {
          filePath: 'NETWORK_REPORT.json',
          maxBytes: budgets.maxNetworkReportBytes,
          log,
          fallbackMode: 'truncate_entries'
        })
      : null;
    const networkDetailsReport = includeNetworkReport && exportApi.buildCurrentNetworkDetailsReport
      ? enforceJsonArtifactBudget(exportApi.buildCurrentNetworkDetailsReport(networkReportInput), {
          filePath: 'network/NETWORK_DETAILS.json',
          maxBytes: budgets.maxNetworkReportBytes,
          log,
          fallbackMode: 'truncate_entries'
        })
      : null;
    const cookieReportInput = {
      generatedAt,
      analyzedUrl: state.target.analyzedUrl,
      policy: state.cookies.policy,
      summary: state.cookies.summary,
      observedCookies: state.cookies.observedCookies,
      findings: state.cookies.findings,
      rawRecords: state.cookies.rawRecords,
      rawExport: {
        included: includeRawCookieExport,
        confirmedAt: includeRawCookieExport ? state.dumpObjectsEnabledAt || generatedAt : null,
        scope: rawCookieScope
      }
    };
    const cookiesReport = state.export.options.includeCookiesReport
      ? enforceJsonArtifactBudget(exportApi.buildCurrentCookiesReport(cookieReportInput), {
          filePath: 'cookies/COOKIES_REPORT.json',
          maxBytes: budgets.maxCookieReportBytes,
          log,
          fallbackMode: 'truncate_entries'
        })
      : null;
    const cookiesSanitizedJson = state.export.options.includeCookiesReport
      ? exportApi.buildCurrentCookiesSanitizedJson(cookieReportInput)
      : null;
    const applicationReportInput = {
      generatedAt,
      analyzedUrl: state.target.analyzedUrl,
      application: state.application,
      cookiesSummary: state.cookies.summary,
      rawExport: {
        included: includeRawApplicationExport,
        confirmedAt: includeRawApplicationExport ? state.dumpObjectsEnabledAt || generatedAt : null,
        scope: rawApplicationScope
      }
    };
    const applicationReport = includeApplicationReport
      ? enforceJsonArtifactBudget(exportApi.buildCurrentApplicationReport(applicationReportInput), {
          filePath: 'application/APPLICATION_REPORT.json',
          maxBytes: budgets.maxApplicationReportBytes,
          log,
          fallbackMode: 'truncate_entries'
        })
      : null;
    const applicationStorageSanitizedJson = includeApplicationReport
      ? exportApi.buildCurrentApplicationStorageSanitizedJson(applicationReportInput)
      : null;
    const applicationIndexedDbInventoryJson = includeApplicationReport
      ? exportApi.buildCurrentApplicationIndexedDbInventoryJson(applicationReportInput)
      : null;
    const applicationCacheStorageInventoryJson = includeApplicationReport
      ? exportApi.buildCurrentApplicationCacheStorageInventoryJson(applicationReportInput)
      : null;
    const manifest = exportApi.buildCurrentManifest({
      generatedAt,
      analyzedUrl: state.target.analyzedUrl,
      exportOptions: state.export.options,
      plan,
      written,
      cookiesSummary: state.cookies.summary,
      includeCookiesReport: state.export.options.includeCookiesReport,
      cookieExport: {
        containsRawCookies: includeRawCookieExport,
        containsReplayableCookieJar: includeRawCookieExport,
        rawCookieExportConfirmedAt: includeRawCookieExport ? state.dumpObjectsEnabledAt || generatedAt : null,
        rawCookieExportScope: rawCookieScope
      },
      networkSummary: networkReport?.totals || null,
      includeNetworkReport,
      applicationSummary: state.application?.summary || null,
      includeApplicationReport,
      applicationExport: {
        containsRawApplicationData: includeRawApplicationExport,
        rawApplicationExportConfirmedAt: includeRawApplicationExport ? state.dumpObjectsEnabledAt || generatedAt : null,
        rawApplicationExportScope: rawApplicationScope
      },
      objectDump: objectDumpMetadata,
      target: targetMetadata,
      moduleStatuses,
      networkEntries: networkEntriesForReport,
      sourcesResources: state.sources?.resources || [],
      application: state.application || null,
      includeDiagnostics: !!state.export.options.includeDiagnostics,
      includeFailedReport: !!state.export.options.includeFailedReport,
      includeLogsJson: !!state.export.options.includeLogsJson,
      includeCookieHtmlReport: !!state.export.options.includeCookieHtmlReport
    });
    const manifestDetails = includeManifestDetails && exportApi.buildCurrentManifestDetails
      ? exportApi.buildCurrentManifestDetails({
        generatedAt,
        analyzedUrl: state.target.analyzedUrl,
        manifest,
        plan,
        written,
        networkEntries: networkEntriesForReport,
        sourcesResources: state.sources?.resources || []
      })
      : null;
    const captureSummary = includeHumanSummary && exportApi.buildCurrentCaptureSummary
      ? exportApi.buildCurrentCaptureSummary({
        generatedAt,
        analyzedUrl: state.target.analyzedUrl,
        manifest,
        networkReport,
        cookiesReport,
        applicationReport,
        objectDump: objectDumpMetadata
      })
      : null;

    if (manifest.validation?.warnings?.length) {
      for (const message of manifest.validation.warnings) {
        log('WARN', 'Manifest validation warning', message);
      }
    }
    if (manifest.validation?.errors?.length) {
      for (const message of manifest.validation.errors) {
        log('WARN', 'Manifest validation error', message);
      }
    }

    reportProgress('Writing manifest', 'Writing manifest', writeCount, totalPlannedWrites);
    await zip.add('MANIFEST.json', exportApi.jsonInput(manifest));
    writeCount++;
    if (manifestDetails) {
      await zip.add('MANIFEST_DETAILS.json', exportApi.jsonInput(manifestDetails));
      writeCount++;
    }
    if (captureSummary) {
      await zip.add('CAPTURE_SUMMARY.md', exportApi.textInput(captureSummary), { mimeType: 'text/markdown' });
      writeCount++;
    }
    if (state.export.options.includeFailedReport && plan.failedResources.length) {
      await zip.add('FAILED_RESOURCES.json', exportApi.jsonInput(plan.failedResources));
      writeCount++;
    }
    if (state.export.options.includeDiagnostics && state.export.options.includeLogsJson) {
      reportProgress('Writing diagnostics', `Writing ${writeCount}/${totalPlannedWrites} files`, writeCount, totalPlannedWrites);
      const diagnosticsPayload = exportApi.buildDiagnosticsDownloadPayload
        ? exportApi.buildDiagnosticsDownloadPayload(state.diagnostics.logs, state.diagnostics.reasonGroups || {}, objectDumpMetadata)
        : { metadata: { objectDump: objectDumpMetadata }, logs: state.diagnostics.logs, reasons: state.diagnostics.reasonGroups || {} };
      await zip.add('logs.json', exportApi.jsonInput(diagnosticsPayload));
      writeCount++;
    }
    if (state.export.options.includeDiagnostics) {
      await zip.add('diagnostics/target.json', exportApi.jsonInput(targetMetadata || {}));
      writeCount++;
      await zip.add('diagnostics/modules.json', exportApi.jsonInput(moduleStatuses || {}));
      writeCount++;
    }
    if (state.export.options.includeCookiesReport) {
      reportProgress('Writing cookie reports', `Writing ${writeCount}/${totalPlannedWrites} files`, writeCount, totalPlannedWrites);
      await zip.add('cookies/COOKIES_REPORT.json', exportApi.jsonInput(cookiesReport));
      writeCount++;
      await zip.add('cookies/cookies.sanitized.json', exportApi.jsonInput(cookiesSanitizedJson));
      writeCount++;
      if (state.export.options.includeCookieHtmlReport) {
        await zip.add('cookies/cookies.html', exportApi.textInput(exportApi.buildCurrentCookiesHtml(cookieReportInput)), { mimeType: 'text/html' });
        writeCount++;
      }
      await zip.add('cookies/cookies.netscape.sanitized.txt', exportApi.textInput(exportApi.buildCurrentNetscapeSanitized(cookieReportInput)), { mimeType: 'text/plain' });
      writeCount++;
      if (includeRawCookieExport) {
        const rawInput = {
          generatedAt,
          analyzedUrl: state.target.analyzedUrl,
          observedCookies: state.cookies.observedCookies,
          confirmedAt: state.dumpObjectsEnabledAt || generatedAt,
          scope: rawCookieScope
        };
        await zip.add('cookies/cookies.raw.json', exportApi.jsonInput(exportApi.buildCurrentRawCookiesJson(rawInput)));
        writeCount++;
        await zip.add('cookies/cookies.raw.netscape.txt', exportApi.textInput(exportApi.buildCurrentRawNetscapeCookies(rawInput)), { mimeType: 'text/plain' });
        writeCount++;
        log('INFO', 'Raw cookie export included', `Raw cookies: ${rawCookieScope.rawCookieCount}; domains: ${rawCookieScope.domains.join(', ') || 'none'}`);
      }
    }
    if (networkReport) {
      reportProgress('Writing network files', `Writing ${writeCount}/${totalPlannedWrites} files`, writeCount, totalPlannedWrites);
      await zip.add('NETWORK_REPORT.json', exportApi.jsonInput(networkReport));
      writeCount++;
      if (networkDetailsReport) {
        await zip.add('network/NETWORK_DETAILS.json', exportApi.jsonInput(networkDetailsReport));
        writeCount++;
      }
    }
    if (includeApplicationReport) {
      reportProgress('Writing application reports', `Writing ${writeCount}/${totalPlannedWrites} files`, writeCount, totalPlannedWrites);
      await zip.add('application/APPLICATION_REPORT.json', exportApi.jsonInput(applicationReport));
      writeCount++;
      await zip.add('application/storage.sanitized.json', exportApi.jsonInput(applicationStorageSanitizedJson));
      writeCount++;
      await zip.add('application/indexeddb.inventory.json', exportApi.jsonInput(applicationIndexedDbInventoryJson));
      writeCount++;
      await zip.add('application/cache-storage.inventory.json', exportApi.jsonInput(applicationCacheStorageInventoryJson));
      writeCount++;
      if (includeRawApplicationExport) {
        await zip.add('application/storage.raw.json', exportApi.jsonInput(exportApi.buildCurrentApplicationRawStorageJson({
          ...applicationReportInput,
          confirmedAt: state.dumpObjectsEnabledAt || generatedAt,
          scope: rawApplicationScope
        })));
        writeCount++;
        log('INFO', 'Raw application storage export included', `Storage values: ${rawApplicationScope.rawStorageItemCount}; origins: ${rawApplicationScope.origins.join(', ') || 'none'}`);
      }
    }

    const totals = manifest.totals;
    log('INFO', 'Export counts', `planned ${totals.plannedFiles}, written ${totals.writtenFiles}, manifest-only ${totals.manifestOnlyEntries}, skipped ${totals.skippedEntries}, failed ${totals.failedEntries}`);
    reportProgress('Generating ZIP', 'Generating ZIP', writeCount, totalPlannedWrites);
    const blob = await zip.generateBlob();
    reportProgress('Download ready', 'Download ready', writeCount, totalPlannedWrites);
    return { blob, totals, written, manifest };
  }

  function indexWrittenNetworkBodies(written) {
    const byId = new Map();
    for (const file of written) {
      if (file.collector === 'network_har' && !byId.has(file.id)) {
        byId.set(file.id, file);
      }
    }
    return byId;
  }

  function compactNetworkEntryForReports(row, zipPath) {
    return {
      id: row?.id,
      url: row?.url || '',
      urlRedacted: row?.urlRedacted || row?.url || '',
      urlHash: row?.urlHash || null,
      method: row?.method || null,
      statusCode: row?.statusCode ?? row?.status ?? null,
      mimeType: row?.mimeType || row?.bodyMimeType || null,
      type: row?.type || null,
      host: row?.host || null,
      startedDateTime: row?.startedDateTime || null,
      size: row?.size ?? null,
      bodySize: row?.bodySize ?? null,
      bodyCaptureStatus: row?.bodyCaptureStatus || row?.status || 'metadata_only',
      bodyCaptureReason: row?.bodyCaptureReason || row?.reason || null,
      bodyCapturedBytes: row?.bodyCapturedBytes || 0,
      bodySizeBytes: row?.bodySizeBytes ?? row?.bodyCapturedBytes ?? 0,
      bodyEncoding: row?.bodyEncoding || row?.encoding || null,
      bodyRenderStatus: row?.bodyRenderStatus || null,
      bodyExportStatus: row?.bodyExportStatus || null,
      bodyRedactionApplied: !!row?.bodyRedactionApplied,
      requestHeadersRedacted: row?.requestHeadersRedacted || undefined,
      responseHeadersRedacted: row?.responseHeadersRedacted || undefined,
      resourceCategory: row?.resourceCategory || null,
      visibleByDefault: row?.visibleByDefault !== false,
      hiddenByDefaultReason: row?.hiddenByDefaultReason || null,
      redactionApplied: !!row?.redactionApplied,
      redactedFields: row?.redactedFields || [],
      zipPath: zipPath || null
    };
  }

  return { writeCurrentCaptureZip };
});
