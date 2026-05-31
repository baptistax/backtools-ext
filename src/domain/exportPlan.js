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
        require('./normalize.js'),
        require('./redaction.js'),
        require('./resourceClassification.js'),
        domain
      );
    } catch {}
  }

  const DEFAULT_EXPORT_BUDGETS = {
    maxObservedItemsForUiRender: 2000,
    maxExportedFiles: 1100,
    maxTotalZipInputBytes: 110 * 1024 * 1024,

    maxSourceCodeFiles: 500,
    maxNetworkCodeBodyFiles: 500,
    maxTotalSourceCodeBytes: 50 * 1024 * 1024,
    maxTotalNetworkCodeBytes: 50 * 1024 * 1024,

    maxStaticAssetFiles: 50,
    maxTotalStaticAssetBytes: 10 * 1024 * 1024,

    maxSingleTextFileBytes: 5 * 1024 * 1024,
    maxSingleBinaryFileBytes: 1 * 1024 * 1024,

    maxCookieReportBytes: 2 * 1024 * 1024,
    maxApplicationReportBytes: 5 * 1024 * 1024,
    maxNetworkReportBytes: 10 * 1024 * 1024,
    maxManifestBytesWarning: 10 * 1024 * 1024
  };

  function buildExportPlanFromStateLike(input) {
    const sourcesState = input.sources || { resources: [] };
    const networkState = input.network || { entries: [] };
    const exportState = input.export || { options: {} };
    return buildExportPlan({
      sources: sourcesState.resources || [],
      network: networkState.entries || [],
      options: exportState.options || {}
    });
  }

  function buildExportPlan({ sources = [], network = [], options = {} }) {
    const budgets = normalizeExportBudgets(options.exportBudgets);
    const plan = {
      plannedFiles: [],
      manifestOnlyResources: [],
      skippedResources: [],
      failedResources: [],
      resources: [],
      budgets,
      budgetSummary: {
        totalFiles: 0,
        totalInputBytes: 0,
        sourceFiles: 0,
        totalSourceBytes: 0,
        networkBodyFiles: 0,
        totalNetworkBodyBytes: 0,
        sourceCodeFiles: 0,
        totalSourceCodeBytes: 0,
        networkCodeBodyFiles: 0,
        totalNetworkCodeBytes: 0,
        staticAssetFiles: 0,
        totalStaticAssetBytes: 0
      },
      counts: {
        plannedFiles: 0,
        dataUrlFiles: 0,
        sourceFiles: 0,
        networkBodyFiles: 0,
        networkMetadataOnly: 0,
        networkReportFiles: 0,
        diagnosticsFiles: 0,
        manifestFiles: 1,
        excludedResources: 0,
        hiddenByDefault: 0
      }
    };
    const allRows = [...sources, ...network];
    plan.resources = allRows.map(resourceToPlanRecord);
    plan.counts.hiddenByDefault = plan.resources.filter(r => r.visibleByDefault === false).length;

    const addFail = (resource, reason, detail = null) => {
      plan.failedResources.push({
        ...resourceToManifestRecord(resource, options),
        reason,
        detail,
        exportStatus: 'failed'
      });
    };

    const addSkipped = (resource, reason) => {
      plan.skippedResources.push({
        ...resourceToManifestRecord(resource, options),
        reason,
        exportStatus: 'skipped'
      });
    };

    const addManifestOnly = (resource, reason, exportStatus = 'metadata_only') => {
      plan.manifestOnlyResources.push({
        ...resourceToManifestRecord(resource, options),
        reason,
        exportStatus
      });
    };

    const totalObservedItems = allRows.length;
    if (totalObservedItems > budgets.maxObservedItemsForUiRender) {
      plan.budgetSummary.observedItemsCappedForUi = totalObservedItems;
    }

    if (options.includeSources === false) {
      for (const resource of sources) {
        addManifestOnly(resource, 'HIDDEN_BY_POLICY', 'skipped');
        plan.counts.excludedResources++;
      }
    } else {
      for (const resource of sortResourcesForExport(sources)) {
        if (domain.isIncludedByExportPolicy && !domain.isIncludedByExportPolicy(resource, options)) {
          addManifestOnly(resource, 'HIDDEN_BY_DEFAULT_EXPORT_DISABLED', 'hidden_by_default');
          plan.counts.excludedResources++;
          continue;
        }

        if (!resource.exportable) {
          addSkipped(resource, resource.reason || 'EMPTY_CONTENT');
          plan.counts.excludedResources++;
          continue;
        }

        if (isDataUrlResource(resource)) {
          if (!options.includeDataUrls) {
            addSkipped(resource, 'DATA_URL_EXPORT_DISABLED');
            plan.counts.excludedResources++;
            continue;
          }
          const decoded = domain.decodeDataUrl ? domain.decodeDataUrl(resource.url) : { ok: false };
          if (!decoded.ok) {
            addFail(resource, 'DATA_URL_DECODE_FAILED');
            continue;
          }
          const decodedResource = {
            ...resource,
            mimeType: decoded.mimeType || resource.mimeType,
            contentKind: decoded.contentKind,
            encoding: decoded.contentKind === 'binary_base64' ? 'base64' : resource.encoding
          };
          const staticDecision = evaluateSourceStaticPolicy(decodedResource, options);
          if (!staticDecision.allowed) {
            addSkipped(resource, staticDecision.reason);
            plan.counts.excludedResources++;
            continue;
          }
          const dataUrlBytes = decoded.bytes?.length || 0;
          const budgetReason = consumeBudget(plan, budgets, getBudgetFamily(decodedResource, 'source'), dataUrlBytes);
          if (budgetReason) {
            addSkipped(resource, budgetReason);
            plan.counts.excludedResources++;
            continue;
          }
          plan.plannedFiles.push({
            resource: decodedResource,
            zipPath: null,
            bytes: decoded.bytes,
            mimeType: decoded.mimeType,
            contentKind: decoded.contentKind,
            isDataUrl: true
          });
          plan.counts.dataUrlFiles++;
          continue;
        }

        const staticDecision = evaluateSourceStaticPolicy(resource, options);
        if (!staticDecision.allowed) {
          addSkipped(resource, staticDecision.reason);
          plan.counts.excludedResources++;
          continue;
        }

        const sourceBytes = estimateSourceBytes(resource);
        const budgetReason = consumeBudget(plan, budgets, getBudgetFamily(resource, 'source'), sourceBytes);
        if (budgetReason) {
          addSkipped(resource, budgetReason);
          plan.counts.excludedResources++;
          continue;
        }

        plan.plannedFiles.push({
          resource,
          zipPath: null,
          content: resource.content,
          encoding: resource.encoding,
          mimeType: sourceMimeHint(resource),
          contentKind: resource.encoding === 'base64' ? 'binary_base64' : 'text_utf8',
          isDataUrl: false
        });
        plan.counts.sourceFiles++;
      }
    }

    if (options.includeNetwork === false) {
      for (const resource of network) {
        addManifestOnly(resource, 'HIDDEN_BY_POLICY', 'skipped');
        plan.counts.networkMetadataOnly++;
      }
    } else {
      for (const resource of sortResourcesForExport(network)) {
        if (domain.isIncludedByExportPolicy && !domain.isIncludedByExportPolicy(resource, options)) {
          addManifestOnly(resource, 'HIDDEN_BY_DEFAULT_EXPORT_DISABLED', 'hidden_by_default');
          plan.counts.networkMetadataOnly++;
          continue;
        }

        if ((resource.bodyCaptureStatus || resource.status) === 'body_captured') {
          if (typeof resource.content !== 'string') {
            addFail(resource, 'NETWORK_CAPTURED_BODY_MISSING');
            continue;
          }
          const staticDecision = evaluateNetworkStaticPolicy(resource, options);
          if (!staticDecision.allowed) {
            addSkipped(resource, staticDecision.reason);
            plan.counts.networkMetadataOnly++;
            continue;
          }
          const networkBytes = estimateNetworkBytes(resource);
          const budgetReason = consumeBudget(plan, budgets, getBudgetFamily(resource, 'network'), networkBytes);
          if (budgetReason) {
            addSkipped(resource, budgetReason);
            plan.counts.networkMetadataOnly++;
            continue;
          }
          plan.plannedFiles.push({
            resource,
            zipPath: null,
            content: resource.content,
            encoding: resource.encoding,
            mimeType: resource.mimeType || resource.bodyMimeType || null,
            contentKind: resource.contentKind || (resource.encoding === 'base64' ? 'binary_base64' : 'text_utf8'),
            isDataUrl: false,
            isNetworkBody: true
          });
          plan.counts.networkBodyFiles++;
          continue;
        }

        addManifestOnly(
          resource,
          resource.bodyCaptureReason || resource.reason || 'METADATA_ONLY_NOT_WRITTEN',
          resource.bodyCaptureStatus || resource.status || 'metadata_only'
        );
        plan.counts.networkMetadataOnly++;
      }
    }

    if (options.includeNetwork && options.includeNetworkSummary !== false) plan.counts.networkReportFiles = 1;
    if (options.includeDiagnostics) plan.counts.diagnosticsFiles = (options.includeLogsJson ? 1 : 0) + 2;
    plan.counts.plannedFiles = plan.plannedFiles.length;
    return plan;
  }

  function resourceToPlanRecord(resource) {
    return {
      id: resource.id,
      url: resource.url,
      urlRedacted: resource.urlRedacted || (domain.redactUrl ? domain.redactUrl(resource.url || '') : resource.url),
      urlHash: resource.urlHash || (domain.hashSensitiveValue ? domain.hashSensitiveValue(resource.url || '') : null),
      collector: resource.collector,
      resourceCategory: resource.resourceCategory || domain.ResourceCategory?.UNKNOWN || 'unknown',
      visibleByDefault: resource.visibleByDefault !== false,
      hiddenByDefaultReason: resource.hiddenByDefaultReason || null,
      redactionApplied: !!resource.redactionApplied,
      redactedFields: resource.redactedFields || [],
      bodyCaptureStatus: resource.bodyCaptureStatus || undefined,
      bodyCaptureReason: resource.bodyCaptureReason || resource.reason || undefined,
      bodyCapturedBytes: resource.bodyCapturedBytes || 0,
      bodySizeBytes: resource.bodySizeBytes ?? resource.bodyCapturedBytes ?? 0,
      bodyEncoding: resource.bodyEncoding || resource.encoding || undefined,
      bodyRenderStatus: resource.bodyRenderStatus || undefined,
      bodyExportStatus: resource.bodyExportStatus || undefined
    };
  }

  function resourceToManifestRecord(resource, options) {
    return {
      ...resourceToPlanRecord(resource),
      requestHeaders: resource.requestHeadersRedacted || undefined,
      responseHeaders: resource.responseHeadersRedacted || undefined,
      bodyRedactionApplied: !!resource.bodyRedactionApplied,
      userIncludedAdvanced: domain.getResourceUserIncludedAdvanced ? domain.getResourceUserIncludedAdvanced(resource, options) : false,
      mimeType: resource.mimeType || sourceMimeHint(resource) || undefined,
      type: resource.type || undefined,
      size: resource.size ?? undefined,
      startedDateTime: resource.startedDateTime || undefined,
      collectedAt: resource.collectedAt || undefined
    };
  }

  function normalizeExportBudgets(value = {}) {
    const input = value || {};
    const merged = { ...DEFAULT_EXPORT_BUDGETS, ...input };

    merged.maxSourceCodeFiles = normalizePositiveNumber(
      input.maxSourceCodeFiles ?? input.maxSourceFiles,
      DEFAULT_EXPORT_BUDGETS.maxSourceCodeFiles
    );
    merged.maxNetworkCodeBodyFiles = normalizePositiveNumber(
      input.maxNetworkCodeBodyFiles ?? input.maxNetworkBodyFiles,
      DEFAULT_EXPORT_BUDGETS.maxNetworkCodeBodyFiles
    );
    merged.maxTotalSourceCodeBytes = normalizePositiveNumber(
      input.maxTotalSourceCodeBytes ?? input.maxTotalSourceBytes,
      DEFAULT_EXPORT_BUDGETS.maxTotalSourceCodeBytes
    );
    merged.maxTotalNetworkCodeBytes = normalizePositiveNumber(
      input.maxTotalNetworkCodeBytes ?? input.maxTotalNetworkBodyBytes,
      DEFAULT_EXPORT_BUDGETS.maxTotalNetworkCodeBytes
    );
    merged.maxSingleTextFileBytes = normalizePositiveNumber(
      input.maxSingleTextFileBytes ?? input.maxSingleFileBytes,
      DEFAULT_EXPORT_BUDGETS.maxSingleTextFileBytes
    );
    merged.maxSingleBinaryFileBytes = normalizePositiveNumber(
      input.maxSingleBinaryFileBytes ?? input.maxSingleFileBytes,
      DEFAULT_EXPORT_BUDGETS.maxSingleBinaryFileBytes
    );

    merged.maxSourceFiles = merged.maxSourceCodeFiles;
    merged.maxNetworkBodyFiles = merged.maxNetworkCodeBodyFiles;
    merged.maxTotalSourceBytes = merged.maxTotalSourceCodeBytes;
    merged.maxTotalNetworkBodyBytes = merged.maxTotalNetworkCodeBytes;
    merged.maxSingleFileBytes = Math.max(merged.maxSingleTextFileBytes, merged.maxSingleBinaryFileBytes);

    return Object.fromEntries(Object.entries(merged).map(([key, current]) => [
      key,
      normalizePositiveNumber(current, DEFAULT_EXPORT_BUDGETS[key] ?? current)
    ]));
  }

  function normalizePositiveNumber(value, fallback) {
    const number = Number(value);
    return Number.isFinite(number) && number > 0 ? number : fallback;
  }

  function isDataUrlResource(resource) {
    return String(resource?.url || '').startsWith('data:');
  }

  function sourceMimeHint(resource) {
    const url = String(resource?.url || '').toLowerCase();
    const rawType = String(resource?.type || '').toLowerCase();
    if (rawType === 'document' || /\.html?($|\?)/.test(url)) return 'text/html';
    if (rawType === 'script' || /\.(mjs|cjs|js|jsx)($|\?)/.test(url)) return 'application/javascript';
    if (/\.(ts|tsx)($|\?)/.test(url)) return 'text/typescript';
    if (rawType === 'stylesheet' || /\.css($|\?)/.test(url)) return 'text/css';
    if (/\.(scss|sass)($|\?)/.test(url)) return 'text/x-scss';
    if (/\.map($|\?)/.test(url)) return 'application/source-map';
    if (rawType === 'json' || /\.(json|jsonld)($|\?)/.test(url)) return 'application/json';
    if (/\.svg($|\?)/.test(url)) return 'image/svg+xml';
    if (/\.xml($|\?)/.test(url)) return 'application/xml';
    if (/\.txt($|\?)/.test(url)) return 'text/plain';
    if (/\.webmanifest($|\?)/.test(url)) return 'application/manifest+json';
    if (/\.wasm($|\?)/.test(url)) return 'application/wasm';
    if (/\.(png|jpe?g|gif|webp|ico|bmp|avif)($|\?)/.test(url)) return 'image/*';
    if (/\.(woff2?|ttf|otf|eot)($|\?)/.test(url)) return 'font/*';
    if (/\.(mp4|webm|m4v|mov|avi|mkv)($|\?)/.test(url)) return 'video/*';
    if (/\.(mp3|wav|ogg|m4a|aac|flac)($|\?)/.test(url)) return 'audio/*';
    return null;
  }

  function classifySourceKind(resource) {
    const url = String(resource?.url || '').toLowerCase();
    const mimeType = String(resource?.mimeType || sourceMimeHint(resource) || '').toLowerCase();
    const rawType = String(resource?.type || '').toLowerCase();
    const encoding = String(resource?.encoding || '').toLowerCase();

    if (mimeType.includes('text/html') || rawType === 'document' || /\.html?($|\?)/.test(url)) return 'document';
    if (mimeType.includes('javascript') || mimeType.includes('ecmascript') || rawType.includes('script') || /\.(mjs|cjs|js|jsx)($|\?)/.test(url)) return 'javascript';
    if (mimeType.includes('typescript') || /\.(ts|tsx)($|\?)/.test(url)) return 'typescript';
    if (mimeType.includes('text/css') || rawType.includes('stylesheet') || /\.css($|\?)/.test(url)) return 'stylesheet';
    if (mimeType.includes('scss') || mimeType.includes('sass') || /\.(scss|sass)($|\?)/.test(url)) return 'stylesheet';
    if (mimeType.includes('source-map') || /\.map($|\?)/.test(url)) return 'sourcemap';
    if (mimeType.includes('json') || rawType === 'json' || /\.(json|jsonld)($|\?)/.test(url)) return 'json';
    if (mimeType.includes('xml') || /\.xml($|\?)/.test(url)) return 'xml';
    if (mimeType === 'image/svg+xml' || /\.svg($|\?)/.test(url)) return 'svg';
    if (mimeType.includes('manifest') || /\.webmanifest($|\?)/.test(url)) return 'manifest';
    if (mimeType === 'application/wasm' || /\.wasm($|\?)/.test(url)) return 'wasm';
    if (mimeType.startsWith('image/') || /\.(png|jpe?g|gif|webp|ico|bmp|avif)($|\?)/.test(url)) return 'image';
    if (mimeType.startsWith('font/') || mimeType.includes('woff') || /\.(woff2?|ttf|otf|eot)($|\?)/.test(url)) return 'font';
    if (mimeType.startsWith('video/') || /\.(mp4|webm|m4v|mov|avi|mkv)($|\?)/.test(url)) return 'video';
    if (mimeType.startsWith('audio/') || /\.(mp3|wav|ogg|m4a|aac|flac)($|\?)/.test(url)) return 'audio';
    if (mimeType.startsWith('text/') || /\.(txt|md|csv|log)($|\?)/.test(url)) return 'text';
    if (encoding === 'base64') return 'binary';
    return 'other';
  }

  function evaluateSourceStaticPolicy(resource, options) {
    const kind = classifySourceKind(resource);
    if (isStaticAssetKind(kind) && !options.includeStaticSourceAssets) {
      return { allowed: false, reason: 'STATIC_ASSET_DISABLED_BY_DEFAULT' };
    }
    if (kind === 'other' && !options.includeStaticSourceAssets) {
      return { allowed: false, reason: 'MIME_NOT_ALLOWED' };
    }
    return { allowed: true, reason: 'NONE' };
  }

  function evaluateNetworkStaticPolicy(resource, options) {
    const kind = classifySourceKind(resource);
    if (isStaticAssetKind(kind) && !options.includeStaticSourceAssets) {
      return { allowed: false, reason: 'STATIC_ASSET_DISABLED_BY_DEFAULT' };
    }
    return { allowed: true, reason: 'NONE' };
  }

  function isStaticAssetKind(kind) {
    return ['image', 'font', 'video', 'audio', 'binary'].includes(kind);
  }

  function getBudgetFamily(resource, origin) {
    const kind = classifySourceKind(resource);
    if (isStaticAssetKind(kind)) return 'static';
    return origin === 'network' ? 'networkCode' : 'sourceCode';
  }

  function sortResourcesForExport(resources) {
    return [...(resources || [])].sort((left, right) => {
      const priorityDiff = getCodeRichPriority(left) - getCodeRichPriority(right);
      if (priorityDiff) return priorityDiff;
      const sequenceDiff = normalizeOrderValue(left?.sequence) - normalizeOrderValue(right?.sequence);
      if (sequenceDiff) return sequenceDiff;
      return String(left?.url || '').localeCompare(String(right?.url || ''));
    });
  }

  function normalizeOrderValue(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number : Number.MAX_SAFE_INTEGER;
  }

  function getCodeRichPriority(resource) {
    const firstPartyOffset = isFirstPartyResource(resource) ? 0 : 5;
    const kind = classifySourceKind(resource);
    const priorityByKind = {
      javascript: 0,
      stylesheet: 1,
      document: 2,
      json: 3,
      typescript: 4,
      sourcemap: 4,
      xml: 8,
      text: 8,
      manifest: 8,
      svg: 9,
      wasm: 10,
      image: 20,
      font: 21,
      video: 22,
      audio: 23,
      binary: 24,
      other: 25
    };

    return (priorityByKind[kind] ?? priorityByKind.other) + firstPartyOffset;
  }

  function isFirstPartyResource(resource) {
    const category = String(resource?.resourceCategory || '').toLowerCase();
    if (category === 'site_first_party' || category === 'site') return true;
    if (resource?.isFirstParty === true || resource?.party === 'first-party') return true;
    return false;
  }

  function estimateSourceBytes(resource) {
    if (resource?.size != null) {
      return Number(resource.size) || 0;
    }
    return estimateTextLikeBytes(resource?.content, resource?.encoding);
  }

  function estimateNetworkBytes(resource) {
    if (resource?.bodyCapturedBytes != null && resource.bodyCapturedBytes > 0) {
      return Number(resource.bodyCapturedBytes) || 0;
    }
    if (resource?.bodySizeBytes != null && resource.bodySizeBytes > 0) {
      return Number(resource.bodySizeBytes) || 0;
    }
    return estimateTextLikeBytes(resource?.content, resource?.encoding);
  }

  function estimateTextLikeBytes(content, encoding) {
    if (typeof content !== 'string') {
      return 0;
    }
    if (String(encoding || '').toLowerCase() === 'base64') {
      return Math.floor(content.length * 0.75);
    }
    return new TextEncoder().encode(content).length;
  }

  function consumeBudget(plan, budgets, family, sizeBytes) {
    const size = Math.max(0, Number(sizeBytes) || 0);
    const isStaticFamily = family === 'static';
    const singleFileLimit = isStaticFamily ? budgets.maxSingleBinaryFileBytes : budgets.maxSingleTextFileBytes;
    if (size > singleFileLimit) {
      return 'SIZE_LIMIT_EXCEEDED';
    }
    if (plan.budgetSummary.totalFiles >= budgets.maxExportedFiles) {
      return 'EXPORT_FILE_LIMIT_EXCEEDED';
    }
    if (plan.budgetSummary.totalInputBytes + size > budgets.maxTotalZipInputBytes) {
      return 'EXPORT_TOTAL_SIZE_LIMIT_EXCEEDED';
    }
    if (family === 'sourceCode') {
      if (plan.budgetSummary.sourceCodeFiles >= budgets.maxSourceCodeFiles) {
        return 'CODE_BUDGET_EXCEEDED';
      }
      if (plan.budgetSummary.totalSourceCodeBytes + size > budgets.maxTotalSourceCodeBytes) {
        return 'CODE_BUDGET_EXCEEDED';
      }
      plan.budgetSummary.sourceCodeFiles++;
      plan.budgetSummary.totalSourceCodeBytes += size;
      plan.budgetSummary.sourceFiles++;
      plan.budgetSummary.totalSourceBytes += size;
    }
    if (family === 'networkCode') {
      if (plan.budgetSummary.networkCodeBodyFiles >= budgets.maxNetworkCodeBodyFiles) {
        return 'CODE_BUDGET_EXCEEDED';
      }
      if (plan.budgetSummary.totalNetworkCodeBytes + size > budgets.maxTotalNetworkCodeBytes) {
        return 'CODE_BUDGET_EXCEEDED';
      }
      plan.budgetSummary.networkCodeBodyFiles++;
      plan.budgetSummary.totalNetworkCodeBytes += size;
      plan.budgetSummary.networkBodyFiles++;
      plan.budgetSummary.totalNetworkBodyBytes += size;
    }
    if (family === 'static') {
      if (plan.budgetSummary.staticAssetFiles >= budgets.maxStaticAssetFiles) {
        return 'STATIC_ASSET_BUDGET_EXCEEDED';
      }
      if (plan.budgetSummary.totalStaticAssetBytes + size > budgets.maxTotalStaticAssetBytes) {
        return 'STATIC_ASSET_BUDGET_EXCEEDED';
      }
      plan.budgetSummary.staticAssetFiles++;
      plan.budgetSummary.totalStaticAssetBytes += size;
    }
    plan.budgetSummary.totalFiles++;
    plan.budgetSummary.totalInputBytes += size;
    return null;
  }

  return {
    DEFAULT_EXPORT_BUDGETS,
    buildExportPlan,
    buildExportPlanFromStateLike
  };
});
