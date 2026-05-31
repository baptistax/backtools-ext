(function () {
function requireApi(path) {
  if (typeof require !== "function") {
    return null;
  }
  try {
    return require(path);
  } catch (_error) {
    return null;
  }
}

function mergeApis(...items) {
  return Object.assign({}, ...items.filter((item) => item && typeof item === "object"));
}

const targetDomain = requireApi("../domain/targetClassification.js") || globalThis.BackToolsDomain;
const redactionDomain = requireApi("../domain/redaction.js") || globalThis.BackToolsDomain;
const evidenceModelBuilder = requireApi("../analysis/evidence/buildEvidenceModel.js") || globalThis.BackToolsEvidenceModelBuilder;
const inspectedPlatform = requireApi("../platform/inspectedWindowAdapter.js");
const networkPlatform = requireApi("../platform/devtoolsNetworkAdapter.js");
const platform = mergeApis(globalThis.BackToolsPlatform, inspectedPlatform, networkPlatform);

const STORAGE_PREFIX = "back-tools-runtime-snapshot-v1:";
const SHARED_ADAPTER_REQUIRED_REASON = "shared_runtime_adapter_required";

function safeString(value) {
  return value === null || value === undefined ? "" : String(value);
}

function safeNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : 0;
}

function toArray(value) {
  return Array.isArray(value) ? value : [];
}

function sanitizeText(value, limit = 320) {
  const text = safeString(value)
    .replace(/https?:\/\/[^\s"'<>]+/g, (match) => redactUrl(match))
    .replace(/chrome-extension:\/\/[^\s"'<>]+/g, (match) => redactUrl(match));
  return text.length > limit ? `${text.slice(0, limit - 1)}...` : text;
}

function classifyTargetUrl(rawUrl, urlSource) {
  if (targetDomain && typeof targetDomain.classifyTargetUrl === "function") {
    return targetDomain.classifyTargetUrl(rawUrl, { urlSource: urlSource || "runtime_snapshot" });
  }

  const targetUrl = safeString(rawUrl).trim() || null;
  const isWeb = /^https?:/i.test(targetUrl || "");
  return {
    targetType: isWeb ? "web_https" : "unknown",
    targetUrl,
    normalizedUrl: targetUrl,
    isNormalWebTarget: isWeb,
    isLimitedTarget: !isWeb,
    isEmptyTarget: !targetUrl,
    classificationReason: isWeb ? null : "target_unavailable",
    captureMode: isWeb ? "web_full_available" : "unknown_target_report_only",
    statusLabel: isWeb ? "Supported web target" : "Empty target",
    message: isWeb
      ? "Supported web target. Back Tools can analyze available Sources, Network, and Application data for this page."
      : "Target information is not available yet. Some collectors may be limited."
  };
}

function redactUrl(rawUrl) {
  const value = safeString(rawUrl).trim();
  if (!value) {
    return "";
  }

  if (redactionDomain && typeof redactionDomain.redactUrl === "function") {
    return redactionDomain.redactUrl(value);
  }

  return value.replace(/([?&])([^=&?#]+)=([^&#]*)/g, (match, separator, key) => {
    return /token|auth|password|pass|secret|session|key|code|state/i.test(key)
      ? `${separator}${key}=[redacted]`
      : match;
  });
}

function targetTypeLabel(target) {
  const type = safeString(target && target.targetType);
  if (type === "web_http" || type === "web_https") {
    return "Website";
  }
  if (type === "extension_page") {
    return "Extension";
  }
  if (type === "chrome_internal" || type === "new_tab") {
    return "Internal";
  }
  if (type === "about_blank") {
    return "Empty target";
  }
  if (type === "file_url") {
    return "Local file";
  }
  if (target && target.isLimitedTarget && !target.isEmptyTarget) {
    return "Limited";
  }
  return "Unknown";
}

function captureModeLabel(captureMode) {
  const value = safeString(captureMode);
  if (value === "web_full_available") {
    return "Full capture available";
  }
  if (value === "limited_target_report_only") {
    return "Limited report";
  }
  if (value === "empty_target_report_only") {
    return "Empty target report";
  }
  if (value === "unknown_target_report_only") {
    return "Unknown target report";
  }
  return "Unknown";
}

function analysisStatusLabel(status) {
  const value = safeString(status);
  if (value === "not_analyzed") {
    return "Not analyzed";
  }
  if (value === "running") {
    return "Running";
  }
  if (value === "complete") {
    return "Complete";
  }
  if (value === "incomplete") {
    return "Incomplete";
  }
  if (value === "error") {
    return "Error";
  }
  if (value === "not_available") {
    return "Not available";
  }
  return "Not available";
}

function syncStatusLabel(status) {
  const value = safeString(status);
  if (value === "fresh") {
    return "Fresh";
  }
  if (value === "out_of_sync") {
    return "Out of sync";
  }
  if (value === "not_analyzed") {
    return "Not analyzed";
  }
  if (value === "not_available") {
    return "Unavailable";
  }
  return "Unavailable";
}

function browserLabel(root) {
  const nav = root && root.navigator ? root.navigator : globalThis.navigator;
  const userAgent = safeString(nav && nav.userAgent);
  const edgeMatch = /Edg\/(\d+[.\d]*)/.exec(userAgent);
  if (edgeMatch) {
    return `Edge/${edgeMatch[1]}`;
  }
  const chromeMatch = /Chrome\/(\d+[.\d]*)/.exec(userAgent);
  if (chromeMatch) {
    return `Chrome/${chromeMatch[1]}`;
  }
  return userAgent ? "Browser runtime" : null;
}

function capabilityLabelsForTarget(target) {
  if (target && target.isNormalWebTarget) {
    return ["Sources API", "Network HAR", "Application storage"];
  }
  if (target && target.isLimitedTarget) {
    return ["Limited report", "Network HAR when available", "Diagnostics export"];
  }
  return [];
}

function capabilityLabelsFromCapabilities(capabilities, fallbackTarget) {
  const labels = [];
  if (capabilities.sourcesApi) {
    labels.push("Sources API");
  }
  if (capabilities.networkHar) {
    labels.push("Network HAR");
  }
  if (capabilities.applicationStorage) {
    labels.push("Application storage");
  }
  if (!labels.length) {
    return capabilityLabelsForTarget(fallbackTarget);
  }
  return labels;
}

function hasSourcesApi(root) {
  const inspectedWindow = root && root.chrome && root.chrome.devtools
    ? root.chrome.devtools.inspectedWindow
    : null;
  return Boolean(inspectedWindow && typeof inspectedWindow.getResources === "function");
}

function hasNetworkHar(root) {
  const network = root && root.chrome && root.chrome.devtools
    ? root.chrome.devtools.network
    : null;
  return Boolean(network && typeof network.getHAR === "function");
}

function hasApplicationStorageAccess(root) {
  const inspectedWindow = root && root.chrome && root.chrome.devtools
    ? root.chrome.devtools.inspectedWindow
    : null;
  return Boolean(inspectedWindow && typeof inspectedWindow.eval === "function");
}

function normalizeActionCapabilities(value) {
  const source = value && typeof value === "object" ? value : {};
  const actions = source.actions && typeof source.actions === "object" ? source.actions : source;
  return {
    analyze: Boolean(actions.analyze),
    reloadAndCapture: Boolean(actions.reloadAndCapture || actions.reloadAndAnalyze),
    copyTargetUrl: Boolean(actions.copyTargetUrl)
  };
}

function buildCapabilities(input, target, root) {
  const direct = input.capabilities || {};
  const labels = Array.isArray(input.capabilityLabels) ? input.capabilityLabels.map(safeString) : [];
  const labelText = labels.join(" ").toLowerCase();
  const sourceAvailable = direct.sourcesApi !== undefined
    ? Boolean(direct.sourcesApi)
    : (labelText.includes("sources api") || hasSourcesApi(root)) && Boolean(target.isNormalWebTarget);
  const networkAvailable = direct.networkHar !== undefined
    ? Boolean(direct.networkHar)
    : labelText.includes("network har") || hasNetworkHar(root);
  const applicationAvailable = direct.applicationStorage !== undefined
    ? Boolean(direct.applicationStorage)
    : (labelText.includes("application storage") || hasApplicationStorageAccess(root)) && Boolean(target.isNormalWebTarget);

  return {
    sourcesApi: sourceAvailable,
    networkHar: networkAvailable,
    applicationStorage: applicationAvailable,
    actions: normalizeActionCapabilities(direct),
    browserVersion: sanitizeText(direct.browserVersion || input.browserVersion || input.browser?.label || browserLabel(root) || "")
  };
}

function normalizeHealthItem(value, fallbackStatus, fallbackMessage) {
  if (!value || typeof value !== "object") {
    return {
      status: fallbackStatus,
      reason: null,
      message: fallbackMessage,
      count: 0
    };
  }

  return {
    status: safeString(value.status || fallbackStatus),
    reason: safeString(value.reason) || null,
    message: sanitizeText(value.message || fallbackMessage),
    count: safeNumber(value.count ?? value.items)
  };
}

function mapModuleStatuses(moduleStatuses) {
  return {
    sources: normalizeHealthItem(moduleStatuses.sources, "not_collected", "Sources have not been analyzed yet."),
    network: normalizeHealthItem(moduleStatuses.network, "not_collected", "Network has not been analyzed yet."),
    cookies: normalizeHealthItem(moduleStatuses.cookies, "not_collected", "Cookies have not been analyzed yet."),
    application: normalizeHealthItem(moduleStatuses.application, "not_collected", "Application storage has not been analyzed yet."),
    diagnostics: normalizeHealthItem(moduleStatuses.diagnostics, "not_collected", "Diagnostics have not been analyzed yet.")
  };
}

function buildModuleHealth(input, target, analyzed) {
  if (input.moduleHealth && typeof input.moduleHealth === "object") {
    return mapModuleStatuses(input.moduleHealth);
  }

  const targetModuleStatuses = input.target && input.target.moduleStatuses;
  if (targetModuleStatuses && typeof targetModuleStatuses === "object") {
    return mapModuleStatuses(targetModuleStatuses);
  }

  if (targetDomain && typeof targetDomain.buildModuleStatuses === "function") {
    return mapModuleStatuses(targetDomain.buildModuleStatuses({
      target,
      analyzed,
      sources: input.sources?.resources || input.sources || [],
      network: input.network?.entries || input.network || [],
      cookiesSummary: input.cookies?.summary || input.cookiesSummary || {},
      application: input.application || {}
    }));
  }

  return mapModuleStatuses({});
}

function countReadableSources(sources) {
  return sources.filter((item) => {
    const status = safeString(item && item.status);
    return item && (item.exportable || status === "readable" || status === "metadata_only");
  }).length;
}

function countCapturedBodies(entries) {
  return entries.filter((item) => {
    const status = safeString(item && (item.bodyCaptureStatus || item.status));
    return status === "body_captured";
  }).length;
}

function countUnavailableBodies(entries) {
  return entries.filter((item) => {
    const status = safeString(item && item.bodyCaptureStatus);
    if (!status) {
      return false;
    }
    return status !== "body_captured" && status !== "not_applicable";
  }).length;
}

function applicationItemCount(application) {
  if (!application || typeof application !== "object") {
    return 0;
  }
  const summary = application.summary || {};
  if (summary.totalInventoryItems !== undefined) {
    return safeNumber(summary.totalInventoryItems);
  }
  return safeNumber(summary.storageItems) +
    safeNumber(summary.indexedDbDatabases) +
    safeNumber(summary.cacheStorageCaches) +
    safeNumber(summary.serviceWorkerRegistrations) +
    safeNumber(summary.manifestLinks);
}

function diagnosticWarningCount(input) {
  if (input.captureSummary && input.captureSummary.diagnosticWarningCount !== undefined) {
    return safeNumber(input.captureSummary.diagnosticWarningCount);
  }
  const reasonGroups = input.diagnostics && input.diagnostics.reasonGroups;
  if (reasonGroups && typeof reasonGroups === "object") {
    return Object.keys(reasonGroups).length;
  }
  return toArray(input.diagnostics && input.diagnostics.logs).filter((item) => {
    const level = safeString(item && item.level).toLowerCase();
    return level === "warn" || level === "warning" || level === "error";
  }).length;
}

function normalizeReasonGroups(value) {
  const groups = {};
  if (!value || typeof value !== "object") {
    return groups;
  }
  Object.entries(value).forEach(([reason, count]) => {
    const key = sanitizeText(reason, 120);
    if (key) {
      groups[key] = safeNumber(count);
    }
  });
  return groups;
}

function logLevel(entry) {
  return safeString(entry && entry.level).toUpperCase();
}

function buildDiagnosticsSummary(input, captureSummary, moduleHealth, analysis) {
  const direct = input.diagnosticsSummary && typeof input.diagnosticsSummary === "object" ? input.diagnosticsSummary : {};
  const diagnostics = input.diagnostics && typeof input.diagnostics === "object" ? input.diagnostics : {};
  const logs = toArray(diagnostics.logs);
  const reasonGroups = normalizeReasonGroups(direct.reasonGroups || diagnostics.reasonGroups);
  const reasonGroupCount = safeNumber(direct.reasonGroupCount ?? Object.keys(reasonGroups).length);
  const errorCount = safeNumber(direct.errorCount ?? direct.errors ?? logs.filter((entry) => logLevel(entry) === "ERROR").length);
  const logWarningCount = logs.filter((entry) => ["WARN", "WARNING"].includes(logLevel(entry))).length;
  const fallbackWarningSource = captureSummary && captureSummary.diagnosticWarningCount !== undefined
    ? captureSummary.diagnosticWarningCount
    : moduleHealth && moduleHealth.diagnostics && moduleHealth.diagnostics.count;
  const fallbackWarningCount = safeNumber(fallbackWarningSource);
  const warningCount = safeNumber(direct.warningCount ?? direct.warnings ?? (logWarningCount + reasonGroupCount || fallbackWarningCount));
  const status = direct.status
    ? safeString(direct.status)
    : errorCount
      ? "error"
      : warningCount || reasonGroupCount
        ? "incomplete"
        : analysis && analysis.status === "not_analyzed"
          ? "idle"
          : "complete";

  return {
    status,
    warningCount,
    errorCount,
    reasonGroupCount,
    reasonGroups,
    message: sanitizeText(direct.message || "")
  };
}

function buildRawPostureSummary(input) {
  const direct = input.rawPostureSummary && typeof input.rawPostureSummary === "object"
    ? input.rawPostureSummary
    : input.objectDump && typeof input.objectDump === "object"
      ? input.objectDump
      : {};
  const dumpObjectsEnabled = Boolean(direct.dumpObjectsEnabled ?? input.dumpObjectsEnabled);
  return {
    dumpObjectsEnabled,
    cookieValueMode: sanitizeText(direct.cookieValueMode || (dumpObjectsEnabled ? "raw" : "protected"), 80),
    applicationValueMode: sanitizeText(direct.applicationValueMode || (dumpObjectsEnabled ? "raw" : "protected"), 80),
    cookieRawVisibleCount: safeNumber(direct.cookieRawVisibleCount ?? direct.cookiesRawVisible),
    applicationRawVisibleCount: safeNumber(direct.applicationRawVisibleCount ?? direct.applicationRawVisible),
    rawValuesIncluded: Boolean(direct.rawValuesIncluded || direct.containsRawCookies || direct.containsRawApplicationValues)
  };
}

function buildCaptureSummary(input) {
  const direct = input.captureSummary || {};
  const sources = toArray(input.sources?.resources || input.sources);
  const network = toArray(input.network?.entries || input.network);
  const cookiesSummary = input.cookies?.summary || input.cookiesSummary || {};
  const observedCookies = toArray(input.cookies?.observedCookies || input.observedCookies);

  return {
    sourceCount: safeNumber(direct.sourceCount ?? sources.length),
    readableSourceCount: safeNumber(direct.readableSourceCount ?? countReadableSources(sources)),
    networkRequestCount: safeNumber(direct.networkRequestCount ?? network.length),
    capturedBodyCount: safeNumber(direct.capturedBodyCount ?? countCapturedBodies(network)),
    unavailableBodyCount: safeNumber(direct.unavailableBodyCount ?? countUnavailableBodies(network)),
    cookieCount: safeNumber(direct.cookieCount ?? cookiesSummary.observedCookies ?? observedCookies.length),
    applicationItemCount: safeNumber(direct.applicationItemCount ?? applicationItemCount(input.application)),
    diagnosticWarningCount: safeNumber(direct.diagnosticWarningCount ?? diagnosticWarningCount(input))
  };
}

function buildAnalysis(input, targetConnected) {
  const source = input.analysis || {};
  const explicitStatus = input.analysisStatus || source.status;
  const status = safeString(explicitStatus || (targetConnected ? "not_analyzed" : "not_available"));
  const running = source.running === true || status === "running";
  const phase = sanitizeText(input.phase || source.phase || "");
  const message = sanitizeText(source.message || phase || analysisStatusLabel(status));

  return {
    status,
    running,
    lastRunAt: safeString(source.lastRunAt || input.lastRunAt) || null,
    message,
    connected: status !== "not_available" && status !== "not_connected",
    label: analysisStatusLabel(status),
    phase: phase || null
  };
}

function buildSync(input, analysis, isOutOfSync) {
  const source = input.sync || {};
  const status = safeString(input.syncStatus || source.status || (
    analysis.status === "not_analyzed" ? "not_analyzed" : isOutOfSync ? "out_of_sync" : "fresh"
  ));

  return {
    connected: status !== "not_available" && status !== "not_connected",
    status,
    label: syncStatusLabel(status)
  };
}

function normalizeNotice(notice, index) {
  if (!notice || typeof notice !== "object") {
    return null;
  }

  const title = sanitizeText(notice.title || notice.label || "");
  const message = sanitizeText(notice.message || notice.body || "");
  const reason = sanitizeText(notice.reason || "");
  const moduleName = sanitizeText(notice.module || "");

  if (!title && !message && !reason) {
    return null;
  }

  return {
    id: safeString(notice.id) || `notice-${index + 1}`,
    type: safeString(notice.type || notice.tone || "info"),
    severity: safeString(notice.severity || notice.level || "info"),
    title: title || "Notice",
    message: message || reason || title,
    reason: reason || null,
    module: moduleName || null
  };
}

function buildExportReadiness(input, target, analysis) {
  if (input.exportReadiness && typeof input.exportReadiness === "object") {
    const direct = input.exportReadiness;
    return {
      blocked: Boolean(direct.blocked),
      safeReady: Boolean(direct.safeReady),
      limitedReport: Boolean(direct.limitedReport),
      reason: sanitizeText(direct.reason || "")
    };
  }

  if (analysis.running) {
    return {
      blocked: true,
      safeReady: false,
      limitedReport: Boolean(target.isLimitedTarget),
      reason: "Analysis is running."
    };
  }

  if (analysis.status === "not_analyzed" || analysis.status === "not_available" || analysis.status === "not_connected") {
    return {
      blocked: true,
      safeReady: false,
      limitedReport: Boolean(target.isLimitedTarget),
      reason: "Analyze the target before exporting."
    };
  }

  if (analysis.status === "error") {
    return {
      blocked: true,
      safeReady: false,
      limitedReport: Boolean(target.isLimitedTarget),
      reason: "Analysis failed. Re-run analysis before exporting."
    };
  }

  if (target.isOutOfSync) {
    return {
      blocked: true,
      safeReady: false,
      limitedReport: Boolean(target.isLimitedTarget),
      reason: "Target changed since the last analysis."
    };
  }

  return {
    blocked: false,
    safeReady: true,
    limitedReport: Boolean(target.isLimitedTarget),
    reason: target.isLimitedTarget ? "Limited report export is available." : "Safe export is ready."
  };
}

function buildNotices(input, target, analysis, moduleHealth, exportReadiness) {
  const notices = toArray(input.notices).map(normalizeNotice).filter(Boolean);

  if (target.isLimitedTarget && target.connected) {
    notices.push({
      id: "limited-target",
      type: "limitation",
      severity: "info",
      title: "Limited target",
      message: sanitizeText(target.statusLabel || "Some page data cannot be accessed in this context."),
      reason: sanitizeText(target.classificationReason || ""),
      module: "target"
    });
  }

  if (target.isOutOfSync) {
    notices.push({
      id: "target-out-of-sync",
      type: "warning",
      severity: "warning",
      title: "Target out of sync",
      message: "Target changed since the last analysis. Re-analyze before exporting.",
      reason: "target_changed_during_capture",
      module: "target"
    });
  }

  if (analysis.status === "error") {
    notices.push({
      id: "analysis-error",
      type: "error",
      severity: "error",
      title: "Analysis failed",
      message: analysis.message || "Analysis failed.",
      reason: "analysis_failed",
      module: "analysis"
    });
  }

  Object.entries(moduleHealth || {}).forEach(([moduleName, item]) => {
    if (!item || !item.reason) {
      return;
    }
    notices.push({
      id: `module-${moduleName}-${item.reason}`,
      type: item.status === "unavailable" ? "limitation" : "info",
      severity: item.status === "failed" ? "error" : "info",
      title: `${moduleName} ${item.status}`,
      message: item.message || item.reason,
      reason: item.reason,
      module: moduleName
    });
  });

  if (exportReadiness.blocked && exportReadiness.reason && !["not_analyzed", "not_available", "not_connected"].includes(analysis.status)) {
    notices.push({
      id: "export-readiness",
      type: "warning",
      severity: "warning",
      title: "Export not ready",
      message: exportReadiness.reason,
      reason: "export_not_ready",
      module: "export"
    });
  }

  const seen = new Set();
  return notices.filter((notice) => {
    const key = [notice.id, notice.title, notice.message, notice.reason, notice.module].join("|");
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  }).slice(0, 12);
}

function normalizeEvidenceModelSummary(value) {
  const source = value && typeof value === "object" ? value : {};
  const sourceSummary = source.summary && typeof source.summary === "object" ? source.summary : source;
  return {
    available: Boolean(source.available || source.schemaVersion || source.summary),
    schemaVersion: safeString(source.schemaVersion || ""),
    summary: {
      originCount: safeNumber(sourceSummary.originCount),
      requestCount: safeNumber(sourceSummary.requestCount),
      resourceCount: safeNumber(sourceSummary.resourceCount),
      cookieCount: safeNumber(sourceSummary.cookieCount),
      storageItemCount: safeNumber(sourceSummary.storageItemCount),
      diagnosticIssueCount: safeNumber(sourceSummary.diagnosticIssueCount),
      findingCount: safeNumber(sourceSummary.findingCount),
      bodyCapturedCount: safeNumber(sourceSummary.bodyCapturedCount),
      bodyUnavailableCount: safeNumber(sourceSummary.bodyUnavailableCount),
      exportBlocked: Boolean(sourceSummary.exportBlocked),
      safeExportReady: Boolean(sourceSummary.safeExportReady)
    }
  };
}

function buildEvidenceModelSummary(input) {
  if (input.evidenceModel && typeof input.evidenceModel === "object") {
    return normalizeEvidenceModelSummary(input.evidenceModel);
  }

  if (!evidenceModelBuilder || typeof evidenceModelBuilder.buildEvidenceModel !== "function") {
    return normalizeEvidenceModelSummary(null);
  }

  try {
    return normalizeEvidenceModelSummary(evidenceModelBuilder.buildEvidenceModel(input));
  } catch (_error) {
    return normalizeEvidenceModelSummary(null);
  }
}

function buildRuntimeSnapshot(input = {}, options = {}) {
  const root = options.root || input.root || globalThis;
  const sourceTarget = input.target || {};
  const rawUrl =
    input.targetUrl ??
    input.url ??
    input.currentUrl ??
    sourceTarget.url ??
    sourceTarget.urlRedacted ??
    sourceTarget.redactedUrl ??
    sourceTarget.targetUrl ??
    sourceTarget.normalizedUrl ??
    "";
  const classified = classifyTargetUrl(rawUrl, options.urlSource || input.urlSource || "runtime_snapshot");
  const targetType = safeString(sourceTarget.targetType || classified.targetType || "unknown");
  const captureMode = safeString(sourceTarget.captureMode || classified.captureMode || "");
  const redactedUrl = redactUrl(classified.normalizedUrl || classified.targetUrl || rawUrl || "");
  const targetConnected = Boolean(redactedUrl || sourceTarget.connected);
  const isOutOfSync = Boolean(sourceTarget.isOutOfSync || input.isOutOfSync || input.sync?.status === "out_of_sync");
  const target = {
    url: targetConnected ? redactedUrl || null : null,
    urlRedacted: targetConnected ? redactedUrl || null : null,
    targetType,
    targetTypeLabel: sanitizeText(sourceTarget.targetTypeLabel || targetTypeLabel({ ...classified, targetType })),
    captureMode: captureMode || null,
    captureLabel: sanitizeText(sourceTarget.captureLabel || sourceTarget.captureModeLabel || captureModeLabel(captureMode)),
    isNormalWebTarget: sourceTarget.isNormalWebTarget !== undefined ? Boolean(sourceTarget.isNormalWebTarget) : Boolean(classified.isNormalWebTarget),
    isLimitedTarget: sourceTarget.isLimitedTarget !== undefined ? Boolean(sourceTarget.isLimitedTarget) : Boolean(classified.isLimitedTarget),
    isOutOfSync,
    connected: targetConnected,
    classificationReason: sanitizeText(sourceTarget.classificationReason || classified.classificationReason || ""),
    statusLabel: sanitizeText(sourceTarget.statusLabel || classified.statusLabel || ""),
    message: sanitizeText(sourceTarget.message || classified.message || "")
  };
  const analysis = buildAnalysis(input, targetConnected);
  const sync = buildSync(input, analysis, isOutOfSync);
  const capabilities = buildCapabilities(input, target, root);
  const analyzed = !["not_analyzed", "not_available", "not_connected"].includes(analysis.status);
  const moduleHealth = buildModuleHealth(input, target, analyzed);
  const captureSummary = buildCaptureSummary(input);
  const exportReadiness = buildExportReadiness(input, target, analysis);
  const diagnosticsSummary = buildDiagnosticsSummary(input, captureSummary, moduleHealth, analysis);
  const rawPostureSummary = buildRawPostureSummary(input);
  const evidenceModel = buildEvidenceModelSummary({
    ...input,
    target,
    analysis,
    moduleHealth,
    captureSummary,
    exportReadiness
  });
  const notices = buildNotices(input, target, analysis, moduleHealth, exportReadiness);

  return finalizeSnapshot({
    version: 2,
    connected: targetConnected,
    reason: input.reason || (targetConnected ? null : "target_unavailable"),
    updatedAt: input.updatedAt || new Date().toISOString(),
    source: options.source || input.source || "runtime",
    target,
    analysis,
    capabilities,
    moduleHealth,
    captureSummary,
    exportReadiness,
    diagnosticsSummary,
    rawPostureSummary,
    evidenceModel,
    notices,
    sync
  });
}

function finalizeSnapshot(snapshot) {
  const target = snapshot.target || {};
  const analysis = snapshot.analysis || {};
  const capabilities = snapshot.capabilities || {};
  const sync = snapshot.sync || {
    connected: false,
    status: "not_available",
    label: syncStatusLabel("not_available")
  };
  const browser = {
    label: sanitizeText(capabilities.browserVersion || snapshot.browser?.label || "")
  };
  const capabilityLabels = Array.isArray(snapshot.capabilityLabels)
    ? snapshot.capabilityLabels.map(safeString).filter(Boolean).slice(0, 8)
    : capabilityLabelsFromCapabilities(capabilities, target).slice(0, 8);

  return {
    version: snapshot.version || 2,
    connected: Boolean(snapshot.connected || target.connected),
    reason: snapshot.reason || null,
    updatedAt: snapshot.updatedAt || new Date().toISOString(),
    source: snapshot.source || "runtime",
    target: {
      url: target.url || null,
      urlRedacted: target.urlRedacted || target.url || null,
      targetType: safeString(target.targetType || "unknown"),
      targetTypeLabel: safeString(target.targetTypeLabel || "Unknown"),
      captureMode: target.captureMode || null,
      captureLabel: safeString(target.captureLabel || "Unknown"),
      isNormalWebTarget: Boolean(target.isNormalWebTarget),
      isLimitedTarget: Boolean(target.isLimitedTarget),
      isOutOfSync: Boolean(target.isOutOfSync),
      connected: Boolean(target.connected),
      classificationReason: target.classificationReason || null,
      statusLabel: target.statusLabel || null,
      message: target.message || null,
      redactedUrl: target.urlRedacted || target.url || null,
      displayUrl: target.urlRedacted || target.url || "Unavailable",
      captureModeLabel: safeString(target.captureLabel || "Unknown")
    },
    analysis: {
      status: safeString(analysis.status || "not_available"),
      running: Boolean(analysis.running),
      lastRunAt: analysis.lastRunAt || null,
      message: sanitizeText(analysis.message || analysisStatusLabel(analysis.status)),
      connected: Boolean(analysis.connected),
      label: safeString(analysis.label || analysisStatusLabel(analysis.status)),
      phase: analysis.phase || null
    },
    capabilities: {
      sourcesApi: Boolean(capabilities.sourcesApi),
      networkHar: Boolean(capabilities.networkHar),
      applicationStorage: Boolean(capabilities.applicationStorage),
      actions: normalizeActionCapabilities(capabilities),
      browserVersion: browser.label || null
    },
    moduleHealth: {
      sources: normalizeHealthItem(snapshot.moduleHealth?.sources, "not_collected", "Sources have not been analyzed yet."),
      network: normalizeHealthItem(snapshot.moduleHealth?.network, "not_collected", "Network has not been analyzed yet."),
      cookies: normalizeHealthItem(snapshot.moduleHealth?.cookies, "not_collected", "Cookies have not been analyzed yet."),
      application: normalizeHealthItem(snapshot.moduleHealth?.application, "not_collected", "Application storage has not been analyzed yet."),
      diagnostics: normalizeHealthItem(snapshot.moduleHealth?.diagnostics, "not_collected", "Diagnostics have not been analyzed yet.")
    },
    captureSummary: {
      sourceCount: safeNumber(snapshot.captureSummary?.sourceCount),
      readableSourceCount: safeNumber(snapshot.captureSummary?.readableSourceCount),
      networkRequestCount: safeNumber(snapshot.captureSummary?.networkRequestCount),
      capturedBodyCount: safeNumber(snapshot.captureSummary?.capturedBodyCount),
      unavailableBodyCount: safeNumber(snapshot.captureSummary?.unavailableBodyCount),
      cookieCount: safeNumber(snapshot.captureSummary?.cookieCount),
      applicationItemCount: safeNumber(snapshot.captureSummary?.applicationItemCount),
      diagnosticWarningCount: safeNumber(snapshot.captureSummary?.diagnosticWarningCount)
    },
    exportReadiness: {
      blocked: Boolean(snapshot.exportReadiness?.blocked),
      safeReady: Boolean(snapshot.exportReadiness?.safeReady),
      limitedReport: Boolean(snapshot.exportReadiness?.limitedReport),
      reason: sanitizeText(snapshot.exportReadiness?.reason || "")
    },
    diagnosticsSummary: buildDiagnosticsSummary(snapshot, snapshot.captureSummary || {}, snapshot.moduleHealth || {}, analysis),
    rawPostureSummary: buildRawPostureSummary(snapshot),
    evidenceModel: normalizeEvidenceModelSummary(snapshot.evidenceModel),
    notices: toArray(snapshot.notices).map(normalizeNotice).filter(Boolean).slice(0, 12),
    sync,
    browser,
    capabilityLabels
  };
}

function disconnectedSnapshot(root, reason) {
  return buildRuntimeSnapshot({
    source: "runtime",
    reason: reason || "runtime_unavailable",
    target: {
      connected: false
    },
    analysis: {
      status: "not_available",
      running: false,
      message: "Runtime snapshot is not available."
    },
    sync: {
      connected: false,
      status: "not_available"
    },
    capabilities: {
      browserVersion: browserLabel(root)
    }
  }, { root, source: "runtime" });
}

function createSnapshotFromTargetUrl(rawUrl, options = {}) {
  return buildRuntimeSnapshot({
    source: options.source || "runtime",
    targetUrl: rawUrl,
    urlSource: options.urlSource || "runtime_snapshot",
    analysis: {
      status: options.analysisStatus || "not_analyzed",
      running: options.analysisStatus === "running",
      phase: options.phase || null,
      lastRunAt: options.lastRunAt || null
    },
    sync: {
      status: options.syncStatus || "not_analyzed"
    },
    capabilities: {
      browserVersion: options.browserLabel || null
    },
    capabilityLabels: Array.isArray(options.capabilityLabels) ? options.capabilityLabels : null,
    updatedAt: options.updatedAt || null
  }, {
    root: options.root || globalThis,
    source: options.source || "runtime",
    urlSource: options.urlSource || "runtime_snapshot"
  });
}

function normalizeStoredSnapshot(input, root) {
  if (!input || typeof input !== "object") {
    return null;
  }
  return buildRuntimeSnapshot(input, { root, source: "panel-runtime", urlSource: "stored_panel_snapshot" });
}

function storageKey(root) {
  const tabId = root && root.chrome && root.chrome.devtools && root.chrome.devtools.inspectedWindow
    ? root.chrome.devtools.inspectedWindow.tabId
    : null;
  return `${STORAGE_PREFIX}${tabId === null || tabId === undefined ? "unknown" : String(tabId)}`;
}

function readStoredSnapshot(root) {
  return new Promise((resolve) => {
    const key = storageKey(root);
    const chromeStorage = root && root.chrome && root.chrome.storage && root.chrome.storage.local;
    if (chromeStorage && typeof chromeStorage.get === "function") {
      try {
        chromeStorage.get(key, (result) => {
          resolve(normalizeStoredSnapshot(result && result[key], root));
        });
        return;
      } catch (_error) {
        resolve(null);
        return;
      }
    }

    try {
      const rawValue = root && root.localStorage ? root.localStorage.getItem(key) : null;
      resolve(normalizeStoredSnapshot(rawValue ? JSON.parse(rawValue) : null, root));
    } catch (_error) {
      resolve(null);
    }
  });
}

function evalInspectedUrlFromRoot(root) {
  return new Promise((resolve) => {
    try {
      const inspectedWindow = root && root.chrome && root.chrome.devtools ? root.chrome.devtools.inspectedWindow : null;
      if (!inspectedWindow || typeof inspectedWindow.eval !== "function") {
        resolve(null);
        return;
      }
      inspectedWindow.eval("location.href", (result, exception) => {
        resolve(exception && (exception.isException || exception.isError) ? null : result || null);
      });
    } catch (_error) {
      resolve(null);
    }
  });
}

function readTargetSnapshot(root) {
  const inspectedWindow = root && root.chrome && root.chrome.devtools ? root.chrome.devtools.inspectedWindow : null;
  if (inspectedWindow && typeof inspectedWindow.eval === "function") {
    return evalInspectedUrlFromRoot(root).then((url) => {
      return url
        ? createSnapshotFromTargetUrl(url, { root, source: "devtools-runtime" })
        : disconnectedSnapshot(root, "target_unavailable");
    });
  }

  if (platform && typeof platform.evalInspectedUrl === "function") {
    return platform.evalInspectedUrl().then((url) => {
      return url
        ? createSnapshotFromTargetUrl(url, { root, source: "devtools-runtime" })
        : disconnectedSnapshot(root, "target_unavailable");
    });
  }

  return Promise.resolve(disconnectedSnapshot(root, "runtime_unavailable"));
}

function sameTarget(first, second) {
  const firstUrl = first && first.target && (first.target.urlRedacted || first.target.redactedUrl);
  const secondUrl = second && second.target && (second.target.urlRedacted || second.target.redactedUrl);
  return Boolean(firstUrl && secondUrl && firstUrl === secondUrl);
}

function mergeSnapshots(runtimeSnapshot, storedSnapshot) {
  if (!storedSnapshot) {
    return finalizeSnapshot(runtimeSnapshot);
  }

  if (!runtimeSnapshot || !runtimeSnapshot.target || !runtimeSnapshot.target.connected) {
    return finalizeSnapshot(storedSnapshot);
  }

  if (!sameTarget(runtimeSnapshot, storedSnapshot)) {
    return finalizeSnapshot(runtimeSnapshot);
  }

  return finalizeSnapshot({
    ...runtimeSnapshot,
    source: "devtools-runtime+panel-runtime",
    analysis: storedSnapshot.analysis,
    sync: storedSnapshot.sync,
    moduleHealth: storedSnapshot.moduleHealth,
    captureSummary: storedSnapshot.captureSummary,
    exportReadiness: storedSnapshot.exportReadiness,
    notices: [...toArray(runtimeSnapshot.notices), ...toArray(storedSnapshot.notices)],
    capabilities: {
      ...runtimeSnapshot.capabilities,
      ...storedSnapshot.capabilities,
      browserVersion: storedSnapshot.capabilities?.browserVersion || runtimeSnapshot.capabilities?.browserVersion || null
    },
    target: {
      ...runtimeSnapshot.target,
      isOutOfSync: Boolean(storedSnapshot.target?.isOutOfSync || storedSnapshot.sync?.status === "out_of_sync")
    },
    browser: storedSnapshot.browser && storedSnapshot.browser.label ? storedSnapshot.browser : runtimeSnapshot.browser,
    capabilityLabels: storedSnapshot.capabilityLabels && storedSnapshot.capabilityLabels.length
      ? storedSnapshot.capabilityLabels
      : runtimeSnapshot.capabilityLabels,
    updatedAt: storedSnapshot.updatedAt || runtimeSnapshot.updatedAt
  });
}

function readSnapshot(root) {
  const runtimeRoot = root || globalThis;
  return Promise.all([readTargetSnapshot(runtimeRoot), readStoredSnapshot(runtimeRoot)]).then(([runtimeSnapshot, storedSnapshot]) => {
    return mergeSnapshots(runtimeSnapshot, storedSnapshot);
  }).catch(() => disconnectedSnapshot(runtimeRoot, "runtime_snapshot_failed"));
}

function addActionNotice(snapshot, action, message, severity = "info", reason = "not_available") {
  return finalizeSnapshot({
    ...snapshot,
    notices: [
      ...toArray(snapshot.notices),
      {
        id: `action-${action}-not-available`,
        type: severity === "error" ? "error" : severity === "warning" ? "warning" : "info",
        severity,
        title: "Action not available",
        message,
        reason,
        module: "runtime"
      }
    ]
  });
}

function unavailableAction(snapshot, action, message, reason = "not_available") {
  return {
    status: "not_available",
    action,
    reason,
    message,
    snapshot
  };
}

function createRuntimeBridge(options = {}) {
  const root = options.root || globalThis;
  const listeners = new Set();
  let snapshot = options.initialSnapshot ? finalizeSnapshot(options.initialSnapshot) : disconnectedSnapshot(root);

  function emit() {
    listeners.forEach((listener) => {
      try {
        listener(snapshot);
      } catch (_error) {}
    });
  }

  function setSnapshot(nextSnapshot) {
    snapshot = finalizeSnapshot(nextSnapshot);
    emit();
    return snapshot;
  }

  return {
    getSnapshot() {
      return snapshot;
    },
    subscribe(listener) {
      if (typeof listener !== "function") {
        return () => {};
      }
      listeners.add(listener);
      try {
        listener(snapshot);
      } catch (_error) {}
      return () => {
        listeners.delete(listener);
      };
    },
    refreshTarget() {
      return readSnapshot(root).then((nextSnapshot) => {
        return {
          status: "ok",
          action: "refreshTarget",
          snapshot: setSnapshot(nextSnapshot)
        };
      }).catch(() => {
        const nextSnapshot = setSnapshot(disconnectedSnapshot(root, "runtime_snapshot_failed"));
        return {
          status: "not_available",
          action: "refreshTarget",
          reason: "runtime_snapshot_failed",
          snapshot: nextSnapshot
        };
      });
    },
    analyze() {
      const message = "UI v2 Analyze requires the shared runtime adapter.";
      const nextSnapshot = setSnapshot(addActionNotice(snapshot, "analyze", message, "warning", SHARED_ADAPTER_REQUIRED_REASON));
      return Promise.resolve(unavailableAction(nextSnapshot, "analyze", message, SHARED_ADAPTER_REQUIRED_REASON));
    },
    reloadAndAnalyze() {
      const message = "UI v2 Reload and capture requires the shared runtime adapter.";
      const nextSnapshot = setSnapshot(addActionNotice(snapshot, "reloadAndAnalyze", message, "warning", SHARED_ADAPTER_REQUIRED_REASON));
      return Promise.resolve(unavailableAction(nextSnapshot, "reloadAndAnalyze", message, SHARED_ADAPTER_REQUIRED_REASON));
    },
    copyTargetUrl() {
      const value = snapshot.target && (snapshot.target.urlRedacted || snapshot.target.url) || "";
      const clipboard = root && root.navigator ? root.navigator.clipboard : globalThis.navigator && globalThis.navigator.clipboard;
      if (!value || !clipboard || typeof clipboard.writeText !== "function") {
        const message = "Clipboard access is not available in this runtime.";
        return Promise.resolve(unavailableAction(setSnapshot(addActionNotice(snapshot, "copyTargetUrl", message)), "copyTargetUrl", message));
      }
      return Promise.resolve()
        .then(() => clipboard.writeText(value))
        .then(() => ({
          status: "ok",
          action: "copyTargetUrl",
          copiedUrl: value,
          snapshot
        }))
        .catch(() => {
          const message = "Copy target URL failed.";
          return unavailableAction(setSnapshot(addActionNotice(snapshot, "copyTargetUrl", message)), "copyTargetUrl", message);
        });
    }
  };
}

function connectRuntimeSnapshot(callback, options) {
  const settings = options || {};
  const root = settings.root || globalThis;
  const bridge = createRuntimeBridge({ root });
  let stopped = false;
  const unsubscribe = bridge.subscribe((snapshot) => {
    if (!stopped && typeof callback === "function") {
      callback(snapshot);
    }
  });

  function refresh() {
    return bridge.refreshTarget();
  }

  refresh();

  const navigatedEvent = root.chrome && root.chrome.devtools && root.chrome.devtools.network
    ? root.chrome.devtools.network.onNavigated
    : null;
  const onNavigated = () => {
    refresh();
  };

  if (navigatedEvent && typeof navigatedEvent.addListener === "function") {
    navigatedEvent.addListener(onNavigated);
  }

  const storageEvent = root.chrome && root.chrome.storage ? root.chrome.storage.onChanged : null;
  const onStorageChanged = (changes, areaName) => {
    if (areaName && areaName !== "local") {
      return;
    }
    if (changes && Object.prototype.hasOwnProperty.call(changes, storageKey(root))) {
      refresh();
    }
  };

  if (storageEvent && typeof storageEvent.addListener === "function") {
    storageEvent.addListener(onStorageChanged);
  }

  return {
    getSnapshot: bridge.getSnapshot,
    refresh,
    refreshTarget: bridge.refreshTarget,
    analyze: bridge.analyze,
    reloadAndAnalyze: bridge.reloadAndAnalyze,
    copyTargetUrl: bridge.copyTargetUrl,
    stop() {
      stopped = true;
      unsubscribe();
      if (navigatedEvent && typeof navigatedEvent.removeListener === "function") {
        navigatedEvent.removeListener(onNavigated);
      }
      if (storageEvent && typeof storageEvent.removeListener === "function") {
        storageEvent.removeListener(onStorageChanged);
      }
    }
  };
}

let defaultBridge = null;

function getDefaultBridge() {
  if (!defaultBridge) {
    defaultBridge = createRuntimeBridge({ root: globalThis });
  }
  return defaultBridge;
}

function getSnapshot() {
  return getDefaultBridge().getSnapshot();
}

function subscribe(listener) {
  return getDefaultBridge().subscribe(listener);
}

function refreshTarget() {
  return getDefaultBridge().refreshTarget();
}

function analyze() {
  return getDefaultBridge().analyze();
}

function reloadAndAnalyze() {
  return getDefaultBridge().reloadAndAnalyze();
}

function copyTargetUrl() {
  return getDefaultBridge().copyTargetUrl();
}

const api = {
  SHARED_ADAPTER_REQUIRED_REASON,
  STORAGE_PREFIX,
  analysisStatusLabel,
  buildRuntimeSnapshot,
  captureModeLabel,
  connectRuntimeSnapshot,
  copyTargetUrl,
  createRuntimeBridge,
  createSnapshotFromTargetUrl,
  disconnectedSnapshot,
  getSnapshot,
  mergeSnapshots,
  normalizeStoredSnapshot,
  readSnapshot,
  readStoredSnapshot,
  redactUrl,
  refreshTarget,
  reloadAndAnalyze,
  storageKey,
  subscribe,
  syncStatusLabel,
  targetTypeLabel,
  analyze
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = api;
}

globalThis.BackToolsRuntimeSnapshot = api;
})();
