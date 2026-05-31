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

const snapshotApi = requireApi("./runtimeSnapshot.js") || globalThis.BackToolsRuntimeSnapshot || {};
const reloadApi = requireApi("./reloadAndCapture.js") || globalThis.BackToolsRuntime || {};
const controllerApi = requireApi("./backToolsController.js") || globalThis.BackToolsController || {};
const UNAVAILABLE_REASON = "shared_runtime_not_connected";
const STABLE_STATUSES = new Set(["idle", "running", "complete", "incomplete", "error", "unavailable", "blocked"]);

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

function isObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function normalizeStatus(value, fallback) {
  const status = safeString(value || fallback || "error");
  return STABLE_STATUSES.has(status) ? status : fallback || "error";
}

function redactUrl(value) {
  const text = safeString(value).trim();
  if (!text) {
    return "";
  }
  if (snapshotApi && typeof snapshotApi.redactUrl === "function") {
    try {
      return snapshotApi.redactUrl(text);
    } catch (_error) {
      return "";
    }
  }
  return text.replace(/([?&])([^=&?#]+)=([^&#]*)/g, (match, separator, key) => {
    return /token|auth|password|pass|secret|session|key|code|state/i.test(key)
      ? `${separator}${key}=[redacted]`
      : match;
  });
}

function sanitizeText(value, limit = 320) {
  const text = safeString(value)
    .replace(/https?:\/\/[^\s"'<>]+/g, (match) => redactUrl(match))
    .replace(/chrome-extension:\/\/[^\s"'<>]+/g, (match) => redactUrl(match));
  return text.length > limit ? `${text.slice(0, limit - 1)}...` : text;
}

function normalizeReasonGroups(value) {
  const groups = {};
  if (!isObject(value)) {
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

function levelOf(entry) {
  return safeString(entry && entry.level).toUpperCase();
}

function buildDiagnosticsSummary(input, baseSnapshot) {
  const direct = isObject(input.diagnosticsSummary) ? input.diagnosticsSummary : {};
  const diagnostics = isObject(input.diagnostics) ? input.diagnostics : {};
  const logs = toArray(diagnostics.logs);
  const reasonGroups = normalizeReasonGroups(direct.reasonGroups || diagnostics.reasonGroups);
  const reasonGroupCount = safeNumber(direct.reasonGroupCount ?? Object.keys(reasonGroups).length);
  const logErrorCount = logs.filter((entry) => levelOf(entry) === "ERROR").length;
  const logWarningCount = logs.filter((entry) => ["WARN", "WARNING"].includes(levelOf(entry))).length;
  const fallbackWarningCount = safeNumber(baseSnapshot.captureSummary && baseSnapshot.captureSummary.diagnosticWarningCount);
  const warningCount = safeNumber(direct.warningCount ?? direct.warnings ?? (logWarningCount + reasonGroupCount || fallbackWarningCount));
  const errorCount = safeNumber(direct.errorCount ?? direct.errors ?? logErrorCount);
  const status = direct.status
    ? normalizeStatus(direct.status, "complete")
    : errorCount
      ? "error"
      : warningCount || reasonGroupCount
        ? "incomplete"
        : baseSnapshot.analysis && baseSnapshot.analysis.status === "not_analyzed"
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
  const direct = isObject(input.rawPostureSummary)
    ? input.rawPostureSummary
    : isObject(input.objectDump)
      ? input.objectDump
      : {};
  const dumpObjectsEnabled = Boolean(direct.dumpObjectsEnabled ?? input.dumpObjectsEnabled);
  const cookieValueMode = sanitizeText(direct.cookieValueMode || (dumpObjectsEnabled ? "raw" : "protected"), 80);
  const applicationValueMode = sanitizeText(direct.applicationValueMode || (dumpObjectsEnabled ? "raw" : "protected"), 80);

  return {
    dumpObjectsEnabled,
    cookieValueMode,
    applicationValueMode,
    cookieRawVisibleCount: safeNumber(direct.cookieRawVisibleCount ?? direct.cookiesRawVisible),
    applicationRawVisibleCount: safeNumber(direct.applicationRawVisibleCount ?? direct.applicationRawVisible),
    rawValuesIncluded: Boolean(direct.rawValuesIncluded || direct.containsRawCookies || direct.containsRawApplicationValues)
  };
}

function buildEvidenceSummary(input, baseSnapshot) {
  const direct = isObject(input.evidenceSummary) ? input.evidenceSummary : {};
  const model = isObject(baseSnapshot.evidenceModel) ? baseSnapshot.evidenceModel : {};
  const summary = isObject(model.summary) ? model.summary : direct;

  return {
    available: Boolean(direct.available ?? model.available),
    schemaVersion: safeString(direct.schemaVersion || model.schemaVersion),
    originCount: safeNumber(direct.originCount ?? summary.originCount),
    requestCount: safeNumber(direct.requestCount ?? summary.requestCount),
    resourceCount: safeNumber(direct.resourceCount ?? summary.resourceCount),
    cookieCount: safeNumber(direct.cookieCount ?? summary.cookieCount),
    storageItemCount: safeNumber(direct.storageItemCount ?? summary.storageItemCount),
    diagnosticIssueCount: safeNumber(direct.diagnosticIssueCount ?? summary.diagnosticIssueCount),
    findingCount: safeNumber(direct.findingCount ?? summary.findingCount),
    bodyCapturedCount: safeNumber(direct.bodyCapturedCount ?? summary.bodyCapturedCount),
    bodyUnavailableCount: safeNumber(direct.bodyUnavailableCount ?? summary.bodyUnavailableCount)
  };
}

function fallbackSnapshot(input, root) {
  if (snapshotApi && typeof snapshotApi.disconnectedSnapshot === "function") {
    return snapshotApi.disconnectedSnapshot(root);
  }
  return {
    connected: false,
    source: "shared-runtime-adapter",
    updatedAt: new Date().toISOString(),
    target: {
      connected: false,
      displayUrl: "Unavailable"
    },
    analysis: {
      status: "not_available",
      running: false,
      message: "Runtime snapshot is not available."
    },
    captureSummary: {},
    exportReadiness: {
      blocked: true,
      safeReady: false,
      limitedReport: false,
      reason: "Runtime snapshot is not available."
    },
    notices: [],
    capabilities: {},
    moduleHealth: {},
    sync: {
      status: "not_available"
    }
  };
}

function buildBaseSnapshot(input, root) {
  const source = isObject(input) ? input : {};
  if (snapshotApi && typeof snapshotApi.buildRuntimeSnapshot === "function") {
    try {
      return snapshotApi.buildRuntimeSnapshot(source, {
        root,
        source: source.source || "shared-runtime-adapter",
        urlSource: source.urlSource || "shared_runtime_adapter"
      });
    } catch (_error) {
      return fallbackSnapshot(source, root);
    }
  }
  return fallbackSnapshot(source, root);
}

function summarizeExportReadiness(snapshot) {
  const analysis = isObject(snapshot.analysis) ? snapshot.analysis : {};
  const target = isObject(snapshot.target) ? snapshot.target : {};
  const sync = isObject(snapshot.sync) ? snapshot.sync : {};
  const readiness = isObject(snapshot.exportReadiness) ? snapshot.exportReadiness : {};
  let status = "incomplete";
  let state = "incomplete";
  let reason = sanitizeText(readiness.reason || "");

  if (!snapshot.connected || !target.connected) {
    status = "unavailable";
    state = "unavailable";
    reason = reason || "Runtime snapshot is not available.";
  } else if (analysis.running || analysis.status === "running") {
    status = "running";
    state = "running";
    reason = reason || "Analysis is running.";
  } else if (analysis.status === "not_analyzed") {
    status = "blocked";
    state = "not_analyzed";
    reason = reason || "Analyze the target before exporting.";
  } else if (target.isOutOfSync || sync.status === "out_of_sync") {
    status = "blocked";
    state = "stale";
    reason = reason || "Target changed since the last analysis.";
  } else if (analysis.status === "error") {
    status = "error";
    state = "error";
    reason = reason || "Analysis failed. Re-run analysis before exporting.";
  } else if (readiness.safeReady && !readiness.blocked) {
    status = "complete";
    state = "ready";
    reason = reason || "Safe export is ready.";
  } else if (readiness.blocked) {
    status = "blocked";
    state = "blocked";
    reason = reason || "Export is blocked.";
  }

  return {
    status,
    state,
    blocked: status === "blocked" || Boolean(readiness.blocked),
    safeReady: status === "complete" && Boolean(readiness.safeReady),
    limitedReport: Boolean(readiness.limitedReport),
    reason
  };
}

function sanitizeSnapshot(input, root) {
  const source = isObject(input) ? input : {};
  const baseSnapshot = buildBaseSnapshot(source, root);
  const snapshot = {
    version: 1,
    connected: Boolean(baseSnapshot.connected),
    source: sanitizeText(source.source || baseSnapshot.source || "shared-runtime-adapter", 120),
    updatedAt: safeString(baseSnapshot.updatedAt || source.updatedAt || new Date().toISOString()),
    target: baseSnapshot.target || {},
    analysis: baseSnapshot.analysis || {},
    captureSummary: baseSnapshot.captureSummary || {},
    evidenceSummary: buildEvidenceSummary(source, baseSnapshot),
    exportReadiness: baseSnapshot.exportReadiness || {},
    diagnosticsSummary: buildDiagnosticsSummary(source, baseSnapshot),
    notices: toArray(baseSnapshot.notices).slice(0, 12),
    capabilities: baseSnapshot.capabilities || {},
    rawPostureSummary: buildRawPostureSummary(source),
    moduleHealth: baseSnapshot.moduleHealth || {},
    sync: baseSnapshot.sync || {}
  };
  snapshot.exportReadiness = summarizeExportReadiness(snapshot);
  return snapshot;
}

function unavailableResult(action, snapshot, message) {
  return {
    ok: false,
    status: "unavailable",
    reason: UNAVAILABLE_REASON,
    message: sanitizeText(message || "The shared production runtime is not connected."),
    action,
    snapshot
  };
}

function errorResult(action, snapshot, reason, message) {
  return {
    ok: false,
    status: "error",
    reason: sanitizeText(reason || "runtime_action_failed", 120),
    message: sanitizeText(message || "Runtime action failed."),
    action,
    snapshot
  };
}

function completeResult(action, snapshot, extra) {
  return {
    ok: true,
    status: "complete",
    action,
    snapshot,
    ...(isObject(extra) ? extra : {})
  };
}

function successfulResult(action, status, snapshot, extra) {
  return {
    ok: true,
    status: normalizeStatus(status, "complete"),
    action,
    snapshot,
    ...(isObject(extra) ? extra : {})
  };
}

function resultExtras(result) {
  if (!isObject(result)) {
    return {};
  }
  const extras = {};
  Object.entries(result).forEach(([key, value]) => {
    if (!["ok", "status", "action", "snapshot", "reason", "message"].includes(key)) {
      extras[key] = value;
    }
  });
  return extras;
}

function controllerFromOptions(root, options = {}) {
  if (options.controller) {
    return options.controller;
  }
  if (root.BackToolsRuntimeController || root.BackToolsProductionRuntimeController) {
    return root.BackToolsRuntimeController || root.BackToolsProductionRuntimeController;
  }
  const rootControllerApi = root.BackToolsController || controllerApi;
  if (rootControllerApi && typeof rootControllerApi.getOrCreateBackToolsController === "function") {
    try {
      return rootControllerApi.getOrCreateBackToolsController(root);
    } catch (_error) {
      return null;
    }
  }
  return null;
}

function findControllerAction(controller, names) {
  if (!controller) {
    return null;
  }
  return names.map((name) => controller[name]).find((value) => typeof value === "function") || null;
}

function platformFromRoot(root) {
  return Object.assign({}, globalThis.BackToolsPlatform || {}, root && root.BackToolsPlatform || {});
}

function canReloadInspectedWindow(root) {
  const adapter = platformFromRoot(root);
  const inspectedWindow = root && root.chrome && root.chrome.devtools ? root.chrome.devtools.inspectedWindow : null;
  return typeof adapter.reloadInspectedWindow === "function" ||
    Boolean(inspectedWindow && typeof inspectedWindow.reload === "function");
}

function canReadInspectedUrl(root) {
  const adapter = platformFromRoot(root);
  const inspectedWindow = root && root.chrome && root.chrome.devtools ? root.chrome.devtools.inspectedWindow : null;
  return typeof adapter.evalInspectedUrl === "function" ||
    Boolean(inspectedWindow && typeof inspectedWindow.eval === "function");
}

function actionCapabilities(controller, root) {
  const canAnalyze = Boolean(findControllerAction(controller, ["analyze"]));
  const canReloadDirectly = Boolean(findControllerAction(controller, ["reloadAndCapture", "reloadAndAnalyze"]));
  const canReloadThroughAnalyze = canAnalyze &&
    typeof reloadApi.reloadAndAnalyze === "function" &&
    canReloadInspectedWindow(root) &&
    canReadInspectedUrl(root);
  const clipboard = root && root.navigator && root.navigator.clipboard;

  return {
    analyze: canAnalyze,
    reloadAndCapture: canReloadDirectly || canReloadThroughAnalyze,
    copyTargetUrl: Boolean(findControllerAction(controller, ["copyTargetUrl"]) || clipboard && typeof clipboard.writeText === "function")
  };
}

function applyActionCapabilities(snapshot, controller, root) {
  const currentCapabilities = isObject(snapshot.capabilities) ? snapshot.capabilities : {};
  return {
    ...snapshot,
    capabilities: {
      ...currentCapabilities,
      actions: actionCapabilities(controller, root)
    }
  };
}

function readTargetUrl(root) {
  const adapter = platformFromRoot(root);
  if (typeof adapter.evalInspectedUrl === "function") {
    return adapter.evalInspectedUrl();
  }
  const inspectedWindow = root && root.chrome && root.chrome.devtools ? root.chrome.devtools.inspectedWindow : null;
  if (!inspectedWindow || typeof inspectedWindow.eval !== "function") {
    return Promise.resolve(null);
  }
  return new Promise((resolve) => {
    try {
      inspectedWindow.eval("location.href", (result, exception) => {
        resolve(exception && (exception.isException || exception.isError) ? null : result || null);
      });
    } catch (_error) {
      resolve(null);
    }
  });
}

function reloadInspectedWindow(root, options) {
  const adapter = platformFromRoot(root);
  if (typeof adapter.reloadInspectedWindow === "function") {
    return adapter.reloadInspectedWindow(options);
  }
  const inspectedWindow = root && root.chrome && root.chrome.devtools ? root.chrome.devtools.inspectedWindow : null;
  if (inspectedWindow && typeof inspectedWindow.reload === "function") {
    return inspectedWindow.reload(options);
  }
  return undefined;
}

function normalizeControllerResult(action, result, snapshot, setSnapshot) {
  const nextSnapshot = result && result.snapshot ? setSnapshot(result.snapshot) : snapshot;
  const rawStatus = safeString(result && result.status);
  if (result && result.ok === false) {
    return {
      ok: false,
      status: normalizeStatus(rawStatus, "error"),
      reason: sanitizeText(result.reason || "runtime_action_failed", 120),
      message: sanitizeText(result.message || "Runtime action failed."),
      action,
      snapshot: nextSnapshot
    };
  }
  if (rawStatus === "running") {
    return {
      ok: false,
      status: "running",
      reason: sanitizeText(result.reason || "runtime_action_running", 120),
      message: sanitizeText(result.message || "Runtime action is already running."),
      action,
      snapshot: nextSnapshot
    };
  }
  if (rawStatus === "not_available" || rawStatus === "unavailable") {
    return unavailableResult(action, nextSnapshot, result && result.message);
  }
  if (result && (result.ok === true || rawStatus === "ok" || rawStatus === "complete" || rawStatus === "incomplete")) {
    const analysisStatus = nextSnapshot && nextSnapshot.analysis && nextSnapshot.analysis.status;
    const status = rawStatus === "ok" ? analysisStatus || "complete" : rawStatus || analysisStatus || "complete";
    return successfulResult(action, status, nextSnapshot, resultExtras(result));
  }
  return completeResult(action, nextSnapshot);
}

function createBackToolsRuntimeAdapter(options = {}) {
  const root = options.root || globalThis;
  const listeners = new Set();
  const configuredController = options.controller || null;
  let adapterReady = false;
  let activeController = null;
  let unsubscribeController = null;
  let syncingControllerSnapshot = false;

  function bindController(controller) {
    if (!adapterReady || controller === activeController) {
      return;
    }
    if (typeof unsubscribeController === "function") {
      unsubscribeController();
    }
    activeController = controller || null;
    unsubscribeController = null;
    if (!controller || typeof controller.subscribe !== "function") {
      return;
    }
    unsubscribeController = controller.subscribe((nextSnapshot) => {
      if (syncingControllerSnapshot) {
        return;
      }
      syncingControllerSnapshot = true;
      try {
        snapshot = applyActionCapabilities(sanitizeSnapshot(nextSnapshot || {}, root), controller, root);
        emit();
      } finally {
        syncingControllerSnapshot = false;
      }
    });
  }

  function getController() {
    const controller = configuredController || controllerFromOptions(root, {});
    bindController(controller);
    return controller;
  }

  function buildAdapterSnapshot(nextSnapshot) {
    return applyActionCapabilities(sanitizeSnapshot(nextSnapshot || {}, root), getController(), root);
  }

  let snapshot = buildAdapterSnapshot(options.initialSnapshot || fallbackSnapshot({}, root));
  adapterReady = true;
  bindController(getController());

  function emit() {
    listeners.forEach((listener) => {
      try {
        listener(snapshot);
      } catch (_error) {}
    });
  }

  function setSnapshot(nextSnapshot) {
    snapshot = buildAdapterSnapshot(nextSnapshot || {});
    emit();
    return snapshot;
  }

  async function runControllerAction(action, names) {
    const controller = getController();
    const handler = findControllerAction(controller, names);
    if (!handler) {
      return unavailableResult(action, snapshot);
    }
    try {
      const result = await handler.call(controller);
      return normalizeControllerResult(action, result, snapshot, setSnapshot);
    } catch (_error) {
      return errorResult(action, snapshot, "runtime_action_failed", "Runtime action failed.");
    }
  }

  async function runReloadThroughAnalyze() {
    const controller = getController();
    const analyzeHandler = findControllerAction(controller, ["analyze"]);
    if (!analyzeHandler || typeof reloadApi.reloadAndAnalyze !== "function" || !canReloadInspectedWindow(root) || !canReadInspectedUrl(root)) {
      return unavailableResult("reloadAndCapture", snapshot);
    }
    try {
      const result = await reloadApi.reloadAndAnalyze({
        root,
        reload: (reloadOptions) => reloadInspectedWindow(root, reloadOptions),
        evalUrl: () => readTargetUrl(root),
        analyze: () => analyzeHandler.call(controller)
      });
      if (result && result.ok === false && !result.snapshot && result.analyzeResult) {
        return normalizeControllerResult("reloadAndCapture", result.analyzeResult, snapshot, setSnapshot);
      }
      return normalizeControllerResult("reloadAndCapture", result && result.analyzeResult ? result.analyzeResult : result, snapshot, setSnapshot);
    } catch (_error) {
      return errorResult("reloadAndCapture", snapshot, "runtime_action_failed", "Runtime action failed.");
    }
  }

  return {
    getSnapshot() {
      snapshot = applyActionCapabilities(snapshot, getController(), root);
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
    async refreshTarget() {
      const controller = getController();
      const controllerRefresh = findControllerAction(controller, ["refreshTarget"]);
      if (controllerRefresh) {
        return runControllerAction("refreshTarget", ["refreshTarget"]);
      }
      if (!snapshotApi || typeof snapshotApi.readSnapshot !== "function") {
        return unavailableResult("refreshTarget", snapshot);
      }
      try {
        const nextSnapshot = await snapshotApi.readSnapshot(root);
        return completeResult("refreshTarget", setSnapshot(nextSnapshot));
      } catch (_error) {
        return errorResult("refreshTarget", snapshot, "runtime_snapshot_failed", "Runtime snapshot refresh failed.");
      }
    },
    analyze() {
      return runControllerAction("analyze", ["analyze"]);
    },
    reloadAndCapture() {
      const controller = getController();
      if (findControllerAction(controller, ["reloadAndCapture", "reloadAndAnalyze"])) {
        return runControllerAction("reloadAndCapture", ["reloadAndCapture", "reloadAndAnalyze"]);
      }
      return runReloadThroughAnalyze();
    },
    getExportReadiness() {
      return snapshot.exportReadiness;
    },
    getDiagnosticsSummary() {
      return snapshot.diagnosticsSummary;
    },
    async copyTargetUrl() {
      const controller = getController();
      const handler = findControllerAction(controller, ["copyTargetUrl"]);
      if (handler) {
        return runControllerAction("copyTargetUrl", ["copyTargetUrl"]);
      }
      const value = snapshot.target && (snapshot.target.urlRedacted || snapshot.target.redactedUrl || snapshot.target.url);
      const clipboard = root.navigator && root.navigator.clipboard;
      if (!value || !clipboard || typeof clipboard.writeText !== "function") {
        return {
          ok: false,
          status: "unavailable",
          reason: value ? "clipboard_unavailable" : "target_url_unavailable",
          message: value ? "Clipboard access is not available." : "Target URL is not available.",
          action: "copyTargetUrl",
          snapshot
        };
      }
      try {
        await clipboard.writeText(value);
        return completeResult("copyTargetUrl", snapshot, { copiedUrl: value });
      } catch (_error) {
        return errorResult("copyTargetUrl", snapshot, "copy_target_url_failed", "Copy target URL failed.");
    }
    },
    stop() {
      if (typeof unsubscribeController === "function") {
        unsubscribeController();
      }
      unsubscribeController = null;
      activeController = null;
      listeners.clear();
    }
  };
}

function snapshotStorageKey(root) {
  if (snapshotApi && typeof snapshotApi.storageKey === "function") {
    try {
      return snapshotApi.storageKey(root);
    } catch (_error) {
      return null;
    }
  }
  return null;
}

function connectRuntimeAdapter(callback, options) {
  const settings = options || {};
  const root = settings.root || globalThis;
  const adapter = createBackToolsRuntimeAdapter({
    root,
    controller: settings.controller,
    initialSnapshot: settings.initialSnapshot
  });
  let stopped = false;
  const unsubscribe = adapter.subscribe((snapshot) => {
    if (!stopped && typeof callback === "function") {
      callback(snapshot);
    }
  });

  function refresh() {
    return adapter.refreshTarget();
  }

  void refresh();

  const navigatedEvent = root.chrome && root.chrome.devtools && root.chrome.devtools.network
    ? root.chrome.devtools.network.onNavigated
    : null;
  const onNavigated = () => {
    void refresh();
  };

  if (navigatedEvent && typeof navigatedEvent.addListener === "function") {
    navigatedEvent.addListener(onNavigated);
  }

  const storageEvent = root.chrome && root.chrome.storage ? root.chrome.storage.onChanged : null;
  const key = snapshotStorageKey(root);
  const onStorageChanged = (changes, areaName) => {
    if (areaName && areaName !== "local") {
      return;
    }
    if (key && changes && !Object.prototype.hasOwnProperty.call(changes, key)) {
      return;
    }
    void refresh();
  };

  if (storageEvent && typeof storageEvent.addListener === "function") {
    storageEvent.addListener(onStorageChanged);
  }

  return {
    getSnapshot: adapter.getSnapshot,
    refresh,
    refreshTarget: adapter.refreshTarget,
    analyze: adapter.analyze,
    reloadAndCapture: adapter.reloadAndCapture,
    reloadAndAnalyze: adapter.reloadAndCapture,
    copyTargetUrl: adapter.copyTargetUrl,
    stop() {
      stopped = true;
      unsubscribe();
      if (typeof adapter.stop === "function") {
        adapter.stop();
      }
      if (navigatedEvent && typeof navigatedEvent.removeListener === "function") {
        navigatedEvent.removeListener(onNavigated);
      }
      if (storageEvent && typeof storageEvent.removeListener === "function") {
        storageEvent.removeListener(onStorageChanged);
      }
    }
  };
}

let defaultAdapter = null;

function getDefaultAdapter() {
  if (!defaultAdapter) {
    defaultAdapter = createBackToolsRuntimeAdapter({ root: globalThis });
  }
  return defaultAdapter;
}

function getSnapshot() {
  return getDefaultAdapter().getSnapshot();
}

function subscribe(listener) {
  return getDefaultAdapter().subscribe(listener);
}

function refreshTarget() {
  return getDefaultAdapter().refreshTarget();
}

function analyze() {
  return getDefaultAdapter().analyze();
}

function reloadAndCapture() {
  return getDefaultAdapter().reloadAndCapture();
}

function getExportReadiness() {
  return getDefaultAdapter().getExportReadiness();
}

function getDiagnosticsSummary() {
  return getDefaultAdapter().getDiagnosticsSummary();
}

function copyTargetUrl() {
  return getDefaultAdapter().copyTargetUrl();
}

const api = {
  UNAVAILABLE_REASON,
  connectRuntimeAdapter,
  copyTargetUrl,
  createBackToolsRuntimeAdapter,
  createRuntimeAdapter: createBackToolsRuntimeAdapter,
  getDiagnosticsSummary,
  getExportReadiness,
  getSnapshot,
  refreshTarget,
  reloadAndCapture,
  sanitizeSnapshot,
  subscribe,
  analyze
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = api;
}

globalThis.BackToolsRuntimeAdapter = api;
})();
