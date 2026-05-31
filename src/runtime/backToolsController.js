(function (root, factory) {
  const api = factory(root);
  root.BackToolsController = Object.assign(root.BackToolsController || {}, api);
  if (api.canCreateBackToolsController(root) && !root.BackToolsRuntimeController) {
    root.BackToolsRuntimeController = api.getOrCreateBackToolsController(root);
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : window, function (root) {
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

  const targetDomain = requireApi("../domain/targetClassification.js");
  const redactionDomain = requireApi("../domain/redaction.js");
  const resourceDomain = requireApi("../domain/resourceClassification.js");
  const exportPlanDomain = requireApi("../domain/exportPlan.js");
  const inspectedPlatform = requireApi("../platform/inspectedWindowAdapter.js");
  const networkPlatform = requireApi("../platform/devtoolsNetworkAdapter.js");
  const sourcesCollector = requireApi("../collectors/sourcesCollector.js");
  const networkCollector = requireApi("../collectors/networkCollector.js");
  const cookiesCollector = requireApi("../collectors/cookiesCollector.js");
  const applicationCollector = requireApi("../collectors/applicationCollector.js");
  const snapshotApi = requireApi("./runtimeSnapshot.js");
  const reloadApi = requireApi("./reloadAndCapture.js");

  const defaultExportOptions = {
    includeSources: true,
    includeNetwork: true,
    includeDiagnostics: false,
    includeApplication: true,
    includeBrowserInternalMetadata: false,
    includeExtensionMetadata: false,
    includeExtensionResources: false,
    includeBrowserInternalResources: false,
    includeDevtoolsInternalResources: false,
    includeMetadataInManifest: true,
    includeFailedReport: false,
    includeLogsJson: false,
    includeNetworkSummary: true,
    preserveHostPath: true,
    filenameStrategy: "safe-category-path",
    exportAsZip: true,
    includeDataUrls: true,
    includeCookiesReport: true,
    includeStaticSourceAssets: false,
    includeCookieHtmlReport: false,
    cookieExportMode: "sanitized_only",
    applicationExportMode: "sanitized_only"
  };

  const controllerCache = new WeakMap();
  const MIN_SCAN_SECONDS = 1;
  const MAX_SCAN_SECONDS = 20;
  const DEFAULT_SCAN_SECONDS = 5;

  function safeString(value) {
    return value === null || value === undefined ? "" : String(value);
  }

  function safeNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) && number > 0 ? number : 0;
  }

  function normalizeScanDurationSeconds(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) {
      return DEFAULT_SCAN_SECONDS;
    }
    return Math.min(MAX_SCAN_SECONDS, Math.max(MIN_SCAN_SECONDS, Math.round(number)));
  }

  function wait(ms, runtimeRoot) {
    return new Promise((resolve) => {
      const timer = runtimeRoot && typeof runtimeRoot.setTimeout === "function"
        ? runtimeRoot.setTimeout.bind(runtimeRoot)
        : setTimeout;
      timer(resolve, Math.max(0, Number(ms) || 0));
    });
  }

  function withTimeout(promise, ms, runtimeRoot) {
    let timerId = null;
    const timerApi = runtimeRoot && typeof runtimeRoot.setTimeout === "function"
      ? runtimeRoot
      : globalThis;
    const clearApi = runtimeRoot && typeof runtimeRoot.clearTimeout === "function"
      ? runtimeRoot
      : globalThis;
    const timeout = new Promise((resolve) => {
      timerId = timerApi.setTimeout(() => resolve({ timedOut: true }), Math.max(0, Number(ms) || 0));
    });
    return Promise.race([
      Promise.resolve(promise).then(
        () => ({ timedOut: false }),
        (error) => ({ timedOut: false, error })
      ),
      timeout
    ]).finally(() => {
      if (timerId != null && typeof clearApi.clearTimeout === "function") {
        clearApi.clearTimeout(timerId);
      }
    });
  }

  function toArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function clone(value) {
    if (typeof structuredClone === "function") {
      return structuredClone(value);
    }
    return JSON.parse(JSON.stringify(value));
  }

  function createFrozenExportState(state) {
    return {
      ...state,
      target: {
        ...(state.target || {})
      },
      analysis: {
        ...(state.analysis || {})
      },
      capture: {
        ...(state.capture || {})
      },
      export: {
        ...(state.export || {}),
        options: {
          ...(state.export?.options || {})
        }
      },
      network: {
        ...(state.network || {}),
        policy: {
          ...(state.network?.policy || {})
        },
        entries: Array.isArray(state.network?.entries) ? state.network.entries : []
      },
      sources: {
        ...(state.sources || {}),
        resources: Array.isArray(state.sources?.resources) ? state.sources.resources : []
      },
      cookies: {
        ...(state.cookies || {}),
        summary: { ...(state.cookies?.summary || {}) },
        findings: Array.isArray(state.cookies?.findings) ? state.cookies.findings : [],
        observedCookies: Array.isArray(state.cookies?.observedCookies) ? state.cookies.observedCookies : [],
        rawRecords: Array.isArray(state.cookies?.rawRecords) ? state.cookies.rawRecords : []
      },
      application: state.application || {},
      diagnostics: {
        ...(state.diagnostics || {}),
        logs: Array.isArray(state.diagnostics?.logs) ? state.diagnostics.logs : [],
        reasonGroups: { ...(state.diagnostics?.reasonGroups || {}) }
      }
    };
  }


  function browserLabel(runtimeRoot) {
    const userAgent = safeString(runtimeRoot && runtimeRoot.navigator && runtimeRoot.navigator.userAgent);
    const edgeMatch = /Edg\/(\d+[.\d]*)/.exec(userAgent);
    if (edgeMatch) {
      return `Edge/${edgeMatch[1]}`;
    }
    const chromeMatch = /Chrome\/(\d+[.\d]*)/.exec(userAgent);
    if (chromeMatch) {
      return `Chrome/${chromeMatch[1]}`;
    }
    return userAgent ? "Browser runtime" : "";
  }

  function directPlatform(runtimeRoot) {
    return {
      evalInspectedUrl() {
        return new Promise((resolve) => {
          try {
            const inspectedWindow = runtimeRoot && runtimeRoot.chrome && runtimeRoot.chrome.devtools
              ? runtimeRoot.chrome.devtools.inspectedWindow
              : null;
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
      },
      evalInInspectedWindow(expression, options) {
        return new Promise((resolve) => {
          try {
            const inspectedWindow = runtimeRoot && runtimeRoot.chrome && runtimeRoot.chrome.devtools
              ? runtimeRoot.chrome.devtools.inspectedWindow
              : null;
            if (!inspectedWindow || typeof inspectedWindow.eval !== "function") {
              resolve({
                ok: false,
                result: null,
                exception: null,
                error: "inspected_window_eval_unavailable"
              });
              return;
            }
            const callback = (result, exception) => {
              const failed = Boolean(exception && (exception.isException || exception.isError));
              resolve({
                ok: !failed,
                result: failed ? null : result,
                exception: exception || null,
                error: failed ? exception.description || exception.value || "Inspected window eval failed." : null
              });
            };
            if (options && Object.keys(options).length) {
              inspectedWindow.eval(expression, options, callback);
            } else {
              inspectedWindow.eval(expression, callback);
            }
          } catch (_error) {
            resolve({
              ok: false,
              result: null,
              exception: null,
              error: "inspected_window_eval_unavailable"
            });
          }
        });
      },
      getResources() {
        return new Promise((resolve) => {
          try {
            const inspectedWindow = runtimeRoot && runtimeRoot.chrome && runtimeRoot.chrome.devtools
              ? runtimeRoot.chrome.devtools.inspectedWindow
              : null;
            if (!inspectedWindow || typeof inspectedWindow.getResources !== "function") {
              resolve([]);
              return;
            }
            inspectedWindow.getResources((resources) => {
              resolve(Array.isArray(resources) ? resources : []);
            });
          } catch (_error) {
            resolve([]);
          }
        });
      },
      getResourceContent(resource) {
        return new Promise((resolve) => {
          try {
            if (!resource || typeof resource.getContent !== "function") {
              resolve({ content: null, encoding: null, error: "resource_content_unavailable" });
              return;
            }
            resource.getContent((content, encoding) => {
              const lastError = runtimeRoot && runtimeRoot.chrome && runtimeRoot.chrome.runtime
                ? runtimeRoot.chrome.runtime.lastError
                : null;
              resolve({ content, encoding, error: lastError && lastError.message || null });
            });
          } catch (_error) {
            resolve({ content: null, encoding: null, error: "resource_content_unavailable" });
          }
        });
      },
      reloadInspectedWindow(options) {
        const inspectedWindow = runtimeRoot && runtimeRoot.chrome && runtimeRoot.chrome.devtools
          ? runtimeRoot.chrome.devtools.inspectedWindow
          : null;
        if (inspectedWindow && typeof inspectedWindow.reload === "function") {
          inspectedWindow.reload(options);
        }
      },
      getHar() {
        return new Promise((resolve) => {
          try {
            const network = runtimeRoot && runtimeRoot.chrome && runtimeRoot.chrome.devtools
              ? runtimeRoot.chrome.devtools.network
              : null;
            if (!network || typeof network.getHAR !== "function") {
              resolve({ entries: [], unavailable: true, reason: "network_har_unavailable" });
              return;
            }
            network.getHAR((har) => resolve(har || { entries: [] }));
          } catch (_error) {
            resolve({ entries: [], unavailable: true, reason: "network_har_unavailable" });
          }
        });
      },
      addRequestFinishedListener(listener) {
        const event = runtimeRoot && runtimeRoot.chrome && runtimeRoot.chrome.devtools && runtimeRoot.chrome.devtools.network
          ? runtimeRoot.chrome.devtools.network.onRequestFinished
          : null;
        if (!event || typeof event.addListener !== "function") {
          return () => {};
        }
        event.addListener(listener);
        return () => {
          if (typeof event.removeListener === "function") {
            event.removeListener(listener);
          }
        };
      },
      getRequestContent(request, options = {}) {
        const timeoutMs = options.timeoutMs || 3000;
        return new Promise((resolve, reject) => {
          if (!request || typeof request.getContent !== "function") {
            resolve({
              ok: false,
              status: "platform_unavailable",
              reason: "GET_CONTENT_UNAVAILABLE"
            });
            return;
          }
          let done = false;
          const timer = setTimeout(() => {
            if (done) {
              return;
            }
            done = true;
            reject(new Error("GET_CONTENT_TIMEOUT"));
          }, timeoutMs);
          try {
            request.getContent((content, encoding) => {
              if (done) {
                return;
              }
              done = true;
              clearTimeout(timer);
              resolve({
                ok: true,
                content,
                encoding: encoding || ""
              });
            });
          } catch (error) {
            if (done) {
              return;
            }
            done = true;
            clearTimeout(timer);
            reject(error);
          }
        });
      }
    };
  }

  function apisForRoot(runtimeRoot, options = {}) {
    const domain = mergeApis(
      targetDomain,
      redactionDomain,
      resourceDomain,
      exportPlanDomain,
      root.BackToolsDomain,
      runtimeRoot && runtimeRoot.BackToolsDomain,
      options.domain
    );
    const collectors = mergeApis(
      sourcesCollector,
      networkCollector,
      cookiesCollector,
      applicationCollector,
      root.BackToolsCollectors,
      runtimeRoot && runtimeRoot.BackToolsCollectors,
      options.collectors
    );
    const platform = mergeApis(
      inspectedPlatform,
      networkPlatform,
      directPlatform(runtimeRoot),
      root.BackToolsPlatform,
      runtimeRoot && runtimeRoot.BackToolsPlatform,
      options.platform
    );
    const snapshot = mergeApis(
      snapshotApi,
      root.BackToolsRuntimeSnapshot,
      runtimeRoot && runtimeRoot.BackToolsRuntimeSnapshot,
      options.snapshot
    );
    const reload = mergeApis(
      reloadApi,
      root.BackToolsRuntime,
      runtimeRoot && runtimeRoot.BackToolsRuntime,
      options.reload
    );
    return { domain, collectors, platform, snapshot, reload };
  }

  function classifyTarget(domain, rawUrl, urlSource) {
    if (typeof domain.classifyTargetUrl === "function") {
      return domain.classifyTargetUrl(rawUrl, { urlSource: urlSource || "inspected_window_eval_location_href" });
    }
    const isWeb = /^https?:/i.test(safeString(rawUrl));
    return {
      targetType: isWeb ? "web_https" : "unknown",
      targetUrl: rawUrl || null,
      normalizedUrl: rawUrl || null,
      isNormalWebTarget: isWeb,
      isLimitedTarget: !isWeb,
      isEmptyTarget: !rawUrl,
      classificationReason: isWeb ? null : "target_empty_url",
      captureMode: isWeb ? "web_full_available" : "unknown_target_report_only",
      statusLabel: isWeb ? "Supported web target" : "Empty target",
      message: isWeb ? "Supported web target." : "Target not identified yet. Back Tools will run a limited analysis.",
      urlSource
    };
  }

  function targetsAreSame(domain, first, second) {
    if (typeof domain.targetsAreSame === "function") {
      return domain.targetsAreSame(first, second);
    }
    return safeString(first && (first.normalizedUrl || first.targetUrl)) === safeString(second && (second.normalizedUrl || second.targetUrl)) &&
      safeString(first && first.targetType) === safeString(second && second.targetType);
  }

  function targetCapabilities(target) {
    if (target && target.isNormalWebTarget) {
      return ["Sources API", "Network HAR", "Network body capture", "Application storage"];
    }
    return ["Limited report", "Network HAR when available", "Diagnostics export"];
  }

  function buildModuleStatuses(domain, state, analyzed) {
    if (typeof domain.buildModuleStatuses === "function") {
      return domain.buildModuleStatuses({
        target: state.target.analyzed || state.target.current,
        analyzed,
        sources: state.sources.resources,
        network: state.network.entries,
        cookiesSummary: state.cookies.summary,
        application: state.application
      });
    }
    return {};
  }

  function getRedactedUrl(domain, url) {
    if (typeof domain.redactUrl === "function") {
      return domain.redactUrl(url || "");
    }
    return url || "";
  }

  function emptyApplicationState() {
    return {
      status: "not_collected",
      summary: {},
      localStorage: { entries: [] },
      sessionStorage: { entries: [] },
      indexedDB: { databases: [] },
      cacheStorage: { caches: [] },
      serviceWorkers: { registrations: [] },
      manifest: {},
      observations: [],
      rawExportConfirmedAt: null,
      rawExportScope: null
    };
  }

  function createInitialState(domain, runtimeRoot) {
    const initialTarget = classifyTarget(domain, null, "initial_unknown");
    return {
      target: {
        currentUrl: null,
        analyzedUrl: null,
        current: initialTarget,
        analyzed: null,
        isOutOfSync: false,
        browser: browserLabel(runtimeRoot),
        capabilities: targetCapabilities(initialTarget),
        moduleStatuses: {}
      },
      analysis: {
        phase: "Idle",
        status: "not_analyzed",
        running: false,
        lastRunAt: null
      },
      capture: {
        scanDurationSeconds: DEFAULT_SCAN_SECONDS
      },
      dumpObjectsEnabled: false,
      dumpObjectsEnabledAt: null,
      sources: {
        resources: [],
        moduleStatus: null
      },
      network: {
        entries: [],
        policy: null,
        moduleStatus: null,
        captureState: "stopped",
        lastFrozenAt: null,
        liveUpdateThrottleMs: 350
      },
      diagnostics: {
        logs: [],
        reasonGroups: {}
      },
      export: {
        options: clone(defaultExportOptions),
        lastStatus: "Not exported",
        lastPlan: null,
        running: false,
        phase: "Idle",
        startedAt: null,
        finishedAt: null,
        lastError: null,
        progress: {
          current: 0,
          total: 0,
          label: ""
        },
        jobId: null
      },
      cookies: {
        rawValuesAvailable: false,
        revealedCookieIds: [],
        needsReanalyze: false,
        rawExportConfirmedAt: null,
        rawExportScope: null,
        rawRecords: [],
        observedCookies: [],
        filteredCookies: [],
        findings: [],
        summary: {}
      },
      application: emptyApplicationState()
    };
  }

  function runtimeModuleHealthItem(value, fallbackStatus, fallbackMessage) {
    return {
      status: value && value.status || fallbackStatus,
      reason: value && value.reason || null,
      message: value && value.message || fallbackMessage,
      count: safeNumber(value && value.items)
    };
  }

  function summarizeResources(domain, rows) {
    if (typeof domain.summarizeResources === "function") {
      return domain.summarizeResources(rows || []);
    }
    const values = toArray(rows);
    return {
      total: values.length,
      readable: values.filter((row) => row && (row.exportable || row.status === "readable")).length,
      exportable: values.filter((row) => row && row.exportable).length
    };
  }

  function summarizeNetwork(collectors, rows) {
    if (typeof collectors.summarizeNetworkCapture === "function") {
      return collectors.summarizeNetworkCapture(rows || []);
    }
    const summary = {
      bodyCaptured: 0,
      metadataOnly: 0,
      platformUnavailable: 0,
      readFailed: 0
    };
    toArray(rows).forEach((row) => {
      const status = safeString(row && (row.bodyCaptureStatus || row.status));
      if (status === "body_captured") {
        summary.bodyCaptured += 1;
      } else if (status === "metadata_only") {
        summary.metadataOnly += 1;
      } else if (status === "platform_unavailable") {
        summary.platformUnavailable += 1;
      } else if (status === "read_failed") {
        summary.readFailed += 1;
      }
    });
    return summary;
  }

  function buildReasonGroups(domain, state) {
    const groups = typeof domain.buildReasonGroups === "function"
      ? domain.buildReasonGroups([...(state.sources.resources || []), ...(state.network.entries || [])])
      : {};
    Object.values(state.target.moduleStatuses || {}).forEach((moduleStatus) => {
      if (moduleStatus && moduleStatus.reason) {
        groups[moduleStatus.reason] = (groups[moduleStatus.reason] || 0) + 1;
      }
    });
    state.diagnostics.reasonGroups = groups;
  }

  function computeAnalysisStatus(state) {
    const combined = [...(state.sources.resources || []), ...(state.network.entries || [])];
    const hasHardFailures = combined.some((row) => {
      const status = safeString(row && row.status);
      const bodyStatus = safeString(row && row.bodyCaptureStatus);
      if (bodyStatus && ["platform_unavailable", "read_failed"].includes(bodyStatus)) {
        return true;
      }
      return ["unavailable", "failed", "error"].includes(status);
    });
    const appPartial = state.application.status === "partial" || state.application.status === "platform_unavailable";
    const appUnavailableExpected = state.target.analyzed && state.target.analyzed.isLimitedTarget && state.application.status === "platform_unavailable";
    return hasHardFailures || appPartial && !appUnavailableExpected ? "incomplete" : "complete";
  }

  function createSnapshotBuilder({ domain, collectors, platform, snapshot }, state, runtimeRoot) {
    function buildRuntimeModuleHealth() {
      const statuses = state.target.moduleStatuses || {};
      const warningCount = Object.keys(state.diagnostics.reasonGroups || {}).length;
      const errorCount = (state.diagnostics.logs || []).filter((entry) => entry.level === "ERROR").length;
      const analyzed = state.analysis.status !== "not_analyzed";
      return {
        sources: runtimeModuleHealthItem(statuses.sources, "not_collected", "Sources have not been analyzed yet."),
        network: runtimeModuleHealthItem(statuses.network, "not_collected", "Network has not been analyzed yet."),
        cookies: runtimeModuleHealthItem(statuses.cookies, "not_collected", "Cookies have not been analyzed yet."),
        application: runtimeModuleHealthItem(statuses.application, "not_collected", "Application storage has not been analyzed yet."),
        diagnostics: {
          status: errorCount ? "failed" : warningCount ? "warnings" : analyzed ? "ready" : "not_collected",
          reason: null,
          message: errorCount ? "Diagnostics contain errors." : warningCount ? "Diagnostics contain warnings." : analyzed ? "Diagnostics are ready." : "Diagnostics have not been analyzed yet.",
          count: warningCount + errorCount
        }
      };
    }

    function buildRuntimeCaptureSummary() {
      const sourceSummary = summarizeResources(domain, state.sources.resources);
      const networkSummary = summarizeNetwork(collectors, state.network.entries);
      return {
        sourceCount: sourceSummary.total,
        readableSourceCount: sourceSummary.readable,
        networkRequestCount: state.network.entries.length,
        capturedBodyCount: networkSummary.bodyCaptured,
        unavailableBodyCount: (networkSummary.metadataOnly || 0) + (networkSummary.platformUnavailable || 0) + (networkSummary.readFailed || 0),
        cookieCount: state.cookies.summary && state.cookies.summary.observedCookies || 0,
        applicationItemCount: state.application.summary && (state.application.summary.totalInventoryItems || state.application.summary.storageItems) || 0,
        diagnosticWarningCount: Object.keys(state.diagnostics.reasonGroups || {}).length
      };
    }

    function buildRuntimeDiagnosticsSummary() {
      const reasonGroups = Object.fromEntries(
        Object.entries(state.diagnostics.reasonGroups || {}).map(([reason, count]) => [String(reason), Number(count) || 0])
      );
      const reasonGroupCount = Object.keys(reasonGroups).length;
      const errorCount = (state.diagnostics.logs || []).filter((entry) => entry.level === "ERROR").length;
      return {
        status: errorCount ? "error" : reasonGroupCount ? "incomplete" : state.analysis.status === "not_analyzed" ? "idle" : "complete",
        warningCount: reasonGroupCount,
        errorCount,
        reasonGroupCount,
        reasonGroups
      };
    }

    function objectDumpMetadata() {
      const enabled = state.dumpObjectsEnabled === true;
      return {
        dumpObjectsEnabled: enabled,
        cookieValueMode: enabled ? "raw" : "protected",
        applicationValueMode: enabled ? "raw" : "protected",
        cookiesTotal: state.cookies.summary && state.cookies.summary.observedCookies || 0,
        cookiesRawVisible: enabled ? state.cookies.summary && state.cookies.summary.rawAvailableCookies || 0 : 0,
        applicationItemsTotal: state.application.summary && state.application.summary.storageItems || 0,
        applicationRawVisible: enabled ? state.application.summary && state.application.summary.rawAvailableStorageItems || 0 : 0
      };
    }

    function buildRuntimeExportReadiness(targetState) {
      if (state.analysis.running) {
        return {
          blocked: true,
          safeReady: false,
          limitedReport: Boolean(targetState.isLimitedTarget),
          reason: "Analysis is running."
        };
      }
      if (state.export.running) {
        return {
          blocked: true,
          safeReady: false,
          limitedReport: Boolean(targetState.isLimitedTarget),
          reason: "Export is running."
        };
      }
      if (state.analysis.status === "not_analyzed") {
        return {
          blocked: true,
          safeReady: false,
          limitedReport: Boolean(targetState.isLimitedTarget),
          reason: "Analyze the target before exporting."
        };
      }
      if (state.analysis.status === "error") {
        return {
          blocked: true,
          safeReady: false,
          limitedReport: Boolean(targetState.isLimitedTarget),
          reason: "Analysis failed. Re-run analysis before exporting."
        };
      }
      if (state.target.isOutOfSync) {
        return {
          blocked: true,
          safeReady: false,
          limitedReport: Boolean(targetState.isLimitedTarget),
          reason: "Target changed since the last analysis."
        };
      }
      return {
        blocked: false,
        safeReady: true,
        limitedReport: Boolean(targetState.isLimitedTarget),
        reason: targetState.isLimitedTarget ? "Limited report export is available." : "Safe export is ready."
      };
    }

    function buildRuntimeNotices(targetState, moduleHealth, exportReadiness) {
      const notices = [];
      if (targetState.isLimitedTarget && state.target.currentUrl) {
        notices.push({
          id: "limited-target",
          type: "limitation",
          severity: "info",
          title: "Limited target",
          message: targetState.statusLabel || "Some page data cannot be accessed in this context.",
          reason: targetState.classificationReason || null,
          module: "target"
        });
      }
      if (state.target.isOutOfSync) {
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
      if (exportReadiness.blocked && exportReadiness.reason && state.analysis.status !== "not_analyzed") {
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
      return notices.slice(0, 12);
    }

    return function buildSnapshot() {
      const targetState = state.target.current || classifyTarget(domain, null);
      const redactedUrl = getRedactedUrl(domain, state.target.currentUrl || targetState.targetUrl || "") || null;
      const analysisStatus = state.analysis.running ? "running" : state.analysis.status || "not_analyzed";
      const syncStatus = state.analysis.status === "not_analyzed" ? "not_analyzed" : state.target.isOutOfSync ? "out_of_sync" : "fresh";
      const moduleHealth = buildRuntimeModuleHealth();
      const exportReadiness = buildRuntimeExportReadiness(targetState);
      const dump = objectDumpMetadata();
      const input = {
        version: 2,
        source: "shared-controller",
        updatedAt: new Date().toISOString(),
        target: {
          connected: Boolean(redactedUrl),
          url: redactedUrl,
          urlRedacted: redactedUrl,
          redactedUrl,
          targetType: targetState.targetType || "unknown",
          targetTypeLabel: targetState.targetType === "web_http" || targetState.targetType === "web_https" ? "Website" : targetState.statusLabel || "Unknown",
          captureMode: targetState.captureMode || null,
          captureLabel: targetState.captureMode === "web_full_available" ? "Full capture available" : targetState.captureMode === "limited_target_report_only" ? "Limited report" : targetState.captureMode === "empty_target_report_only" ? "Empty target report" : "Unknown target report",
          statusLabel: targetState.statusLabel || null,
          isLimitedTarget: Boolean(targetState.isLimitedTarget),
          isNormalWebTarget: Boolean(targetState.isNormalWebTarget),
          isOutOfSync: Boolean(state.target.isOutOfSync)
        },
        targetUrl: redactedUrl,
        analysis: {
          connected: true,
          status: analysisStatus,
          running: Boolean(state.analysis.running),
          message: state.analysis.phase || null,
          phase: state.analysis.phase || null,
          lastRunAt: state.analysis.lastRunAt || null
        },
        sync: {
          connected: true,
          status: syncStatus
        },
        capabilities: {
          sourcesApi: Boolean(targetState.isNormalWebTarget),
          networkHar: Boolean(typeof platform.getHar === "function"),
          applicationStorage: Boolean(targetState.isNormalWebTarget),
          browserVersion: state.target.browser || null
        },
        moduleHealth,
        captureSummary: buildRuntimeCaptureSummary(),
        exportReadiness,
        diagnosticsSummary: buildRuntimeDiagnosticsSummary(),
        rawPostureSummary: {
          dumpObjectsEnabled: dump.dumpObjectsEnabled,
          cookieValueMode: dump.cookieValueMode,
          applicationValueMode: dump.applicationValueMode,
          cookieRawVisibleCount: dump.cookiesRawVisible,
          applicationRawVisibleCount: dump.applicationRawVisible,
          rawValuesIncluded: false
        },
        notices: buildRuntimeNotices(targetState, moduleHealth, exportReadiness),
        browser: {
          label: state.target.browser || null
        },
        export: {
          running: Boolean(state.export.running),
          phase: state.export.phase || null,
          startedAt: state.export.startedAt || null,
          finishedAt: state.export.finishedAt || null,
          lastError: state.export.lastError || null,
          progress: state.export.progress || { current: 0, total: 0, label: "" }
        },
        capabilityLabels: (state.target.capabilities || []).map(String).filter(Boolean).slice(0, 8),
        sources: {
          resources: state.sources.resources
        },
        network: {
          entries: state.network.entries,
          captureState: state.network.captureState || "stopped",
          lastFrozenAt: state.network.lastFrozenAt || null
        },
        cookies: {
          summary: state.cookies.summary,
          observedCookies: state.cookies.observedCookies
        },
        application: state.application,
        diagnostics: state.diagnostics
      };
      if (typeof snapshot.buildRuntimeSnapshot === "function") {
        return snapshot.buildRuntimeSnapshot(input, {
          root: runtimeRoot,
          source: "shared-controller",
          urlSource: "shared_controller"
        });
      }
      return {
        connected: Boolean(redactedUrl),
        source: "shared-controller",
        updatedAt: input.updatedAt,
        target: input.target,
        analysis: input.analysis,
        sync: input.sync,
        capabilities: input.capabilities,
        moduleHealth,
        captureSummary: input.captureSummary,
        exportReadiness,
        diagnosticsSummary: input.diagnosticsSummary,
        rawPostureSummary: input.rawPostureSummary,
        notices: input.notices,
        export: input.export,
        network: input.network
      };
    };
  }

  function normalizeControllerResult(action, result, snapshot) {
    if (result && typeof result === "object" && (result.ok !== undefined || result.status || result.snapshot)) {
      return {
        ...result,
        action: result.action || action,
        snapshot: result.snapshot || snapshot
      };
    }
    return {
      ok: true,
      status: "complete",
      action,
      snapshot
    };
  }

  function unavailableResult(action, snapshot, reason, message) {
    return {
      ok: false,
      status: "unavailable",
      reason: reason || "controller_unavailable",
      message: message || "Runtime controller is not available.",
      action,
      snapshot
    };
  }

  function errorResult(action, snapshot, reason, message) {
    return {
      ok: false,
      status: "error",
      reason: reason || "controller_action_failed",
      message: message || "Runtime controller action failed.",
      action,
      snapshot
    };
  }

  
function createBackToolsController(options = {}) {
    const runtimeRoot = options.root || root;
    const apis = apisForRoot(runtimeRoot, options);
    const { domain, collectors, platform, reload } = apis;
    const state = options.initialState || createInitialState(domain, runtimeRoot);
    state.target.moduleStatuses = buildModuleStatuses(domain, state, false);
    const listeners = new Set();
    const buildSnapshot = createSnapshotBuilder(apis, state, runtimeRoot);
    let lastSnapshot = buildSnapshot();
    let captureSeq = 0;
    let stopNetworkCapture = null;
    let activeNetworkCaptureSession = null;
    let analyzeSeq = 0;
    let exportSeq = 0;
    let networkUpdateTimer = null;
    let pendingNetworkEntries = null;
    let pendingNetworkUpdate = false;

    function emit() {
      lastSnapshot = buildSnapshot();
      listeners.forEach((listener) => {
        try {
          listener(lastSnapshot);
        } catch (_error) {}
      });
      return lastSnapshot;
    }

    function log(level, event, detail) {
      state.diagnostics.logs.push({
        timestamp: new Date().toISOString(),
        level,
        event,
        detail: safeString(detail)
      });
    }

    function summarizeRawCookieScopeForExport() {
      return typeof domain.summarizeRawCookieScope === "function"
        ? domain.summarizeRawCookieScope(state.cookies.observedCookies || [])
        : { rawCookieCount: 0, domains: [] };
    }

    function summarizeRawApplicationScopeForExport() {
      return typeof domain.summarizeRawApplicationScope === "function"
        ? domain.summarizeRawApplicationScope(state.application || {})
        : { rawStorageItemCount: 0, origins: [], storageTypes: [] };
    }

    function syncDumpExportModesWithState() {
      if (!state.export?.options) {
        return;
      }

      state.export.options.applicationExportMode = "sanitized_only";
      if (state.dumpObjectsEnabled !== true) {
        state.export.options.cookieExportMode = "sanitized_only";
        state.cookies.rawExportConfirmedAt = null;
        state.cookies.rawExportScope = null;
        state.application.rawExportConfirmedAt = null;
        state.application.rawExportScope = null;
        return;
      }

      const confirmedAt = state.dumpObjectsEnabledAt || new Date().toISOString();
      state.dumpObjectsEnabledAt = confirmedAt;
      state.export.options.cookieExportMode = "raw_confirmed";
      state.cookies.rawExportConfirmedAt = confirmedAt;
      state.cookies.rawExportScope = summarizeRawCookieScopeForExport();
      state.application.rawExportConfirmedAt = null;
      state.application.rawExportScope = null;
    }

    function refreshModuleStatuses(analyzed = state.analysis.status !== "not_analyzed") {
      state.target.moduleStatuses = buildModuleStatuses(domain, state, analyzed);
      buildReasonGroups(domain, state);
    }

    function syncTargetState() {
      state.target.isOutOfSync = Boolean(
        state.target.analyzed &&
          state.target.current &&
          !targetsAreSame(domain, state.target.analyzed, state.target.current)
      );
    }

    function applyTargetUrl(rawUrl, urlSource) {
      if (!rawUrl && urlSource === "inspected_window_eval_location_href" && state.target.current && state.target.current.targetUrl) {
        return false;
      }
      const next = classifyTarget(domain, rawUrl, urlSource);
      const previous = state.target.current;
      state.target.current = next;
      state.target.currentUrl = next.targetUrl;
      state.target.capabilities = targetCapabilities(next);
      syncTargetState();
      refreshModuleStatuses(state.analysis.status !== "not_analyzed");
      return !targetsAreSame(domain, previous, next);
    }

    function setPhase(phase) {
      state.analysis.phase = phase;
      emit();
    }

    function exportSnapshotView() {
      return {
        running: Boolean(state.export.running),
        phase: state.export.phase || null,
        startedAt: state.export.startedAt || null,
        finishedAt: state.export.finishedAt || null,
        lastError: state.export.lastError || null,
        progress: state.export.progress || { current: 0, total: 0, label: "" }
      };
    }

    function emitExportProgressSnapshot() {
      lastSnapshot = {
        ...(lastSnapshot || {}),
        updatedAt: new Date().toISOString(),
        export: exportSnapshotView(),
        exportReadiness: state.export.running
          ? {
              blocked: true,
              safeReady: false,
              limitedReport: Boolean(lastSnapshot?.target?.isLimitedTarget),
              reason: "Export is running."
            }
          : {
              ...(lastSnapshot?.exportReadiness || {}),
              blocked: Boolean(lastSnapshot?.analysis?.running),
              safeReady: !lastSnapshot?.analysis?.running && !lastSnapshot?.target?.isOutOfSync,
              limitedReport: Boolean(lastSnapshot?.target?.isLimitedTarget),
              reason: lastSnapshot?.target?.isOutOfSync
                ? "Target changed since the last analysis."
                : lastSnapshot?.analysis?.running
                  ? "Analysis is running."
                  : "Safe export is ready."
            }
      };
      listeners.forEach((listener) => {
        try {
          listener(lastSnapshot);
        } catch (_error) {}
      });
      return lastSnapshot;
    }

    function updateExportState(patch = {}, shouldEmit = true) {
      const previous = state.export || {};
      state.export = {
        ...previous,
        ...patch,
        progress: {
          ...(previous.progress || { current: 0, total: 0, label: "" }),
          ...(patch.progress || {})
        }
      };
      if (shouldEmit) {
        const patchKeys = Object.keys(patch || {});
        const progressOnly = patchKeys.length > 0 && patchKeys.every((key) => key === "phase" || key === "progress");
        if (progressOnly && lastSnapshot) {
          emitExportProgressSnapshot();
        } else {
          emit();
        }
      }
      return state.export;
    }

    async function evalUrl() {
      return typeof platform.evalInspectedUrl === "function" ? platform.evalInspectedUrl() : null;
    }

    function applyCookieAnalysisFromEntries(entries) {
      try {
        const cookieAnalysis = typeof collectors.collectCookieMetadata === "function"
          ? collectors.collectCookieMetadata(entries || [], state.target.currentUrl)
          : { rawRecords: [], observedCookies: [], findings: [], summary: {} };
        state.cookies.rawRecords = cookieAnalysis.rawRecords || [];
        state.cookies.observedCookies = cookieAnalysis.observedCookies || [];
        state.cookies.findings = cookieAnalysis.findings || [];
        state.cookies.summary = cookieAnalysis.summary || {};
        state.cookies.rawValuesAvailable = (cookieAnalysis.summary && cookieAnalysis.summary.rawAvailableCookies || 0) > 0;
        state.cookies.filteredCookies = state.cookies.observedCookies;
      } catch (error) {
        log("ERROR", "Cookie analysis failed", error && error.message || error);
        state.cookies.rawRecords = [];
        state.cookies.observedCookies = [];
        state.cookies.findings = [];
        state.cookies.summary = {};
        state.cookies.rawValuesAvailable = false;
        state.cookies.filteredCookies = [];
      }
    }

    function applyNetworkSnapshot(entries, options = {}) {
      state.network.entries = Array.isArray(entries) ? entries : [];
      state.network.moduleStatus = entries && entries.moduleStatus || null;
      applyCookieAnalysisFromEntries(state.network.entries);
      if (state.dumpObjectsEnabled === true) {
        syncDumpExportModesWithState();
      }
      if (state.analysis.status !== "not_analyzed" || options.fromLiveUpdate) {
        refreshModuleStatuses(true);
        state.analysis.status = computeAnalysisStatus(state);
        emit();
      }
    }

    function flushPendingNetworkUpdate(force = false) {
      if (!pendingNetworkEntries) {
        if (networkUpdateTimer) {
          clearTimeout(networkUpdateTimer);
          networkUpdateTimer = null;
        }
        return;
      }
      if (!force && !pendingNetworkUpdate) {
        return;
      }
      if (networkUpdateTimer) {
        clearTimeout(networkUpdateTimer);
        networkUpdateTimer = null;
      }
      const entries = pendingNetworkEntries;
      const fromLiveUpdate = pendingNetworkUpdate;
      pendingNetworkEntries = null;
      pendingNetworkUpdate = false;
      applyNetworkSnapshot(entries, { fromLiveUpdate });
    }

    function scheduleNetworkSnapshot(entries) {
      pendingNetworkEntries = entries;
      pendingNetworkUpdate = true;
      if (networkUpdateTimer) {
        return;
      }
      const delayMs = safeNumber(state.network.liveUpdateThrottleMs) || 350;
      networkUpdateTimer = setTimeout(() => {
        flushPendingNetworkUpdate(true);
      }, delayMs);
    }

    async function stopActiveNetworkCapture(reason = "stopped") {
      if (!stopNetworkCapture) {
        if (reason) {
          state.network.captureState = reason;
          if (reason === "frozen_for_export") {
            state.network.lastFrozenAt = new Date().toISOString();
          }
          emit();
        }
        return;
      }
      try {
        const stopped = await withTimeout(stopNetworkCapture(), 1200, runtimeRoot);
        if (stopped?.timedOut) {
          log("WARN", "Stopping network capture timed out", "Proceeding with current captured entries.");
        } else if (stopped?.error) {
          log("WARN", "Stopping network capture failed", stopped.error && stopped.error.message || stopped.error);
        }
      } catch (error) {
        log("WARN", "Stopping network capture failed", error && error.message || error);
      } finally {
        stopNetworkCapture = null;
        activeNetworkCaptureSession = null;
        captureSeq++;
        flushPendingNetworkUpdate(true);
        state.network.captureState = reason;
        if (reason === "frozen_for_export") {
          state.network.lastFrozenAt = new Date().toISOString();
        }
        emit();
      }
    }

    async function startNetworkCapture() {
      await stopActiveNetworkCapture("stopped");
      const currentSeq = ++captureSeq;
      if (typeof collectors.startNetworkCapture !== "function") {
        state.network.captureState = "stopped";
        return [];
      }
      const session = await collectors.startNetworkCapture(
        {
          getHar: platform.getHar,
          addRequestFinishedListener: platform.addRequestFinishedListener,
          getRequestContent: platform.getRequestContent
        },
        state.target.currentUrl,
        {
          target: state.target.current,
          policy: state.network.policy || collectors.DEFAULT_NETWORK_BODY_POLICY,
          onUpdate: (entries) => {
            if (currentSeq !== captureSeq || state.export.running) {
              return;
            }
            scheduleNetworkSnapshot(entries);
          }
        }
      );
      activeNetworkCaptureSession = session || null;
      stopNetworkCapture = session && typeof session.stop === "function" ? () => session.stop() : null;
      state.network.captureState = stopNetworkCapture ? "live" : "stopped";
      state.network.lastFrozenAt = null;
      state.network.policy = session && typeof session.getPolicy === "function"
        ? session.getPolicy()
        : state.network.policy || collectors.DEFAULT_NETWORK_BODY_POLICY;
      state.network.moduleStatus = session && typeof session.getModuleStatus === "function" ? session.getModuleStatus() : null;
      return session && typeof session.getEntries === "function" ? session.getEntries() : [];
    }

    function getActiveNetworkEntries() {
      if (activeNetworkCaptureSession && typeof activeNetworkCaptureSession.getEntries === "function") {
        try {
          return activeNetworkCaptureSession.getEntries() || [];
        } catch (_error) {}
      }
      return state.network.entries || [];
    }

    async function waitForCaptureWindow() {
      const seconds = normalizeScanDurationSeconds(state.capture?.scanDurationSeconds);
      state.capture = {
        ...(state.capture || {}),
        scanDurationSeconds: seconds
      };
      setPhase(`Capturing network for ${seconds}s`);
      await wait(seconds * 1000, runtimeRoot);
    }

    async function collectSources() {
      return typeof collectors.collectSources === "function"
        ? collectors.collectSources(
            {
              getResources: platform.getResources,
              getResourceContent: platform.getResourceContent
            },
            state.target.currentUrl,
            { target: state.target.current }
          )
        : [];
    }

    async function collectApplication() {
      return typeof collectors.collectApplicationMetadata === "function"
        ? collectors.collectApplicationMetadata(
            { evalInInspectedWindow: platform.evalInInspectedWindow },
            state.target.currentUrl,
            { target: state.target.current }
          )
        : emptyApplicationState();
    }

    return {
      getSnapshot() {
        syncTargetState();
        refreshModuleStatuses(state.analysis.status !== "not_analyzed");
        return emit();
      },
      subscribe(listener) {
        if (typeof listener !== "function") {
          return () => {};
        }
        listeners.add(listener);
        try {
          listener(lastSnapshot);
        } catch (_error) {}
        return () => {
          listeners.delete(listener);
        };
      },
      async refreshTarget() {
        try {
          applyTargetUrl(await evalUrl(), "inspected_window_eval_location_href");
          return {
            ok: true,
            status: "complete",
            action: "refreshTarget",
            snapshot: emit()
          };
        } catch (_error) {
          return errorResult("refreshTarget", emit(), "target_refresh_failed", "Target refresh failed.");
        }
      },
      async analyze() {
        if (state.export.running) {
          return {
            ok: false,
            status: "running",
            reason: "export_running",
            message: "Export is already running.",
            action: "analyze",
            snapshot: emit()
          };
        }
        if (state.analysis.running) {
          return {
            ok: false,
            status: "running",
            reason: "analysis_running",
            message: "Analysis is already running.",
            action: "analyze",
            snapshot: emit()
          };
        }
        const seq = ++analyzeSeq;
        state.analysis.running = true;
        setPhase("Analyzing");
        try {
          applyTargetUrl(await evalUrl(), "inspected_window_eval_location_href");
          log("INFO", "Analyze started", getRedactedUrl(domain, state.target.currentUrl) || "Unavailable");
          await startNetworkCapture();
          await waitForCaptureWindow();
          const [sources, application] = await Promise.all([
            collectSources(),
            collectApplication()
          ]);
          flushPendingNetworkUpdate(true);
          const networkEntries = getActiveNetworkEntries();
          if (seq !== analyzeSeq) {
            return {
              ok: false,
              status: "blocked",
              reason: "analysis_superseded",
              message: "Analysis was superseded by a newer run.",
              action: "analyze",
              snapshot: emit()
            };
          }
          state.sources.resources = Array.isArray(sources) ? sources : [];
          state.sources.moduleStatus = sources && sources.moduleStatus || null;
          state.application = {
            ...emptyApplicationState(),
            ...(application || {}),
            rawExportConfirmedAt: null,
            rawExportScope: null
          };
          applyNetworkSnapshot(Array.isArray(networkEntries) ? networkEntries : []);
          state.cookies.needsReanalyze = false;
          syncDumpExportModesWithState();
          state.target.analyzedUrl = state.target.currentUrl;
          state.target.analyzed = state.target.current;
          refreshModuleStatuses(true);
          state.analysis.lastRunAt = new Date().toISOString();
          state.analysis.status = computeAnalysisStatus(state);
          state.analysis.running = false;
          state.analysis.phase = state.analysis.status === "complete" ? "Analysis complete" : "Analysis incomplete";
          log("INFO", "Analyze completed", `Sources: ${state.sources.resources.length}, Network: ${state.network.entries.length}, Application inventory: ${state.application.summary && state.application.summary.totalInventoryItems || 0}`);
          return {
            ok: true,
            status: state.analysis.status,
            action: "analyze",
            snapshot: emit()
          };
        } catch (error) {
          log("ERROR", "Analyze failed", error && error.message || error);
          state.analysis.status = "error";
          state.analysis.running = false;
          state.analysis.phase = "Analyze failed";
          return errorResult("analyze", emit(), "analyze_failed", "Analyze failed.");
        } finally {
          state.analysis.running = false;
        }
      },
      async reloadAndCapture() {
        if (state.export.running) {
          return {
            ok: false,
            status: "running",
            reason: "export_running",
            message: "Export is already running.",
            action: "reloadAndCapture",
            snapshot: emit()
          };
        }
        if (typeof reload.reloadAndAnalyze !== "function" || typeof platform.reloadInspectedWindow !== "function") {
          return unavailableResult("reloadAndCapture", emit(), "reload_unavailable", "Reload inspected window is not available.");
        }
        try {
          const result = await reload.reloadAndAnalyze({
            root: runtimeRoot,
            reload: platform.reloadInspectedWindow,
            evalUrl,
            applyTargetUrl,
            analyze: this.analyze.bind(this),
            beforeReload: () => setPhase("Reloading target")
          });
          return normalizeControllerResult("reloadAndCapture", result, emit());
        } catch (_error) {
          return errorResult("reloadAndCapture", emit(), "reload_failed", "Reload and capture failed.");
        }
      },
      beginExportJob() {
        if (state.export.running) {
          return {
            ok: false,
            status: "running",
            reason: "export_running",
            message: "Export is already running.",
            action: "export",
            snapshot: emit()
          };
        }
        if (state.analysis.running) {
          return {
            ok: false,
            status: "running",
            reason: "analysis_running",
            message: "Analysis is still running.",
            action: "export",
            snapshot: emit()
          };
        }
        const jobId = `export-${++exportSeq}`;
        updateExportState({
          running: true,
          phase: "Preparing export plan",
          startedAt: new Date().toISOString(),
          finishedAt: null,
          lastError: null,
          lastStatus: "Exporting",
          progress: {
            current: 0,
            total: 0,
            label: "Preparing export plan"
          },
          jobId
        });
        return {
          ok: true,
          status: "started",
          action: "export",
          jobId,
          snapshot: lastSnapshot
        };
      },
      async freezeExportSnapshot(jobId) {
        if (!state.export.running || state.export.jobId !== jobId) {
          return {
            ok: false,
            status: "blocked",
            reason: "stale_export_job",
            message: "Export job is no longer active.",
            action: "export",
            snapshot: emit()
          };
        }
        updateExportState({
          phase: "Freezing capture snapshot",
          progress: {
            current: 0,
            total: 0,
            label: "Freezing capture snapshot"
          }
        });
        await stopActiveNetworkCapture("frozen_for_export");
        const frozenState = createFrozenExportState(state);
        frozenState.export = {
          ...frozenState.export,
          running: false,
          phase: "Frozen snapshot",
          progress: {
            current: 0,
            total: 0,
            label: "Frozen snapshot"
          }
        };
        return {
          ok: true,
          status: "complete",
          action: "freezeExportSnapshot",
          jobId,
          state: frozenState,
          snapshot: emit()
        };
      },
      updateExportJob(jobId, patch = {}) {
        if (!state.export.running || state.export.jobId !== jobId) {
          return {
            ok: false,
            status: "blocked",
            reason: "stale_export_job",
            action: "export",
            snapshot: emit()
          };
        }
        updateExportState(patch);
        return {
          ok: true,
          status: "updated",
          action: "export",
          jobId,
          snapshot: lastSnapshot
        };
      },
      finishExportJob(jobId, patch = {}) {
        if (state.export.jobId !== jobId) {
          return {
            ok: false,
            status: "blocked",
            reason: "stale_export_job",
            action: "export",
            snapshot: emit()
          };
        }
        updateExportState({
          ...patch,
          running: false,
          finishedAt: new Date().toISOString(),
          jobId: null
        });
        return {
          ok: true,
          status: "complete",
          action: "export",
          snapshot: lastSnapshot
        };
      },
      getExportReadiness() {
        return this.getSnapshot().exportReadiness;
      },
      getDiagnosticsSummary() {
        return this.getSnapshot().diagnosticsSummary;
      },
      async copyTargetUrl() {
        const value = getRedactedUrl(domain, state.target.currentUrl) || "";
        const clipboard = runtimeRoot && runtimeRoot.navigator ? runtimeRoot.navigator.clipboard : null;
        if (!value || !clipboard || typeof clipboard.writeText !== "function") {
          return unavailableResult("copyTargetUrl", emit(), value ? "clipboard_unavailable" : "target_url_unavailable", value ? "Clipboard access is not available." : "Target URL is not available.");
        }
        try {
          await clipboard.writeText(value);
          log("INFO", "URL copied", value || "empty");
          return {
            ok: true,
            status: "complete",
            action: "copyTargetUrl",
            copiedUrl: value,
            snapshot: emit()
          };
        } catch (_error) {
          return errorResult("copyTargetUrl", emit(), "copy_target_url_failed", "Copy target URL failed.");
        }
      },
      stop() {
        void stopActiveNetworkCapture();
      },
      notify: emit,
      state
    };
  }
  function createBackToolsControllerFacade(delegate = {}) {
    const listeners = new Set();

    function getSnapshot() {
      return typeof delegate.getSnapshot === "function" ? delegate.getSnapshot() : {};
    }

    function emit() {
      const snapshot = getSnapshot();
      listeners.forEach((listener) => {
        try {
          listener(snapshot);
        } catch (_error) {}
      });
      return snapshot;
    }

    async function run(action, names) {
      const handler = names.map((name) => delegate[name]).find((value) => typeof value === "function");
      if (!handler) {
        return unavailableResult(action, emit(), "controller_action_unavailable", "Runtime controller action is not available.");
      }
      try {
        const result = await handler.call(delegate);
        return normalizeControllerResult(action, result, emit());
      } catch (_error) {
        return errorResult(action, emit(), "controller_action_failed", "Runtime controller action failed.");
      }
    }

    return {
      getSnapshot,
      subscribe(listener) {
        if (typeof listener !== "function") {
          return () => {};
        }
        listeners.add(listener);
        try {
          listener(getSnapshot());
        } catch (_error) {}
        return () => {
          listeners.delete(listener);
        };
      },
      refreshTarget() {
        return run("refreshTarget", ["refreshTarget"]);
      },
      analyze() {
        return run("analyze", ["analyze"]);
      },
      reloadAndCapture() {
        return run("reloadAndCapture", ["reloadAndCapture", "reloadAndAnalyze"]);
      },
      reloadAndAnalyze() {
        return run("reloadAndCapture", ["reloadAndCapture", "reloadAndAnalyze"]);
      },
      getExportReadiness() {
        return typeof delegate.getExportReadiness === "function" ? delegate.getExportReadiness() : getSnapshot().exportReadiness;
      },
      getDiagnosticsSummary() {
        return typeof delegate.getDiagnosticsSummary === "function" ? delegate.getDiagnosticsSummary() : getSnapshot().diagnosticsSummary;
      },
      copyTargetUrl() {
        return run("copyTargetUrl", ["copyTargetUrl"]);
      },
      notify: emit
    };
  }

  function canCreateBackToolsController(runtimeRoot, options = {}) {
    const apis = apisForRoot(runtimeRoot || root, options);
    const targetRoot = runtimeRoot || root;
    const inspectedWindow = targetRoot && targetRoot.chrome && targetRoot.chrome.devtools
      ? targetRoot.chrome.devtools.inspectedWindow
      : null;
    const hasTargetAccess = Boolean(inspectedWindow && typeof inspectedWindow.eval === "function") ||
      options.allowPlatformController === true && typeof options.platform?.evalInspectedUrl === "function";
    const hasCollectors = typeof apis.collectors.collectSources === "function" &&
      typeof apis.collectors.startNetworkCapture === "function" &&
      typeof apis.collectors.collectApplicationMetadata === "function";
    return Boolean(hasTargetAccess && hasCollectors);
  }

  function getOrCreateBackToolsController(runtimeRoot, options = {}) {
    const targetRoot = runtimeRoot || root;
    if (options.controller) {
      return options.controller;
    }
    if (!canCreateBackToolsController(targetRoot, options)) {
      return null;
    }
    if (controllerCache.has(targetRoot)) {
      return controllerCache.get(targetRoot);
    }
    const controller = createBackToolsController({ ...options, root: targetRoot });
    controllerCache.set(targetRoot, controller);
    return controller;
  }

  return {
    canCreateBackToolsController,
    createBackToolsController,
    createBackToolsControllerFacade,
    getOrCreateBackToolsController
  };
});
