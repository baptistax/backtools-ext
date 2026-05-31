
(() => {
  "use strict";

  const controllerFactory = window.BackToolsController || {};
  const controller =
    window.BackToolsRuntimeController ||
    (typeof controllerFactory.getOrCreateBackToolsController === "function"
      ? controllerFactory.getOrCreateBackToolsController(window)
      : null);

  const exportUi = window.BackToolsExportUi || {};
  const exportStorage = window.BackToolsExportStorage || {};
  const domain = window.BackToolsDomain || {};
  const exportCore = window.BackToolsExport || {};

  const MIN_SCAN_SECONDS = 1;
  const MAX_SCAN_SECONDS = 20;
  const DEFAULT_SCAN_SECONDS = 5;

  const FIXED_EXPORT_OPTIONS = {
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

  const DEFAULT_EXPORT_UI = {
    groupBy: "source",
    filterText: "",
    expandedPaths: [],
    exportOptionsOpen: false
  };

  const DEFAULT_EXPORT_OPTIONS = { ...FIXED_EXPORT_OPTIONS };

  const OPTION_BINDINGS = {};

  const q = (id) => document.getElementById(id);

  function mergeExportOptions(value) {
    const incoming = value && typeof value === "object" ? value : {};
    const current = controller?.state?.export?.options || {};
    const cookieExportMode = controller?.state?.dumpObjectsEnabled === true ||
      incoming.cookieExportMode === "raw_confirmed" ||
      current.cookieExportMode === "raw_confirmed"
      ? "raw_confirmed"
      : "sanitized_only";

    return {
      ...DEFAULT_EXPORT_OPTIONS,
      cookieExportMode,
      applicationExportMode: "sanitized_only"
    };
  }

  function normalizeScanDurationSeconds(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) {
      return DEFAULT_SCAN_SECONDS;
    }
    return Math.min(MAX_SCAN_SECONDS, Math.max(MIN_SCAN_SECONDS, Math.round(number)));
  }

  function syncScanDuration(value) {
    controller.state.capture = {
      ...(controller.state.capture || {}),
      scanDurationSeconds: normalizeScanDurationSeconds(value)
    };
  }

  function mergeExportUi(value) {
    const incoming = value && typeof value === "object" ? value : {};
    const merged = {
      ...DEFAULT_EXPORT_UI,
      ...(controller?.state?.export?.ui || {}),
      ...incoming
    };

    if (!merged.groupBy && incoming.structView === "source") {
      merged.groupBy = "source";
    }

    if (typeof exportUi.normalizeEvidenceGroupBy === "function") {
      merged.groupBy = exportUi.normalizeEvidenceGroupBy(merged.groupBy);
    } else {
      merged.groupBy = DEFAULT_EXPORT_UI.groupBy;
    }

    merged.filterText = String(merged.filterText || "");
    merged.expandedPaths = Array.isArray(merged.expandedPaths) ? [...new Set(merged.expandedPaths.filter(Boolean))] : [];
    merged.exportOptionsOpen = merged.exportOptionsOpen === true;
    return merged;
  }

  function redactedUrl(value) {
    return typeof domain.redactUrl === "function" ? domain.redactUrl(value || "") : value || "";
  }

  function buildExportPlan() {
    if (typeof domain.buildExportPlanFromStateLike === "function") {
      return domain.buildExportPlanFromStateLike(controller.state);
    }
    return {
      counts: {
        plannedFiles: 0,
        dataUrlFiles: 0,
        sourceFiles: 0,
        networkBodyFiles: 0,
        networkMetadataOnly: 0,
        networkReportFiles: 0,
        diagnosticsFiles: 0,
        manifestFiles: 0,
        excludedResources: 0,
        hiddenByDefault: 0
      },
      plannedFiles: [],
      manifestOnlyResources: [],
      skippedResources: [],
      failedResources: []
    };
  }


  function summarizeRowsForCache(rows = []) {
    let totalSize = 0;
    let totalCapturedBytes = 0;
    let visible = 0;
    let metadataOnly = 0;
    let failed = 0;
    const head = [];
    const tail = [];
    for (let index = 0; index < rows.length; index++) {
      const row = rows[index] || {};
      totalSize += Number(row.size || 0);
      totalCapturedBytes += Number(row.bodyCapturedBytes || 0);
      if (row.visibleByDefault !== false) visible++;
      if ((row.bodyCaptureStatus || row.status) === "metadata_only") metadataOnly++;
      if ((row.status || "").includes("failed") || (row.bodyCaptureStatus || "").includes("failed")) failed++;
      const marker = `${row.id || row.url || index}:${row.status || row.bodyCaptureStatus || ""}:${row.size || row.bodyCapturedBytes || 0}`;
      if (head.length < 3) head.push(marker);
      if (tail.length === 3) tail.shift();
      tail.push(marker);
    }
    return [rows.length, totalSize, totalCapturedBytes, visible, metadataOnly, failed, head.join(","), tail.join(",")].join(":");
  }


  let lastPlanCacheKey = "";
  let lastModuleRenderKey = "";
  let lastPlanCacheValue = null;

  function exportPlanCacheKey() {
    const state = controller?.state || {};
    const optionsJson = JSON.stringify(state.export?.options || {});
    return [
      state.target?.analyzedUrl || state.target?.currentUrl || "",
      summarizeRowsForCache(state.sources?.resources || []),
      summarizeRowsForCache(state.network?.entries || []),
      state.cookies?.observedCookies?.length || 0,
      state.application?.summary?.totalInventoryItems || state.application?.summary?.storageItems || 0,
      optionsJson
    ].join("|");
  }

  function getCachedExportPlan() {
    const key = exportPlanCacheKey();
    if (key === lastPlanCacheKey && lastPlanCacheValue) {
      return lastPlanCacheValue;
    }
    lastPlanCacheKey = key;
    lastPlanCacheValue = buildExportPlan();
    return lastPlanCacheValue;
  }

  function moduleRenderKey(snapshot) {
    const state = controller?.state || {};
    return [
      snapshot?.analysis?.status || "",
      Boolean(snapshot?.analysis?.running),
      state.target?.analyzedUrl || state.target?.currentUrl || "",
      state.sources?.resources?.length || 0,
      state.network?.entries?.length || 0,
      state.cookies?.observedCookies?.length || 0,
      state.application?.summary?.totalInventoryItems || state.application?.summary?.storageItems || 0,
      exportPlanCacheKey(),
      state.export?.ui?.groupBy || "",
      state.export?.ui?.filterText || "",
      JSON.stringify(state.export?.ui?.expandedPaths || [])
    ].join("|");
  }

  function summarizeRawCookieScope() {
    return typeof domain.summarizeRawCookieScope === "function"
      ? domain.summarizeRawCookieScope(controller?.state?.cookies?.observedCookies || [])
      : { rawCookieCount: 0, domains: [] };
  }

  function summarizeRawApplicationScope() {
    return typeof domain.summarizeRawApplicationScope === "function"
      ? domain.summarizeRawApplicationScope(controller?.state?.application || {})
      : { rawStorageItemCount: 0, origins: [], storageTypes: [] };
  }

  function syncDumpExportModes(enabled, confirmedAt = new Date().toISOString()) {
    if (!controller?.state?.export?.options) {
      return;
    }

    controller.state.dumpObjectsEnabled = enabled === true;
    controller.state.dumpObjectsEnabledAt = controller.state.dumpObjectsEnabled ? confirmedAt : null;
    controller.state.export.options = mergeExportOptions(controller.state.export.options);
    controller.state.export.options.applicationExportMode = "sanitized_only";

    if (!controller.state.dumpObjectsEnabled) {
      controller.state.export.options.cookieExportMode = "sanitized_only";
      if (controller.state.cookies) {
        controller.state.cookies.rawExportConfirmedAt = null;
        controller.state.cookies.rawExportScope = null;
      }
      if (controller.state.application) {
        controller.state.application.rawExportConfirmedAt = null;
        controller.state.application.rawExportScope = null;
      }
      return;
    }

    controller.state.export.options.cookieExportMode = "raw_confirmed";
    if (controller.state.cookies) {
      controller.state.cookies.rawExportConfirmedAt = confirmedAt;
      controller.state.cookies.rawExportScope = summarizeRawCookieScope();
    }
    if (controller.state.application) {
      controller.state.application.rawExportConfirmedAt = null;
      controller.state.application.rawExportScope = null;
    }
  }

  function log(level, event, detail) {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      event,
      detail: detail == null ? "" : String(detail)
    };
    if (controller?.state?.diagnostics?.logs) {
      controller.state.diagnostics.logs.push(entry);
    }
    const consoleMethod = level === "ERROR" ? console.error : level === "WARN" ? console.warn : console.log;
    consoleMethod(`[Back Tools Export] ${event}`, entry.detail);
  }

  function normalizeTheme(value) {
    const theme = String(value || "System").toLowerCase();
    if (theme === "dark" || theme === "light" || theme === "system") {
      return theme;
    }
    return "system";
  }

  function applyTheme(value) {
    document.documentElement.dataset.theme = normalizeTheme(value);
  }

  function themeLabel(value) {
    const theme = normalizeTheme(value);
    return theme.charAt(0).toUpperCase() + theme.slice(1);
  }

  async function persistUiState() {
    await exportStorage.setMany({
      theme: themeLabel(document.documentElement.dataset.theme || "system"),
      exportOptions: controller?.state?.export?.options || mergeExportOptions(),
      dumpObjectsEnabled: controller?.state?.dumpObjectsEnabled === true,
      evidenceGroupBy: controller?.state?.export?.ui?.groupBy || DEFAULT_EXPORT_UI.groupBy,
      evidenceFilterText: controller?.state?.export?.ui?.filterText || "",
      evidenceExpandedPaths: controller?.state?.export?.ui?.expandedPaths || [],
      exportOptionsOpen: controller?.state?.export?.ui?.exportOptionsOpen === true,
      scanDurationSeconds: normalizeScanDurationSeconds(controller?.state?.capture?.scanDurationSeconds)
    });
  }

  function syncHeader(snapshot) {
    const targetUrlElement = q("targetUrl");
    const targetCopyButton = q("targetCopyBtn");
    const exportButton = q("exportTopBtn");
    const reloadButton = q("reloadCaptureTopBtn");
    const exportStatus = q("exportStatusText");
    const currentUrl = controller?.state?.target?.currentUrl || "";
    const displayUrl = snapshot?.target?.redactedUrl || redactedUrl(currentUrl) || "Unavailable";
    const exportState = snapshot?.export || controller?.state?.export || {};
    const hasPlannedFiles = Boolean(controller.state?.export?.lastPlan?.counts?.plannedFiles);
    const progress = exportState.progress || {};
    const exportLabel = exportState.running
      ? progress.label
        ? `Exporting... ${progress.label}`
        : "Exporting..."
      : "Export";

    if (targetUrlElement) {
      targetUrlElement.textContent = displayUrl;
      targetUrlElement.title = displayUrl;
    }

    if (targetCopyButton) {
      targetCopyButton.disabled = !currentUrl;
      targetCopyButton.title = currentUrl ? "Click to copy target URL" : "Target URL unavailable";
    }

    if (exportButton) {
      exportButton.disabled = Boolean(snapshot?.analysis?.running) || Boolean(exportState.running) || !hasPlannedFiles;
      exportButton.textContent = exportLabel;
    }

    if (reloadButton) {
      reloadButton.disabled = Boolean(snapshot?.analysis?.running) || Boolean(exportState.running);
      reloadButton.textContent = snapshot?.analysis?.running ? "Capturing..." : "Analyze and capture";
    }

    if (exportStatus) {
      exportStatus.textContent = exportState.running
        ? exportLabel
        : exportState.lastStatus || "";
    }
  }

  function render(snapshot) {
    controller.state.export.options = mergeExportOptions(controller.state.export.options);
    controller.state.export.ui = mergeExportUi(controller.state.export.ui);
    controller.state.preferences = {
      ...(controller.state.preferences || {}),
      theme: themeLabel(document.documentElement.dataset.theme || "system")
    };
    controller.state.export.lastPlan = getCachedExportPlan();

    const nextModuleRenderKey = moduleRenderKey(snapshot);
    const moduleContent = q("moduleContent");
    if (
      moduleContent &&
      typeof exportUi.renderExportModule === "function" &&
      nextModuleRenderKey !== lastModuleRenderKey
    ) {
      moduleContent.innerHTML = exportUi.renderExportModule(controller.state, controller.state.export.lastPlan);
      lastModuleRenderKey = nextModuleRenderKey;
      bindRenderedEvents();
    }

    syncHeader(snapshot);
  }


  async function exportZip() {
    const snapshot = controller.getSnapshot();
    if (snapshot?.analysis?.running) {
      return { ok: false, status: "running", reason: "analysis_running" };
    }

    if (controller.state?.export?.running) {
      return { ok: false, status: "running", reason: "export_running" };
    }

    if (controller.state?.target?.isOutOfSync) {
      const message = "Target changed since last analysis. Re-analyze before exporting.";
      log("ERROR", "Export blocked", message);
      alert(message);
      return { ok: false, status: "blocked", reason: "target_out_of_sync" };
    }

    const begin = typeof controller.beginExportJob === "function"
      ? controller.beginExportJob()
      : { ok: true, jobId: `export-${Date.now()}` };

    if (!begin?.ok) {
      return begin;
    }

    const jobId = begin.jobId;

    try {
      const frozen = typeof controller.freezeExportSnapshot === "function"
        ? await controller.freezeExportSnapshot(jobId)
        : { ok: true, state: JSON.parse(JSON.stringify(controller.state)) };

      if (!frozen?.ok || !frozen?.state) {
        throw new Error(frozen?.message || "Could not freeze export snapshot.");
      }

      const exportState = frozen.state;
      const plan = typeof domain.buildExportPlanFromStateLike === "function"
        ? domain.buildExportPlanFromStateLike(exportState)
        : buildExportPlan();

      controller.state.export.lastPlan = plan;
      if (typeof controller.updateExportJob === "function") {
        controller.updateExportJob(jobId, {
          phase: "Preparing export plan",
          progress: {
            current: 0,
            total: plan?.plannedFiles?.length || 0,
            label: "Preparing export plan"
          }
        });
      }
      render(controller.getSnapshot());

      const result = await exportCore.writeCurrentCaptureZip({
        plan,
        state: exportState,
        log,
        onProgress: (progress) => {
          if (typeof controller.updateExportJob === "function") {
            controller.updateExportJob(jobId, {
              phase: progress?.phase || "Exporting",
              progress: {
                current: progress?.current || 0,
                total: progress?.total || 0,
                label: progress?.label || progress?.phase || "Exporting"
              }
            });
          }
        }
      });

      if (!(result?.blob instanceof Blob)) {
        throw new Error("Export did not return a valid Blob.");
      }

      const blobUrl = URL.createObjectURL(result.blob);
      try {
        const anchor = document.createElement("a");
        anchor.href = blobUrl;
        anchor.download = "back-tools-capture.zip";
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
      } finally {
        window.setTimeout(() => URL.revokeObjectURL(blobUrl), 30_000);
      }

      controller.state.export.lastPlan = plan;
      controller.state.export.lastManifest = result?.manifest || null;
      if (typeof controller.finishExportJob === "function") {
        controller.finishExportJob(jobId, {
          phase: "Download ready",
          lastStatus: "Export complete",
          lastError: null,
          progress: {
            current: result?.totals?.writtenFiles || 0,
            total: result?.totals?.writtenFiles || 0,
            label: "Download ready"
          }
        });
      } else {
        controller.state.export.running = false;
        controller.state.export.lastStatus = "Export complete";
      }
      log("INFO", "Export completed", `written ${result?.totals?.writtenFiles || 0} files`);
      render(controller.getSnapshot());
      return { ok: true, status: "complete", result };
    } catch (error) {
      if (typeof controller.finishExportJob === "function") {
        controller.finishExportJob(jobId, {
          phase: "Export failed",
          lastStatus: "Export failed",
          lastError: error?.message || String(error),
          progress: {
            current: 0,
            total: 0,
            label: "Export failed"
          }
        });
      } else {
        controller.state.export.running = false;
        controller.state.export.lastStatus = "Export failed";
      }
      log("ERROR", "Export failed", error?.message || error);
      alert(error?.message || "Export failed.");
      render(controller.getSnapshot());
      return { ok: false, status: "error", reason: "export_failed", error };
    }
  }

  async function copyTargetUrl() {
    const value = controller?.state?.target?.currentUrl || "";
    if (!value) {
      return;
    }

    try {
      await navigator.clipboard.writeText(value);
    } catch {
      const input = document.createElement("textarea");
      input.value = value;
      document.body.appendChild(input);
      input.select();
      document.execCommand("copy");
      input.remove();
    }
  }

  function bindStaticEvents() {
    const reloadButton = q("reloadCaptureTopBtn");
    const exportButton = q("exportTopBtn");
    const targetCopyButton = q("targetCopyBtn");

    if (reloadButton) {
      reloadButton.onclick = async () => {
        await controller.reloadAndCapture();
      };
    }

    if (exportButton) {
      exportButton.onclick = async () => {
        await exportZip();
      };
    }

    if (targetCopyButton) {
      targetCopyButton.onclick = async () => {
        await copyTargetUrl();
      };
    }
  }


  function bindRenderedEvents() {
    const groupBy = q("evidenceGroupBy");
    if (groupBy) {
      groupBy.onchange = async () => {
        controller.state.export.ui = mergeExportUi({
          ...controller.state.export.ui,
          groupBy: groupBy.value,
          expandedPaths: []
        });
        await persistUiState();
        render(controller.getSnapshot());
      };
    }

    const filterInput = q("evidenceFilterInput");
    if (filterInput) {
      filterInput.oninput = async () => {
        controller.state.export.ui = mergeExportUi({
          ...controller.state.export.ui,
          filterText: filterInput.value
        });
        await persistUiState();
        render(controller.getSnapshot());
      };
    }

    const expandAllButton = q("expandAllEvidenceBtn");
    if (expandAllButton) {
      expandAllButton.onclick = async () => {
        const expandedPaths = Array.from(document.querySelectorAll(".tree-node[data-node-path]"))
          .map((node) => node.dataset.nodePath)
          .filter(Boolean);
        controller.state.export.ui = mergeExportUi({
          ...controller.state.export.ui,
          expandedPaths
        });
        await persistUiState();
        render(controller.getSnapshot());
      };
    }

    const collapseAllButton = q("collapseAllEvidenceBtn");
    if (collapseAllButton) {
      collapseAllButton.onclick = async () => {
        controller.state.export.ui = mergeExportUi({
          ...controller.state.export.ui,
          expandedPaths: []
        });
        await persistUiState();
        render(controller.getSnapshot());
      };
    }

    const scanDurationInput = q("scanDurationInput");
    if (scanDurationInput) {
      scanDurationInput.onchange = async () => {
        syncScanDuration(scanDurationInput.value);
        scanDurationInput.value = String(normalizeScanDurationSeconds(controller.state.capture?.scanDurationSeconds));
        await persistUiState();
        render(controller.getSnapshot());
      };
    }

    const dumpCookiesToggle = q("dumpCookiesToggle");
    if (dumpCookiesToggle) {
      dumpCookiesToggle.onchange = async () => {
        syncDumpExportModes(dumpCookiesToggle.checked);
        controller.state.export.lastPlan = buildExportPlan();
        await persistUiState();
        render(controller.getSnapshot());
      };
    }

    const themeSelect = q("themeSelect");
    if (themeSelect) {
      themeSelect.onchange = async () => {
        applyTheme(themeSelect.value);
        controller.state.preferences = {
          ...(controller.state.preferences || {}),
          theme: themeLabel(themeSelect.value)
        };
        await persistUiState();
      };
    }

    const exportOptionsDetails = q("exportOptionsDetails");
    if (exportOptionsDetails) {
      exportOptionsDetails.addEventListener("toggle", async () => {
        controller.state.export.ui = mergeExportUi({
          ...controller.state.export.ui,
          exportOptionsOpen: exportOptionsDetails.open === true
        });
        await persistUiState();
      });
    }

    Object.entries(OPTION_BINDINGS).forEach(([id, optionKey]) => {
      const element = q(id);
      if (!element) {
        return;
      }
      element.onchange = async () => {
        controller.state.export.options = mergeExportOptions({
          ...controller.state.export.options,
          [optionKey]: element.checked
        });
        controller.state.export.lastPlan = buildExportPlan();
        await persistUiState();
        render(controller.getSnapshot());
      };
    });

    document.querySelectorAll(".tree-node[data-node-path]").forEach((detail) => {
      detail.addEventListener("toggle", async (event) => {
        const path = event.currentTarget?.dataset?.nodePath;
        if (!path) {
          return;
        }
        const expanded = new Set(controller.state.export.ui?.expandedPaths || []);
        if (event.currentTarget.open) {
          expanded.add(path);
        } else {
          expanded.delete(path);
        }
        controller.state.export.ui = mergeExportUi({
          ...controller.state.export.ui,
          expandedPaths: [...expanded]
        });
        await persistUiState();
      });
    });
  }
  async function hydrateState() {
    const saved = await exportStorage.getMany([
      "theme",
      "exportOptions",
      "dumpObjectsEnabled",
      "evidenceGroupBy",
      "evidenceFilterText",
      "evidenceExpandedPaths",
      "exportOptionsOpen",
      "scanDurationSeconds"
    ]);
    syncScanDuration(saved?.scanDurationSeconds);
    controller.state.export.options = mergeExportOptions(saved?.exportOptions);
    controller.state.export.ui = mergeExportUi({
      groupBy: saved?.evidenceGroupBy,
      filterText: saved?.evidenceFilterText,
      expandedPaths: saved?.evidenceExpandedPaths,
      exportOptionsOpen: saved?.exportOptionsOpen === true
    });
    syncDumpExportModes(saved?.dumpObjectsEnabled === true, new Date().toISOString());
    applyTheme(saved?.theme || "System");
  }

  async function initialize() {
    if (!controller?.state) {
      const moduleContent = q("moduleContent");
      if (moduleContent) {
        moduleContent.innerHTML = '<section class="module"><div class="module-card"><h2>Export</h2><p>Runtime controller is unavailable in this DevTools session.</p></div></section>';
      }
      return;
    }

    await hydrateState();
    bindStaticEvents();

    controller.subscribe((snapshot) => {
      render(snapshot || controller.getSnapshot());
    });

    await controller.refreshTarget();
  }

  void initialize();
})();
