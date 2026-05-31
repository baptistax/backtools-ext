
(function (root, factory) {
  const api = factory(root);
  root.BackToolsExportUi = Object.assign(root.BackToolsExportUi || {}, api);
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : window, function (root) {
  const domain = root.BackToolsDomain || {};

  const EVIDENCE_SOURCE_LABELS = {
    sources: "Sources",
    application: "Application",
    network: "Network"
  };

  const TYPE_ORDER = [
    "Document",
    "JavaScript",
    "Stylesheet",
    "Image",
    "Font",
    "Fetch/XHR",
    "Storage",
    "Cookie",
    "IndexedDB",
    "Cache Storage",
    "Service Worker",
    "Manifest",
    "Report",
    "Other"
  ];

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function displayUrl(resource) {
    return (
      resource?.urlRedacted ||
      (typeof domain.redactUrl === "function" ? domain.redactUrl(resource?.url || resource?.path || "") : "") ||
      resource?.url ||
      resource?.path ||
      ""
    );
  }

  function normalizeEvidenceGroupBy(value) {
    return value === "type" || value === "domain" || value === "time" ? value : "source";
  }

  function safeParseUrl(value) {
    if (!value) {
      return null;
    }
    try {
      return new URL(value);
    } catch {
      return null;
    }
  }

  function toBaseDomain(hostname) {
    const value = String(hostname || "").toLowerCase().replace(/^\.+|\.+$/g, "");
    if (!value) {
      return "";
    }
    const parts = value.split(".").filter(Boolean);
    if (parts.length <= 2) {
      return value;
    }
    const last = parts[parts.length - 1];
    const second = parts[parts.length - 2];
    if (last.length === 2 && second.length <= 3 && parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  function classifyParty(domainName, targetDomainName) {
    const domainValue = String(domainName || "").toLowerCase();
    const targetValue = String(targetDomainName || "").toLowerCase();
    if (!domainValue || !targetValue) {
      return "";
    }
    const left = toBaseDomain(domainValue);
    const right = toBaseDomain(targetValue);
    if (!left || !right) {
      return "";
    }
    return left === right ? "first-party" : "third-party";
  }

  function summarizeDisplayName(pathValue, urlValue, fallback = "item") {
    const pathText = String(pathValue || "");
    if (pathText) {
      const parts = pathText.split("/").filter(Boolean);
      if (parts.length) {
        return parts[parts.length - 1];
      }
    }

    const parsed = safeParseUrl(urlValue);
    if (parsed) {
      const parts = parsed.pathname.split("/").filter(Boolean);
      if (!parts.length) {
        return parsed.hostname || fallback;
      }
      return parts[parts.length - 1];
    }

    return fallback;
  }

  function normalizeEvidenceType(input = {}) {
    const pathValue = String(input.path || input.exportPath || "").toLowerCase();
    const urlValue = String(input.url || "").toLowerCase();
    const mimeType = String(input.mimeType || "").toLowerCase();
    const rawType = String(input.type || input.resourceType || "").toLowerCase();
    const name = String(input.displayName || "").toLowerCase();
    const sourceLabel = String(input.sourceLabel || "").toLowerCase();

    if (
      pathValue === "manifest.json" ||
      pathValue.includes("_report.json") ||
      pathValue.includes("failed_resources") ||
      pathValue.includes("diagnostics/") ||
      pathValue.endsWith("logs.json") ||
      sourceLabel.includes("report")
    ) {
      return "Report";
    }
    if (pathValue.includes("indexeddb") || name.includes("indexeddb")) {
      return "IndexedDB";
    }
    if (pathValue.includes("cache-storage") || name.includes("cache storage")) {
      return "Cache Storage";
    }
    if (pathValue.includes("service-worker") || pathValue.includes("service_worker") || name.includes("service worker")) {
      return "Service Worker";
    }
    if (
      name.endsWith(".webmanifest") ||
      pathValue.endsWith(".webmanifest") ||
      rawType.includes("manifest") ||
      mimeType.includes("manifest+json") ||
      urlValue.endsWith(".webmanifest")
    ) {
      return "Manifest";
    }
    if (pathValue.includes("cookie") || name.includes("cookie")) {
      return "Cookie";
    }
    if (pathValue.includes("storage") || name.includes("localstorage") || name.includes("sessionstorage")) {
      return "Storage";
    }
    if (mimeType.includes("javascript") || /\.m?js($|\?)/.test(pathValue || urlValue) || rawType.includes("script") || rawType === "javascript") {
      return "JavaScript";
    }
    if (mimeType.includes("css") || /\.css($|\?)/.test(pathValue || urlValue) || rawType.includes("stylesheet") || rawType === "css") {
      return "Stylesheet";
    }
    if (mimeType.includes("image/") || /\.(png|jpe?g|gif|webp|svg|ico|bmp|avif)($|\?)/.test(pathValue || urlValue) || rawType.includes("image")) {
      return "Image";
    }
    if (mimeType.includes("font") || /\.(woff2?|ttf|otf|eot)($|\?)/.test(pathValue || urlValue) || rawType.includes("font")) {
      return "Font";
    }
    if (
      rawType.includes("xhr") ||
      rawType.includes("fetch") ||
      rawType === "xmlhttprequest" ||
      rawType === "fetch" ||
      mimeType.includes("application/json") ||
      mimeType.includes("text/xml") ||
      mimeType.includes("application/xml")
    ) {
      return "Fetch/XHR";
    }
    if (
      mimeType.includes("text/html") ||
      rawType.includes("document") ||
      rawType === "html" ||
      /(^|\/)(index|login|home)(\.[a-z0-9]+)?$/i.test(pathValue || urlValue)
    ) {
      return "Document";
    }
    return "Other";
  }

  function classifyEntryGroup(path) {
    const text = String(path || "");
    if (text.startsWith("application/")) {
      return "application";
    }
    if (text.startsWith("sources/") || text.startsWith("network/") || text.startsWith("data-urls/")) {
      return "sources";
    }
    return "shared";
  }

  function resolvePlannedFilePath(item, index) {
    if (item?.zipPath) {
      return item.zipPath;
    }

    const resource = item?.resource || {};
    if (item?.isDataUrl) {
      if (typeof domain.buildSafeDataUrlZipPath === "function") {
        return domain.buildSafeDataUrlZipPath(resource, index, item?.mimeType);
      }
      return `data-urls/data-url-${index + 1}.bin`;
    }

    if (item?.isNetworkBody && typeof domain.buildSafeZipPath === "function") {
      return domain.buildSafeZipPath(resource, { mimeType: item?.mimeType || resource?.mimeType });
    }

    if (typeof domain.buildSafeSourceZipPath === "function") {
      return domain.buildSafeSourceZipPath(resource);
    }

    if (typeof domain.buildCurrentSourceZipPath === "function") {
      return domain.buildCurrentSourceZipPath(resource);
    }

    return `sources/item-${index + 1}.bin`;
  }

  function makeArchiveEntry(path, itemType, item, extras = {}) {
    return {
      path,
      itemType,
      status: extras.status || item?.exportStatus || "planned",
      collector: extras.collector || item?.collector || item?.resource?.collector || null,
      url: extras.url || displayUrl(item?.resource || item),
      reason: extras.reason || item?.reason || item?.resource?.reason || null,
      contentKind: extras.contentKind || item?.contentKind || null,
      sourceLabel: extras.sourceLabel || null,
      pathSource: extras.pathSource || "archive",
      isVirtual: extras.isVirtual === true,
      pathFilterGroup: extras.pathFilterGroup || classifyEntryGroup(path),
      item
    };
  }

  function buildPrimaryOutputEntries(state) {
    const options = state?.export?.options || {};
    const entries = [];

    if (options.includeNetwork && options.includeNetworkSummary !== false) {
      entries.push(makeArchiveEntry("NETWORK_REPORT.json", "network_report", null, {
        status: "generated",
        sourceLabel: "Network summary report",
        pathFilterGroup: "shared",
        isVirtual: true
      }));
    }

    if (options.includeApplication) {
      entries.push(makeArchiveEntry("application/APPLICATION_REPORT.json", "application_report", null, {
        status: "generated",
        sourceLabel: "Application inventory report",
        pathFilterGroup: "application",
        isVirtual: true
      }));
    }

    if (options.includeCookiesReport) {
      entries.push(makeArchiveEntry("cookies/COOKIES_REPORT.json", "cookie_report", null, {
        status: "generated",
        sourceLabel: "Cookie analyzer report",
        pathFilterGroup: "shared",
        isVirtual: true
      }));
    }

    return entries;
  }

  function isRawCookieExportEnabled(state) {
    const mode = state?.export?.options?.cookieExportMode;
    return state?.dumpObjectsEnabled === true && (mode === "raw" || mode === "raw_confirmed");
  }

  function isRawApplicationExportEnabled(_state) {
    return false;
  }

  function normalizeScanDurationSeconds(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) {
      return 5;
    }
    return Math.min(20, Math.max(1, Math.round(number)));
  }

  function buildArchiveEntries(state, plan) {
    const options = state?.export?.options || {};
    const entries = [];

    (plan?.plannedFiles || []).forEach((item, index) => {
      entries.push(makeArchiveEntry(resolvePlannedFilePath(item, index), "planned_file", item, {
        sourceLabel: item?.isDataUrl ? "Decoded data URL" : item?.isNetworkBody ? "Captured network body" : "Captured source"
      }));
    });

    entries.push(makeArchiveEntry("MANIFEST.json", "manifest", null, {
      status: "generated",
      sourceLabel: "Manifest report",
      pathFilterGroup: "shared",
      isVirtual: true
    }));

    if (options.includeFailedReport !== false && (plan?.failedResources || []).length > 0) {
      entries.push(makeArchiveEntry("FAILED_RESOURCES.json", "failed_report", null, {
        status: "generated",
        sourceLabel: "Failed resources report",
        pathFilterGroup: "shared",
        isVirtual: true
      }));
    }

    if (options.includeNetwork && options.includeNetworkSummary !== false) {
      entries.push(makeArchiveEntry("NETWORK_REPORT.json", "network_report", null, {
        status: "generated",
        sourceLabel: "Network summary report",
        pathFilterGroup: "sources",
        isVirtual: true
      }));
    }

    if (options.includeDiagnostics) {
      if (options.includeLogsJson !== false) {
        entries.push(makeArchiveEntry("logs.json", "diagnostics_log", null, {
          status: "generated",
          sourceLabel: "Diagnostics log export",
          pathFilterGroup: "shared",
          isVirtual: true
        }));
      }

      entries.push(makeArchiveEntry("diagnostics/target.json", "diagnostics_report", null, {
        status: "generated",
        sourceLabel: "Target diagnostics",
        pathFilterGroup: "shared",
        isVirtual: true
      }));
      entries.push(makeArchiveEntry("diagnostics/modules.json", "diagnostics_report", null, {
        status: "generated",
        sourceLabel: "Module diagnostics",
        pathFilterGroup: "shared",
        isVirtual: true
      }));
    }

    if (options.includeCookiesReport) {
      entries.push(makeArchiveEntry("cookies/COOKIES_REPORT.json", "cookie_report", null, {
        status: "generated",
        sourceLabel: "Cookie analyzer report",
        pathFilterGroup: "shared",
        isVirtual: true
      }));
      entries.push(makeArchiveEntry("cookies/cookies.sanitized.json", "cookie_export", null, {
        status: "generated",
        sourceLabel: "Sanitized cookie JSON",
        pathFilterGroup: "shared",
        isVirtual: true
      }));
      entries.push(makeArchiveEntry("cookies/cookies.html", "cookie_export", null, {
        status: "generated",
        sourceLabel: "Cookie HTML export",
        pathFilterGroup: "shared",
        isVirtual: true
      }));
      entries.push(makeArchiveEntry("cookies/cookies.netscape.sanitized.txt", "cookie_export", null, {
        status: "generated",
        sourceLabel: "Sanitized Netscape cookie jar",
        pathFilterGroup: "shared",
        isVirtual: true
      }));

      if (isRawCookieExportEnabled(state)) {
        entries.push(makeArchiveEntry("cookies/cookies.raw.json", "cookie_export", null, {
          status: "generated",
          sourceLabel: "Raw cookie JSON",
          pathFilterGroup: "shared",
          isVirtual: true
        }));
        entries.push(makeArchiveEntry("cookies/cookies.raw.netscape.txt", "cookie_export", null, {
          status: "generated",
          sourceLabel: "Raw Netscape cookie jar",
          pathFilterGroup: "shared",
          isVirtual: true
        }));
      }
    }

    if (options.includeApplication) {
      entries.push(makeArchiveEntry("application/APPLICATION_REPORT.json", "application_report", null, {
        status: "generated",
        sourceLabel: "Application inventory report",
        pathFilterGroup: "application",
        isVirtual: true
      }));
      entries.push(makeArchiveEntry("application/storage.sanitized.json", "application_export", null, {
        status: "generated",
        sourceLabel: "Sanitized storage export",
        pathFilterGroup: "application",
        isVirtual: true
      }));
      entries.push(makeArchiveEntry("application/indexeddb.inventory.json", "application_export", null, {
        status: "generated",
        sourceLabel: "IndexedDB inventory",
        pathFilterGroup: "application",
        isVirtual: true
      }));
      entries.push(makeArchiveEntry("application/cache-storage.inventory.json", "application_export", null, {
        status: "generated",
        sourceLabel: "Cache Storage inventory",
        pathFilterGroup: "application",
        isVirtual: true
      }));

      if (isRawApplicationExportEnabled(state)) {
        entries.push(makeArchiveEntry("application/storage.raw.json", "application_export", null, {
          status: "generated",
          sourceLabel: "Raw storage export",
          pathFilterGroup: "application",
          isVirtual: true
        }));
      }
    }

    return entries;
  }

  function filterArchiveEntries(entries, structView, state) {
    const view = String(structView || "reports");
    if (view === "reports") {
      return buildPrimaryOutputEntries(state);
    }
    if (view === "all") {
      return entries;
    }
    return entries.filter((entry) => entry?.pathFilterGroup === view);
  }

  function createFolderNode(name, path, depth) {
    return {
      kind: "folder",
      name,
      path,
      depth,
      folders: [],
      files: [],
      fileCount: 0
    };
  }

  function createFileNode(name, path, depth, entry) {
    return {
      kind: "file",
      name,
      path,
      depth,
      entry
    };
  }

  function sortEntriesByPath(entries) {
    return [...entries].sort((left, right) => String(left?.path || "").localeCompare(String(right?.path || "")));
  }

  function buildArchiveTree(entries) {
    const rootNode = createFolderNode("", "", -1);

    sortEntriesByPath(entries).forEach((entry) => {
      const rawParts = String(entry?.path || "").split("/").filter(Boolean);
      if (!rawParts.length) {
        return;
      }

      let current = rootNode;
      let currentPath = "";
      rawParts.forEach((part, index) => {
        currentPath = currentPath ? `${currentPath}/${part}` : part;
        const isLeaf = index === rawParts.length - 1;
        if (isLeaf) {
          current.files.push(createFileNode(part, currentPath, index, entry));
          return;
        }

        let folder = current.folders.find((item) => item.name === part);
        if (!folder) {
          folder = createFolderNode(part, currentPath, index);
          current.folders.push(folder);
        }
        current = folder;
      });
    });

    function finalize(node) {
      node.folders.sort((left, right) => left.name.localeCompare(right.name));
      node.files.sort((left, right) => left.name.localeCompare(right.name));
      const folderFiles = node.folders.reduce((total, folder) => total + finalize(folder), 0);
      node.fileCount = node.files.length + folderFiles;
      return node.fileCount;
    }

    finalize(rootNode);
    return rootNode;
  }


  function createEvidenceId(prefix, value) {
    return `${prefix}:${String(value || "").replace(/[^\w:/.-]+/g, "_")}`;
  }

  function buildPathFromResource(item, index) {
    if (item?.exportPath) {
      return item.exportPath;
    }
    if (item?.zipPath) {
      return item.zipPath;
    }
    if (item?.resource) {
      return resolvePlannedFilePath(item, index);
    }
    return item?.path || "";
  }

  function buildCaptureState(item, fallback = "captured") {
    const status = String(item?.status || item?.exportStatus || item?.reason || "").toLowerCase();
    const pathValue = String(item?.path || item?.exportPath || "").toLowerCase();

    if (status.includes("generated")) {
      return "generated";
    }
    if (status.includes("skip")) {
      return "skipped";
    }
    if (status.includes("fail")) {
      return "failed";
    }
    if (status.includes("hidden") || status.includes("metadata") || status.includes("not_captured") || status.includes("body_not_captured")) {
      return "metadata-only";
    }
    if (status.includes("inventory")) {
      return "inventory-only";
    }
    if (status.includes("raw") || pathValue.includes(".raw.")) {
      return "raw";
    }
    if (status.includes("sanitize") || pathValue.includes("sanitized")) {
      return "sanitized";
    }
    if (pathValue.includes("inventory")) {
      return "inventory-only";
    }
    if (pathValue.includes("sanitized")) {
      return "sanitized";
    }
    if (pathValue.includes(".raw.")) {
      return "raw";
    }
    return fallback;
  }

  function normalizeSourceLabel(value) {
    return EVIDENCE_SOURCE_LABELS[value] || "Unknown";
  }

  function deriveDomain(urlValue, fallbackPath) {
    const parsed = safeParseUrl(urlValue);
    if (parsed?.hostname) {
      return parsed.hostname.toLowerCase();
    }
    const pathText = String(fallbackPath || "");
    const match = pathText.match(/^(sources|network|data-urls)\/([^/]+)/);
    return match ? match[2].toLowerCase() : "";
  }

  function domainForApplication(targetDomain, explicitDomain) {
    return explicitDomain || targetDomain || "";
  }

  function buildGeneratedNetworkItems(state, targetDomain) {
    const options = state?.export?.options || {};
    const items = [];
    if (options.includeNetwork && options.includeNetworkSummary !== false) {
      items.push({
        id: "network:report",
        source: "network",
        domain: targetDomain || "",
        hasRealDomain: false,
        path: "NETWORK_REPORT.json",
        exportPath: "NETWORK_REPORT.json",
        displayName: "NETWORK_REPORT.json",
        type: "Report",
        captureState: "generated",
        sourceLabel: "Network summary report"
      });
    }
    return items;
  }

  function buildGeneratedApplicationItems(state, targetDomain) {
    const options = state?.export?.options || {};
    if (!options.includeApplication && !options.includeCookiesReport) {
      return [];
    }

    const items = [];

    if (options.includeApplication) {
      items.push({
        id: "application:report",
        source: "application",
        domain: domainForApplication(targetDomain),
        hasRealDomain: false,
        path: "application/APPLICATION_REPORT.json",
        exportPath: "application/APPLICATION_REPORT.json",
        displayName: "APPLICATION_REPORT.json",
        type: "Report",
        captureState: "generated",
        sourceLabel: "Application inventory report"
      });
      items.push({
        id: "application:storage:sanitized",
        source: "application",
        domain: domainForApplication(targetDomain),
        hasRealDomain: false,
        path: "application/storage.sanitized.json",
        exportPath: "application/storage.sanitized.json",
        displayName: "storage.sanitized.json",
        type: "Storage",
        captureState: "sanitized",
        sourceLabel: "Sanitized storage snapshot"
      });
      items.push({
        id: "application:indexeddb",
        source: "application",
        domain: domainForApplication(targetDomain),
        hasRealDomain: false,
        path: "application/indexeddb.inventory.json",
        exportPath: "application/indexeddb.inventory.json",
        displayName: "indexeddb.inventory.json",
        type: "IndexedDB",
        captureState: "inventory-only",
        sourceLabel: "IndexedDB inventory"
      });
      items.push({
        id: "application:cache-storage",
        source: "application",
        domain: domainForApplication(targetDomain),
        hasRealDomain: false,
        path: "application/cache-storage.inventory.json",
        exportPath: "application/cache-storage.inventory.json",
        displayName: "cache-storage.inventory.json",
        type: "Cache Storage",
        captureState: "inventory-only",
        sourceLabel: "Cache Storage inventory"
      });

      if (isRawApplicationExportEnabled(state)) {
        items.push({
          id: "application:storage:raw",
          source: "application",
          domain: domainForApplication(targetDomain),
          hasRealDomain: false,
          path: "application/storage.raw.json",
          exportPath: "application/storage.raw.json",
          displayName: "storage.raw.json",
          type: "Storage",
          captureState: "raw",
          sourceLabel: "Raw storage snapshot"
        });
      }
    }

    if (options.includeCookiesReport) {
      items.push({
        id: "application:cookies:report",
        source: "application",
        domain: domainForApplication(targetDomain),
        hasRealDomain: false,
        path: "cookies/COOKIES_REPORT.json",
        exportPath: "cookies/COOKIES_REPORT.json",
        displayName: "COOKIES_REPORT.json",
        type: "Report",
        captureState: "generated",
        sourceLabel: "Cookie analyzer report"
      });
      items.push({
        id: "application:cookies:sanitized",
        source: "application",
        domain: domainForApplication(targetDomain),
        hasRealDomain: false,
        path: "cookies/cookies.sanitized.json",
        exportPath: "cookies/cookies.sanitized.json",
        displayName: "cookies.sanitized.json",
        type: "Cookie",
        captureState: "sanitized",
        sourceLabel: "Sanitized cookie snapshot"
      });

      if (isRawCookieExportEnabled(state)) {
        items.push({
          id: "application:cookies:raw",
          source: "application",
          domain: domainForApplication(targetDomain),
          hasRealDomain: false,
          path: "cookies/cookies.raw.json",
          exportPath: "cookies/cookies.raw.json",
          displayName: "cookies.raw.json",
          type: "Cookie",
          captureState: "raw",
          sourceLabel: "Raw cookie snapshot"
        });
      }
    }

    const appManifest = state?.application?.manifest;
    if (appManifest?.href) {
      items.push({
        id: "application:manifest:url",
        source: "application",
        url: appManifest.href,
        domain: deriveDomain(appManifest.href, ""),
        hasRealDomain: true,
        path: "",
        exportPath: "",
        displayName: summarizeDisplayName("", appManifest.href, "manifest"),
        type: "Manifest",
        captureState: "metadata-only",
        sourceLabel: "Page manifest"
      });
    }

    if (Array.isArray(state?.application?.serviceWorkers?.registrations) && state.application.serviceWorkers.registrations.length) {
      items.push({
        id: "application:service-workers",
        source: "application",
        domain: domainForApplication(targetDomain),
        hasRealDomain: false,
        path: "",
        exportPath: "",
        displayName: "service-workers.json",
        type: "Service Worker",
        captureState: "inventory-only",
        sourceLabel: "Service worker registrations"
      });
    }

    return items;
  }

  function normalizeEvidenceItem(input, index, targetDomain) {
    const source = input?.source || (input?.collector === "network_har" || input?.isNetworkBody ? "network" : "sources");
    const exportPath = input?.exportPath || input?.path || "";
    const urlValue = input?.urlRedacted || input?.url || "";
    const parsedUrl = safeParseUrl(input?.url || input?.urlRedacted || "");
    const hasRealDomain = input?.hasRealDomain === true || Boolean(parsedUrl?.hostname);
    const domainValue = source === "application"
      ? domainForApplication(targetDomain, input?.domain || deriveDomain(urlValue, exportPath))
      : (input?.domain || deriveDomain(urlValue, exportPath));
    const displayName = input?.displayName || summarizeDisplayName(exportPath, urlValue, `item-${index + 1}`);
    const evidenceType = normalizeEvidenceType({
      displayName,
      path: exportPath,
      exportPath,
      url: input?.url,
      mimeType: input?.mimeType,
      type: input?.type || input?.resourceType,
      sourceLabel: input?.sourceLabel
    });

    let capturedAt = null;
    if (input?.capturedAt != null) {
      capturedAt = input.capturedAt;
    } else if (input?.startedDateTime) {
      const millis = Date.parse(input.startedDateTime);
      capturedAt = Number.isFinite(millis) ? millis : null;
    }

    return {
      id: input?.id || createEvidenceId(source, input?.exportPath || input?.url || input?.displayName || index),
      source,
      url: input?.url || "",
      urlRedacted: input?.urlRedacted || urlValue,
      domain: domainValue,
      hasRealDomain,
      path: input?.path || exportPath,
      displayName,
      type: evidenceType,
      method: input?.method || "",
      statusCode: input?.statusCode ?? input?.status ?? null,
      capturedAt,
      sizeBytes: input?.sizeBytes ?? input?.bodyCapturedBytes ?? input?.size ?? null,
      status: input?.status || input?.exportStatus || "",
      isFirstParty: classifyParty(domainValue, targetDomain),
      exportPath,
      captureState: input?.captureState || buildCaptureState(input),
      sourceLabel: input?.sourceLabel || "",
      collector: input?.collector || "",
      reason: input?.reason || input?.skipReason || "",
      skipReason: input?.skipReason || input?.reason || "",
      mimeType: input?.mimeType || "",
      item: input?.item || null,
      order: index
    };
  }

  function buildEvidenceItems(state, plan) {
    const targetUrl = state?.target?.currentUrl || state?.target?.analyzedUrl || "";
    const targetDomain = deriveDomain(targetUrl, "");
    const items = [];

    (plan?.plannedFiles || []).forEach((planned, index) => {
      const resource = planned?.resource || {};
      const exportPath = buildPathFromResource(planned, index);
      const source = planned?.isNetworkBody || resource?.collector === "network_har" ? "network" : "sources";
      items.push(normalizeEvidenceItem({
        id: resource.id || createEvidenceId(source, resource.url || exportPath || index),
        source,
        url: resource.url || "",
        urlRedacted: resource.urlRedacted || displayUrl(resource),
        domain: deriveDomain(resource.urlRedacted || resource.url, exportPath),
        path: exportPath,
        exportPath,
        displayName: summarizeDisplayName(exportPath, resource.url, resource.type || `item-${index + 1}`),
        type: resource.type || resource.resourceType || planned?.contentKind || "",
        method: resource.method || resource.requestMethod || "",
        statusCode: resource.statusCode ?? resource.status ?? null,
        capturedAt: resource.startedDateTime ? Date.parse(resource.startedDateTime) : null,
        sizeBytes: resource.bodyCapturedBytes ?? resource.bodySizeBytes ?? resource.size ?? null,
        status: resource.bodyCaptureStatus || "captured",
        captureState: "captured",
        sourceLabel: planned?.isNetworkBody ? "Captured network body" : "Captured source",
        collector: resource.collector || "",
        reason: resource.reason || planned?.reason || "",
        mimeType: planned?.mimeType || resource?.mimeType || "",
        item: planned
      }, items.length, targetDomain));
    });

    (plan?.manifestOnlyResources || []).forEach((resource, index) => {
      const source = resource?.collector === "network_har" ? "network" : "sources";
      items.push(normalizeEvidenceItem({
        id: resource.id || createEvidenceId(source, resource.url || index),
        source,
        url: resource.url || "",
        urlRedacted: resource.urlRedacted || displayUrl(resource),
        domain: deriveDomain(resource.urlRedacted || resource.url, ""),
        path: "",
        exportPath: "",
        displayName: summarizeDisplayName("", resource.url, `metadata-${index + 1}`),
        type: resource.type || resource.resourceType || "",
        method: resource.method || resource.requestMethod || "",
        statusCode: resource.statusCode ?? resource.status ?? null,
        capturedAt: resource.startedDateTime ? Date.parse(resource.startedDateTime) : null,
        sizeBytes: resource.bodyCapturedBytes ?? resource.bodySizeBytes ?? resource.size ?? null,
        status: resource.exportStatus || resource.bodyCaptureStatus || "metadata-only",
        captureState: buildCaptureState(resource, "metadata-only"),
        sourceLabel: "Metadata-only capture",
        collector: resource.collector || "",
        reason: resource.reason || resource.bodyCaptureReason || "",
        skipReason: resource.bodyCaptureReason || resource.reason || "",
        mimeType: resource.mimeType || "",
        item: resource
      }, items.length, targetDomain));
    });

    (plan?.failedResources || []).forEach((resource, index) => {
      const source = resource?.collector === "network_har" ? "network" : "sources";
      items.push(normalizeEvidenceItem({
        id: resource.id || createEvidenceId(source, resource.url || `failed-${index}`),
        source,
        url: resource.url || "",
        urlRedacted: resource.urlRedacted || displayUrl(resource),
        domain: deriveDomain(resource.urlRedacted || resource.url, ""),
        path: "",
        exportPath: "",
        displayName: summarizeDisplayName("", resource.url, `failed-${index + 1}`),
        type: resource.type || "",
        method: resource.method || resource.requestMethod || "",
        statusCode: resource.statusCode ?? resource.status ?? null,
        capturedAt: resource.startedDateTime ? Date.parse(resource.startedDateTime) : null,
        sizeBytes: null,
        status: resource.exportStatus || "failed",
        captureState: "failed",
        sourceLabel: "Failed capture",
        collector: resource.collector || "",
        reason: resource.reason || "",
        skipReason: resource.reason || "",
        mimeType: resource.mimeType || "",
        item: resource
      }, items.length, targetDomain));
    });

    buildGeneratedNetworkItems(state, targetDomain).forEach((item) => {
      items.push(normalizeEvidenceItem(item, items.length, targetDomain));
    });

    buildGeneratedApplicationItems(state, targetDomain).forEach((item) => {
      items.push(normalizeEvidenceItem(item, items.length, targetDomain));
    });

    return items;
  }

  function matchesEvidenceFilter(item, text) {
    const needle = String(text || "").trim().toLowerCase();
    if (!needle) {
      return true;
    }
    const haystack = [
      item.displayName,
      item.domain,
      item.url,
      item.urlRedacted,
      item.path,
      item.exportPath,
      item.type,
      item.captureState,
      item.source,
      normalizeSourceLabel(item.source),
      item.collector,
      item.reason,
      item.skipReason,
      item.method,
      item.statusCode,
      item.mimeType
    ]
      .filter(Boolean)
      .join("\n")
      .toLowerCase();
    return haystack.includes(needle);
  }

  function filterEvidenceItems(items, filterText) {
    return (items || []).filter((item) => matchesEvidenceFilter(item, filterText));
  }

  function compareText(left, right) {
    return String(left || "").localeCompare(String(right || ""));
  }

  function sortEvidenceItems(items, groupBy) {
    const view = normalizeEvidenceGroupBy(groupBy);
    return [...items].sort((left, right) => {
      if (view === "time") {
        const leftTime = left.capturedAt != null ? left.capturedAt : Number.MAX_SAFE_INTEGER;
        const rightTime = right.capturedAt != null ? right.capturedAt : Number.MAX_SAFE_INTEGER;
        if (leftTime !== rightTime) {
          return leftTime - rightTime;
        }
        if (left.order !== right.order) {
          return left.order - right.order;
        }
      }
      const byName = compareText(left.displayName, right.displayName);
      if (byName !== 0) {
        return byName;
      }
      return compareText(left.id, right.id);
    });
  }

  function applicationBucketForItem(item) {
    if (item.type === "Storage" || item.type === "Cookie") {
      return item.type;
    }
    if (item.type === "IndexedDB" || item.type === "Cache Storage" || item.type === "Service Worker" || item.type === "Manifest") {
      return item.type;
    }
    return "Reports";
  }

  function createGroupNode(key, label) {
    return {
      key,
      label,
      children: [],
      items: [],
      count: 0
    };
  }

  function getOrCreateGroup(parent, key, label) {
    let group = parent.children.find((entry) => entry.key === key);
    if (!group) {
      group = createGroupNode(key, label);
      parent.children.push(group);
    }
    return group;
  }

  function stripExportPathPrefix(item, pathValue) {
    const text = String(pathValue || "");
    if (!text) {
      return "";
    }
    if (item.source === "sources") {
      return text.replace(/^sources\/[^/]+\/?/, "");
    }
    if (item.source === "network") {
      return text.replace(/^(network|data-urls)\/[^/]+\/?/, "");
    }
    if (item.source === "application") {
      return text.replace(/^(application|cookies)\/?/, "");
    }
    return text;
  }

  function buildPathSegments(item) {
    const exportPath = String(item.exportPath || item.path || "");
    let segments = [];

    if (exportPath) {
      segments = stripExportPathPrefix(item, exportPath)
        .split("/")
        .filter(Boolean);
    }

    if (!segments.length && item.url) {
      const parsed = safeParseUrl(item.url);
      if (parsed) {
        segments = parsed.pathname.split("/").filter(Boolean);
      }
    }

    if (!segments.length) {
      segments = [item.displayName];
    }

    if (segments[segments.length - 1] !== item.displayName) {
      segments = [...segments.slice(0, -1), item.displayName];
    }

    if (!segments.length) {
      segments = [item.displayName];
    }

    return segments;
  }

  function appendPathToGroup(parent, item, baseKey) {
    const segments = buildPathSegments(item);
    let current = parent;
    segments.slice(0, -1).forEach((segment, index) => {
      current = getOrCreateGroup(
        current,
        `${baseKey}:path:${segments.slice(0, index + 1).join("/")}`,
        segment
      );
    });
    current.items.push(item);
  }

  function appendApplicationItem(parent, item, baseKey) {
    const bucket = applicationBucketForItem(item);
    const bucketGroup = getOrCreateGroup(parent, `${baseKey}:bucket:${bucket}`, bucket);
    appendPathToGroup(bucketGroup, item, `${baseKey}:bucket:${bucket}`);
  }

  function finalizeGroup(group) {
    group.children.sort((left, right) => compareText(left.label, right.label));
    group.items.sort((left, right) => compareText(left.displayName, right.displayName));
    group.children.forEach((child) => finalizeGroup(child));
    group.count =
      group.items.length +
      group.children.reduce((total, child) => total + child.count, 0);
    return group;
  }

  function buildEvidenceGroups(items, groupBy) {
    const normalizedGroupBy = normalizeEvidenceGroupBy(groupBy);
    const sortedItems = sortEvidenceItems(items, normalizedGroupBy);

    if (normalizedGroupBy === "source") {
      const roots = [
        createGroupNode("source:sources", "Sources"),
        createGroupNode("source:application", "Application"),
        createGroupNode("source:network", "Network")
      ];
      const bySource = new Map([
        ["sources", roots[0]],
        ["application", roots[1]],
        ["network", roots[2]]
      ]);

      sortedItems.forEach((item) => {
        const root = bySource.get(item.source);
        if (!root) {
          return;
        }

        if (item.source === "application") {
          appendApplicationItem(root, item, root.key);
          return;
        }

        const domainLabel = item.domain || "unknown";
        const domainGroup = getOrCreateGroup(root, `${root.key}:domain:${domainLabel}`, domainLabel);
        appendPathToGroup(domainGroup, item, `${root.key}:domain:${domainLabel}`);
      });

      return roots.map((group) => finalizeGroup(group));
    }

    if (normalizedGroupBy === "type") {
      const groups = [];
      TYPE_ORDER.forEach((type) => {
        const typeItems = sortedItems.filter((item) => item.type === type);
        if (!typeItems.length) {
          return;
        }
        const root = createGroupNode(`type:${type}`, type);
        typeItems.forEach((item) => {
          const sourceGroup = getOrCreateGroup(root, `${root.key}:source:${item.source}`, normalizeSourceLabel(item.source));
          if (item.source === "application") {
            appendApplicationItem(sourceGroup, item, `${root.key}:source:${item.source}`);
          } else {
            const domainLabel = item.domain || "unknown";
            const domainGroup = getOrCreateGroup(sourceGroup, `${root.key}:source:${item.source}:domain:${domainLabel}`, domainLabel);
            appendPathToGroup(domainGroup, item, `${root.key}:source:${item.source}:domain:${domainLabel}`);
          }
        });
        groups.push(finalizeGroup(root));
      });
      return groups;
    }

    if (normalizedGroupBy === "domain") {
      const domainMap = new Map();
      sortedItems.forEach((item) => {
        const domainLabel = item.source === "application" && !item.hasRealDomain
          ? "Generated"
          : (item.domain || "unknown");
        let root = domainMap.get(domainLabel);
        if (!root) {
          root = createGroupNode(`domain:${domainLabel}`, domainLabel);
          domainMap.set(domainLabel, root);
        }
        const sourceGroup = getOrCreateGroup(root, `${root.key}:source:${item.source}`, normalizeSourceLabel(item.source));
        if (item.source === "application") {
          appendApplicationItem(sourceGroup, item, `${root.key}:source:${item.source}`);
        } else {
          appendPathToGroup(sourceGroup, item, `${root.key}:source:${item.source}`);
        }
      });
      return [...domainMap.values()].sort((left, right) => compareText(left.label, right.label)).map((group) => finalizeGroup(group));
    }

    const timeline = createGroupNode("time:capture-order", "Capture order");
    timeline.items = sortedItems;
    return [finalizeGroup(timeline)];
  }

  function formatRelativeTime(timestamp, baseline) {
    if (!Number.isFinite(timestamp)) {
      return "—";
    }
    const diff = Math.max(0, timestamp - baseline);
    const seconds = diff / 1000;
    return seconds.toFixed(3).padStart(8, "0");
  }

  function renderBadge(text, cssClass = "") {
    return `<span class="evidence-badge${cssClass ? ` ${cssClass}` : ""}">${escapeHtml(text)}</span>`;
  }

  function renderEvidenceBadges(item) {
    const badges = [
      renderBadge(normalizeSourceLabel(item.source)),
      renderBadge(item.type),
      item.isFirstParty ? renderBadge(item.isFirstParty, item.isFirstParty) : "",
      item.captureState ? renderBadge(item.captureState) : ""
    ];
    return badges.join("");
  }

  function renderEvidenceMeta(item) {
    const rows = [
      `<div><span>Name</span><b title="${escapeHtml(item.displayName)}">${escapeHtml(item.displayName)}</b></div>`,
      `<div><span>Source</span><b>${escapeHtml(normalizeSourceLabel(item.source))}</b></div>`,
      `<div><span>Type</span><b>${escapeHtml(item.type || "Other")}</b></div>`,
      item.captureState ? `<div><span>Capture state</span><b>${escapeHtml(item.captureState)}</b></div>` : "",
      item.urlRedacted ? `<div><span>URL</span><b title="${escapeHtml(item.urlRedacted)}">${escapeHtml(item.urlRedacted)}</b></div>` : "",
      item.domain ? `<div><span>Domain</span><b title="${escapeHtml(item.domain)}">${escapeHtml(item.domain)}</b></div>` : "",
      item.exportPath ? `<div><span>Export path</span><b title="${escapeHtml(item.exportPath)}">${escapeHtml(item.exportPath)}</b></div>` : "",
      item.skipReason ? `<div><span>Skip reason</span><b>${escapeHtml(item.skipReason)}</b></div>` : "",
      item.mimeType ? `<div><span>MIME type</span><b>${escapeHtml(item.mimeType)}</b></div>` : "",
      item.sizeBytes != null ? `<div><span>Size</span><b>${escapeHtml(item.sizeBytes)} bytes</b></div>` : "",
      item.statusCode != null && item.statusCode !== "" ? `<div><span>Status</span><b>${escapeHtml(item.statusCode)}</b></div>` : "",
      item.method ? `<div><span>Method</span><b>${escapeHtml(item.method)}</b></div>` : "",
      item.isFirstParty ? `<div><span>Party</span><b>${escapeHtml(item.isFirstParty)}</b></div>` : "",
      item.sourceLabel ? `<div><span>Evidence label</span><b>${escapeHtml(item.sourceLabel)}</b></div>` : "",
      item.collector ? `<div><span>Collector</span><b>${escapeHtml(item.collector)}</b></div>` : ""
    ];
    return rows.filter(Boolean).join("");
  }

  function shouldNodeOpen(nodePath, depth, options) {
    const expanded = options?.expandedPaths instanceof Set ? options.expandedPaths : new Set();
    if (expanded.has(nodePath)) {
      return true;
    }
    return depth < (options?.defaultOpenDepth ?? 0);
  }

  function renderEvidenceItem(item, options, depth) {
    const nodePath = `item:${item.id}`;
    const baseline = options?.timeBaseline ?? 0;
    const timePrefix = options?.showTime ? `<span class="evidence-time">${escapeHtml(formatRelativeTime(item.capturedAt, baseline))}</span>` : "";
    return `<details class="tree-node evidence-item" data-node-path="${escapeHtml(nodePath)}" data-depth="${escapeHtml(depth)}" style="--tree-depth:${escapeHtml(depth)}"${shouldNodeOpen(nodePath, 99, options) ? " open" : ""}><summary><div class="tree-branch" aria-hidden="true"></div><div class="evidence-main"><span class="tree-label" title="${escapeHtml(item.displayName)}">${timePrefix}${escapeHtml(item.displayName)}</span></div><span class="tree-badges">${renderEvidenceBadges(item)}</span></summary><div class="tree-children"><div class="tree-meta">${renderEvidenceMeta(item)}</div></div></details>`;
  }

  function renderGroup(group, depth, options) {
    const nodePath = `group:${group.key}`;
    const childMarkup = (group.children || []).map((child) => renderGroup(child, depth + 1, options)).join("");
    const itemMarkup = (group.items || []).map((item) => renderEvidenceItem(item, options, depth + 1)).join("");
    const count = (group.items || []).length + (group.children || []).reduce((total, child) => total + child.count, 0);
    group.count = count;
    return `<details class="tree-node tree-folder evidence-group" data-node-path="${escapeHtml(nodePath)}" data-depth="${escapeHtml(depth)}" style="--tree-depth:${escapeHtml(depth)}"${shouldNodeOpen(nodePath, depth, options) ? " open" : ""}><summary><div class="tree-branch" aria-hidden="true"></div><span class="tree-label" title="${escapeHtml(group.label)}">${escapeHtml(group.label)}</span><span class="tree-badges"><span class="evidence-badge">${escapeHtml(count)} items</span></span></summary><div class="tree-children">${childMarkup}${itemMarkup || (!childMarkup ? '<div class="tree-empty">No evidence in this branch.</div>' : "")}</div></details>`;
  }

  function renderViewControls(state) {
    const ui = state?.export?.ui || {};
    const groupBy = normalizeEvidenceGroupBy(ui.groupBy);
    const filterText = String(ui.filterText || "");
    return `<div class="view-controls"><div class="view-controls-header"><div class="view-controls-label">View</div><div class="view-controls-actions"><button id="expandAllEvidenceBtn" type="button">Expand all</button><button id="collapseAllEvidenceBtn" type="button">Collapse all</button></div></div><div class="view-controls-grid"><label class="field-label">Group by<select id="evidenceGroupBy"><option value="source"${groupBy === "source" ? " selected" : ""}>Source</option><option value="type"${groupBy === "type" ? " selected" : ""}>Type</option><option value="domain"${groupBy === "domain" ? " selected" : ""}>Domain</option><option value="time"${groupBy === "time" ? " selected" : ""}>Time</option></select></label><label class="field-label">Filter<input id="evidenceFilterInput" type="text" value="${escapeHtml(filterText)}" placeholder="name, URL, domain, source, type, state, export path" /></label></div></div>`;
  }

  function renderEvidenceSummary(state, items) {
    const counts = {
      sources: items.filter((item) => item.source === "sources").length,
      application: items.filter((item) => item.source === "application").length,
      network: items.filter((item) => item.source === "network").length
    };
    const captureState = state?.network?.captureState || "stopped";
    const captureLabel = captureState === "live"
      ? "Network capture: live"
      : captureState === "frozen_for_export"
        ? "Network capture: frozen for export"
        : "Network capture: stopped";
    return `<div class="tree-summary-row"><span>Sources <b>${escapeHtml(counts.sources)}</b></span><span>Application <b>${escapeHtml(counts.application)}</b></span><span>Network <b>${escapeHtml(counts.network)}</b></span><span>Total <b>${escapeHtml(items.length)}</b></span><span>${escapeHtml(captureLabel)}</span></div>`;
  }

  function renderEvidenceSection(state, plan) {
    const allItems = buildEvidenceItems(state, plan);
    const filterText = state?.export?.ui?.filterText || "";
    const filteredItems = filterEvidenceItems(allItems, filterText);
    const groups = buildEvidenceGroups(filteredItems, state?.export?.ui?.groupBy);
    const expandedPaths = new Set(state?.export?.ui?.expandedPaths || []);
    const timeValues = filteredItems.map((item) => item.capturedAt).filter((value) => Number.isFinite(value));
    const baseline = timeValues.length ? Math.min(...timeValues) : 0;
    const options = {
      expandedPaths,
      defaultOpenDepth: 0,
      showTime: normalizeEvidenceGroupBy(state?.export?.ui?.groupBy) === "time",
      timeBaseline: baseline
    };

    return `<div class="module-card"><div class="section-header"><h2>Evidence tree</h2></div>${renderViewControls(state)}${renderEvidenceSummary(state, filteredItems)}<div class="tree-root tree-root-evidence">${groups.length ? groups.map((group) => renderGroup(group, 0, options)).join("") : '<div class="tree-empty">No evidence matched the current filter.</div>'}</div></div>`;
  }
  function renderStat(label, value) {
    return `<div class="stat-box"><span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>`;
  }

  function renderExportPlanSummary(state, plan) {
    return `<div class="stat-grid">${renderStat("Source files", plan?.counts?.sourceFiles || 0)}${renderStat("Application evidence", state?.export?.options?.includeApplication ? 4 : 0)}${renderStat("Network bodies", plan?.counts?.networkBodyFiles || 0)}${renderStat("Network metadata-only", plan?.counts?.networkMetadataOnly || 0)}${renderStat("Manifest/report files", (plan?.counts?.manifestFiles || 0) + (plan?.counts?.diagnosticsFiles || 0) + (state?.export?.options?.includeNetworkSummary ? 1 : 0) + (state?.export?.options?.includeCookiesReport ? 1 : 0))}${renderStat("Skipped", plan?.skippedResources?.length || 0)}${renderStat("Failed", plan?.failedResources?.length || 0)}${renderStat("Excluded", plan?.counts?.excludedResources || 0)}${renderStat("Budgeted input", `${Math.round(((plan?.budgetSummary?.totalInputBytes || 0) / (1024 * 1024)) * 10) / 10} MB`)}</div>`;
  }

  function renderCaptureSettingsPanel(state, plan) {
    const seconds = normalizeScanDurationSeconds(state?.capture?.scanDurationSeconds);
    return `<div class="module-card module-card-compact"><div class="section-inline"><div><h3>Capture settings</h3><p class="section-hint">Public v1 uses one default export profile. Network capture waits for the selected scan time before Sources/Application are collected.</p></div><label class="field-label scan-duration-field">Scan time (seconds)<input id="scanDurationInput" type="number" min="1" max="20" step="1" value="${escapeHtml(seconds)}" /></label><label class="toggle-row"><input id="dumpCookiesToggle" type="checkbox" ${state?.dumpObjectsEnabled ? "checked" : ""}/> Include raw cookie dump</label></div><div class="inline-note">Default export includes code/text evidence, compact reports, sanitized Application storage, and sanitized cookies. Raw Application storage is not exported in v1.</div><div class="section-subtitle">Export plan</div>${renderExportPlanSummary(state, plan)}</div>`;
  }

  function renderExportModule(state, plan) {
    return `<section class="module">${renderEvidenceSection(state, plan)}${renderCaptureSettingsPanel(state, plan)}</section>`;
  }

  return {
    buildArchiveEntries,
    buildArchiveTree,
    buildEvidenceGroups,
    buildEvidenceItems,
    buildPrimaryOutputEntries,
    classifyEntryGroup,
    displayUrl,
    escapeHtml,
    filterArchiveEntries,
    filterEvidenceItems,
    normalizeEvidenceGroupBy,
    normalizeEvidenceType,
    renderExportModule,
    resolvePlannedFilePath
  };
});
