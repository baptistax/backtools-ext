(function (root, factory) {
  const api = factory(root);
  root.BackToolsRuntime = Object.assign(root.BackToolsRuntime || {}, api);
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : window, function (root) {
  function safeString(value) {
    return value === null || value === undefined ? "" : String(value);
  }

  function normalizeStatus(value, fallback) {
    const status = safeString(value || fallback || "complete");
    return status === "ok" ? "complete" : status;
  }

  function wait(ms, runtimeRoot) {
    return new Promise((resolve) => {
      const timer = runtimeRoot && typeof runtimeRoot.setTimeout === "function" ? runtimeRoot.setTimeout.bind(runtimeRoot) : setTimeout;
      timer(resolve, ms);
    });
  }

  async function waitForStableTargetUrl(options = {}) {
    const runtimeRoot = options.root || root;
    const evalUrl = options.evalUrl;
    const timeoutMs = Number.isFinite(Number(options.timeoutMs)) ? Number(options.timeoutMs) : 12000;
    const intervalMs = Number.isFinite(Number(options.intervalMs)) ? Number(options.intervalMs) : 400;
    const stableReads = Number.isFinite(Number(options.stableReads)) ? Number(options.stableReads) : 2;
    const startedAt = Date.now();
    let lastUrl = null;
    let stableCount = 0;

    if (typeof evalUrl !== "function") {
      return null;
    }

    while (Date.now() - startedAt < timeoutMs) {
      const nextUrl = safeString(await evalUrl()).trim() || null;

      if (nextUrl && nextUrl === lastUrl) {
        stableCount += 1;
        if (stableCount >= stableReads) {
          return nextUrl;
        }
      } else {
        lastUrl = nextUrl;
        stableCount = nextUrl ? 1 : 0;
      }

      await wait(intervalMs, runtimeRoot);
    }

    return lastUrl;
  }

  async function reloadAndAnalyze(options = {}) {
    const reload = options.reload;
    const analyze = options.analyze;
    const applyTargetUrl = options.applyTargetUrl;
    const beforeReload = options.beforeReload;
    const runtimeRoot = options.root || root;

    if (typeof reload !== "function") {
      return {
        ok: false,
        status: "unavailable",
        reason: "reload_unavailable",
        message: "Reload inspected window is not available."
      };
    }

    if (typeof analyze !== "function") {
      return {
        ok: false,
        status: "unavailable",
        reason: "analyze_unavailable",
        message: "Analyze is not available."
      };
    }

    if (typeof beforeReload === "function") {
      await beforeReload();
    }

    await reload({ ignoreCache: true });

    const targetUrl = await waitForStableTargetUrl({
      root: runtimeRoot,
      evalUrl: options.evalUrl,
      timeoutMs: options.timeoutMs,
      intervalMs: options.intervalMs,
      stableReads: options.stableReads
    });

    if (targetUrl && typeof applyTargetUrl === "function") {
      await applyTargetUrl(targetUrl, "inspected_window_eval_location_href");
    }

    const analyzeResult = await analyze();
    const status = normalizeStatus(analyzeResult && analyzeResult.status, "complete");

    if (analyzeResult && analyzeResult.ok === false) {
      return {
        ...analyzeResult,
        action: "reloadAndCapture",
        targetUrl,
        analyzeResult
      };
    }

    return {
      ok: analyzeResult && analyzeResult.ok !== undefined ? analyzeResult.ok : true,
      status,
      action: "reloadAndCapture",
      targetUrl,
      analyzeResult,
      snapshot: analyzeResult && analyzeResult.snapshot
    };
  }

  return {
    reloadAndAnalyze,
    waitForStableTargetUrl
  };
});
