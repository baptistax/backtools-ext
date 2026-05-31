(function(root, factory) {
  const api = factory();
  root.BackToolsDomain = Object.assign(root.BackToolsDomain || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function() {
  const TargetType = {
    WEB_HTTP: 'web_http',
    WEB_HTTPS: 'web_https',
    NEW_TAB: 'new_tab',
    ABOUT_BLANK: 'about_blank',
    CHROME_INTERNAL: 'chrome_internal',
    EXTENSION_PAGE: 'extension_page',
    FILE_URL: 'file_url',
    UNKNOWN: 'unknown'
  };

  const CaptureMode = {
    WEB_FULL_AVAILABLE: 'web_full_available',
    LIMITED_TARGET_REPORT_ONLY: 'limited_target_report_only',
    EMPTY_TARGET_REPORT_ONLY: 'empty_target_report_only',
    UNKNOWN_TARGET_REPORT_ONLY: 'unknown_target_report_only'
  };

  const Reason = {
    TARGET_NOT_WEB_PAGE: 'target_not_web_page',
    TARGET_EMPTY_URL: 'target_empty_url',
    TARGET_BLANK_PAGE: 'target_blank_page',
    CHROME_INTERNAL_TARGET: 'chrome_internal_target',
    NO_HTTP_ORIGIN: 'no_http_origin',
    PLATFORM_RETURNED_NO_RESOURCES: 'platform_returned_no_resources',
    INSPECTED_WINDOW_EVAL_UNAVAILABLE: 'inspected_window_eval_unavailable',
    APPLICATION_STORAGE_UNAVAILABLE: 'application_storage_unavailable',
    NO_NETWORK_REQUESTS_OBSERVED: 'no_network_requests_observed',
    TARGET_CHANGED_DURING_CAPTURE: 'target_changed_during_capture',
    EXPORT_REPORT_ONLY_LIMITED_TARGET: 'export_report_only_limited_target',
    EXPORT_EMPTY_BUT_VALID_REPORT: 'export_empty_but_valid_report'
  };

  function classifyTargetUrl(rawUrl, options = {}) {
    const input = normalizeInput(rawUrl);
    const urlSource = options.urlSource || 'initial_unknown';

    if (!input) {
      return buildTarget({
        targetType: TargetType.UNKNOWN,
        targetUrl: null,
        normalizedUrl: null,
        scheme: null,
        isNormalWebTarget: false,
        isLimitedTarget: true,
        isEmptyTarget: true,
        classificationReason: Reason.TARGET_EMPTY_URL,
        captureMode: CaptureMode.UNKNOWN_TARGET_REPORT_ONLY,
        statusLabel: 'Empty target',
        message: 'Target not identified yet. Back Tools will run a limited analysis.',
        urlSource
      });
    }

    const parsed = parseUrl(input);

    if (!parsed) {
      return buildTarget({
        targetType: TargetType.UNKNOWN,
        targetUrl: input,
        normalizedUrl: input,
        scheme: null,
        isNormalWebTarget: false,
        isLimitedTarget: true,
        isEmptyTarget: false,
        classificationReason: Reason.TARGET_NOT_WEB_PAGE,
        captureMode: CaptureMode.UNKNOWN_TARGET_REPORT_ONLY,
        statusLabel: 'Limited browser/new-tab target',
        message: limitedMessage(),
        urlSource
      });
    }

    const scheme = parsed.protocol.replace(':', '').toLowerCase();
    const normalizedUrl = parsed.href;

    if (scheme === 'http' || scheme === 'https') {
      return buildTarget({
        targetType: scheme === 'http' ? TargetType.WEB_HTTP : TargetType.WEB_HTTPS,
        targetUrl: normalizedUrl,
        normalizedUrl,
        scheme,
        isNormalWebTarget: true,
        isLimitedTarget: false,
        isEmptyTarget: false,
        classificationReason: null,
        captureMode: CaptureMode.WEB_FULL_AVAILABLE,
        statusLabel: 'Supported web target',
        message: 'Supported web target. Back Tools can analyze available Sources, Network, and Application data for this page.',
        urlSource
      });
    }

    if (scheme === 'about' && normalizedUrl.toLowerCase() === 'about:blank') {
      return buildTarget({
        targetType: TargetType.ABOUT_BLANK,
        targetUrl: normalizedUrl,
        normalizedUrl,
        scheme,
        isNormalWebTarget: false,
        isLimitedTarget: true,
        isEmptyTarget: true,
        classificationReason: Reason.TARGET_BLANK_PAGE,
        captureMode: CaptureMode.EMPTY_TARGET_REPORT_ONLY,
        statusLabel: 'Empty target',
        message: 'Empty target. Back Tools is running in limited mode because no normal website is loaded yet.',
        urlSource
      });
    }

    if (scheme === 'chrome') {
      const host = parsed.hostname.toLowerCase();
      const isNewTab = ['newtab', 'new-tab-page', 'new-tab-page-third-party'].includes(host);
      return buildTarget({
        targetType: isNewTab ? TargetType.NEW_TAB : TargetType.CHROME_INTERNAL,
        targetUrl: normalizedUrl,
        normalizedUrl,
        scheme,
        isNormalWebTarget: false,
        isLimitedTarget: true,
        isEmptyTarget: false,
        classificationReason: Reason.CHROME_INTERNAL_TARGET,
        captureMode: CaptureMode.LIMITED_TARGET_REPORT_ONLY,
        statusLabel: isNewTab ? 'Limited browser/new-tab target' : 'Internal Chrome target',
        message: limitedMessage(),
        urlSource
      });
    }

    if (scheme === 'chrome-extension') {
      return buildTarget({
        targetType: TargetType.EXTENSION_PAGE,
        targetUrl: normalizedUrl,
        normalizedUrl,
        scheme,
        isNormalWebTarget: false,
        isLimitedTarget: true,
        isEmptyTarget: false,
        classificationReason: Reason.TARGET_NOT_WEB_PAGE,
        captureMode: CaptureMode.LIMITED_TARGET_REPORT_ONLY,
        statusLabel: 'Limited browser/new-tab target',
        message: limitedMessage(),
        urlSource
      });
    }

    if (scheme === 'file') {
      return buildTarget({
        targetType: TargetType.FILE_URL,
        targetUrl: normalizedUrl,
        normalizedUrl,
        scheme,
        isNormalWebTarget: false,
        isLimitedTarget: true,
        isEmptyTarget: false,
        classificationReason: Reason.NO_HTTP_ORIGIN,
        captureMode: CaptureMode.LIMITED_TARGET_REPORT_ONLY,
        statusLabel: 'Limited browser/new-tab target',
        message: limitedMessage(),
        urlSource
      });
    }

    return buildTarget({
      targetType: TargetType.UNKNOWN,
      targetUrl: normalizedUrl,
      normalizedUrl,
      scheme,
      isNormalWebTarget: false,
      isLimitedTarget: true,
      isEmptyTarget: false,
      classificationReason: Reason.TARGET_NOT_WEB_PAGE,
      captureMode: CaptureMode.UNKNOWN_TARGET_REPORT_ONLY,
      statusLabel: 'Limited browser/new-tab target',
      message: limitedMessage(),
      urlSource
    });
  }

  function buildTarget(input) {
    return {
      targetType: input.targetType,
      targetUrl: input.targetUrl,
      normalizedUrl: input.normalizedUrl,
      scheme: input.scheme,
      isNormalWebTarget: input.isNormalWebTarget,
      isLimitedTarget: input.isLimitedTarget,
      isEmptyTarget: input.isEmptyTarget,
      classificationReason: input.classificationReason,
      captureMode: input.captureMode,
      statusLabel: input.statusLabel,
      message: input.message,
      urlSource: input.urlSource
    };
  }

  function normalizeInput(rawUrl) {
    if (rawUrl === null || rawUrl === undefined) return '';
    return String(rawUrl).trim();
  }

  function parseUrl(value) {
    try {
      return new URL(value);
    } catch {
      return null;
    }
  }

  function limitedMessage() {
    return 'Back Tools is running in limited mode because this is not a normal web page. Some browser-managed data is not exposed through DevTools APIs.';
  }

  function targetIdentity(target) {
    const model = target || classifyTargetUrl(null);
    return [model.targetType || TargetType.UNKNOWN, model.normalizedUrl || model.targetUrl || ''].join('|');
  }

  function targetsAreSame(a, b) {
    return targetIdentity(a) === targetIdentity(b);
  }

  function moduleReasonForTarget(target, moduleName) {
    const model = target || classifyTargetUrl(null);
    if (model.isNormalWebTarget) return null;
    if (moduleName === 'network' || moduleName === 'cookies') return Reason.NO_NETWORK_REQUESTS_OBSERVED;
    if (moduleName === 'sources') {
      if (model.isEmptyTarget) return Reason.PLATFORM_RETURNED_NO_RESOURCES;
      return model.classificationReason || Reason.TARGET_NOT_WEB_PAGE;
    }
    if (moduleName === 'application') {
      if (model.targetType === TargetType.UNKNOWN) return Reason.INSPECTED_WINDOW_EVAL_UNAVAILABLE;
      if (model.targetType === TargetType.ABOUT_BLANK || model.targetType === TargetType.FILE_URL) return Reason.NO_HTTP_ORIGIN;
      return Reason.APPLICATION_STORAGE_UNAVAILABLE;
    }
    if (moduleName === 'export') {
      return model.isEmptyTarget ? Reason.EXPORT_EMPTY_BUT_VALID_REPORT : Reason.EXPORT_REPORT_ONLY_LIMITED_TARGET;
    }
    return model.classificationReason || Reason.TARGET_NOT_WEB_PAGE;
  }

  function buildModuleStatuses(input = {}) {
    const target = input.target || classifyTargetUrl(null);
    const analyzed = input.analyzed === true;
    const sources = Array.isArray(input.sources) ? input.sources : [];
    const network = Array.isArray(input.network) ? input.network : [];
    const application = input.application || {};
    const cookiesSummary = input.cookiesSummary || {};

    if (!analyzed) {
      return {
        sources: status('not_collected', null, 'Sources have not been analyzed yet.', 0),
        network: status('not_collected', null, 'Network has not been analyzed yet.', 0),
        cookies: status('not_collected', null, 'Cookies have not been analyzed yet.', 0),
        application: status('not_collected', null, 'Application storage has not been analyzed yet.', 0),
        export: status('not_ready', null, 'Analyze the target before exporting.', 0)
      };
    }

    const sourceStatus = sources.length
      ? status('collected', null, 'Sources resources were collected.', sources.length)
      : status(target.isNormalWebTarget ? 'empty' : target.isEmptyTarget ? 'empty' : 'unavailable', moduleReasonForTarget(target, 'sources'), target.isNormalWebTarget ? 'No Sources resources were returned by DevTools.' : 'Sources resources are not available for this target.', 0);

    const networkStatus = network.length
      ? status('collected', null, 'Network requests were observed.', network.length)
      : status('empty', moduleReasonForTarget(target, 'network'), 'No network requests were observed for this target.', 0);

    const observedCookies = cookiesSummary.observedCookies || 0;
    const cookieStatus = observedCookies
      ? status('collected', null, 'Cookie metadata was derived from observed Network data.', observedCookies)
      : status('empty', moduleReasonForTarget(target, 'cookies'), 'No cookies were observed in current Network data.', 0);

    const appItems = application.summary?.totalInventoryItems || 0;
    const appReason = firstObservationReason(application) || moduleReasonForTarget(target, 'application');
    const appStatus = application.status === 'collected'
      ? status(appItems ? 'collected' : 'empty', appItems ? null : Reason.APPLICATION_STORAGE_UNAVAILABLE, appItems ? 'Application inventory was collected.' : 'No Application storage items were found.', appItems)
      : application.status === 'partial'
        ? status('partial', appReason, 'Application inventory is partial for this target.', appItems)
        : status('unavailable', appReason, 'Application storage is not available for this target.', appItems);

    return {
      sources: sourceStatus,
      network: networkStatus,
      cookies: cookieStatus,
      application: appStatus,
      export: status('ready', moduleReasonForTarget(target, 'export'), target.isLimitedTarget ? 'Limited report export is available.' : 'Export is available for the analyzed target.', sourceStatus.items + networkStatus.items + cookieStatus.items + appStatus.items)
    };
  }

  function firstObservationReason(application) {
    const found = (application?.observations || []).find(item => item?.reason || item?.message);
    return found?.reason || null;
  }

  function status(value, reason, message, items) {
    return {
      status: value,
      reason: reason || null,
      message,
      items: Number(items || 0)
    };
  }

  function summarizeModuleStatuses(moduleStatuses = {}) {
    const entries = Object.entries(moduleStatuses || {}).map(([name, value]) => ({
      name,
      status: value?.status || 'unknown',
      reason: value?.reason || null,
      message: value?.message || null,
      items: value?.items || 0
    }));
    return {
      modules: entries,
      unavailableModules: entries.filter(item => item.status === 'unavailable'),
      emptySections: entries.filter(item => item.status === 'empty'),
      warnings: entries.filter(item => item.reason).map(item => ({
        module: item.name,
        reason: item.reason,
        message: item.message
      }))
    };
  }

  return {
    TargetType,
    CaptureMode,
    TargetReason: Reason,
    classifyTargetUrl,
    limitedMessage,
    targetIdentity,
    targetsAreSame,
    moduleReasonForTarget,
    buildModuleStatuses,
    summarizeModuleStatuses
  };
});
