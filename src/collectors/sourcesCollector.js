(function(root, factory) {
  const api = factory(root);
  root.BackToolsCollectors = Object.assign(root.BackToolsCollectors || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  const SOURCE_CONTENT_CONCURRENCY = 1;
  const MAX_SINGLE_SOURCE_BYTES = 2 * 1024 * 1024;
  const MAX_TOTAL_SOURCE_BYTES = 20 * 1024 * 1024;

  let domain = root.BackToolsDomain || {};
  if (typeof require === 'function') {
    try {
      domain = Object.assign(
        {},
        require('../domain/normalize.js'),
        require('../domain/classify.js'),
        require('../domain/targetClassification.js'),
        require('../domain/redaction.js'),
        require('../domain/resourceClassification.js'),
        domain
      );
    } catch {}
  }

  async function collectSources(adapters = {}, targetUrl, options = {}) {
    const target = options.target || safeClassifyTarget(targetUrl);
    const out = [];
    let resources = [];
    let totalCapturedBytes = 0;
    try {
      resources = typeof adapters.getResources === 'function' ? await adapters.getResources() : [];
    } catch {
      return attachModuleStatus(out, {
        status: 'unavailable',
        reason: 'platform_returned_no_resources',
        message: 'Sources resources are not available for this target.',
        items: 0,
        target
      });
    }
    await mapWithConcurrency(Array.isArray(resources) ? resources : [], SOURCE_CONTENT_CONCURRENCY, async (res, index) => {
      const row = await collectSourceResource(adapters, targetUrl, res, index, {
        remainingBytes: Math.max(0, MAX_TOTAL_SOURCE_BYTES - totalCapturedBytes)
      });
      out[index] = row;
      totalCapturedBytes += Number(row?.size) || 0;
    });
    return attachModuleStatus(out, buildSourcesStatus(target, out));
  }

  async function collectSourceResource(adapters, targetUrl, res, index, budget = {}) {
    const p = domain.parseUrl(res.url || '');
    const urlRedaction = domain.redactUrlWithMetadata(res.url || '');
    let row = {
      id: `src:${res.url || `resource:${index}`}`,
      url: res.url,
      urlRedacted: urlRedaction.value,
      urlHash: urlRedaction.hash,
      redactionApplied: urlRedaction.redacted,
      redactedFields: urlRedaction.redacted ? ['url.query'] : [],
      path: p.path,
      host: p.host,
      scheme: p.scheme,
      type: domain.inferType(res.url),
      status: 'metadata_only',
      size: null,
      exportable: false,
      reason: 'EMPTY_CONTENT',
      content: null,
      encoding: null,
      collector: 'chrome_sources'
    };
    row = domain.classifyResourceRecord(row, targetUrl);

    if (shouldSkipSourceContent(row)) {
      row.status = 'metadata_only';
      row.reason = 'STATIC_ASSET_DISABLED_BY_DEFAULT';
      return row;
    }

    if ((Number(budget.remainingBytes) || 0) <= 0) {
      row.status = 'metadata_only';
      row.reason = 'EXPORT_TOTAL_SIZE_LIMIT_EXCEEDED';
      return row;
    }

    let rc = null;
    try {
      rc = typeof adapters.getResourceContent === 'function'
        ? await adapters.getResourceContent(res)
        : { error: 'GET_CONTENT_UNAVAILABLE' };
    } catch {
      rc = { error: 'GET_CONTENT_FAILED' };
    }

    if (rc?.error) {
      row.status = 'unavailable';
      row.reason = 'GET_CONTENT_FAILED';
    } else if (typeof rc?.content === 'string' && rc.content.length) {
      const size = rc.encoding === 'base64'
        ? Math.floor(rc.content.length * 0.75)
        : new TextEncoder().encode(rc.content).length;
      if (size > MAX_SINGLE_SOURCE_BYTES) {
        row.status = 'metadata_only';
        row.reason = 'SIZE_LIMIT_EXCEEDED';
        row.size = size;
        return row;
      }
      if (size > (Number(budget.remainingBytes) || 0)) {
        row.status = 'metadata_only';
        row.reason = 'EXPORT_TOTAL_SIZE_LIMIT_EXCEEDED';
        row.size = size;
        return row;
      }
      row.content = rc.content;
      row.encoding = rc.encoding || null;
      row.size = size;
      row.status = 'readable';
      row.exportable = true;
      row.reason = null;
    }

    return row;
  }

  function shouldSkipSourceContent(row = {}) {
    const type = String(row.type || '').toLowerCase();
    return type === 'image'
      || type === 'font'
      || type === 'media'
      || type === 'video'
      || type === 'audio';
  }

  async function mapWithConcurrency(items, limit, iteratee) {
    let nextIndex = 0;
    const workerCount = Math.min(Math.max(1, limit), items.length);
    const workers = Array.from({ length: workerCount }, async () => {
      while (nextIndex < items.length) {
        const index = nextIndex++;
        await iteratee(items[index], index);
      }
    });
    await Promise.all(workers);
  }

  function buildSourcesStatus(target, rows) {
    if (rows.length) {
      return {
        status: 'collected',
        reason: null,
        message: 'Sources resources were collected.',
        items: rows.length,
        target
      };
    }
    const reason = target.isNormalWebTarget
      ? 'platform_returned_no_resources'
      : typeof domain.moduleReasonForTarget === 'function'
        ? domain.moduleReasonForTarget(target, 'sources')
        : 'target_not_web_page';
    return {
      status: target.isNormalWebTarget || target.isEmptyTarget ? 'empty' : 'unavailable',
      reason,
      message: target.isNormalWebTarget ? 'No Sources resources were returned by DevTools.' : 'Sources resources are not available for this target.',
      items: 0,
      target
    };
  }

  function attachModuleStatus(rows, status) {
    Object.defineProperty(rows, 'moduleStatus', {
      value: status,
      enumerable: false,
      configurable: true
    });
    return rows;
  }

  function safeClassifyTarget(targetUrl) {
    if (typeof domain.classifyTargetUrl === 'function') {
      return domain.classifyTargetUrl(targetUrl, { urlSource: 'inspected_window_eval_location_href' });
    }
    return { isNormalWebTarget: /^https?:/i.test(String(targetUrl || '')), isEmptyTarget: !targetUrl };
  }

  return { collectSources };
});
