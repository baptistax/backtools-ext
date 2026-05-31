(function(root, factory) {
  const api = factory(root);
  root.BackToolsCollectors = Object.assign(root.BackToolsCollectors || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
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
    } catch (error) {
      domain.__bootstrapError = error;
    }
  }

  const BodyCaptureStatus = {
    BODY_CAPTURED: 'body_captured',
    METADATA_ONLY: 'metadata_only',
    MIME_BLOCKED: 'mime_blocked',
    SIZE_LIMIT_EXCEEDED: 'size_limit_exceeded',
    POLICY_BLOCKED: 'policy_blocked',
    PLATFORM_UNAVAILABLE: 'platform_unavailable',
    READ_FAILED: 'read_failed',
    ENCODING_UNSUPPORTED: 'encoding_unsupported',
    HIDDEN_BY_DEFAULT: 'hidden_by_default'
  };

  const DEFAULT_NETWORK_BODY_POLICY = {
    captureBodies: true,
    captureHiddenBodies: false,
    maxBodyBytes: 1024 * 1024,
    maxTotalBodyBytes: 25 * 1024 * 1024,
    maxBodyRenderBytes: 64 * 1024,
    maxWasmBodyBytes: 256 * 1024,
    maxSmallBinaryBytes: 64 * 1024,
    includeSmallBinaryBodies: false,
    readTimeoutMs: 3000,
    allowedMimeTypes: [
      'text/html',
      'text/css',
      'text/javascript',
      'application/javascript',
      'application/x-javascript',
      'application/ecmascript',
      'text/ecmascript',
      'application/json',
      'application/ld+json',
      'application/manifest+json',
      'application/source-map',
      'application/xml',
      'text/xml',
      'text/plain',
      'image/svg+xml',
      'application/wasm'
    ]
  };

  function collectHarEntries(adapters, targetUrl, options = {}) {
    return startNetworkCapture(adapters, targetUrl, {
      ...options,
      listen: options.listen === true
    }).then(session => session.getEntries());
  }

  async function startNetworkCapture(adapters, targetUrl, options = {}) {
    const session = createNetworkCaptureSession(adapters, targetUrl, options);
    await session.start();
    return session;
  }

  function createNetworkCaptureSession(adapters, targetUrl, options = {}) {
    adapters = adapters || {};
    const policy = normalizePolicy(options.policy);
    const rowsByKey = new Map();
    const rowsInOrder = [];
    const rowIndexByKey = new Map();
    let sequence = 0;
    let totalCapturedBodyBytes = 0;
    let stopListener = null;
    let stopped = false;
    let processingQueue = Promise.resolve();
    let harUnavailable = false;
    let harUnavailableReason = null;
    const target = options.target || safeClassifyTarget(targetUrl);

    function getEntries() {
      const rows = rowsInOrder.slice();
      return attachModuleStatus(rows, buildNetworkStatus(target, rows, harUnavailable, harUnavailableReason));
    }

    function emitUpdate() {
      if (typeof options.onUpdate === 'function') {
        try {
          const entries = getEntries();
          options.onUpdate(entries, summarizeNetworkCapture(entries));
        } catch {}
      }
    }

    function reportError(error) {
      if (typeof options.onError === 'function') {
        try {
          options.onError(error);
        } catch {}
      }
    }

    function upsert(row) {
      if (stopped || !row) return row;
      const current = rowsByKey.get(row.dedupeKey);
      const merged = mergeNetworkRecord(current, row);
      rowsByKey.set(row.dedupeKey, merged);
      if (current) {
        rowsInOrder[rowIndexByKey.get(row.dedupeKey)] = merged;
      } else {
        rowIndexByKey.set(row.dedupeKey, rowsInOrder.length);
        rowsInOrder.push(merged);
      }
      emitUpdate();
      return merged;
    }

    function enqueue(entry, source) {
      processingQueue = processingQueue
        .then(() => processEntry(entry, source))
        .catch(error => {
          reportError(error);
          return null;
        });
      return processingQueue;
    }

    async function processEntry(entry, source) {
      if (stopped || !entry) return null;

      let row;
      try {
        row = normalizeHarEntry(entry, targetUrl, sequence++, source);
      } catch (error) {
        const fallbackRow = createFallbackNetworkRow(entry, sequence++, source);
        return upsert(applyCaptureStatus(
          fallbackRow,
          BodyCaptureStatus.READ_FAILED,
          String(error?.message || error || 'NORMALIZE_FAILED')
        ));
      }

      try {
        const inlineContent = getInlineHarContent(entry);
        const contentReaderAvailable = inlineContent.hasContent || typeof entry?.getContent === 'function';
        const decision = evaluateBodyCapture(row, policy, totalCapturedBodyBytes, contentReaderAvailable);
        let updated = applyCaptureStatus(row, decision.status, decision.reason, decision.extra);

        if (!decision.eligible) return upsert(updated);

        if (inlineContent.hasContent) {
          updated = applyCapturedContent(row, inlineContent.content, inlineContent.encoding, policy, totalCapturedBodyBytes);
          if (updated.bodyCaptureStatus === BodyCaptureStatus.BODY_CAPTURED) {
            totalCapturedBodyBytes += updated.bodyCapturedBytes || 0;
          }
          return upsert(updated);
        }

        const contentResult = await adapters.getRequestContent(entry, { timeoutMs: policy.readTimeoutMs });
        if (stopped) return null;

        if (!contentResult || contentResult.ok === false) {
          return upsert(applyCaptureStatus(
            row,
            contentResult?.status || BodyCaptureStatus.PLATFORM_UNAVAILABLE,
            contentResult?.reason || 'GET_CONTENT_UNAVAILABLE'
          ));
        }

        updated = applyCapturedContent(row, contentResult.content, contentResult.encoding, policy, totalCapturedBodyBytes);
        if (updated.bodyCaptureStatus === BodyCaptureStatus.BODY_CAPTURED) {
          totalCapturedBodyBytes += updated.bodyCapturedBytes || 0;
        }
        return upsert(updated);
      } catch (error) {
        if (stopped) return null;
        return upsert(applyCaptureStatus(
          row,
          BodyCaptureStatus.READ_FAILED,
          String(error?.message || error || 'GET_CONTENT_FAILED')
        ));
      }
    }

    async function start() {
      let har = { entries: [] };
      try {
        har = adapters.getHar ? await adapters.getHar() : { entries: [] };
      } catch {
        harUnavailable = true;
        harUnavailableReason = 'network_har_unavailable';
      }
      if (har?.unavailable) {
        harUnavailable = true;
        harUnavailableReason = har.reason || 'network_har_unavailable';
      }
      const entries = har?.entries || [];
      for (const entry of entries) {
        enqueue(entry, 'getHAR');
      }

      if (options.listen !== false && typeof adapters.addRequestFinishedListener === 'function') {
        stopListener = adapters.addRequestFinishedListener(entry => {
          void enqueue(entry, 'onRequestFinished');
        });
      }

      await processingQueue;
      return getEntries();
    }

    async function stop() {
      stopped = true;
      if (typeof stopListener === 'function') stopListener();
      stopListener = null;
      try {
        await processingQueue;
      } catch {}
    }

    return {
      start,
      stop,
      getEntries,
      getModuleStatus: () => buildNetworkStatus(target, rowsInOrder, harUnavailable, harUnavailableReason),
      getSummary: () => summarizeNetworkCapture(rowsInOrder),
      getPolicy: () => ({
        ...policy,
        allowedMimeTypes: new Set(policy.allowedMimeTypes)
      })
    };
  }

  function buildNetworkStatus(target, rows, harUnavailable, harUnavailableReason) {
    if (rows.length) {
      return {
        status: 'collected',
        reason: null,
        message: 'Network requests were observed.',
        items: rows.length,
        target
      };
    }
    if (harUnavailable) {
      return {
        status: 'unavailable',
        reason: harUnavailableReason || 'network_har_unavailable',
        message: 'Network data is not available from DevTools for this target.',
        items: 0,
        target
      };
    }
    return {
      status: 'empty',
      reason: 'no_network_requests_observed',
      message: 'No network requests were observed for this target.',
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

  function normalizePolicy(policy = {}) {
    const merged = { ...DEFAULT_NETWORK_BODY_POLICY, ...(policy || {}) };
    const allowedMimeTypes = toArray(merged.allowedMimeTypes)
      .map(normalizeMimeType)
      .filter(Boolean);

    merged.captureBodies = merged.captureBodies !== false;
    merged.captureHiddenBodies = merged.captureHiddenBodies === true;
    merged.includeSmallBinaryBodies = merged.includeSmallBinaryBodies === true;
    merged.maxBodyBytes = normalizeLimit(merged.maxBodyBytes, DEFAULT_NETWORK_BODY_POLICY.maxBodyBytes);
    merged.maxTotalBodyBytes = normalizeLimit(merged.maxTotalBodyBytes, DEFAULT_NETWORK_BODY_POLICY.maxTotalBodyBytes);
    merged.maxBodyRenderBytes = normalizeLimit(merged.maxBodyRenderBytes, DEFAULT_NETWORK_BODY_POLICY.maxBodyRenderBytes);
    merged.maxWasmBodyBytes = normalizeLimit(merged.maxWasmBodyBytes, DEFAULT_NETWORK_BODY_POLICY.maxWasmBodyBytes);
    merged.maxSmallBinaryBytes = normalizeLimit(merged.maxSmallBinaryBytes, DEFAULT_NETWORK_BODY_POLICY.maxSmallBinaryBytes);
    merged.readTimeoutMs = normalizeLimit(merged.readTimeoutMs, DEFAULT_NETWORK_BODY_POLICY.readTimeoutMs);
    merged.allowedMimeTypes = new Set(allowedMimeTypes);

    return merged;
  }

  function normalizeHarEntry(entry, targetUrl, sequence, source) {
    const request = entry?.request || {};
    const response = entry?.response || {};
    const content = response.content || {};
    const rawUrl = request.url || entry?.url || null;
    const parsedUrl = safeParseUrl(rawUrl || '');
    const method = request.method || null;
    const statusCode = response.status ?? null;
    const bodySize = getResponseBodySize(entry);
    const mimeType = content.mimeType || getHeaderValue(response.headers, 'content-type') || null;
    const rawRequestHeaders = request.headers || [];
    const rawResponseHeaders = response.headers || [];
    const urlRedaction = safeRedactUrlWithMetadata(rawUrl || '');
    const requestHeadersRedacted = safeRedactHeaders(rawRequestHeaders);
    const responseHeadersRedacted = safeRedactHeaders(rawResponseHeaders);
    const requestHeadersWereRedacted = safeHasRedactedHeaders(rawRequestHeaders, requestHeadersRedacted);
    const responseHeadersWereRedacted = safeHasRedactedHeaders(rawResponseHeaders, responseHeadersRedacted);
    const dedupeKey = buildNetworkDedupeKey(entry);
    const row = {
      id: `network:${stableHash(dedupeKey)}`,
      dedupeKey,
      sequence,
      source,
      url: urlRedaction.value,
      urlRedacted: urlRedaction.value,
      urlHash: urlRedaction.hash,
      redactionApplied: !!(urlRedaction.redacted || requestHeadersWereRedacted || responseHeadersWereRedacted),
      redactedFields: [
        ...(urlRedaction.redacted ? ['url.query'] : []),
        ...(requestHeadersWereRedacted ? ['request.headers'] : []),
        ...(responseHeadersWereRedacted ? ['response.headers'] : [])
      ],
      host: parsedUrl.host ?? null,
      scheme: parsedUrl.scheme ?? null,
      method,
      statusCode,
      startedDateTime: entry?.startedDateTime || null,
      mimeType,
      bodyMimeType: mimeType,
      type: safeInferType(rawUrl, mimeType),
      size: bodySize,
      bodySize,
      bodyAvailable: false,
      bodyCaptureStatus: BodyCaptureStatus.METADATA_ONLY,
      bodyStatus: BodyCaptureStatus.METADATA_ONLY,
      bodyCaptureReason: 'BODY_NOT_CAPTURED',
      bodyCapturedBytes: 0,
      bodySizeBytes: null,
      bodyEncoding: null,
      bodyRedactionApplied: false,
      bodyRenderStatus: 'not_rendered',
      bodyExportStatus: 'not_exportable',
      exportable: false,
      isExportable: false,
      reason: 'BODY_NOT_CAPTURED',
      content: null,
      encoding: null,
      contentKind: null,
      collector: 'network_har',
      requestHeaders: requestHeadersRedacted,
      responseHeaders: responseHeadersRedacted,
      requestHeadersRedacted,
      responseHeadersRedacted,
      requestCookieHeadersRaw: extractHeaderValues(rawRequestHeaders, 'cookie'),
      responseSetCookieHeadersRaw: extractHeaderValues(rawResponseHeaders, 'set-cookie'),
      requestCookiesRaw: normalizeHarCookiesForAnalysis(request.cookies),
      responseCookiesRaw: normalizeHarCookiesForAnalysis(response.cookies)
    };

    return safeClassifyResourceRecord(row, targetUrl);
  }

  function createFallbackNetworkRow(entry, sequence, source) {
    const request = entry?.request || {};
    const response = entry?.response || {};
    const urlRedaction = safeRedactUrlWithMetadata(request.url || entry?.url || '');
    const dedupeKey = buildNetworkDedupeKey(entry);

    return {
      id: `network:${stableHash(dedupeKey)}`,
      dedupeKey,
      sequence,
      source,
      url: urlRedaction.value,
      urlRedacted: urlRedaction.value,
      urlHash: urlRedaction.hash,
      redactionApplied: !!urlRedaction.redacted,
      redactedFields: urlRedaction.redacted ? ['url.query'] : [],
      host: null,
      scheme: null,
      method: request.method || null,
      statusCode: response.status ?? null,
      startedDateTime: entry?.startedDateTime || null,
      mimeType: response?.content?.mimeType || null,
      bodyMimeType: response?.content?.mimeType || null,
      type: 'other',
      size: getResponseBodySize(entry),
      bodySize: getResponseBodySize(entry),
      bodyAvailable: false,
      bodyCaptureStatus: BodyCaptureStatus.METADATA_ONLY,
      bodyStatus: BodyCaptureStatus.METADATA_ONLY,
      bodyCaptureReason: 'BODY_NOT_CAPTURED',
      bodyCapturedBytes: 0,
      bodySizeBytes: null,
      bodyEncoding: null,
      bodyRedactionApplied: false,
      bodyRenderStatus: 'not_rendered',
      bodyExportStatus: 'not_exportable',
      exportable: false,
      isExportable: false,
      reason: 'BODY_NOT_CAPTURED',
      content: null,
      encoding: null,
      contentKind: null,
      collector: 'network_har',
      requestHeaders: [],
      responseHeaders: [],
      requestHeadersRedacted: [],
      responseHeadersRedacted: [],
      requestCookieHeadersRaw: [],
      responseSetCookieHeadersRaw: [],
      requestCookiesRaw: [],
      responseCookiesRaw: []
    };
  }

  function mergeNetworkRecord(current, next) {
    if (!current) return next;

    const currentCaptured = current.bodyCaptureStatus === BodyCaptureStatus.BODY_CAPTURED;
    const nextCaptured = next.bodyCaptureStatus === BodyCaptureStatus.BODY_CAPTURED;
    const preferCurrent = currentCaptured && !nextCaptured;
    const preferred = preferCurrent ? current : next;
    const secondary = preferCurrent ? next : current;

    return {
      ...secondary,
      ...preferred,
      sequence: current.sequence,
      seenSources: Array.from(
        new Set([...(current.seenSources || [current.source]).filter(Boolean), ...(next.seenSources || [next.source]).filter(Boolean)])
      ),
      redactionApplied: !!(current.redactionApplied || next.redactionApplied),
      bodyRedactionApplied: !!(current.bodyRedactionApplied || next.bodyRedactionApplied),
      redactedFields: Array.from(new Set([...(current.redactedFields || []), ...(next.redactedFields || [])])),
      requestCookieHeadersRaw: uniqueStrings([...(current.requestCookieHeadersRaw || []), ...(next.requestCookieHeadersRaw || [])]),
      responseSetCookieHeadersRaw: uniqueStrings([...(current.responseSetCookieHeadersRaw || []), ...(next.responseSetCookieHeadersRaw || [])]),
      requestCookiesRaw: mergeCookieArrays(current.requestCookiesRaw, next.requestCookiesRaw),
      responseCookiesRaw: mergeCookieArrays(current.responseCookiesRaw, next.responseCookiesRaw)
    };
  }

  function evaluateBodyCapture(row, policy, totalCapturedBodyBytes, contentReaderAvailable) {
    if (!policy.captureBodies) {
      return blocked(BodyCaptureStatus.POLICY_BLOCKED, 'NETWORK_BODY_CAPTURE_DISABLED');
    }

    if (row.visibleByDefault === false && !policy.captureHiddenBodies) {
      return blocked(BodyCaptureStatus.HIDDEN_BY_DEFAULT, 'HIDDEN_BY_DEFAULT');
    }

    if (isNoBodyStatus(row.statusCode) || row.bodySize === 0) {
      return blocked(BodyCaptureStatus.METADATA_ONLY, 'NO_RESPONSE_BODY');
    }

    const mimeDecision = isMimeAllowed(row.mimeType, row.bodySize, policy);
    if (!mimeDecision.allowed) {
      return blocked(
        mimeDecision.reason === 'BODY_SIZE_LIMIT_EXCEEDED' || mimeDecision.reason === 'TOTAL_BODY_SIZE_LIMIT_EXCEEDED'
          ? BodyCaptureStatus.SIZE_LIMIT_EXCEEDED
          : BodyCaptureStatus.MIME_BLOCKED,
        mimeDecision.reason
      );
    }

    if (!contentReaderAvailable) {
      return blocked(
        row.source === 'getHAR' ? BodyCaptureStatus.METADATA_ONLY : BodyCaptureStatus.PLATFORM_UNAVAILABLE,
        row.source === 'getHAR' ? 'INITIAL_HAR_METADATA_ONLY' : 'GET_CONTENT_UNAVAILABLE'
      );
    }

    return { eligible: true, status: BodyCaptureStatus.METADATA_ONLY, reason: 'BODY_READ_PENDING' };
  }

  function blocked(status, reason, extra = {}) {
    return { eligible: false, status, reason, extra };
  }

  function applyCaptureStatus(row, status, reason, extra = {}) {
    return {
      ...row,
      ...extra,
      status,
      bodyCaptureStatus: status,
      bodyStatus: status,
      bodyCaptureReason: reason || null,
      bodyAvailable: status === BodyCaptureStatus.BODY_CAPTURED,
      exportable: status === BodyCaptureStatus.BODY_CAPTURED,
      isExportable: status === BodyCaptureStatus.BODY_CAPTURED,
      bodyExportStatus: status === BodyCaptureStatus.BODY_CAPTURED ? 'exportable_body' : 'not_exportable',
      bodyRenderStatus: status === BodyCaptureStatus.BODY_CAPTURED ? row.bodyRenderStatus || 'not_rendered' : 'not_renderable',
      reason: status === BodyCaptureStatus.BODY_CAPTURED ? null : reason || null,
      content: status === BodyCaptureStatus.BODY_CAPTURED ? row.content : null,
      encoding: status === BodyCaptureStatus.BODY_CAPTURED ? row.encoding : null,
      bodyCapturedBytes: status === BodyCaptureStatus.BODY_CAPTURED ? row.bodyCapturedBytes : 0,
      bodySizeBytes: status === BodyCaptureStatus.BODY_CAPTURED ? row.bodySizeBytes : null
    };
  }

  function applyCapturedContent(row, content, encoding, policy, totalCapturedBodyBytes) {
    if (content == null) {
      return applyCaptureStatus(row, BodyCaptureStatus.PLATFORM_UNAVAILABLE, 'CONTENT_NOT_AVAILABLE');
    }

    const normalizedEncoding = encoding || '';
    if (normalizedEncoding && normalizedEncoding !== 'base64') {
      return applyCaptureStatus(row, BodyCaptureStatus.ENCODING_UNSUPPORTED, `UNSUPPORTED_ENCODING_${normalizedEncoding}`);
    }

    const capturedBytes = estimateContentBytes(content, normalizedEncoding);

    if (normalizeMimeType(row.mimeType) === 'application/wasm' && capturedBytes > policy.maxWasmBodyBytes) {
      return applyCaptureStatus(row, BodyCaptureStatus.SIZE_LIMIT_EXCEEDED, 'WASM_SIZE_LIMIT_EXCEEDED');
    }

    let safeContent = String(content);
    let redaction = { value: safeContent, redacted: false, redactedFields: [] };

    if (!normalizedEncoding && isTextualMime(row.mimeType)) {
      redaction = redactTextBody(safeContent, row.mimeType);
      safeContent = redaction.value;
    }

    return {
      ...row,
      status: BodyCaptureStatus.BODY_CAPTURED,
      bodyCaptureStatus: BodyCaptureStatus.BODY_CAPTURED,
      bodyStatus: BodyCaptureStatus.BODY_CAPTURED,
      bodyCaptureReason: null,
      bodyAvailable: true,
      exportable: true,
      isExportable: true,
      reason: null,
      content: safeContent,
      encoding: normalizedEncoding,
      bodyEncoding: normalizedEncoding || 'utf8',
      bodyCapturedBytes: capturedBytes,
      bodySizeBytes: capturedBytes,
      bodyRedactionApplied: redaction.redacted,
      bodyRenderStatus: capturedBytes > policy.maxBodyRenderBytes ? 'render_size_limit_exceeded' : 'not_rendered',
      bodyExportStatus: 'exportable_body',
      redactionApplied: !!(row.redactionApplied || redaction.redacted),
      redactedFields: Array.from(new Set([...(row.redactedFields || []), ...(redaction.redactedFields || [])])),
      contentKind: normalizedEncoding === 'base64' ? 'binary_base64' : 'text_utf8'
    };
  }

  function getInlineHarContent(entry) {
    const content = entry?.response?.content || {};
    if (typeof content.text !== 'string') {
      return { hasContent: false };
    }

    return {
      hasContent: true,
      content: content.text,
      encoding: content.encoding || ''
    };
  }

  function buildNetworkDedupeKey(entry) {
    const request = entry?.request || {};
    const response = entry?.response || {};
    const content = response.content || {};
    const urlRedaction = safeRedactUrlWithMetadata(request.url || entry?.url || '');

    return [
      request.method || '',
      urlRedaction.value || '',
      entry?.startedDateTime || '',
      response.status ?? '',
      response.bodySize ?? content.size ?? ''
    ].join('|');
  }

  function getResponseBodySize(entry) {
    const response = entry?.response || {};
    const content = response.content || {};
    const candidates = [response.bodySize, content.size];

    for (const value of candidates) {
      if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value;
    }

    if (typeof content.text === 'string') {
      return estimateContentBytes(content.text, content.encoding || '');
    }

    return null;
  }

  function getHeaderValue(headers, name) {
    const expected = String(name).toLowerCase();
    const found = (headers || []).find(header => String(header?.name || '').toLowerCase() === expected);
    return found?.value || null;
  }

  function extractHeaderValues(headers, name) {
    const expected = String(name || '').toLowerCase();
    return (headers || [])
      .filter(header => String(header?.name || '').toLowerCase() === expected)
      .map(header => String(header?.value || ''))
      .filter(Boolean);
  }

  function normalizeHarCookiesForAnalysis(cookies) {
    return (cookies || [])
      .filter(cookie => cookie && cookie.name)
      .map(cookie => ({
        name: String(cookie.name || ''),
        value: cookie.value == null ? null : String(cookie.value),
        domain: cookie.domain || null,
        path: cookie.path || null,
        expires: cookie.expires || null,
        expirationDate: cookie.expirationDate ?? null,
        httpOnly: cookie.httpOnly ?? null,
        secure: cookie.secure ?? null,
        sameSite: cookie.sameSite || null
      }));
  }

  function uniqueStrings(values) {
    return [...new Set((values || []).filter(Boolean).map(String))];
  }

  function mergeCookieArrays(a = [], b = []) {
    const byKey = new Map();
    [...a, ...b].forEach(cookie => {
      if (!cookie?.name) return;
      const key = [cookie.name, cookie.domain || '', cookie.path || '', cookie.value || ''].join('|');
      byKey.set(key, cookie);
    });
    return [...byKey.values()];
  }

  function isNoBodyStatus(statusCode) {
    if (statusCode == null) return false;
    return statusCode < 200 || statusCode === 204 || statusCode === 205 || statusCode === 304;
  }

  function normalizeMimeType(mimeType) {
    return String(mimeType || '').split(';')[0].trim().toLowerCase();
  }

  function isTextualMime(mimeType) {
    const mime = normalizeMimeType(mimeType);
    return (
      mime.startsWith('text/') ||
      mime.endsWith('+json') ||
      mime.endsWith('+xml') ||
      [
        'application/json',
        'application/javascript',
        'application/x-javascript',
        'application/ecmascript',
        'application/ld+json',
        'application/manifest+json',
        'application/source-map',
        'application/xml',
        'text/xml',
        'image/svg+xml'
      ].includes(mime)
    );
  }

  function isMimeAllowed(mimeType, bodySize, policy) {
    const mime = normalizeMimeType(mimeType);

    if (!mime) return { allowed: false, reason: 'MIME_UNKNOWN' };

    if (mime === 'application/wasm') {
      if (bodySize != null && bodySize > policy.maxWasmBodyBytes) {
        return { allowed: false, reason: 'WASM_SIZE_LIMIT_EXCEEDED' };
      }
      return { allowed: true };
    }

    if (
      policy.allowedMimeTypes.has(mime) ||
      (mime.endsWith('+json') && policy.allowedMimeTypes.has('application/json')) ||
      (mime.endsWith('+xml') && (policy.allowedMimeTypes.has('application/xml') || policy.allowedMimeTypes.has('text/xml')))
    ) {
      return { allowed: true };
    }

    if (policy.includeSmallBinaryBodies && bodySize != null && bodySize <= policy.maxSmallBinaryBytes) {
      return { allowed: true };
    }

    return { allowed: false, reason: 'MIME_NOT_ALLOWED' };
  }

  function estimateContentBytes(content, encoding) {
    const text = String(content || '');
    if (encoding === 'base64') return estimateBase64Bytes(text);
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(text).length;
    if (typeof Buffer !== 'undefined') return Buffer.byteLength(text, 'utf8');
    return text.length;
  }

  function estimateBase64Bytes(value) {
    const clean = String(value || '').replace(/\s+/g, '');
    if (!clean) return 0;
    const padding = clean.endsWith('==') ? 2 : clean.endsWith('=') ? 1 : 0;
    return Math.max(0, Math.floor(clean.length * 3 / 4) - padding);
  }

  function stableHash(value) {
    if (typeof domain.hashSensitiveValue === 'function') return domain.hashSensitiveValue(value);

    let hash = 0x811c9dc5;
    const text = String(value ?? '');
    for (let i = 0; i < text.length; i++) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, '0');
  }

  function redactTextBody(content, mimeType) {
    const text = String(content ?? '');
    const mime = normalizeMimeType(mimeType);

    if (mime === 'application/json' || mime.endsWith('+json') || looksLikeJson(text)) {
      const json = redactJsonBody(text);
      if (json.redacted) return json;
    }

    return redactGenericSensitiveText(text);
  }

  function looksLikeJson(text) {
    const trimmed = String(text || '').trim();
    return trimmed.startsWith('{') || trimmed.startsWith('[');
  }

  function redactJsonBody(text) {
    try {
      const data = JSON.parse(text);
      const redactedFields = [];
      const redacted = redactJsonValue(data, [], redactedFields);

      if (!redactedFields.length) {
        return { value: text, redacted: false, redactedFields: [] };
      }

      return {
        value: JSON.stringify(redacted, null, 2),
        redacted: true,
        redactedFields: redactedFields.map(path => `body.${path}`)
      };
    } catch {
      return { value: text, redacted: false, redactedFields: [] };
    }
  }

  function redactJsonValue(value, path, redactedFields) {
    if (Array.isArray(value)) {
      return value.map((item, index) => redactJsonValue(item, [...path, String(index)], redactedFields));
    }

    if (!value || typeof value !== 'object') return value;

    const output = {};
    Object.entries(value).forEach(([key, child]) => {
      const nextPath = [...path, key];
      if (safeIsSensitiveQueryKey(key)) {
        output[key] = getRedactedToken();
        redactedFields.push(nextPath.join('.'));
      } else {
        output[key] = redactJsonValue(child, nextPath, redactedFields);
      }
    });

    return output;
  }

  function redactGenericSensitiveText(text) {
    const keys = Array.isArray(domain.SENSITIVE_QUERY_KEYS) ? domain.SENSITIVE_QUERY_KEYS : [];
    if (!keys.length) return { value: text, redacted: false, redactedFields: [] };

    const keyPattern = keys.map(escapeRegExp).join('|');
    const redactedFields = new Set();
    let output = String(text ?? '');

    output = output.replace(
      new RegExp(`((?:^|[?&\\s])(${keyPattern})=)([^&\\s"'<>]+)`, 'gi'),
      (match, prefix, key) => {
        redactedFields.add(`body.${key}`);
        return `${prefix}${getRedactedToken()}`;
      }
    );

    output = output.replace(
      new RegExp(`((?:["']?(?:${keyPattern})["']?)\\s*:\\s*)([^\\s,;]+)`, 'gi'),
      (match, prefix) => {
        const key = prefix.split(':')[0].replace(/["'\s]/g, '');
        redactedFields.add(`body.${key}`);
        return `${prefix}${getRedactedToken()}`;
      }
    );

    return {
      value: output,
      redacted: redactedFields.size > 0,
      redactedFields: [...redactedFields]
    };
  }

  function escapeRegExp(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function summarizeNetworkCapture(entries = []) {
    const summary = {
      total: entries.length,
      bodyCaptured: 0,
      metadataOnly: 0,
      mimeBlocked: 0,
      sizeLimitExceeded: 0,
      policyBlocked: 0,
      platformUnavailable: 0,
      readFailed: 0,
      encodingUnsupported: 0,
      hiddenByDefault: 0,
      capturedBytes: 0
    };

    entries.forEach(entry => {
      const status = entry.bodyCaptureStatus || entry.status;
      if (status === BodyCaptureStatus.BODY_CAPTURED) summary.bodyCaptured++;
      if (status === BodyCaptureStatus.METADATA_ONLY) summary.metadataOnly++;
      if (status === BodyCaptureStatus.MIME_BLOCKED) summary.mimeBlocked++;
      if (status === BodyCaptureStatus.SIZE_LIMIT_EXCEEDED) summary.sizeLimitExceeded++;
      if (status === BodyCaptureStatus.POLICY_BLOCKED) summary.policyBlocked++;
      if (status === BodyCaptureStatus.PLATFORM_UNAVAILABLE) summary.platformUnavailable++;
      if (status === BodyCaptureStatus.READ_FAILED) summary.readFailed++;
      if (status === BodyCaptureStatus.ENCODING_UNSUPPORTED) summary.encodingUnsupported++;
      if (status === BodyCaptureStatus.HIDDEN_BY_DEFAULT) summary.hiddenByDefault++;
      summary.capturedBytes += entry.bodyCapturedBytes || 0;
    });

    return summary;
  }

  function toArray(value) {
    if (value == null) return [];
    if (Array.isArray(value)) return value;
    if (typeof value === 'string') return [value];
    if (typeof value[Symbol.iterator] === 'function') return Array.from(value);
    return [];
  }

  function normalizeLimit(value, fallback) {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0
      ? Math.floor(value)
      : fallback;
  }

  function safeParseUrl(url) {
    try {
      if (typeof domain.parseUrl === 'function') {
        const parsed = domain.parseUrl(url);
        if (parsed && typeof parsed === 'object') {
          return {
            host: parsed.host ?? null,
            scheme: parsed.scheme ?? null
          };
        }
      }
    } catch {}

    try {
      const parsed = new URL(url);
      return {
        host: parsed.host || null,
        scheme: parsed.protocol ? parsed.protocol.replace(/:$/, '') : null
      };
    } catch {
      return {
        host: null,
        scheme: null
      };
    }
  }

  function safeInferType(url, mimeType) {
    try {
      if (typeof domain.inferType === 'function') {
        return domain.inferType(url, mimeType);
      }
    } catch {}
    return 'other';
  }

  function safeClassifyResourceRecord(row, targetUrl) {
    try {
      if (typeof domain.classifyResourceRecord === 'function') {
        return domain.classifyResourceRecord(row, targetUrl);
      }
    } catch {}
    return row;
  }

  function safeRedactUrlWithMetadata(url) {
    try {
      if (typeof domain.redactUrlWithMetadata === 'function') {
        const redacted = domain.redactUrlWithMetadata(url);
        if (redacted && typeof redacted === 'object') {
          return {
            value: redacted.value ?? url,
            hash: redacted.hash ?? null,
            redacted: !!redacted.redacted
          };
        }
      }
    } catch {}

    return {
      value: url,
      hash: null,
      redacted: false
    };
  }

  function safeRedactHeaders(headers) {
    try {
      if (typeof domain.redactHeaders === 'function') {
        const redacted = domain.redactHeaders(headers || []);
        if (Array.isArray(redacted)) return redacted;
      }
    } catch {}
    return Array.isArray(headers) ? headers : [];
  }

  function safeHasRedactedHeaders(originalHeaders, redactedHeaders) {
    try {
      if (typeof domain.hasRedactedHeaders === 'function') {
        return !!domain.hasRedactedHeaders(originalHeaders);
      }
    } catch {}

    try {
      return JSON.stringify(originalHeaders || []) !== JSON.stringify(redactedHeaders || []);
    } catch {
      return false;
    }
  }

  function safeIsSensitiveQueryKey(key) {
    try {
      if (typeof domain.isSensitiveQueryKey === 'function') {
        return !!domain.isSensitiveQueryKey(key);
      }
    } catch {}

    const keys = Array.isArray(domain.SENSITIVE_QUERY_KEYS) ? domain.SENSITIVE_QUERY_KEYS : [];
    return keys.includes(key);
  }

  function getRedactedToken() {
    return domain.REDACTED || '[redacted]';
  }

  return {
    BodyCaptureStatus,
    DEFAULT_NETWORK_BODY_POLICY,
    collectHarEntries,
    startNetworkCapture,
    createNetworkCaptureSession,
    normalizeHarEntry,
    buildNetworkDedupeKey,
    isMimeAllowed,
    redactTextBody,
    summarizeNetworkCapture
  };
});
