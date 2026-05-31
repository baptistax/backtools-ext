(function(root, factory) {
  const api = factory(root);
  root.BackToolsDomain = Object.assign(root.BackToolsDomain || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  let domain = root.BackToolsDomain || {};
  if (typeof require === 'function') {
    try { domain = Object.assign({}, require('./normalize.js'), domain); } catch {}
  }

  const COOKIE_SOURCES = {
    HAR_REQUEST_COOKIE: 'har_request_cookie',
    HAR_RESPONSE_COOKIE: 'har_response_cookie',
    COOKIE_HEADER: 'cookie_header',
    SET_COOKIE_HEADER: 'set_cookie_header',
    DOCUMENT_COOKIE: 'document_cookie',
    CHROME_COOKIES: 'chrome_cookies',
    UNKNOWN: 'unknown'
  };

  const SENSITIVE_COOKIE_TERMS = [
    'session',
    'token',
    'auth',
    'jwt',
    'csrf',
    'xsrf',
    'bearer',
    'secret',
    'password',
    'credential',
    'sid',
    'sess',
    'id_token',
    'access_token',
    'refresh_token'
  ];

  const PROTECTED_VALUES = new Set(['[protected]', '[redacted]', '[masked]', '']);

  function lowerHeaders(headers) {
    const m = {};
    (headers || []).forEach(h => {
      if (!h?.name) return;
      const k = h.name.toLowerCase();
      (m[k] = m[k] || []).push(h.value || '');
    });
    return m;
  }

  function firstKnown(...values) {
    for (const value of values) {
      if (value !== undefined && value !== null && value !== '') return value;
    }
    return null;
  }

  function parseSetCookieLine(line) {
    const parts = (line || '').split(';');
    const first = parts.shift() || '';
    const eq = first.indexOf('=');
    if (eq < 1) return null;
    const name = first.slice(0, eq).trim();
    const value = first.slice(eq + 1);
    const attrs = {
      domain: null,
      path: null,
      expires: null,
      maxAge: null,
      secure: false,
      httpOnly: false,
      sameSite: 'unknown',
      priority: null,
      partitioned: 'unknown',
      partitionKey: null,
      extras: {}
    };

    for (const raw of parts) {
      const seg = raw.trim();
      if (!seg) continue;
      const idx = seg.indexOf('=');
      const an = (idx >= 0 ? seg.slice(0, idx) : seg).trim().toLowerCase();
      const av = (idx >= 0 ? seg.slice(idx + 1) : '').trim();
      if (an === 'domain') attrs.domain = av || null;
      else if (an === 'path') attrs.path = av || null;
      else if (an === 'expires') attrs.expires = av || null;
      else if (an === 'max-age') attrs.maxAge = av || null;
      else if (an === 'secure') attrs.secure = true;
      else if (an === 'httponly') attrs.httpOnly = true;
      else if (an === 'samesite') attrs.sameSite = av || 'unknown';
      else if (an === 'priority') attrs.priority = av || null;
      else if (an === 'partitioned') attrs.partitioned = true;
      else attrs.extras[an] = av || true;
    }

    return { name, value, attributes: attrs };
  }

  function parseCookieHeader(line) {
    return (line || '')
      .split(';')
      .map(x => x.trim())
      .filter(Boolean)
      .map(pair => {
        const i = pair.indexOf('=');
        if (i < 1) return null;
        return { name: pair.slice(0, i).trim(), value: pair.slice(i + 1) };
      })
      .filter(Boolean);
  }

  function normalizeHarCookie(cookie, fallback = {}) {
    if (!cookie || !cookie.name) return null;
    return {
      name: String(cookie.name),
      value: cookie.value == null ? null : String(cookie.value),
      domain: firstKnown(cookie.domain, fallback.domain),
      hostOnly: cookie.hostOnly ?? null,
      path: firstKnown(cookie.path, fallback.path),
      expires: firstKnown(cookie.expires, fallback.expires),
      expirationDate: firstKnown(cookie.expirationDate, fallback.expirationDate),
      session: cookie.session ?? null,
      secure: cookie.secure ?? fallback.secure ?? 'unknown',
      httpOnly: cookie.httpOnly ?? fallback.httpOnly ?? 'unknown',
      sameSite: firstKnown(cookie.sameSite, fallback.sameSite, 'unknown'),
      partitionKey: firstKnown(cookie.partitionKey, fallback.partitionKey),
      storeId: firstKnown(cookie.storeId, fallback.storeId)
    };
  }

  function isProtectedValue(value) {
    if (value === undefined || value === null) return true;
    return PROTECTED_VALUES.has(String(value).toLowerCase());
  }

  function isPossibleJwt(value) {
    return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(String(value || ''));
  }

  function hasSensitiveCookieTerm(name, value) {
    const text = `${name || ''} ${value || ''}`.toLowerCase();
    return SENSITIVE_COOKIE_TERMS.some(term => text.includes(term));
  }

  function cookieClass(name, value) {
    const n = (name || '').toLowerCase();
    const v = String(value || '').toLowerCase();
    const has = arr => arr.some(x => n.includes(x) || v.includes(x));
    return {
      session: has(['session', 'sid', 'sess', 'auth', 'token', 'access', 'refresh', 'jwt', 'id_token', 'bearer', 'login']),
      csrf: has(['csrf', 'xsrf']),
      tracking: has(['ga', 'gid', 'gcl', 'fbp', 'fbc', 'analytics', 'track'])
    };
  }

  function classifyCookieValue(name, rawValue) {
    if (!isProtectedValue(rawValue) && isPossibleJwt(rawValue)) return 'jwt_like';
    const cls = cookieClass(name, rawValue);
    if (cls.csrf) return 'csrf_like';
    if (cls.session) return 'auth_like';
    if (cls.tracking) return 'tracking_like';
    return 'general';
  }

  function riskForCookie(cookie, classification) {
    const risks = [];
    if (classification === 'jwt_like' || classification === 'auth_like') risks.push('auth_like');
    if (cookie.httpOnly === false && risks.includes('auth_like')) risks.push('script_accessible_auth_cookie');
    if (cookie.secure === false && risks.includes('auth_like')) risks.push('transport_replay_risk');
    if ((cookie.sameSite || '').toLowerCase() === 'none' && cookie.secure === false) risks.push('cross_site_without_secure');
    if (cookie.value?.rawAvailable) risks.push('replay_risk_if_raw_exported');
    return risks;
  }

  function deterministicMiddle(value) {
    const raw = String(value || '');
    if (raw.length < 16) return '';
    const start = Math.max(4, Math.floor((raw.length - 3) / 2));
    return raw.slice(start, start + 3);
  }

  function maskCookieValue(rawValue, cookie = {}) {
    if (isProtectedValue(rawValue)) {
      return {
        rawAvailable: false,
        rawIncluded: false,
        rawValue: null,
        masked: 'not_available',
        length: null,
        visibleRawChars: 0,
        fingerprint: null,
        fingerprintAlgorithm: null,
        maskPolicy: 'not_available',
        redactionReason: 'Raw value is not available from the current collector.'
      };
    }
    const raw = String(rawValue);
    const length = raw.length;
    const sensitive = hasSensitiveCookieTerm(cookie.name, raw) || isPossibleJwt(raw);
    let masked;
    let maskPolicy;
    if (length <= 8) {
      masked = '#'.repeat(length);
      maskPolicy = 'full_mask_when_short';
    } else if (length <= 15 || sensitive) {
      masked = `${raw.slice(0, 4)}${'#'.repeat(Math.max(4, length - 4))}`;
      maskPolicy = sensitive ? 'sensitive_prefix4_only' : 'prefix4_when_medium';
    } else {
      masked = `${raw.slice(0, 4)}########${deterministicMiddle(raw)}########`;
      maskPolicy = 'prefix4_middle3_when_long';
    }
    const visibleRawChars = maskPolicy === 'full_mask_when_short'
      ? 0
      : maskPolicy === 'prefix4_middle3_when_long'
        ? 7
        : 4;
    return {
      rawAvailable: true,
      rawIncluded: false,
      rawValue: null,
      masked,
      length,
      visibleRawChars,
      fingerprint: buildCookieFingerprint(raw),
      fingerprintAlgorithm: 'SHA-256',
      maskPolicy,
      redactionReason: sensitive ? 'Sensitive cookie value masked by policy.' : 'Cookie value masked by default.'
    };
  }

  function buildCookieFingerprint(value) {
    if (isProtectedValue(value)) return null;
    return {
      algorithm: 'SHA-256',
      version: 'v1',
      truncatedBits: 128,
      value: sha256Hex(String(value)).slice(0, 32),
      warning: 'Not suitable for low-entropy value proof against brute force'
    };
  }

  function sanitizeSetCookieLine(line) {
    const parsed = parseSetCookieLine(line);
    if (!parsed) return 'Set-Cookie: [unparseable metadata]';
    const attrs = [];
    const a = parsed.attributes;
    if (a.domain) attrs.push(`Domain=${a.domain}`);
    if (a.path) attrs.push(`Path=${a.path}`);
    if (a.expires) attrs.push(`Expires=${a.expires}`);
    if (a.maxAge) attrs.push(`Max-Age=${a.maxAge}`);
    if (a.httpOnly) attrs.push('HttpOnly');
    if (a.secure) attrs.push('Secure');
    if (a.sameSite !== 'unknown') attrs.push(`SameSite=${a.sameSite}`);
    if (a.priority) attrs.push(`Priority=${a.priority}`);
    if (a.partitioned === true) attrs.push('Partitioned');
    return `Set-Cookie: ${parsed.name}=[protected]${attrs.length ? `; ${attrs.join('; ')}` : ''}`;
  }

  function sanitizeCookieHeaderLine(line) {
    const names = parseCookieHeader(line).map(x => `${x.name}=[protected]`);
    return `Cookie: ${names.join('; ')}`;
  }

  function observedContext(entry, source) {
    const url = entry.url || null;
    const redactedUrl = domain.redactUrl ? domain.redactUrl(url || '') : url;
    const urlHash = domain.hashSensitiveValue ? domain.hashSensitiveValue(url || '') : null;
    return {
      source,
      method: entry.method || null,
      url: redactedUrl,
      urlRedacted: redactedUrl,
      urlHash,
      status: entry.statusCode ?? null,
      timestamp: entry.startedDateTime || null
    };
  }

  function sourceUrl(entry) {
    return entry.url || null;
  }

  function createCookieModel(base, targetUrl) {
    const rawValue = isProtectedValue(base.rawValue) ? null : String(base.rawValue);
    const value = maskCookieValue(rawValue, { name: base.name });
    const classification = classifyCookieValue(base.name, rawValue);
    const originHost = firstKnown(base.originHost, parseHost(sourceUrl(base.entry)), parseHost(targetUrl));
    const domainValue = firstKnown(base.domain, originHost, 'unknown');
    const path = firstKnown(base.path, '/');
    const key = `${base.name}|${domainValue}|${path}|${base.source}`;
    const isFirst = parseHost(targetUrl) && originHost ? parseHost(targetUrl) === originHost : 'unknown';
    const expirationDate = normalizeExpirationDate(base.expirationDate, base.expires, base.maxAge);
    const session = base.session ?? (!expirationDate && !base.expires && !base.maxAge);
    const model = {
      id: `oc:${stableId(key)}`,
      key,
      name: base.name,
      normalizedName: String(base.name || '').toLowerCase(),
      domain: base.domain || null,
      hostOnly: base.hostOnly ?? (base.domain ? false : true),
      originHost,
      path,
      expires: base.expires || null,
      expirationDate,
      maxAge: base.maxAge || null,
      session,
      secure: base.secure ?? 'unknown',
      httpOnly: base.httpOnly ?? 'unknown',
      sameSite: base.sameSite || 'unknown',
      partitionKey: base.partitionKey || null,
      storeId: base.storeId || null,
      source: base.source || COOKIE_SOURCES.UNKNOWN,
      sources: [base.source || COOKIE_SOURCES.UNKNOWN],
      observedIn: [base.observedIn].filter(Boolean),
      observedInResponse: base.observedInResponse === true,
      observedInRequest: base.observedInRequest === true,
      sourceUrls: [sourceUrl(base.entry)].filter(Boolean),
      value,
      rawValue,
      rawAvailable: value.rawAvailable,
      valueRepresentation: 'masked',
      valueKind: value.rawAvailable ? 'raw_available_masked' : 'protected',
      classification,
      risk: [],
      exportability: {
        sanitizedJson: true,
        html: true,
        netscapeSanitized: true,
        rawJson: value.rawAvailable,
        rawNetscape: value.rawAvailable,
        rawUnavailableReason: value.rawAvailable ? null : 'Raw value is not available from the current collector.'
      },
      priority: base.priority || null,
      partitioned: base.partitioned ?? 'unknown',
      attributesKnown: !!base.attributesKnown,
      visibleToDocument: base.visibleToDocument || 'not_collected',
      isFirstParty: isFirst,
      isThirdParty: isFirst === 'unknown' ? 'unknown' : !isFirst,
      isSessionLikeName: cookieClass(base.name, rawValue).session,
      isAuthLikeName: cookieClass(base.name, rawValue).session,
      isCsrfLikeName: cookieClass(base.name, rawValue).csrf,
      isTrackingLikeName: cookieClass(base.name, rawValue).tracking,
      isJwtLikeValue: rawValue ? isPossibleJwt(rawValue) : 'not_analyzed',
      isLongLived: Number(base.maxAge || 0) > 15552000 || 'unknown',
      occurrenceCount: 1,
      findings: []
    };
    model.risk = riskForCookie(model, classification);
    return model;
  }

  function mergeCookie(existing, incoming) {
    existing.occurrenceCount++;
    existing.sourceUrls = unique(existing.sourceUrls.concat(incoming.sourceUrls));
    existing.sources = unique(existing.sources.concat(incoming.sources));
    existing.observedIn = mergeObserved(existing.observedIn, incoming.observedIn);
    existing.observedInResponse = existing.observedInResponse || incoming.observedInResponse;
    existing.observedInRequest = existing.observedInRequest || incoming.observedInRequest;
    if (!existing.rawAvailable && incoming.rawAvailable) {
      existing.rawValue = incoming.rawValue;
      existing.rawAvailable = true;
      existing.value = incoming.value;
      existing.valueKind = incoming.valueKind;
      existing.exportability.rawJson = true;
      existing.exportability.rawNetscape = true;
      existing.exportability.rawUnavailableReason = null;
    }
    if (incoming.attributesKnown && !existing.attributesKnown) {
      [
        'domain',
        'hostOnly',
        'path',
        'expires',
        'expirationDate',
        'maxAge',
        'session',
        'secure',
        'httpOnly',
        'sameSite',
        'partitionKey',
        'storeId',
        'priority',
        'partitioned',
        'attributesKnown'
      ].forEach(key => {
        existing[key] = incoming[key];
      });
    }
    existing.classification = existing.classification === 'jwt_like' || incoming.classification !== 'general'
      ? incoming.classification
      : existing.classification;
    existing.risk = unique(existing.risk.concat(incoming.risk));
    return existing;
  }

  function mergeObserved(a, b) {
    const byKey = new Map();
    [...(a || []), ...(b || [])].forEach(item => {
      const key = `${item.source}|${item.method}|${item.urlHash}|${item.status}|${item.timestamp}`;
      byKey.set(key, item);
    });
    return [...byKey.values()];
  }

  function analyzeCookies(entries, targetUrl) {
    const rawRecords = [];
    const observed = new Map();
    const findings = [];

    const addObs = base => {
      const model = createCookieModel(base, targetUrl);
      const mergeKey = `${model.name}|${model.domain || model.originHost || 'unknown'}|${model.path || '/'}|${model.source}`;
      model.key = mergeKey;
      model.id = `oc:${stableId(mergeKey)}`;
      const ex = observed.get(mergeKey);
      if (ex) return mergeCookie(ex, model);
      observed.set(mergeKey, model);
      return model;
    };

    entries.forEach((e, i) => {
      const hhReq = lowerHeaders(e.requestCookieHeadersRaw?.map(value => ({ name: 'Cookie', value })) || e.requestHeaders || []);
      const hhRes = lowerHeaders(e.responseSetCookieHeadersRaw?.map(value => ({ name: 'Set-Cookie', value })) || e.responseHeaders || []);
      const reqUrl = e.url || null;
      const originHost = parseHost(reqUrl);

      (e.requestCookiesRaw || e.requestCookies || []).forEach((cookie, j) => {
        const normalized = normalizeHarCookie(cookie, { domain: originHost });
        if (!normalized) return;
        rawRecords.push(rawRecord(`cr:${i}:${j}:har_req`, COOKIE_SOURCES.HAR_REQUEST_COOKIE, e, targetUrl, normalized.name, normalized.value, null));
        addObs({
          ...normalized,
          source: COOKIE_SOURCES.HAR_REQUEST_COOKIE,
          rawValue: normalized.value,
          originHost,
          entry: e,
          observedIn: observedContext(e, COOKIE_SOURCES.HAR_REQUEST_COOKIE),
          observedInResponse: false,
          observedInRequest: true,
          attributesKnown: true
        });
      });

      (e.responseCookiesRaw || e.responseCookies || []).forEach((cookie, j) => {
        const normalized = normalizeHarCookie(cookie, { domain: originHost });
        if (!normalized) return;
        rawRecords.push(rawRecord(`cr:${i}:${j}:har_res`, COOKIE_SOURCES.HAR_RESPONSE_COOKIE, e, targetUrl, normalized.name, normalized.value, null));
        addObs({
          ...normalized,
          source: COOKIE_SOURCES.HAR_RESPONSE_COOKIE,
          rawValue: normalized.value,
          originHost,
          entry: e,
          observedIn: observedContext(e, COOKIE_SOURCES.HAR_RESPONSE_COOKIE),
          observedInResponse: true,
          observedInRequest: false,
          attributesKnown: true
        });
      });

      (hhRes['set-cookie'] || []).forEach((line, j) => {
        const p = parseSetCookieLine(line);
        rawRecords.push(rawRecord(`cr:${i}:${j}:s`, COOKIE_SOURCES.SET_COOKIE_HEADER, e, targetUrl, p?.name || null, p?.value || null, sanitizeSetCookieLine(line)));
        if (!p) return;
        addObs({
          name: p.name,
          rawValue: p.value,
          domain: p.attributes.domain,
          hostOnly: p.attributes.domain ? false : true,
          originHost,
          path: p.attributes.path || '/',
          expires: p.attributes.expires,
          maxAge: p.attributes.maxAge,
          secure: p.attributes.secure,
          httpOnly: p.attributes.httpOnly,
          sameSite: p.attributes.sameSite,
          priority: p.attributes.priority,
          partitioned: p.attributes.partitioned,
          partitionKey: p.attributes.partitionKey,
          source: COOKIE_SOURCES.SET_COOKIE_HEADER,
          entry: e,
          observedIn: observedContext(e, COOKIE_SOURCES.SET_COOKIE_HEADER),
          observedInResponse: true,
          observedInRequest: false,
          attributesKnown: true
        });
      });

      (hhReq['cookie'] || []).forEach((line, j) => {
        rawRecords.push(rawRecord(`cr:${i}:${j}:r`, COOKIE_SOURCES.COOKIE_HEADER, e, targetUrl, null, null, sanitizeCookieHeaderLine(line)));
        parseCookieHeader(line).forEach(c => {
          addObs({
            name: c.name,
            rawValue: c.value,
            domain: null,
            hostOnly: true,
            originHost,
            path: '/',
            secure: 'unknown',
            httpOnly: 'unknown',
            sameSite: 'unknown',
            source: COOKIE_SOURCES.COOKIE_HEADER,
            entry: e,
            observedIn: observedContext(e, COOKIE_SOURCES.COOKIE_HEADER),
            observedInResponse: false,
            observedInRequest: true,
            attributesKnown: false
          });
        });
      });
    });

    const list = [...observed.values()];
    const addFinding = (c, ruleId, severity, evidence, recommendation, confidence = 'confirmed', attributeKnown = true) => {
      const f = {
        id: `f:${ruleId}:${c.key}`,
        ruleId,
        severity,
        category: 'cookies',
        cookieName: c.name,
        cookieKey: c.key,
        targetUrl: targetUrl || null,
        sourceUrls: c.sourceUrls,
        evidence,
        recommendation,
        mode: 'safe',
        confidence,
        attributeKnown
      };
      findings.push(f);
      c.findings.push(ruleId);
    };

    list.forEach(c => {
      if (c.observedInRequest && !c.observedInResponse && !c.attributesKnown) {
        addFinding(c, 'cookies.attributes_unknown', 'info', 'Cookie observed only in request Cookie header; Set-Cookie attributes were not captured.', 'Reload and capture the login/session flow to inspect Set-Cookie attributes.', 'unknown', false);
        return;
      }
      if (c.isSessionLikeName && c.attributesKnown && c.httpOnly === false) addFinding(c, 'cookies.session_without_httponly', 'medium', 'Session/auth-like name observed without HttpOnly attribute.', 'Set HttpOnly for session/auth-like cookies.');
      if (c.isSessionLikeName && c.attributesKnown && c.secure === false) addFinding(c, 'cookies.session_without_secure', c.sourceUrls.some(u => (u || '').startsWith('http:')) ? 'high' : 'medium', 'Session/auth-like name observed without Secure attribute.', 'Set Secure and serve over HTTPS only.');
      if (c.isSessionLikeName && c.attributesKnown && c.sameSite === 'unknown') addFinding(c, 'cookies.samesite_missing_sensitive', 'medium', 'Session/auth-like name observed without SameSite attribute.', 'Set SameSite=Lax or SameSite=Strict.');
      if ((c.sameSite || '').toLowerCase() === 'none' && c.secure === false) addFinding(c, 'cookies.samesite_none_without_secure', 'medium', 'SameSite=None is set without Secure.', 'Set Secure whenever SameSite=None is used.');
      if (c.sameSite !== 'unknown' && !['strict', 'lax', 'none'].includes((c.sameSite || '').toLowerCase())) addFinding(c, 'cookies.invalid_samesite', 'low', 'SameSite attribute value is not valid.', 'Use SameSite=Strict, SameSite=Lax, or SameSite=None.');
      if (c.isSessionLikeName && c.domain && c.domain.startsWith('.')) addFinding(c, 'cookies.broad_domain_sensitive', 'medium', 'Session/auth-like name uses a broad Domain scope.', 'Prefer host-only cookies when possible.', 'likely');
      if (c.name.startsWith('__Host-') && (c.secure !== true || !!c.domain || c.path !== '/')) addFinding(c, 'cookies.invalid_host_prefix', c.isSessionLikeName ? 'high' : 'medium', '__Host- prefix requirements are not satisfied.', 'For __Host- cookies: set Secure, omit Domain, and set Path=/.');
      if (c.name.startsWith('__Secure-') && c.secure !== true) addFinding(c, 'cookies.invalid_secure_prefix', c.isSessionLikeName ? 'high' : 'medium', '__Secure- cookie is missing Secure.', 'Set Secure on __Secure- prefixed cookies.');
      if (c.isSessionLikeName && Number(c.maxAge || 0) > 15552000) addFinding(c, 'cookies.long_lived_sensitive', 'medium', 'Session/auth-like cookie appears long-lived (>180 days).', 'Reduce session lifetime where possible.', 'likely');
    });
    const sev = { high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => sev[f.severity]++);
    const rawAvailableCookies = list.filter(c => c.value.rawAvailable).length;
    return {
      rawRecords,
      observedCookies: list,
      findings,
      summary: {
        observedCookies: list.length,
        setCookieRecords: rawRecords.filter(r => r.source === COOKIE_SOURCES.SET_COOKIE_HEADER).length,
        cookieHeaderRecords: rawRecords.filter(r => r.source === COOKIE_SOURCES.COOKIE_HEADER).length,
        harRequestCookieRecords: rawRecords.filter(r => r.source === COOKIE_SOURCES.HAR_REQUEST_COOKIE).length,
        harResponseCookieRecords: rawRecords.filter(r => r.source === COOKIE_SOURCES.HAR_RESPONSE_COOKIE).length,
        rawAvailableCookies,
        rawUnavailableCookies: list.length - rawAvailableCookies,
        sessionAuthLikeCookies: list.filter(c => c.isSessionLikeName).length,
        findings: findings.length,
        ...sev
      }
    };
  }

  function rawRecord(id, source, entry, targetUrl, name, rawValue, sanitizedLine) {
    const rawAvailable = !isProtectedValue(rawValue);
    return {
      id,
      source,
      targetUrl: targetUrl || null,
      requestUrl: entry.url || null,
      headerName: source === COOKIE_SOURCES.COOKIE_HEADER ? 'Cookie' : source === COOKIE_SOURCES.SET_COOKIE_HEADER ? 'Set-Cookie' : null,
      cookieName: name,
      rawLineSanitized: sanitizedLine || (name ? `${name}=[protected]` : '[protected]'),
      capturedAt: new Date().toISOString(),
      mode: 'safe',
      valueRepresentation: 'protected',
      rawAvailable,
      rawIncluded: false,
      value: rawAvailable ? maskCookieValue(rawValue, { name }) : maskCookieValue(null)
    };
  }

  function buildSanitizedCookie(cookie) {
    const sourceUrls = (cookie.sourceUrls || []).map(url => domain.redactUrl ? domain.redactUrl(url || '') : url);
    const value = cookie.value || maskCookieValue(cookie.rawValue, cookie);
    const classification = cookie.classification || classifyCookieValue(cookie.name, cookie.rawValue);
    return {
      id: cookie.id || null,
      name: cookie.name || null,
      domain: cookie.domain || cookie.originHost || null,
      hostOnly: cookie.hostOnly ?? null,
      path: cookie.path || null,
      expires: cookie.expires || null,
      expirationDate: cookie.expirationDate || null,
      session: cookie.session ?? null,
      secure: cookie.secure ?? null,
      httpOnly: cookie.httpOnly ?? null,
      sameSite: cookie.sameSite || null,
      partitionKey: cookie.partitionKey || null,
      storeId: cookie.storeId || null,
      source: cookie.source || COOKIE_SOURCES.UNKNOWN,
      sources: cookie.sources || [cookie.source || COOKIE_SOURCES.UNKNOWN],
      observedIn: (cookie.observedIn || []).map(item => ({
        ...item,
        url: item.urlRedacted || item.url || null,
        urlRedacted: item.urlRedacted || item.url || null
      })),
      sourceUrls,
      value: stripRawCookieValue(value),
      classification,
      risk: cookie.risk || riskForCookie({ ...cookie, value }, classification),
      exportability: {
        sanitizedJson: true,
        html: true,
        netscapeSanitized: true,
        rawJson: !!cookie.value?.rawAvailable,
        rawNetscape: !!cookie.value?.rawAvailable,
        rawUnavailableReason: cookie.value?.rawAvailable ? null : 'Raw value is not available from the current collector.'
      },
      findings: cookie.findings || []
    };
  }

  function buildRawCookie(cookie) {
    if (!cookie?.value?.rawAvailable || isProtectedValue(cookie.rawValue)) return null;
    const sanitized = buildSanitizedCookie(cookie);
    return {
      ...sanitized,
      value: {
        ...sanitized.value,
        rawIncluded: true,
        rawValue: String(cookie.rawValue)
      }
    };
  }

  function stripRawCookieValue(value) {
    const out = {
      ...(value || {}),
      rawIncluded: false
    };
    delete out.rawValue;
    return out;
  }

  function buildCookiesSanitizedJson({ generatedAt, analyzedUrl, summary, cookies, findings = [] }) {
    return {
      schemaVersion: 'backtools.cookies.v1',
      generatedAt,
      inspectedUrl: domain.redactUrl ? domain.redactUrl(analyzedUrl || '') : analyzedUrl,
      containsRawCookies: false,
      containsReplayableCookieJar: false,
      summary,
      cookies: (cookies || []).map(buildSanitizedCookie),
      findings
    };
  }

  function buildCookiesRawJson({ generatedAt, analyzedUrl, cookies, confirmedAt, scope }) {
    const rawCookies = (cookies || []).map(buildRawCookie).filter(Boolean);
    return {
      schemaVersion: 'backtools.cookies.raw.v1',
      generatedAt,
      inspectedUrl: domain.redactUrl ? domain.redactUrl(analyzedUrl || '') : analyzedUrl,
      containsRawCookies: rawCookies.length > 0,
      containsReplayableCookieJar: rawCookies.length > 0,
      rawCookieExportConfirmedAt: confirmedAt || null,
      rawCookieExportScope: scope || summarizeRawCookieScope(cookies || []),
      cookies: rawCookies
    };
  }

  function buildCookiesHtml({ generatedAt, analyzedUrl, summary, cookies }) {
    const rows = (cookies || []).map(buildSanitizedCookie);
    return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Back Tools Cookies</title>
<style>
body{margin:0;background:#0e1116;color:#e8edf5;font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
main{padding:24px;max-width:1280px;margin:0 auto}
h1{font-size:24px;margin:0 0 6px}
.meta,.warn{color:#aab6c8}
.warn{border:1px solid #7a5b24;background:#1c1710;padding:10px;border-radius:8px;margin:16px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin:18px 0}
.box{border:1px solid #283241;background:#151a22;border-radius:8px;padding:12px}
.box b{display:block;font-size:20px}
table{width:100%;border-collapse:collapse;background:#111720;border:1px solid #283241}
th,td{padding:8px 10px;border-bottom:1px solid #283241;text-align:left;vertical-align:top}
th{color:#aab6c8;background:#151a22}
code{color:#d6e4ff;word-break:break-all}
.pill{display:inline-block;border:1px solid #344154;border-radius:999px;padding:2px 7px;color:#c6d2e4;margin:1px}
</style>
</head>
<body>
<main>
<h1>Back Tools Cookies</h1>
<div class="meta">Generated ${escapeHtml(generatedAt || '')} for ${escapeHtml(domain.redactUrl ? domain.redactUrl(analyzedUrl || '') : analyzedUrl || '')}</div>
<div class="warn">Cookie values are masked. This HTML report does not include raw cookie values and is not valid for replay.</div>
<section class="grid">
${metricBox('Observed', summary?.observedCookies || rows.length)}
${metricBox('Raw available', summary?.rawAvailableCookies || 0)}
${metricBox('Findings', summary?.findings || 0)}
${metricBox('Auth-like', summary?.sessionAuthLikeCookies || 0)}
</section>
<table>
<thead><tr><th>Name</th><th>Domain</th><th>Path</th><th>Source</th><th>Flags</th><th>Classification</th><th>Protected value</th><th>Fingerprint</th><th>Findings</th></tr></thead>
<tbody>
${rows.map(row => `<tr><td>${escapeHtml(row.name)}</td><td>${escapeHtml(row.domain || '-')}</td><td>${escapeHtml(row.path || '-')}</td><td>${escapeHtml((row.sources || []).join(', ') || row.source || '-')}</td><td>${flagPills(row)}</td><td>${escapeHtml(row.classification)}</td><td><code>${escapeHtml(row.value?.masked || 'not_available')}</code></td><td><code>${escapeHtml(row.value?.fingerprint?.value || 'not_available')}</code></td><td>${escapeHtml((row.findings || []).join(', ') || '-')}</td></tr>`).join('\n')}
</tbody>
</table>
</main>
</body>
</html>`;
  }

  function metricBox(label, value) {
    return `<div class="box"><span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>`;
  }

  function flagPills(row) {
    return [
      `Secure=${row.secure}`,
      `HttpOnly=${row.httpOnly}`,
      `SameSite=${row.sameSite || 'unknown'}`,
      row.session ? 'Session' : 'Persistent'
    ].map(value => `<span class="pill">${escapeHtml(value)}</span>`).join(' ');
  }

  function buildNetscapeSanitized(cookies) {
    const lines = [
      '# Back Tools sanitized Netscape cookie file',
      '# Values are intentionally masked and are NOT valid for replay.',
      '# Do not use this file with curl/wget for authentication.'
    ];
    (cookies || []).map(buildSanitizedCookie).forEach(cookie => {
      lines.push(netscapeLine(cookie, cookie.value?.masked || 'not_available'));
    });
    return `${lines.join('\n')}\n`;
  }

  function buildNetscapeRaw(cookies) {
    const lines = [
      '# Back Tools raw Netscape cookie file',
      '# This file may contain replayable authentication material.'
    ];
    (cookies || []).map(buildRawCookie).filter(Boolean).forEach(cookie => {
      lines.push(netscapeLine(cookie, cookie.value.rawValue));
    });
    return `${lines.join('\n')}\n`;
  }

  function netscapeLine(cookie, value) {
    const domainValue = cookie.domain || 'unknown';
    const includeSubdomains = domainValue.startsWith('.') || cookie.hostOnly === false ? 'TRUE' : 'FALSE';
    const path = cookie.path || '/';
    const secure = cookie.secure === true ? 'TRUE' : 'FALSE';
    const expires = cookie.expirationDate ? Math.floor(Number(cookie.expirationDate)) : 0;
    return [domainValue, includeSubdomains, path, secure, expires, cookie.name || '', value || ''].join('\t');
  }

  function summarizeRawCookieScope(cookies) {
    const rawCookies = (cookies || []).filter(cookie => cookie?.value?.rawAvailable && !isProtectedValue(cookie.rawValue));
    return {
      rawCookieCount: rawCookies.length,
      domains: unique(rawCookies.map(cookie => cookie.domain || cookie.originHost || 'unknown')).sort()
    };
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function parseHost(url) {
    try {
      if (domain.parseUrl) return domain.parseUrl(url || '').host;
    } catch {}
    try {
      return new URL(url || '').host || null;
    } catch {
      return null;
    }
  }

  function normalizeExpirationDate(expirationDate, expires, maxAge) {
    if (expirationDate != null && Number.isFinite(Number(expirationDate))) return Number(expirationDate);
    if (maxAge != null && maxAge !== '' && Number.isFinite(Number(maxAge))) return Math.floor(Date.now() / 1000) + Number(maxAge);
    if (expires) {
      const time = Date.parse(expires);
      if (Number.isFinite(time)) return Math.floor(time / 1000);
    }
    return null;
  }

  function stableId(value) {
    return domain.hashSensitiveValue ? domain.hashSensitiveValue(value) : fnv1a(value);
  }

  function unique(values) {
    return [...new Set((values || []).filter(value => value !== undefined && value !== null && value !== ''))];
  }

  function fnv1a(value) {
    let hash = 0x811c9dc5;
    const text = String(value ?? '');
    for (let i = 0; i < text.length; i++) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, '0');
  }

  function sha256Hex(value) {
    if (typeof require === 'function') {
      try {
        const crypto = require('node:crypto');
        return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
      } catch {}
    }
    return sha256Pure(value);
  }

  function utf8Bytes(value) {
    if (typeof TextEncoder !== 'undefined') return Array.from(new TextEncoder().encode(String(value)));
    if (typeof Buffer !== 'undefined') return Array.from(Buffer.from(String(value), 'utf8'));
    return Array.from(unescape(encodeURIComponent(String(value)))).map(ch => ch.charCodeAt(0));
  }

  function sha256Pure(value) {
    const bytes = utf8Bytes(value);
    const bitLength = bytes.length * 8;
    bytes.push(0x80);
    while ((bytes.length % 64) !== 56) bytes.push(0);
    const high = Math.floor(bitLength / 0x100000000);
    const low = bitLength >>> 0;
    bytes.push((high >>> 24) & 255, (high >>> 16) & 255, (high >>> 8) & 255, high & 255);
    bytes.push((low >>> 24) & 255, (low >>> 16) & 255, (low >>> 8) & 255, low & 255);

    const k = [
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    let h0 = 0x6a09e667;
    let h1 = 0xbb67ae85;
    let h2 = 0x3c6ef372;
    let h3 = 0xa54ff53a;
    let h4 = 0x510e527f;
    let h5 = 0x9b05688c;
    let h6 = 0x1f83d9ab;
    let h7 = 0x5be0cd19;
    const w = new Array(64);

    for (let i = 0; i < bytes.length; i += 64) {
      for (let j = 0; j < 16; j++) {
        w[j] = ((bytes[i + j * 4] << 24) | (bytes[i + j * 4 + 1] << 16) | (bytes[i + j * 4 + 2] << 8) | bytes[i + j * 4 + 3]) >>> 0;
      }
      for (let j = 16; j < 64; j++) {
        const s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >>> 3);
        const s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
      }
      let a = h0;
      let b = h1;
      let c = h2;
      let d = h3;
      let e = h4;
      let f = h5;
      let g = h6;
      let h = h7;
      for (let j = 0; j < 64; j++) {
        const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + s1 + ch + k[j] + w[j]) >>> 0;
        const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (s0 + maj) >>> 0;
        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
      }
      h0 = (h0 + a) >>> 0;
      h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0;
      h5 = (h5 + f) >>> 0;
      h6 = (h6 + g) >>> 0;
      h7 = (h7 + h) >>> 0;
    }

    return [h0, h1, h2, h3, h4, h5, h6, h7].map(n => n.toString(16).padStart(8, '0')).join('');
  }

  function rotr(value, bits) {
    return (value >>> bits) | (value << (32 - bits));
  }

  return {
    COOKIE_SOURCES,
    SENSITIVE_COOKIE_TERMS,
    lowerHeaders,
    parseSetCookieLine,
    parseCookieHeader,
    normalizeHarCookie,
    isPossibleJwt,
    cookieClass,
    classifyCookieValue,
    maskCookieValue,
    buildCookieFingerprint,
    sanitizeSetCookieLine,
    sanitizeCookieHeaderLine,
    analyzeCookies,
    buildSanitizedCookie,
    buildRawCookie,
    buildCookiesSanitizedJson,
    buildCookiesRawJson,
    buildCookiesHtml,
    buildNetscapeSanitized,
    buildNetscapeRaw,
    summarizeRawCookieScope
  };
});
