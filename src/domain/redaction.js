(function(root, factory) {
  const api = factory();
  root.BackToolsDomain = Object.assign(root.BackToolsDomain || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function() {
  const REDACTED = '[redacted]';
  const PROTECTED = '[protected]';

  const SENSITIVE_QUERY_KEYS = [
    'token',
    'access_token',
    'id_token',
    'refresh_token',
    'jwt',
    'key',
    'api_key',
    'signature',
    'sig',
    'auth',
    'authorization',
    'password',
    'pass',
    'secret',
    'session',
    'sid',
    'cookie',
    'csrf',
    'xsrf',
    'saml',
    'oauth',
    'bearer',
    'credential',
    'code',
    'state',
    'fbclid',
    'gclid',
    'msclkid',
    'igshid'
  ];

  const SENSITIVE_KEY_FRAGMENTS = [
    'token',
    'auth',
    'password',
    'passwd',
    'secret',
    'session',
    'cookie',
    'csrf',
    'xsrf',
    'saml',
    'oauth',
    'bearer',
    'credential',
    'signature'
  ];

  const SENSITIVE_HEADER_NAMES = [
    'authorization',
    'cookie',
    'set-cookie',
    'x-api-key',
    'proxy-authorization'
  ];

  function normalizeName(value) {
    return String(value || '').trim().toLowerCase();
  }

  function isSensitiveQueryKey(key, sensitiveKeys = SENSITIVE_QUERY_KEYS) {
    const normalized = normalizeName(key);
    if (!normalized) {
      return false;
    }
    if (sensitiveKeys.map(normalizeName).includes(normalized)) {
      return true;
    }
    return SENSITIVE_KEY_FRAGMENTS.some(fragment => normalized.includes(fragment));
  }

  function looksLikeOpaqueSecret(value) {
    const text = String(value || '');
    if (text.length < 48) {
      return false;
    }
    if (/^https?:\/\//i.test(text)) {
      return false;
    }
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(text)) {
      return true;
    }
    const compact = text.replace(/[^A-Za-z0-9_-]/g, '');
    if (compact.length < 48) {
      return false;
    }
    const unique = new Set(compact.slice(0, 96).split('')).size;
    return unique >= 12;
  }

  function redactSensitivePath(parsed, redactedKeys) {
    const parts = parsed.pathname.split('/').map((part, index, list) => {
      if (!part) {
        return part;
      }
      const previous = normalizeName(list[index - 1] || '');
      const decoded = safeDecodeURIComponent(part);
      if (
        SENSITIVE_KEY_FRAGMENTS.some(fragment => previous.includes(fragment)) ||
        looksLikeOpaqueSecret(decoded)
      ) {
        redactedKeys.push('path');
        return REDACTED;
      }
      return part;
    });
    parsed.pathname = parts.join('/');
  }

  function safeDecodeURIComponent(value) {
    try {
      return decodeURIComponent(String(value || ''));
    } catch {
      return String(value || '');
    }
  }

  function isSensitiveHeaderName(name) {
    return SENSITIVE_HEADER_NAMES.includes(normalizeName(name));
  }

  function stableHash(value) {
    const text = String(value ?? '');
    let hash = 0x811c9dc5;
    for (let i = 0; i < text.length; i++) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, '0');
  }

  function hashSensitiveValue(value) {
    return stableHash(value);
  }

  function redactUrlWithMetadata(url, sensitiveKeys = SENSITIVE_QUERY_KEYS) {
    const raw = String(url ?? '');
    try {
      const parsed = new URL(raw);
      const redactedKeys = [];
      parsed.searchParams.forEach((value, key) => {
        if (isSensitiveQueryKey(key, sensitiveKeys) || looksLikeOpaqueSecret(value)) {
          parsed.searchParams.set(key, REDACTED);
          redactedKeys.push(key);
        }
      });
      redactSensitivePath(parsed, redactedKeys);
      if (parsed.hash && (parsed.hash.length > 24 || /token|session|auth|access|secret|code|state/i.test(parsed.hash))) {
        parsed.hash = `#${REDACTED}`;
        redactedKeys.push('fragment');
      }
      return {
        value: parsed.toString(),
        redacted: redactedKeys.length > 0,
        redactedKeys: [...new Set(redactedKeys)],
        hash: stableHash(raw)
      };
    } catch {
      const redactedKeys = [];
      let output = raw.replace(/([?&])([^=&?#]+)=([^&#]*)/g, (match, sep, key, value) => {
        if (!isSensitiveQueryKey(key, sensitiveKeys) && !looksLikeOpaqueSecret(value)) return match;
        redactedKeys.push(key);
        return `${sep}${key}=${REDACTED}`;
      });
      output = output.replace(/#(.{24,}|.*(?:token|session|auth|access|secret|code|state).*)$/i, () => {
        redactedKeys.push('fragment');
        return `#${REDACTED}`;
      });
      return {
        value: output,
        redacted: redactedKeys.length > 0,
        redactedKeys: [...new Set(redactedKeys)],
        hash: stableHash(raw)
      };
    }
  }

  function redactQueryParams(url, sensitiveKeys = SENSITIVE_QUERY_KEYS) {
    return redactUrlWithMetadata(url, sensitiveKeys).value;
  }

  function redactUrl(url) {
    return redactUrlWithMetadata(url).value;
  }

  function redactHeaderRecord(header) {
    const name = header?.name ?? header?.key ?? '';
    const valueKey = Object.prototype.hasOwnProperty.call(header || {}, 'value') ? 'value' : 'value';
    if (isSensitiveHeaderName(name)) {
      return { ...header, [valueKey]: REDACTED, redactionApplied: true };
    }
    return { ...header, redactionApplied: false };
  }

  function redactHeaders(headers) {
    if (Array.isArray(headers)) return headers.map(redactHeaderRecord);
    if (!headers || typeof headers !== 'object') return headers;
    const out = {};
    Object.entries(headers).forEach(([name, value]) => {
      out[name] = isSensitiveHeaderName(name) ? REDACTED : value;
    });
    return out;
  }

  function redactCookieRecord(cookie) {
    if (!cookie || typeof cookie !== 'object') return cookie;
    const rawValue = cookie.rawValue ?? cookie.value;
    const out = {
      ...cookie,
      value: PROTECTED,
      rawValue: null,
      valueRepresentation: 'protected',
      valueKind: 'protected',
      redactionApplied: true
    };
    if (rawValue != null && rawValue !== PROTECTED && rawValue !== REDACTED) {
      out.valueHash = hashSensitiveValue(rawValue);
      out.valueSize = String(rawValue).length;
    }
    return out;
  }

  function hasRedactedHeaders(headers) {
    return (headers || []).some(h => isSensitiveHeaderName(h?.name));
  }

  return {
    REDACTED,
    PROTECTED,
    SENSITIVE_QUERY_KEYS,
    SENSITIVE_KEY_FRAGMENTS,
    SENSITIVE_HEADER_NAMES,
    isSensitiveQueryKey,
    isSensitiveHeaderName,
    looksLikeOpaqueSecret,
    hashSensitiveValue,
    redactUrl,
    redactUrlWithMetadata,
    redactQueryParams,
    redactHeaders,
    redactCookieRecord,
    hasRedactedHeaders
  };
});
