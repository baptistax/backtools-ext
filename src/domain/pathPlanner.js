(function(root, factory) {
  const api = factory(root);
  root.BackToolsDomain = Object.assign(root.BackToolsDomain || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  let domain = root.BackToolsDomain || {};
  if (typeof require === 'function') {
    try {
      domain = Object.assign(
        {},
        require('./classify.js'),
        require('./resourceClassification.js'),
        require('./redaction.js'),
        domain
      );
    } catch {}
  }

  const MAX_SEGMENT_LENGTH = 48;
  const MAX_PATH_LENGTH = 170;

  const MIME_EXTENSIONS = {
    'application/javascript': 'js',
    'application/json': 'json',
    'application/pdf': 'pdf',
    'application/wasm': 'wasm',
    'font/woff2': 'woff2',
    'image/gif': 'gif',
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/svg+xml': 'svg',
    'image/webp': 'webp',
    'text/css': 'css',
    'text/html': 'html',
    'text/javascript': 'js',
    'text/plain': 'txt'
  };

  function stablePathHash(value) {
    if (typeof domain.hashSensitiveValue === 'function') return domain.hashSensitiveValue(value).slice(0, 8);
    let hash = 0x811c9dc5;
    const text = String(value ?? '');
    for (let i = 0; i < text.length; i++) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, '0');
  }

  function splitUrlForPath(url) {
    try {
      const parsed = new URL(url || '');
      return {
        ok: true,
        protocol: parsed.protocol.replace(':', '').toLowerCase(),
        host: parsed.host,
        pathname: parsed.pathname || '/',
        noQueryUrl: `${parsed.protocol}//${parsed.host}${parsed.pathname || '/'}`
      };
    } catch {
      return {
        ok: false,
        protocol: null,
        host: null,
        pathname: String(url || 'unknown'),
        noQueryUrl: String(url || 'unknown').split(/[?#]/)[0] || 'unknown'
      };
    }
  }

  function sanitizeSegment(value, fallback = 'item') {
    const normalized = String(value || '')
      .normalize('NFKC')
      .replace(/[\u0000-\u001f\u007f]/g, '')
      .replace(/[<>:"\\|?*]+/g, '-')
      .replace(/[\/]+/g, '-')
      .replace(/\s+/g, '-')
      .replace(/\.+/g, '.')
      .replace(/^-+|-+$/g, '')
      .replace(/^\.+|\.+$/g, '');
    const safe = normalized && normalized !== '..' && normalized !== '.' ? normalized : fallback;
    return safe.length > MAX_SEGMENT_LENGTH ? safe.slice(0, MAX_SEGMENT_LENGTH) : safe;
  }

  function inferExtension(pathname, mimeType, resourceType) {
    const mime = String(mimeType || '').split(';')[0].trim().toLowerCase();
    if (MIME_EXTENSIONS[mime]) return MIME_EXTENSIONS[mime];
    const clean = String(pathname || '').split(/[?#]/)[0];
    const last = clean.split('/').filter(Boolean).pop() || '';
    const match = /\.([A-Za-z0-9]{1,10})$/.exec(last);
    if (match) return match[1].toLowerCase();
    if (resourceType === 'script') return 'js';
    if (resourceType === 'stylesheet') return 'css';
    if (resourceType === 'document') return 'html';
    if (resourceType === 'json') return 'json';
    return 'bin';
  }

  function stripKnownExtension(name, ext) {
    const suffix = `.${ext}`;
    return name.toLowerCase().endsWith(suffix.toLowerCase()) ? name.slice(0, -suffix.length) : name;
  }

  function getPrefix(resource) {
    const category = resource?.resourceCategory || domain.classifyResourceUrl?.(resource?.url || '') || 'unknown';
    if (category === domain.ResourceCategory?.EXTENSION_RESOURCE) return 'extension';
    if (category === domain.ResourceCategory?.BROWSER_INTERNAL) return 'browser-internal';
    if (category === domain.ResourceCategory?.DEVTOOLS_INTERNAL) return 'devtools';
    if (category === domain.ResourceCategory?.DATA_URL) return 'data-urls';
    if (category === domain.ResourceCategory?.BLOB_URL) return 'blob-urls';
    if (resource?.collector === 'network_har') return 'network';
    return 'sources';
  }

  function trimPathToLimit(path) {
    if (path.length <= MAX_PATH_LENGTH) return path;
    const parts = path.split('/');
    const file = parts.pop();
    const prefix = parts.shift();
    const host = parts.shift();
    const compactHost = sanitizeSegment(host, 'unknown-host').slice(0, 32);
    const head = [prefix, compactHost].filter(Boolean).join('/');
    const availableFileLength = Math.max(24, MAX_PATH_LENGTH - head.length - 1);
    let safeFile = file || 'resource.bin';
    if (safeFile.length > availableFileLength) {
      const match = /(\.[A-Za-z0-9]{1,10})$/.exec(safeFile);
      const ext = match ? match[1] : '';
      safeFile = `${safeFile.slice(0, Math.max(1, availableFileLength - ext.length))}${ext}`;
    }
    return [head, safeFile].filter(Boolean).join('/');
  }

  function buildSafeZipPath(resource, options = {}) {
    const url = resource?.url || resource?.path || resource?.id || 'unknown';
    const prefix = getPrefix(resource);
    const hash = stablePathHash(url);
    const parsed = splitUrlForPath(url);
    const host = sanitizeSegment(resource?.host || parsed.host || parsed.protocol || 'unknown-host', 'unknown-host');
    const mimeType = options.mimeType || resource?.mimeType || null;
    const ext = inferExtension(parsed.pathname, mimeType, resource?.type);

    if (prefix === 'data-urls') {
      return `data-urls/data-url--${hash}.${ext}`;
    }

    const segments = parsed.pathname
      .split('/')
      .filter(Boolean)
      .map(segment => decodeURIComponentSafe(segment));
    const rawFile = segments.pop() || (parsed.pathname.endsWith('/') ? 'index' : 'resource');
    const safeDirs = segments.slice(-3).map(segment => sanitizeSegment(segment, 'dir'));
    const safeBase = sanitizeSegment(stripKnownExtension(rawFile, ext), 'index');
    const file = `${safeBase}--${hash}.${ext}`;
    return trimPathToLimit([prefix, host, ...safeDirs, file].filter(Boolean).join('/'));
  }

  function decodeURIComponentSafe(value) {
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }

  function buildSafeSourceZipPath(resource) {
    return buildSafeZipPath(resource);
  }

  function buildSafeDataUrlZipPath(resource, index, mimeType) {
    const ext = inferExtension('', mimeType, resource?.type);
    const hash = stablePathHash(resource?.url || resource?.id || `data-url-${index}`);
    return `data-urls/data-url-${index + 1}--${hash}.${ext}`;
  }

  return {
    MAX_SEGMENT_LENGTH,
    MAX_PATH_LENGTH,
    sanitizeSegment,
    inferExtension,
    buildSafeZipPath,
    buildSafeSourceZipPath,
    buildSafeDataUrlZipPath,
    stablePathHash
  };
});
