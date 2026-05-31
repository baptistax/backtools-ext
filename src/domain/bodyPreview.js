(function(root, factory) {
  const api = factory(root);
  root.BackToolsDomain = Object.assign(root.BackToolsDomain || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  const BodyRenderStatus = {
    NOT_RENDERABLE: 'not_renderable',
    RENDERED_FULL: 'rendered_full',
    PARTIAL_PREVIEW: 'partial_preview',
    BINARY_PREVIEW: 'binary_preview',
    RENDER_FAILED: 'render_failed'
  };

  const BodyExportStatus = {
    EXPORTABLE_BODY: 'exportable_body',
    NOT_EXPORTABLE: 'not_exportable',
    EXPORT_BLOCKED: 'export_blocked'
  };

  const DEFAULT_TEXT_RENDER_CHARS = 64 * 1024;
  const TEXT_RENDER_CHUNK_CHARS = 64 * 1024;
  const DEFAULT_HEXDUMP_BYTES = 4096;
  const HEXDUMP_CHUNK_BYTES = 4096;
  const COPY_ALL_SAFE_CHARS = 2 * 1024 * 1024;

  const MIME_EXTENSIONS = {
    'application/javascript': 'js',
    'application/json': 'json',
    'application/pdf': 'pdf',
    'application/wasm': 'wasm',
    'application/xml': 'xml',
    'font/woff': 'woff',
    'font/woff2': 'woff2',
    'image/avif': 'avif',
    'image/gif': 'gif',
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/svg+xml': 'svg',
    'image/webp': 'webp',
    'text/css': 'css',
    'text/html': 'html',
    'text/javascript': 'js',
    'text/plain': 'txt',
    'text/xml': 'xml'
  };

  function normalizeMimeType(mimeType) {
    return String(mimeType || '').split(';')[0].trim().toLowerCase();
  }

  function isTextualMime(mimeType) {
    const mime = normalizeMimeType(mimeType);
    return mime.startsWith('text/') || [
      'application/graphql',
      'application/javascript',
      'application/json',
      'application/ld+json',
      'application/x-www-form-urlencoded',
      'application/xml',
      'image/svg+xml'
    ].includes(mime) || mime.endsWith('+json') || mime.endsWith('+xml');
  }

  function isBase64Body(row) {
    return row?.encoding === 'base64' || row?.bodyEncoding === 'base64' || row?.contentKind === 'binary_base64';
  }

  function isTextualBody(row) {
    return !isBase64Body(row) || isTextualMime(row?.bodyMimeType || row?.mimeType);
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

  function normalizeBase64(value) {
    const clean = String(value || '').replace(/\s+/g, '');
    if (!clean) return '';
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) throw new Error('Invalid base64 body content.');
    if (clean.length % 4 === 1) throw new Error('Invalid base64 body length.');
    if (clean.includes('=') && clean.length % 4 !== 0) throw new Error('Invalid base64 body padding.');
    if (/=/.test(clean.replace(/={0,2}$/, ''))) throw new Error('Invalid base64 body padding order.');
    return clean.length % 4 === 0 ? clean : clean.padEnd(clean.length + (4 - (clean.length % 4)), '=');
  }

  function decodeBase64ToBytes(value) {
    const padded = normalizeBase64(value);
    if (!padded) return new Uint8Array(0);
    if (typeof atob === 'function') {
      const binary = atob(padded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    }
    if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(padded, 'base64'));
    throw new Error('No base64 decoder is available.');
  }

  function textToBytes(value) {
    const text = String(value || '');
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(text);
    if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(text, 'utf8'));
    const bytes = new Uint8Array(text.length);
    for (let i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i) & 0xff;
    return bytes;
  }

  function bytesToText(bytes) {
    if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8').decode(bytes);
    if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('utf8');
    let output = '';
    for (let i = 0; i < bytes.length; i++) output += String.fromCharCode(bytes[i]);
    return output;
  }

  function getBodyStatus(row) {
    return row?.bodyStatus || row?.bodyCaptureStatus || row?.status || 'metadata_only';
  }

  function getBodyEncoding(row) {
    if (isBase64Body(row)) return 'base64';
    return row?.bodyEncoding || row?.encoding || 'utf8';
  }

  function getBodyReason(row) {
    const status = getBodyStatus(row);
    if (status === 'platform_unavailable') {
      return 'DevTools did not provide this body, or it was evicted before Back Tools could read it.';
    }
    if (status === 'policy_blocked') return 'Body capture disabled by policy.';
    if (status === 'read_failed') return row?.bodyCaptureReason || row?.reason || 'Back Tools could not read this body. See diagnostics for technical details.';
    if (status === 'metadata_only') return row?.bodyCaptureReason || row?.reason || 'Body metadata is available, but the body content is not in the current state.';
    return row?.bodyCaptureReason || row?.reason || null;
  }

  function getCapturedBytes(row, content) {
    if (Number.isFinite(Number(row?.bodySizeBytes))) return Number(row.bodySizeBytes);
    if (Number.isFinite(Number(row?.bodyCapturedBytes))) return Number(row.bodyCapturedBytes);
    if (Number.isFinite(Number(row?.capturedBytes))) return Number(row.capturedBytes);
    if (typeof content === 'string') return estimateContentBytes(content, isBase64Body(row) ? 'base64' : '');
    return Number.isFinite(Number(row?.bodySize)) ? Number(row.bodySize) : null;
  }

  function getTextBody(row) {
    if (getBodyStatus(row) !== 'body_captured') {
      return { ok: false, reason: getBodyReason(row) || 'Body is not captured.' };
    }
    if (typeof row?.content !== 'string') {
      return { ok: false, reason: 'Captured body content is missing from the current state.' };
    }
    if (!isTextualBody(row)) {
      return { ok: false, reason: 'Binary bodies can be downloaded, not copied as text.' };
    }
    try {
      const text = isBase64Body(row) ? bytesToText(decodeBase64ToBytes(row.content)) : row.content;
      return { ok: true, text };
    } catch (error) {
      return { ok: false, reason: String(error?.message || error || 'Body text decode failed.') };
    }
  }

  function getBodyBytes(row) {
    if (getBodyStatus(row) !== 'body_captured') {
      return { ok: false, reason: getBodyReason(row) || 'Body is not captured.' };
    }
    if (typeof row?.content !== 'string') {
      return { ok: false, reason: 'Captured body content is missing from the current state.' };
    }
    try {
      const bytes = isBase64Body(row) ? decodeBase64ToBytes(row.content) : textToBytes(row.content);
      return { ok: true, bytes };
    } catch (error) {
      return { ok: false, reason: String(error?.message || error || 'Body byte decode failed.') };
    }
  }

  function createBodyPreview(row, options = {}) {
    const status = getBodyStatus(row);
    const mimeType = row?.bodyMimeType || row?.mimeType || null;
    const encoding = getBodyEncoding(row);
    const content = typeof row?.content === 'string' ? row.content : '';
    const capturedBytes = getCapturedBytes(row, content);
    const captured = status === 'body_captured';
    const base = {
      bodyStatus: status,
      bodyRenderStatus: BodyRenderStatus.NOT_RENDERABLE,
      bodyExportStatus: captured ? BodyExportStatus.EXPORTABLE_BODY : BodyExportStatus.NOT_EXPORTABLE,
      mimeType,
      encoding,
      bodySizeBytes: capturedBytes,
      capturedBytes,
      renderedBytes: 0,
      renderedChars: 0,
      totalChars: null,
      preview: '',
      previewKind: 'none',
      exportable: captured,
      reason: captured ? null : getBodyReason(row),
      message: captured ? null : getBodyReason(row),
      isTextual: captured ? isTextualBody(row) : false,
      isBinary: captured ? !isTextualBody(row) : false,
      loadMoreAvailable: false,
      showFullAvailable: false,
      canCopyVisible: false,
      canCopyAll: false,
      copyAllSafe: false,
      canDownload: captured,
      downloadFilename: makeBodyDownloadFilename(row)
    };
    if (!captured) return base;
    if (typeof row?.content !== 'string') {
      return {
        ...base,
        bodyRenderStatus: BodyRenderStatus.RENDER_FAILED,
        bodyExportStatus: BodyExportStatus.EXPORT_BLOCKED,
        exportable: false,
        reason: 'Captured body content is missing from the current state.',
        message: 'Captured body content is missing from the current state.',
        canDownload: false
      };
    }
    try {
      if (!isTextualBody(row)) {
        const bytesResult = getBodyBytes(row);
        if (!bytesResult.ok) throw new Error(bytesResult.reason);
        const totalBytes = bytesResult.bytes.length;
        const renderLimit = clampLimit(options.renderLimit, DEFAULT_HEXDUMP_BYTES, totalBytes);
        const renderedBytes = Math.min(totalBytes, renderLimit);
        const preview = makeHexdump(bytesResult.bytes, 0, renderedBytes);
        return {
          ...base,
          bodyRenderStatus: BodyRenderStatus.BINARY_PREVIEW,
          previewKind: 'hexdump',
          preview,
          renderedBytes,
          renderedChars: preview.length,
          bodySizeBytes: capturedBytes ?? totalBytes,
          capturedBytes: capturedBytes ?? totalBytes,
          loadMoreAvailable: renderedBytes < totalBytes,
          nextRenderLimit: Math.min(totalBytes, renderedBytes + HEXDUMP_CHUNK_BYTES),
          canCopyVisible: preview.length > 0,
          message: `Body captured. Showing hexdump first ${renderedBytes} of ${totalBytes} bytes.`
        };
      }
      const textResult = getTextBody(row);
      if (!textResult.ok) throw new Error(textResult.reason);
      const fullText = textResult.text;
      const totalChars = fullText.length;
      const totalBytes = capturedBytes ?? estimateContentBytes(fullText, '');
      const renderLimit = clampLimit(options.renderLimit, DEFAULT_TEXT_RENDER_CHARS, totalChars);
      const renderedChars = Math.min(totalChars, renderLimit);
      const preview = fullText.slice(0, renderedChars);
      const renderedBytes = estimateContentBytes(preview, '');
      const partial = renderedChars < totalChars;
      return {
        ...base,
        bodyRenderStatus: partial ? BodyRenderStatus.PARTIAL_PREVIEW : BodyRenderStatus.RENDERED_FULL,
        previewKind: 'text',
        preview,
        renderedBytes,
        renderedChars,
        totalChars,
        bodySizeBytes: totalBytes,
        capturedBytes: totalBytes,
        loadMoreAvailable: partial,
        showFullAvailable: partial,
        nextRenderLimit: Math.min(totalChars, renderedChars + TEXT_RENDER_CHUNK_CHARS),
        canCopyVisible: preview.length > 0,
        canCopyAll: true,
        copyAllSafe: totalChars <= COPY_ALL_SAFE_CHARS,
        message: partial
          ? `Body captured. Showing first ${renderedChars} of ${totalChars} characters (${renderedBytes} of ${totalBytes} bytes).`
          : `Body captured. Showing full body (${renderedChars} characters, ${totalBytes} bytes).`
      };
    } catch (error) {
      return {
        ...base,
        bodyRenderStatus: BodyRenderStatus.RENDER_FAILED,
        reason: String(error?.message || error || 'Body preview failed.'),
        message: String(error?.message || error || 'Body preview failed.')
      };
    }
  }

  function clampLimit(value, fallback, total) {
    const numeric = Number(value);
    const start = Number.isFinite(numeric) && numeric > 0 ? numeric : fallback;
    if (!Number.isFinite(Number(total))) return Math.max(0, Math.floor(start));
    return Math.max(0, Math.min(Number(total), Math.floor(start)));
  }

  function makeHexdump(bytes, offset = 0, limit = bytes?.length || 0) {
    const source = bytes instanceof Uint8Array ? bytes : new Uint8Array(0);
    const start = Math.max(0, Number(offset) || 0);
    const end = Math.min(source.length, start + Math.max(0, Number(limit) || 0));
    const lines = [];
    for (let i = start; i < end; i += 16) {
      const chunk = source.slice(i, Math.min(end, i + 16));
      const hex = Array.from(chunk).map(byte => byte.toString(16).toUpperCase().padStart(2, '0')).join(' ');
      const ascii = Array.from(chunk).map(byte => (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.').join('');
      lines.push(`${i.toString(16).toUpperCase().padStart(8, '0')}  ${hex.padEnd(47, ' ')}  ${ascii}`);
    }
    return lines.join('\n');
  }

  function makeBodyDownloadFilename(row) {
    const method = safeFilenamePart(row?.method || 'body', 'body').toLowerCase();
    const status = safeFilenamePart(row?.statusCode ?? 'status', 'status');
    const hash = safeFilenamePart(row?.urlHash || stableHash(row?.url || row?.id || 'body'), 'body');
    const ext = inferBodyExtension(row?.bodyMimeType || row?.mimeType, row?.type);
    return `network-body-${method}-${status}-${hash}.${ext}`;
  }

  function inferBodyExtension(mimeType, type) {
    const mime = normalizeMimeType(mimeType);
    if (MIME_EXTENSIONS[mime]) return MIME_EXTENSIONS[mime];
    if (type === 'script') return 'js';
    if (type === 'stylesheet') return 'css';
    if (type === 'document') return 'html';
    if (type === 'json') return 'json';
    return isTextualMime(mime) ? 'txt' : 'bin';
  }

  function safeFilenamePart(value, fallback = 'item') {
    const cleaned = String(value || fallback)
      .replace(/[^a-zA-Z0-9._-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 80);
    return cleaned || fallback;
  }

  function stableHash(value) {
    let hash = 0x811c9dc5;
    const text = String(value ?? '');
    for (let i = 0; i < text.length; i++) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, '0');
  }

  function getBodyDownloadData(row) {
    if (getBodyStatus(row) !== 'body_captured') {
      return { ok: false, reason: getBodyReason(row) || 'Body is not captured.' };
    }
    if (typeof row?.content !== 'string') {
      return { ok: false, reason: 'Captured body content is missing from the current state.' };
    }
    const mimeType = row?.bodyMimeType || row?.mimeType || (isTextualBody(row) ? 'text/plain;charset=utf-8' : 'application/octet-stream');
    try {
      if (isBase64Body(row)) {
        return {
          ok: true,
          kind: 'bytes',
          data: decodeBase64ToBytes(row.content),
          mimeType,
          filename: makeBodyDownloadFilename(row)
        };
      }
      return {
        ok: true,
        kind: 'text',
        data: row.content,
        mimeType,
        filename: makeBodyDownloadFilename(row)
      };
    } catch (error) {
      return { ok: false, reason: String(error?.message || error || 'Body download preparation failed.') };
    }
  }

  return {
    BodyRenderStatus,
    BodyExportStatus,
    DEFAULT_TEXT_RENDER_CHARS,
    TEXT_RENDER_CHUNK_CHARS,
    DEFAULT_HEXDUMP_BYTES,
    HEXDUMP_CHUNK_BYTES,
    COPY_ALL_SAFE_CHARS,
    normalizeMimeType,
    isTextualMime,
    isTextualBody,
    isBase64Body,
    estimateContentBytes,
    estimateBase64Bytes,
    decodeBase64ToBytes,
    getTextBody,
    getBodyBytes,
    getBodyDownloadData,
    createBodyPreview,
    makeHexdump,
    makeBodyDownloadFilename
  };
});
