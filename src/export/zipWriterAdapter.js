(function(root, factory) {
  const api = factory(root);
  root.BackToolsExport = Object.assign(root.BackToolsExport || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  const toString = Object.prototype.toString;

  /**
   * @typedef {'text'|'json'|'bytes'|'arrayBuffer'|'blob'|'base64'} ZipInputKind
   *
   * @typedef {Object} ZipInput
   * @property {ZipInputKind} kind
   * @property {string|unknown|Uint8Array|ArrayBuffer|Blob} data
   *
   * @typedef {Object} ZipEntryOptions
   * @property {string=} mimeType
   * @property {Date=} modifiedAt
   * @property {'store'|'deflate'=} compression
   */

  function textInput(data) {
    return { kind: 'text', data };
  }

  function jsonInput(data) {
    return { kind: 'json', data };
  }

  function bytesInput(data) {
    return { kind: 'bytes', data };
  }

  function arrayBufferInput(data) {
    return { kind: 'arrayBuffer', data };
  }

  function blobInput(data) {
    return { kind: 'blob', data };
  }

  function base64Input(data) {
    return { kind: 'base64', data };
  }

  function isUint8Array(value) {
    return value instanceof Uint8Array || toString.call(value) === '[object Uint8Array]';
  }

  function isArrayBuffer(value) {
    return value instanceof ArrayBuffer || toString.call(value) === '[object ArrayBuffer]';
  }

  function isBlobLike(value) {
    return value && typeof value.arrayBuffer === 'function' && typeof value.size === 'number';
  }

  function normalizeBase64(value) {
    if (typeof value !== 'string') {
      throw new Error('Invalid base64 input: expected a string');
    }
    const clean = value.replace(/\s+/g, '');
    if (!clean) return '';
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) {
      throw new Error('Invalid base64 input: contains non-base64 characters');
    }
    if (clean.length % 4 === 1) {
      throw new Error('Invalid base64 input: invalid length');
    }
    if (clean.includes('=') && clean.length % 4 !== 0) {
      throw new Error('Invalid base64 input: invalid padding');
    }
    if (/=/.test(clean.replace(/={0,2}$/, ''))) {
      throw new Error('Invalid base64 input: padding must be at the end');
    }
    return clean.length % 4 === 0 ? clean : clean.padEnd(clean.length + (4 - (clean.length % 4)), '=');
  }

  function decodeBase64ToBytes(value) {
    const padded = normalizeBase64(value);
    try {
      if (typeof atob === 'function') {
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
      }
      if (typeof Buffer !== 'undefined') {
        return new Uint8Array(Buffer.from(padded, 'base64'));
      }
    } catch (error) {
      throw new Error(`Invalid base64 input: ${error.message}`);
    }
    throw new Error('Invalid base64 input: no decoder available');
  }

  function mapCompression(compression) {
    if (compression == null) return undefined;
    if (compression === 'store') return 'STORE';
    if (compression === 'deflate') return 'DEFLATE';
    throw new Error(`Unsupported ZIP compression: ${compression}`);
  }

  function normalizeEntryOptions(options) {
    const out = { createFolders: false };
    if (options.modifiedAt) out.date = options.modifiedAt;
    const compression = mapCompression(options.compression);
    if (compression) out.compression = compression;
    return out;
  }

  async function normalizeInput(input) {
    if (!input || typeof input.kind !== 'string') {
      throw new Error('Invalid ZIP input: expected an input kind');
    }
    switch (input.kind) {
      case 'text':
        if (typeof input.data !== 'string') throw new Error('Invalid ZIP text input: expected a string');
        return { data: input.data, options: {} };
      case 'json':
        return { data: JSON.stringify(input.data, null, 2), options: {} };
      case 'bytes':
        if (!isUint8Array(input.data)) throw new Error('Invalid ZIP bytes input: expected Uint8Array');
        return { data: input.data, options: {} };
      case 'arrayBuffer':
        if (!isArrayBuffer(input.data)) throw new Error('Invalid ZIP arrayBuffer input: expected ArrayBuffer');
        return { data: input.data, options: {} };
      case 'blob':
        if (!isBlobLike(input.data)) throw new Error('Invalid ZIP blob input: expected Blob');
        return { data: input.data, options: {} };
      case 'base64':
        return { data: normalizeBase64(input.data), options: { base64: true } };
      default:
        throw new Error(`Unsupported ZIP input kind: ${input.kind}`);
    }
  }

  function legacyInput(data, options = {}) {
    if (options.base64) return base64Input(data);
    if (typeof data === 'string') return textInput(data);
    if (isUint8Array(data)) return bytesInput(data);
    if (isArrayBuffer(data)) return arrayBufferInput(data);
    if (isBlobLike(data)) return blobInput(data);
    throw new Error('Unsupported legacy ZIP input: use jsonInput for objects or bytesInput for binary data');
  }

  function legacyOptions(options = {}) {
    return {
      createFolders: false,
      modifiedAt: options.date,
      compression: options.compression === 'STORE' ? 'store'
        : options.compression === 'DEFLATE' ? 'deflate'
          : options.compression
    };
  }

  class ZipWriterAdapter {
    constructor(options = {}) {
      const JSZipCtor = options.JSZip || options.ZipCtor || root.JSZip;
      if (typeof JSZipCtor !== 'function') throw new Error('JSZip is required to create a ZIP writer');
      this.zip = new JSZipCtor();
    }

    /**
     * @param {string} path
     * @param {ZipInput} input
     * @param {ZipEntryOptions=} options
     * @returns {Promise<void>}
     */
    async add(path, input, options = {}) {
      if (typeof path !== 'string' || !path) throw new Error('Invalid ZIP path: expected a non-empty string');
      const normalized = await normalizeInput(input);
      this.zip.file(path, normalized.data, {
        ...normalizeEntryOptions(options),
        ...(normalized.options || {})
      });
    }

    /**
     * @returns {Promise<Blob>}
     */
    async generateBlob() {
      if (typeof Blob === 'undefined') throw new Error('Blob is required to generate a ZIP blob');
      return this.zip.generateAsync({ type: 'blob' });
    }

    get raw() {
      return this.zip;
    }
  }

  function createZipWriter(ZipCtor) {
    const adapter = new ZipWriterAdapter({ JSZip: ZipCtor });
    const pending = [];
    const writer = {
      add(path, input, options) {
        return adapter.add(path, input, options);
      },
      generateBlob() {
        return adapter.generateBlob();
      },
      file(path, data, options = {}) {
        pending.push(adapter.add(path, legacyInput(data, options), legacyOptions(options)));
        return writer;
      },
      async generateAsync(options = {}) {
        await Promise.all(pending);
        if (options.type && options.type !== 'blob') return adapter.raw.generateAsync(options);
        return adapter.generateBlob();
      },
      raw: adapter.raw,
      adapter
    };
    return writer;
  }

  function createCurrentZipWriter() {
    return createZipWriter(root.JSZip);
  }

  return {
    ZipWriterAdapter,
    textInput,
    jsonInput,
    bytesInput,
    arrayBufferInput,
    blobInput,
    base64Input,
    decodeBase64ToBytes,
    createZipWriter,
    createCurrentZipWriter
  };
});
