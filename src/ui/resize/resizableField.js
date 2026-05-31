(function(root, factory) {
  const api = factory(root);
  root.BackToolsUI = Object.assign(root.BackToolsUI || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  const DEFAULT_MIN_SIZE = 120;
  const DEFAULT_MAX_SIZE = 720;
  const DEFAULT_SIZE = 280;

  function numberOr(value, fallback) {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : fallback;
  }

  function clampResizableSize(value, options = {}) {
    const min = numberOr(options.minSize ?? options.minHeight ?? options.minWidth, DEFAULT_MIN_SIZE);
    const maxValue = options.maxSize ?? options.maxHeight ?? options.maxWidth;
    const max = Math.max(min, numberOr(maxValue, DEFAULT_MAX_SIZE));
    const fallback = numberOr(options.defaultSize ?? options.defaultHeight ?? options.defaultWidth, DEFAULT_SIZE);
    const numeric = numberOr(value, fallback);
    return Math.min(max, Math.max(min, Math.round(numeric)));
  }

  function selectedTextActive() {
    try {
      return !!root.getSelection?.()?.toString?.();
    } catch {
      return false;
    }
  }

  function readStoredSize(key, options) {
    if (!key) return null;
    try {
      const stored = root.localStorage?.getItem?.(key);
      if (!stored) return null;
      return clampResizableSize(Number(stored), options);
    } catch {
      return null;
    }
  }

  function writeStoredSize(key, size) {
    if (!key) return;
    try {
      root.localStorage?.setItem?.(key, String(size));
    } catch {}
  }

  function createResizableField(contentElement, options = {}) {
    const documentRef = root.document;
    if (!documentRef?.createElement || !contentElement) {
      return {
        element: contentElement,
        content: contentElement,
        handle: null,
        setSize: () => null,
        reset: () => null
      };
    }

    const axis = options.axis || 'vertical';
    const storageKey = options.persistedSizeKey || '';
    const sizeOptions = {
      minSize: options.minSize ?? options.minHeight,
      maxSize: options.maxSize ?? options.maxHeight,
      defaultSize: options.defaultSize ?? options.defaultHeight
    };
    const defaultSize = clampResizableSize(sizeOptions.defaultSize, sizeOptions);
    const wrapper = documentRef.createElement('div');
    const handle = documentRef.createElement('div');
    let currentSize = readStoredSize(storageKey, sizeOptions) || defaultSize;
    let startPointer = 0;
    let startSize = currentSize;

    wrapper.className = `resizable-field resizable-field-${axis}${options.className ? ` ${options.className}` : ''}`;
    handle.className = 'resizable-field-handle';
    handle.tabIndex = 0;
    handle.title = options.title || 'Drag to resize';
    handle.setAttribute('role', 'separator');
    handle.setAttribute('aria-label', options.label || 'Resize field');
    handle.setAttribute('aria-orientation', axis === 'horizontal' ? 'vertical' : 'horizontal');

    if (contentElement.classList?.add) contentElement.classList.add('resizable-field-content');
    wrapper.appendChild(contentElement);
    wrapper.appendChild(handle);

    function setSize(value, persist) {
      currentSize = clampResizableSize(value, sizeOptions);
      contentElement.style.height = `${currentSize}px`;
      contentElement.style.maxHeight = 'none';
      contentElement.style.minHeight = `${numberOr(sizeOptions.minSize, DEFAULT_MIN_SIZE)}px`;
      handle.setAttribute('aria-valuemin', String(numberOr(sizeOptions.minSize, DEFAULT_MIN_SIZE)));
      handle.setAttribute('aria-valuemax', String(numberOr(sizeOptions.maxSize, DEFAULT_MAX_SIZE)));
      handle.setAttribute('aria-valuenow', String(currentSize));
      if (persist) writeStoredSize(storageKey, currentSize);
      return currentSize;
    }

    function reset() {
      return setSize(defaultSize, true);
    }

    function expand() {
      return setSize(sizeOptions.maxSize ?? DEFAULT_MAX_SIZE, true);
    }

    function finishDrag() {
      documentRef.removeEventListener?.('pointermove', onPointerMove);
      documentRef.removeEventListener?.('pointerup', finishDrag);
      documentRef.removeEventListener?.('pointercancel', finishDrag);
      documentRef.body?.classList?.remove('resizable-field-resizing');
      writeStoredSize(storageKey, currentSize);
    }

    function onPointerMove(event) {
      event.preventDefault?.();
      setSize(startSize + (event.clientY - startPointer), false);
    }

    handle.addEventListener('pointerdown', event => {
      if (selectedTextActive()) return;
      event.preventDefault?.();
      startPointer = event.clientY;
      startSize = currentSize;
      documentRef.body?.classList?.add('resizable-field-resizing');
      documentRef.addEventListener?.('pointermove', onPointerMove);
      documentRef.addEventListener?.('pointerup', finishDrag, { once: true });
      documentRef.addEventListener?.('pointercancel', finishDrag, { once: true });
      handle.setPointerCapture?.(event.pointerId);
    });

    handle.addEventListener('keydown', event => {
      if (event.key === 'ArrowUp') {
        event.preventDefault?.();
        setSize(currentSize - (options.keyboardStep || 24), true);
      }
      if (event.key === 'ArrowDown') {
        event.preventDefault?.();
        setSize(currentSize + (options.keyboardStep || 24), true);
      }
      if (event.key === 'Home') {
        event.preventDefault?.();
        reset();
      }
      if (event.key === 'End') {
        event.preventDefault?.();
        expand();
      }
    });

    handle.addEventListener('dblclick', event => {
      event.preventDefault?.();
      reset();
    });

    setSize(currentSize, false);

    return {
      element: wrapper,
      content: contentElement,
      handle,
      setSize,
      reset
    };
  }

  return {
    clampResizableSize,
    createResizableField
  };
});
