(function(root, factory) {
  const api = factory(root);
  root.BackToolsUI = Object.assign(root.BackToolsUI || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  const DRAWER_STORAGE_KEY = 'backtools.itemDetails.drawerWidth';
  const DEFAULT_DRAWER_WIDTH = 760;
  const MIN_DRAWER_WIDTH = 420;
  const MAX_DRAWER_VIEWPORT_RATIO = 0.94;
  let resizeApi = root.BackToolsUI || {};
  if (typeof require === 'function') {
    try {
      resizeApi = Object.assign({}, require('../resize/resizableField.js'), resizeApi);
    } catch {}
  }

  function setSafeText(element, value) {
    if (!element) return element;
    element.textContent = value === undefined || value === null ? '' : String(value);
    return element;
  }

  function createElement(tagName, className, text) {
    const element = root.document.createElement(tagName);
    if (className) element.className = className;
    if (text !== undefined) setSafeText(element, text);
    return element;
  }

  function appendButton(parent, label, className, onClick, options = {}) {
    const button = createElement('button', className || '', label);
    button.type = 'button';
    if (options.disabled) button.disabled = true;
    if (options.title) button.title = String(options.title);
    if (typeof onClick === 'function') button.addEventListener('click', onClick);
    parent.appendChild(button);
    return button;
  }

  function safeResizeKeyPart(value, fallback = 'field') {
    const cleaned = String(value || fallback)
      .replace(/[^a-zA-Z0-9._-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 80);
    return cleaned || fallback;
  }

  function resizeStorageKey(detail, tab, suffix = 'content') {
    return `backtools.itemDetails.fieldHeight.${safeResizeKeyPart(detail?.kind)}.${safeResizeKeyPart(tab?.id)}.${safeResizeKeyPart(suffix)}`;
  }

  function defaultMaxFieldHeight() {
    const viewport = Number(root.innerHeight) || 760;
    return Math.max(280, Math.floor(viewport * 0.72));
  }

  function appendResizablePre(parent, pre, options = {}) {
    const createResizableField = resizeApi.createResizableField || root.BackToolsUI?.createResizableField;
    if (typeof createResizableField !== 'function') {
      parent.appendChild(pre);
      return pre;
    }
    const field = createResizableField(pre, {
      axis: 'vertical',
      minHeight: options.minHeight ?? 140,
      maxHeight: options.maxHeight ?? defaultMaxFieldHeight(),
      defaultHeight: options.defaultHeight ?? 280,
      persistedSizeKey: options.persistedSizeKey || '',
      label: options.label || 'Resize field',
      title: options.title || 'Drag to resize'
    });
    parent.appendChild(field.element || pre);
    return pre;
  }

  function ensureRoot() {
    let rootElement = root.document.getElementById('itemDetailsRoot');
    if (!rootElement) {
      rootElement = root.document.createElement('div');
      rootElement.id = 'itemDetailsRoot';
      root.document.body.appendChild(rootElement);
    }
    return rootElement;
  }

  function closeItemDetailsView() {
    const rootElement = root.document?.getElementById?.('itemDetailsRoot');
    if (rootElement) rootElement.textContent = '';
    root.document?.body?.classList?.remove('item-details-resizing');
    root.document?.body?.classList?.remove('item-details-open');
  }

  function clampDrawerWidth(width, viewportWidth) {
    const viewport = Number(viewportWidth) || DEFAULT_DRAWER_WIDTH;
    const max = Math.max(MIN_DRAWER_WIDTH, Math.floor(viewport * MAX_DRAWER_VIEWPORT_RATIO));
    const min = Math.min(MIN_DRAWER_WIDTH, max);
    const numeric = Number(width);
    const fallback = Number.isFinite(numeric) ? numeric : DEFAULT_DRAWER_WIDTH;
    return Math.min(max, Math.max(min, Math.round(fallback)));
  }

  function readStoredDrawerWidth() {
    try {
      const stored = root.localStorage?.getItem?.(DRAWER_STORAGE_KEY);
      return clampDrawerWidth(stored ? Number(stored) : DEFAULT_DRAWER_WIDTH, root.innerWidth);
    } catch {
      return clampDrawerWidth(DEFAULT_DRAWER_WIDTH, root.innerWidth);
    }
  }

  function writeStoredDrawerWidth(width) {
    try {
      root.localStorage?.setItem?.(DRAWER_STORAGE_KEY, String(width));
    } catch {}
  }

  function applyDrawerWidth(drawer, width) {
    const next = clampDrawerWidth(width, root.innerWidth);
    drawer.style.width = `${next}px`;
    drawer.style.setProperty('--item-details-current-width', `${next}px`);
    return next;
  }

  function createResizeHandle(drawer) {
    const handle = createElement('button', 'item-details-resize-handle');
    handle.type = 'button';
    handle.setAttribute('aria-label', 'Resize details panel');
    handle.title = 'Drag to resize details panel';

    let startX = 0;
    let startWidth = 0;

    function finishDrag() {
      root.document.removeEventListener('pointermove', onPointerMove);
      root.document.removeEventListener('pointerup', finishDrag);
      root.document.body?.classList?.remove('item-details-resizing');
      writeStoredDrawerWidth(drawer.getBoundingClientRect().width);
    }

    function onPointerMove(event) {
      const next = startWidth + (startX - event.clientX);
      applyDrawerWidth(drawer, next);
    }

    handle.addEventListener('pointerdown', event => {
      event.preventDefault();
      startX = event.clientX;
      startWidth = drawer.getBoundingClientRect().width;
      root.document.body?.classList?.add('item-details-resizing');
      root.document.addEventListener('pointermove', onPointerMove);
      root.document.addEventListener('pointerup', finishDrag, { once: true });
      handle.setPointerCapture?.(event.pointerId);
    });

    handle.addEventListener('keydown', event => {
      const current = drawer.getBoundingClientRect().width;
      if (event.key === 'ArrowLeft') {
        event.preventDefault();
        writeStoredDrawerWidth(applyDrawerWidth(drawer, current + 32));
      }
      if (event.key === 'ArrowRight') {
        event.preventDefault();
        writeStoredDrawerWidth(applyDrawerWidth(drawer, current - 32));
      }
      if (event.key === 'Home') {
        event.preventDefault();
        writeStoredDrawerWidth(applyDrawerWidth(drawer, DEFAULT_DRAWER_WIDTH));
      }
      if (event.key === 'End') {
        event.preventDefault();
        writeStoredDrawerWidth(applyDrawerWidth(drawer, root.innerWidth * MAX_DRAWER_VIEWPORT_RATIO));
      }
    });

    handle.addEventListener('dblclick', () => {
      writeStoredDrawerWidth(applyDrawerWidth(drawer, DEFAULT_DRAWER_WIDTH));
    });

    return handle;
  }

  function renderItemDetailsView(detail, handlers = {}) {
    const rootElement = ensureRoot();
    rootElement.textContent = '';
    root.document?.body?.classList?.add('item-details-open');

    const overlay = createElement('div', 'item-details-overlay');
    const backdrop = createElement('button', 'item-details-backdrop');
    backdrop.type = 'button';
    backdrop.setAttribute('aria-label', 'Close details');
    backdrop.addEventListener('click', () => {
      if (typeof handlers.onClose === 'function') handlers.onClose(detail);
    });

    const drawer = createElement('aside', 'item-details-drawer');
    drawer.setAttribute('role', 'dialog');
    drawer.setAttribute('aria-modal', 'true');
    drawer.setAttribute('aria-labelledby', 'itemDetailsTitle');
    applyDrawerWidth(drawer, readStoredDrawerWidth());
    drawer.appendChild(createResizeHandle(drawer));

    const header = createElement('header', 'item-details-header');
    const titleWrap = createElement('div', 'item-details-title-wrap');
    const kicker = createElement('div', 'item-details-kicker', detail.headerKicker || String(detail.kind || 'item').replace(/_/g, ' '));
    const title = createElement('h2', '', detail.displayTitle || detail.title || 'Item details');
    title.id = 'itemDetailsTitle';
    title.title = String(detail.titleFull || detail.displayTitle || detail.title || '');
    const subtitleValue = detail.headerSubtitle ?? detail.subtitle ?? '';
    const subtitle = createElement('div', 'item-details-subtitle', subtitleValue);
    if (subtitleValue) subtitle.title = String(subtitleValue);
    titleWrap.appendChild(kicker);
    titleWrap.appendChild(title);
    if (subtitleValue && subtitleValue !== detail.displayTitle) titleWrap.appendChild(subtitle);
    if (Array.isArray(detail.headerBadges) && detail.headerBadges.length) {
      const badges = createElement('div', 'item-details-badges');
      detail.headerBadges.forEach(badge => badges.appendChild(createStatusBadge(badge.label, badge.tone)));
      titleWrap.appendChild(badges);
    }

    const headerActions = createElement('div', 'item-details-actions');
    if (getDetailUrlCopyValue(detail)) appendButton(headerActions, 'Copy URL', 'item-details-secondary-action', () => copyDetailUrl(detail, handlers), {
      title: 'Item action: copy primary URL or path'
    });
    appendButton(headerActions, 'Copy JSON', 'item-details-secondary-action', () => handlers.onCopy?.(detail));
    appendButton(headerActions, 'Export JSON', '', () => handlers.onExport?.(detail), {
      disabled: detail.exportDisabled === true,
      title: detail.exportDisabledReason || ''
    });
    appendButton(headerActions, 'Close', 'item-details-close item-details-secondary-action', () => handlers.onClose?.(detail));
    header.appendChild(titleWrap);
    header.appendChild(headerActions);

    const panel = createElement('section', 'item-details-panel');
    renderDetailPanel(panel, detail);

    drawer.appendChild(header);
    drawer.appendChild(panel);

    overlay.appendChild(backdrop);
    overlay.appendChild(drawer);
    rootElement.appendChild(overlay);
    drawer.focus?.();
  }

  function createPill(label, value) {
    const pill = createElement('span', 'pill item-details-pill');
    const strong = createElement('b', '', `${label}: `);
    const body = createElement('span', '', value);
    pill.appendChild(strong);
    pill.appendChild(body);
    return pill;
  }

  async function copyDetailUrl(detail, handlers) {
    const value = getDetailUrlCopyValue(detail);
    if (typeof handlers.onCopyUrl === 'function') {
      try {
        const handled = await handlers.onCopyUrl(detail, value);
        if (handled !== false) return handled;
      } catch {}
    }
    return copyText(value);
  }

  function getDetailUrlCopyValue(detail) {
    return String(detail?.primaryUrl || detail?.rawJson?.urlRedacted || detail?.subtitle || '');
  }

  function createStatusBadge(label, tone = 'info') {
    const badge = createElement('span', `item-details-badge item-details-badge-${tone || 'info'}`, label);
    return badge;
  }

  function renderDetailPanel(parent, detail) {
    appendNoticeStack(parent, detail.notices || []);
    appendSummaryCard(parent, detail);
    appendInterpretationCard(parent, detail.interpretation);
    appendExportStateCard(parent, detail.exportState || []);
    appendDetailSections(parent, detail);
    appendRawDisclosure(parent, detail);
  }

  function appendNoticeStack(parent, notices) {
    const filtered = (notices || []).filter(item => item && (item.title || item.message));
    if (!filtered.length) return;
    const stack = createElement('section', 'item-details-notice-stack');
    filtered.forEach(item => stack.appendChild(createNotice(item)));
    parent.appendChild(stack);
  }

  function createNotice(item) {
    const level = item.level || 'info';
    const box = createElement('div', `item-details-notice item-details-notice-${level}`);
    if (item.title) box.appendChild(createElement('strong', '', item.title));
    if (item.message) box.appendChild(createElement('span', '', item.message));
    return box;
  }

  function setNoticeLevel(element, level) {
    if (element) element.className = `item-details-notice item-details-notice-${level || 'info'}`;
  }

  function appendSummaryCard(parent, detail) {
    const fields = Array.isArray(detail.summaryFields) && detail.summaryFields.length
      ? detail.summaryFields
      : getFallbackSummaryFields(detail);
    if (!fields.length) return;
    const card = createCard('Summary');
    appendFieldGrid(card, fields, { compact: true });
    parent.appendChild(card);
  }

  function appendInterpretationCard(parent, interpretation) {
    if (!interpretation?.body) return;
    const card = createCard(interpretation.title || 'What this means', 'item-details-interpretation');
    card.appendChild(createElement('p', '', interpretation.body));
    parent.appendChild(card);
  }

  function appendExportStateCard(parent, fields) {
    if (!fields.length) return;
    const card = createCard('Export state');
    const grid = createElement('div', 'item-details-export-grid');
    fields.forEach(field => {
      const item = createElement('div', `item-details-export-item item-details-export-${field.tone || 'info'}`);
      item.appendChild(createElement('span', '', field.label || 'Export'));
      item.appendChild(createElement('b', '', field.value || '-'));
      grid.appendChild(item);
    });
    card.appendChild(grid);
    parent.appendChild(card);
  }

  function appendDetailSections(parent, detail) {
    const sections = Array.isArray(detail.sections) && detail.sections.length ? detail.sections : [];
    sections.forEach(section => {
      const card = createCard(section.title || section.label || section.id || 'Details');
      renderTabContent(card, section, detail);
      parent.appendChild(card);
    });
  }

  function appendRawDisclosure(parent, detail) {
    const disclosure = createElement('details', 'item-details-disclosure');
    const summary = createElement('summary', '', detail.developerDetailsLabel || 'Developer details (sanitized JSON)');
    const pre = createElement('pre', 'item-details-pre');
    setSafeText(pre, JSON.stringify(getRenderableRawJson(detail), null, 2));
    disclosure.appendChild(summary);
    disclosure.appendChild(pre);
    parent.appendChild(disclosure);
  }

  function createCard(title, className = '') {
    const card = createElement('section', `item-details-card${className ? ` ${className}` : ''}`);
    if (title) card.appendChild(createElement('h3', '', title));
    return card;
  }

  function getFallbackSummaryFields(detail) {
    const summary = (detail.tabs || []).find(tab => tab.id === 'summary');
    return summary?.fields || [];
  }

  function renderTabContent(parent, tab, detail) {
    if (tab.notice) {
      parent.appendChild(createElement('p', 'item-details-notice item-details-notice-info', tab.notice));
    }
    if (tab.type === 'fields') {
      appendFields(parent, tab.fields || [], {
        scope: `${safeResizeKeyPart(detail.kind)}.${safeResizeKeyPart(tab.id)}`
      });
      return;
    }
    if (tab.type === 'bodyPreview') {
      renderBodyPreviewTab(parent, tab, detail);
      return;
    }
    if (tab.type === 'cookieValue') {
      renderCookieValueTab(parent, tab, detail);
      return;
    }
    if (tab.type === 'storageValue') {
      renderStorageValueTab(parent, tab, detail);
      return;
    }
    if (tab.type === 'cookieExport') {
      renderCookieExportTab(parent, tab, detail);
      return;
    }
    if (tab.type === 'text') {
      const pre = createElement('pre', 'item-details-pre');
      setSafeText(pre, tab.text || '');
      appendResizablePre(parent, pre, {
        defaultHeight: 300,
        persistedSizeKey: resizeStorageKey(detail, tab, 'text'),
        label: `Resize ${tab.label || 'text'} preview`
      });
      return;
    }
    if (tab.type === 'emptyState') {
      parent.appendChild(createElement('p', 'item-details-empty-state', tab.message || 'Content preview is not available for this item.'));
      return;
    }
    if (tab.type === 'jsonBlocks') {
      (tab.blocks || []).forEach(block => {
        const section = createElement('section', 'item-details-block');
        section.appendChild(createElement('h3', '', block.title || 'JSON'));
        const pre = createElement('pre', 'item-details-pre');
        setSafeText(pre, JSON.stringify(block.value, null, 2));
        appendResizablePre(section, pre, {
          defaultHeight: 260,
          persistedSizeKey: resizeStorageKey(detail, tab, block.title || 'json'),
          label: `Resize ${block.title || tab.label || 'JSON'}`
        });
        parent.appendChild(section);
      });
      return;
    }
    const pre = createElement('pre', 'item-details-pre');
    setSafeText(pre, JSON.stringify(getRenderableRawJson(detail), null, 2));
    appendResizablePre(parent, pre, {
      defaultHeight: 340,
      persistedSizeKey: resizeStorageKey(detail, tab, 'raw-json'),
      label: `Resize ${tab.label || 'Raw JSON'}`
    });
  }

  function getRenderableRawJson(detail) {
    const raw = detail.rawJson || {};
    if (detail.kind !== 'cookie' || !detail.__rawCookieRevealed || !detail.rawPayload?.rawAvailable) return raw;
    return {
      ...raw,
      value: {
        ...(raw.value || {}),
        rawAvailable: true,
        rawIncluded: true,
        rawValue: detail.rawPayload.rawValue
      }
    };
  }

  function renderCookieValueTab(parent, tab, detail) {
    appendFields(parent, tab.fields || [], {
      scope: `${safeResizeKeyPart(detail.kind)}.${safeResizeKeyPart(tab.id)}`
    });
    const notice = createElement('p', 'item-details-notice item-details-notice-info');
    parent.appendChild(notice);
    const actions = createElement('div', 'item-details-actions');
    parent.appendChild(actions);
    const rawHost = createElement('div', 'item-details-block');
    parent.appendChild(rawHost);
    let confirmVisible = false;

    function update() {
      actions.textContent = '';
      rawHost.textContent = '';
      if (!detail.rawPayload?.rawAvailable) {
        setNoticeLevel(notice, 'info');
        setSafeText(notice, 'Raw value is not available from the current collector.');
        return;
      }
      if (detail.__dumpObjectsEnabled) {
        setNoticeLevel(notice, 'critical');
        setSafeText(notice, 'Raw value is visible because Dump objects is enabled for this DevTools session.');
        const pre = createElement('pre', 'item-details-pre');
        setSafeText(pre, detail.rawPayload.rawValue);
        appendResizablePre(rawHost, pre, {
          minHeight: 120,
          defaultHeight: 180,
          persistedSizeKey: '',
          label: 'Resize raw cookie value'
        });
        return;
      }
      if (detail.__rawCookieRevealed) {
        setNoticeLevel(notice, 'critical');
        setSafeText(notice, 'Raw value is visible only in this detail drawer.');
        appendButton(actions, 'Hide raw', '', () => {
          detail.__rawCookieRevealed = false;
          confirmVisible = false;
          update();
        });
        const pre = createElement('pre', 'item-details-pre');
        setSafeText(pre, detail.rawPayload.rawValue);
        appendResizablePre(rawHost, pre, {
          minHeight: 120,
          defaultHeight: 180,
          persistedSizeKey: '',
          label: 'Resize raw cookie value'
        });
        return;
      }
      setNoticeLevel(notice, 'critical');
      setSafeText(notice, 'This may expose usable authentication material.');
      appendButton(actions, 'Reveal raw value', '', () => {
        confirmVisible = true;
        update();
      });
      if (confirmVisible) appendSensitiveConfirmation(rawHost, {
        phrase: 'REVEAL',
        checkboxLabel: 'I understand this value may grant access to an account or session.',
        confirmLabel: 'Reveal',
        onConfirm: () => {
          detail.__rawCookieRevealed = true;
          confirmVisible = false;
          update();
        }
      });
    }

    update();
  }

  function renderStorageValueTab(parent, tab, detail) {
    appendFields(parent, tab.fields || [], {
      scope: `${safeResizeKeyPart(detail.kind)}.${safeResizeKeyPart(tab.id)}`
    });
    const notice = createElement('p', 'item-details-notice item-details-notice-info');
    parent.appendChild(notice);
    const actions = createElement('div', 'item-details-actions');
    parent.appendChild(actions);
    const rawHost = createElement('div', 'item-details-block');
    parent.appendChild(rawHost);
    let confirmVisible = false;

    function update() {
      actions.textContent = '';
      rawHost.textContent = '';
      if (!detail.rawPayload?.rawAvailable) {
        setNoticeLevel(notice, 'info');
        setSafeText(notice, 'Raw value is not available from the current collector.');
        return;
      }
      if (detail.__dumpObjectsEnabled) {
        setNoticeLevel(notice, 'critical');
        setSafeText(notice, 'Raw value is visible because Dump objects is enabled for this DevTools session.');
        const pre = createElement('pre', 'item-details-pre');
        setSafeText(pre, detail.rawPayload.rawValue);
        appendResizablePre(rawHost, pre, {
          minHeight: 120,
          defaultHeight: 180,
          persistedSizeKey: '',
          label: 'Resize raw storage value'
        });
        return;
      }
      if (detail.__rawStorageRevealed) {
        setNoticeLevel(notice, 'critical');
        setSafeText(notice, 'Raw value is visible only in this detail drawer.');
        appendButton(actions, 'Hide raw', '', () => {
          detail.__rawStorageRevealed = false;
          confirmVisible = false;
          update();
        });
        const pre = createElement('pre', 'item-details-pre');
        setSafeText(pre, detail.rawPayload.rawValue);
        appendResizablePre(rawHost, pre, {
          minHeight: 120,
          defaultHeight: 180,
          persistedSizeKey: '',
          label: 'Resize raw storage value'
        });
        return;
      }
      setNoticeLevel(notice, 'critical');
      setSafeText(notice, 'This may expose browser-side session data, tokens, or credentials.');
      appendButton(actions, 'Reveal raw value', '', () => {
        confirmVisible = true;
        update();
      });
      if (confirmVisible) appendSensitiveConfirmation(rawHost, {
        phrase: 'REVEAL APPLICATION VALUE',
        checkboxLabel: 'I understand this value may expose private application data.',
        confirmLabel: 'Reveal',
        onConfirm: () => {
          detail.__rawStorageRevealed = true;
          confirmVisible = false;
          update();
        }
      });
    }

    update();
  }

  function renderCookieExportTab(parent, tab, detail) {
    appendFields(parent, tab.fields || [], {
      scope: `${safeResizeKeyPart(detail.kind)}.${safeResizeKeyPart(tab.id)}`
    });
    const notice = createElement('p', 'item-details-notice item-details-notice-warning', tab.notice || '');
    const actions = createElement('div', 'item-details-actions');
    const confirmHost = createElement('div', 'item-details-block');
    parent.appendChild(notice);
    parent.appendChild(actions);
    parent.appendChild(confirmHost);
    appendButton(actions, 'Export sanitized cookie JSON', '', () => {
      downloadJson(detail.exportJson || detail.rawJson || {}, detail.exportFilename || 'cookie.sanitized.json');
      setSafeText(notice, 'Sanitized cookie JSON export started.');
    });
    appendButton(actions, 'Export raw cookie JSON', '', () => showRawExportConfirm('json'), {
      disabled: !detail.rawPayload?.rawAvailable,
      title: detail.rawPayload?.rawAvailable ? '' : 'Raw value is not available from the current collector.'
    });
    appendButton(actions, 'Export raw Netscape cookie jar', '', () => showRawExportConfirm('netscape'), {
      disabled: !detail.rawPayload?.rawAvailable,
      title: detail.rawPayload?.rawAvailable ? '' : 'Raw value is not available from the current collector.'
    });

    function showRawExportConfirm(kind) {
      confirmHost.textContent = '';
      const domainText = detail.rawPayload?.domain || 'unknown';
      confirmHost.appendChild(createElement('p', 'item-details-notice item-details-notice-critical', `Raw export includes 1 cookie for ${domainText}. This may expose replayable authentication material.`));
      appendSensitiveConfirmation(confirmHost, {
        phrase: 'EXPORT RAW COOKIES',
        checkboxLabel: 'I understand this export may grant access to an account or session.',
        confirmLabel: kind === 'json' ? 'Export raw JSON' : 'Export raw Netscape',
        onConfirm: () => {
          const rawCookie = buildSingleRawCookiePayload(detail);
          if (kind === 'json') {
            downloadJson(rawCookie, `cookie-${safeDownloadPart(detail.rawPayload?.name || 'cookie')}.raw.json`);
          } else {
            downloadText(buildSingleRawNetscape(rawCookie), `cookie-${safeDownloadPart(detail.rawPayload?.name || 'cookie')}.raw.netscape.txt`, 'text/plain');
          }
          confirmHost.textContent = '';
          setSafeText(notice, kind === 'json' ? 'Raw cookie JSON export started.' : 'Raw Netscape cookie export started.');
        }
      });
    }
  }

  function appendSensitiveConfirmation(parent, options) {
    const box = createElement('div', 'sensitive-confirmation');
    const label = createElement('label', 'sensitive-confirmation-check');
    const checkbox = root.document.createElement('input');
    checkbox.type = 'checkbox';
    const labelText = createElement('span', '', options.checkboxLabel || 'I understand the risk.');
    label.appendChild(checkbox);
    label.appendChild(labelText);
    const phrase = createElement('div', 'modal-phrase');
    phrase.appendChild(createElement('label', '', 'Type exactly:'));
    phrase.appendChild(createElement('code', '', options.phrase || 'CONFIRM'));
    const input = root.document.createElement('input');
    input.type = 'text';
    input.autocomplete = 'off';
    const actions = createElement('div', 'item-details-actions');
    const confirm = appendButton(actions, options.confirmLabel || 'Confirm', '', () => {
      if (!isSensitiveConfirmationReady(input.value, checkbox.checked, options.phrase)) return;
      options.onConfirm?.();
    }, { disabled: true });
    const update = () => {
      confirm.disabled = !isSensitiveConfirmationReady(input.value, checkbox.checked, options.phrase);
    };
    checkbox.addEventListener('input', update);
    input.addEventListener('input', update);
    box.appendChild(label);
    box.appendChild(phrase);
    box.appendChild(input);
    box.appendChild(actions);
    parent.appendChild(box);
    input.focus?.();
  }

  function isSensitiveConfirmationReady(inputValue, checked, phrase) {
    return checked === true && String(inputValue || '') === String(phrase || '');
  }

  function buildSingleRawCookiePayload(detail) {
    const raw = getRenderableRawJson({
      ...detail,
      __rawCookieRevealed: true
    });
    return {
      schemaVersion: 'backtools.cookie.raw.v1',
      containsRawCookies: true,
      containsReplayableCookieJar: true,
      rawCookieExportConfirmedAt: new Date().toISOString(),
      rawCookieExportScope: {
        rawCookieCount: 1,
        domains: [detail.rawPayload?.domain || 'unknown']
      },
      cookie: raw
    };
  }

  function buildSingleRawNetscape(payload) {
    const cookie = payload.cookie || {};
    const value = cookie.value?.rawValue || '';
    const domainValue = cookie.domain || 'unknown';
    const includeSubdomains = domainValue.startsWith('.') || cookie.hostOnly === false ? 'TRUE' : 'FALSE';
    const path = cookie.path || '/';
    const secure = cookie.secure === true ? 'TRUE' : 'FALSE';
    const expires = cookie.expirationDate ? Math.floor(Number(cookie.expirationDate)) : 0;
    return [
      '# Back Tools raw Netscape cookie file',
      '# This file may contain replayable authentication material.',
      [domainValue, includeSubdomains, path, secure, expires, cookie.name || '', value].join('\t'),
      ''
    ].join('\n');
  }

  function downloadJson(value, filename) {
    downloadText(JSON.stringify(value, null, 2), filename, 'application/json');
  }

  function downloadText(value, filename, mimeType) {
    if (typeof Blob === 'undefined' || !root.URL?.createObjectURL) return;
    const blob = new Blob([String(value || '')], { type: mimeType || 'text/plain' });
    const url = root.URL.createObjectURL(blob);
    const link = root.document.createElement('a');
    link.href = url;
    link.download = filename || 'download.txt';
    link.click();
    setTimeout(() => root.URL.revokeObjectURL(url), 5000);
  }

  function safeDownloadPart(value) {
    return String(value || 'item')
      .replace(/[^a-zA-Z0-9._-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 80) || 'item';
  }

  function renderBodyPreviewTab(parent, tab, detail) {
    const initialBody = tab.body || {};
    const payload = detail.bodyPayload || {};
    let renderLimit = initialBody.previewKind === 'hexdump'
      ? initialBody.renderedBytes
      : initialBody.renderedChars;

    const metaHost = createElement('div', 'item-details-body-meta');
    const notice = createElement('p', 'item-details-notice item-details-notice-info');
    const actions = createElement('div', 'item-details-actions item-details-body-actions');
    const previewHost = createElement('div', 'item-details-body-preview-host');

    const loadMoreButton = appendButton(actions, 'Load more', '', () => {
      const body = getCurrentBodyPreview(payload, initialBody, renderLimit);
      renderLimit = body.nextRenderLimit || renderLimit;
      update();
    });
    const showFullButton = appendButton(actions, 'Show full body', '', () => {
      const body = getCurrentBodyPreview(payload, initialBody, renderLimit);
      if (!body.showFullAvailable) return;
      const shouldContinue = !root.confirm || root.confirm('Rendering the full body may slow this DevTools panel. Continue?');
      if (!shouldContinue) return;
      renderLimit = body.totalChars || body.capturedBytes || renderLimit;
      update();
    });
    const copyVisibleButton = appendButton(actions, 'Copy visible', '', async () => {
      const body = getCurrentBodyPreview(payload, initialBody, renderLimit);
      const result = await copyText(body.preview || '');
      setSafeText(notice, result.ok ? 'Visible body preview copied.' : result.reason);
    });
    const copyAllButton = appendButton(actions, 'Copy all', '', async () => {
      const body = getCurrentBodyPreview(payload, initialBody, renderLimit);
      if (!body.canCopyAll) return;
      const shouldContinue = body.copyAllSafe || !root.confirm || root.confirm('Copying the full body may be slow for very large content. Continue?');
      if (!shouldContinue) return;
      const textResult = root.BackToolsDomain?.getTextBody ? root.BackToolsDomain.getTextBody(payload) : { ok: false, reason: 'Body text helper is not available.' };
      if (!textResult.ok) {
        setSafeText(notice, textResult.reason);
        return;
      }
      const result = await copyText(textResult.text);
      setSafeText(notice, result.ok ? 'Full body copied.' : result.reason);
    });
    const downloadButton = appendButton(actions, 'Download body', '', () => {
      const result = downloadBody(payload);
      setSafeText(notice, result.ok ? 'Body download started.' : result.reason);
    });

    parent.appendChild(metaHost);
    parent.appendChild(notice);
    parent.appendChild(actions);
    parent.appendChild(previewHost);
    update();

    function update() {
      const body = getCurrentBodyPreview(payload, initialBody, renderLimit);
      metaHost.textContent = '';
      previewHost.textContent = '';
      appendFields(metaHost, [
        { label: 'Body status', value: body.bodyStatus || body.state || '-' },
        { label: 'MIME', value: body.mimeType || '-' },
        { label: 'Encoding', value: body.encoding || '-' },
        { label: 'Captured bytes', value: formatBodyValue(body.capturedBytes ?? body.bodySizeBytes) },
        { label: 'Rendered bytes/chars', value: `${formatBodyValue(body.renderedBytes)} bytes / ${formatBodyValue(body.renderedChars)} chars` },
        { label: 'Exportable', value: body.exportable ? 'yes' : 'no' },
        { label: 'Reason', value: body.reason || '-' }
      ]);
      if (body.preview) {
        setSafeText(notice, body.message || body.reason || '');
        notice.className = body.exportable ? 'item-details-notice item-details-notice-success' : 'item-details-notice item-details-notice-warning';
        const pre = createElement('pre', 'item-details-pre item-details-body-pre');
        setSafeText(pre, body.preview);
        appendResizablePre(previewHost, pre, {
          minHeight: 180,
          defaultHeight: 360,
          persistedSizeKey: resizeStorageKey(detail, tab, 'body-preview'),
          label: 'Resize body preview'
        });
      } else {
        setSafeText(notice, '');
        notice.className = 'item-details-notice item-details-notice-info hidden';
        previewHost.appendChild(createElement('p', 'item-details-empty-state', `Content preview is not available for this item. Reason: ${body.reason || body.bodyStatus || 'not available'}.`));
      }
      loadMoreButton.disabled = !body.loadMoreAvailable;
      showFullButton.disabled = !body.showFullAvailable;
      copyVisibleButton.disabled = !body.canCopyVisible;
      copyAllButton.disabled = !body.canCopyAll;
      downloadButton.disabled = !body.canDownload;
    }
  }

  function getCurrentBodyPreview(payload, fallback, renderLimit) {
    if (root.BackToolsDomain?.createBodyPreview && payload && payload.bodyCaptureStatus) {
      return root.BackToolsDomain.createBodyPreview(payload, { renderLimit });
    }
    return fallback || {};
  }

  async function copyText(value) {
    const text = String(value || '');
    if (!text) return { ok: false, reason: 'Nothing to copy.' };
    try {
      if (root.navigator?.clipboard?.writeText) {
        await root.navigator.clipboard.writeText(text);
        return { ok: true };
      }
    } catch (error) {
      return { ok: false, reason: String(error?.message || error || 'Copy failed.') };
    }
    return { ok: false, reason: 'Clipboard API is not available.' };
  }

  function downloadBody(payload) {
    try {
      const helper = root.BackToolsDomain?.getBodyDownloadData;
      if (typeof helper !== 'function') return { ok: false, reason: 'Body download helper is not available.' };
      const result = helper(payload);
      if (!result.ok) return result;
      if (typeof Blob === 'undefined' || !root.URL?.createObjectURL) return { ok: false, reason: 'Blob download is not available in this environment.' };
      const blob = new Blob([result.data], { type: result.mimeType || 'application/octet-stream' });
      const url = root.URL.createObjectURL(blob);
      const link = root.document.createElement('a');
      link.href = url;
      link.download = result.filename || 'network-body.bin';
      link.click();
      setTimeout(() => root.URL.revokeObjectURL(url), 5000);
      return { ok: true };
    } catch (error) {
      return { ok: false, reason: String(error?.message || error || 'Body download failed.') };
    }
  }

  function formatBodyValue(value) {
    if (value === undefined || value === null || value === '') return '-';
    return String(value);
  }

  function isLongFieldValue(value) {
    const output = String(value ?? '');
    return output.length > 220 || output.includes('\n');
  }

  function appendFieldGrid(parent, fields, options = {}) {
    const list = createElement('dl', options.compact ? 'item-details-fields item-details-fields-compact' : 'item-details-fields');
    fields.forEach(field => {
      const row = createElement('div', 'item-details-field');
      if (field.wide) row.classList.add('item-details-field-wide');
      row.appendChild(createElement('dt', '', field.label || 'Field'));
      const dd = createElement('dd');
      appendFieldValue(dd, field, options);
      row.appendChild(dd);
      list.appendChild(row);
    });
    parent.appendChild(list);
  }

  function appendFieldValue(parent, field, options = {}) {
    const value = field?.value;
    if (field?.title || typeof value === 'string') parent.title = String(field?.title || value || '');
    if (value && typeof value === 'object') {
      const pre = createElement('pre', 'item-details-inline-json');
      setSafeText(pre, JSON.stringify(value, null, 2));
      appendResizablePre(parent, pre, {
        minHeight: 90,
        maxHeight: 420,
        defaultHeight: 160,
        persistedSizeKey: options.scope ? `backtools.itemDetails.fieldHeight.${safeResizeKeyPart(options.scope)}.${safeResizeKeyPart(field.label)}` : '',
        label: `Resize ${field.label || 'field'}`
      });
    } else if (isLongFieldValue(value)) {
      const pre = createElement('pre', 'item-details-inline-json');
      setSafeText(pre, value);
      appendResizablePre(parent, pre, {
        minHeight: options.compact ? 64 : 80,
        maxHeight: 360,
        defaultHeight: options.compact ? 96 : 140,
        persistedSizeKey: options.scope ? `backtools.itemDetails.fieldHeight.${safeResizeKeyPart(options.scope)}.${safeResizeKeyPart(field.label)}` : '',
        label: `Resize ${field.label || 'field'}`
      });
    } else {
      const valueText = createElement('span', 'item-details-value-text');
      setSafeText(valueText, value);
      parent.appendChild(valueText);
    }
    if (field?.copyValue) {
      appendButton(parent, 'Copy', 'item-details-copy-button', () => copyText(field.copyValue), {
        title: `Copy ${field.label || 'value'}`
      });
    }
  }

  function appendFields(parent, fields, options = {}) {
    appendFieldGrid(parent, fields, options);
  }

  return {
    clampDrawerWidth,
    isSensitiveConfirmationReady,
    setSafeText,
    renderItemDetailsView,
    closeItemDetailsView
  };
});
