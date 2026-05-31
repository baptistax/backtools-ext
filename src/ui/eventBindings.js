(function(root, factory) {
  const api = factory();
  root.BackToolsUI = Object.assign(root.BackToolsUI || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function() {
  const TEXT_FILTER_RENDER_DELAY_MS = 120;

  function createDebouncedAction(action, delayMs) {
    let timer = null;
    const run = () => {
      timer = null;
      action();
    };
    return {
      schedule() {
        if (timer != null) clearTimeout(timer);
        timer = setTimeout(run, delayMs);
      },
      cancel() {
        if (timer != null) clearTimeout(timer);
        timer = null;
      }
    };
  }

  function bindDynamic(deps) {
    const { q, state, modalState, uiState, render, rerenderPreserveFocus, storage, closeConfirmModal, resetCookieSessionState, log, applyCookieMode, openConfirmModal, openItemDetails, openCookieDetailsById, buildDiagnosticsPayload } = deps;
    const deferredFilterRender = createDebouncedAction(rerenderPreserveFocus, TEXT_FILTER_RENDER_DELAY_MS);
    const sourceNetworkFilterIds = ['srcSearch', 'netSearch', 'netMethod', 'netFamily', 'netBodyFilter', 'srcOnlyExportable', 'visSite', 'visThird', 'visExt', 'visBrowser', 'visDevtools', 'visDataBlob', 'visUnknown'];
    const sourceNetworkTextFilterIds = ['srcSearch', 'netSearch'];
    const cookieFilterIds = ['cookieSearch', 'cookieSource', 'cookieSeverity', 'cookieParty', 'cookieSessionOnly', 'cookieFindingsOnly'];
    const cookieTextFilterIds = ['cookieSearch'];
    const applicationFilterIds = ['appSearch', 'appOrigin', 'appType', 'appSensitive', 'appRawAvailable'];
    const applicationTextFilterIds = ['appSearch'];

    function requestFilterRender(deferred) {
      if (deferred) {
        deferredFilterRender.schedule();
        return;
      }
      deferredFilterRender.cancel();
      rerenderPreserveFocus();
    }

    q('moduleContent').oninput = e => {
      const id = e.target.id;
      if (sourceNetworkFilterIds.includes(id)) {
        state.uiFilters.srcSearch = q('srcSearch')?.value || '';
        state.uiFilters.srcOnlyExportable = !!q('srcOnlyExportable')?.checked;
        state.uiFilters.netSearch = q('netSearch')?.value || '';
        state.uiFilters.netMethod = q('netMethod')?.value || '';
        state.uiFilters.netFamily = q('netFamily')?.value || '';
        state.uiFilters.netBodyFilter = q('netBodyFilter')?.value || '';
        state.uiFilters.resourceVisibility = {
          ...state.uiFilters.resourceVisibility,
          siteResources: q('visSite')?.checked ?? state.uiFilters.resourceVisibility.siteResources,
          thirdPartyResources: q('visThird')?.checked ?? state.uiFilters.resourceVisibility.thirdPartyResources,
          extensionResources: q('visExt')?.checked ?? state.uiFilters.resourceVisibility.extensionResources,
          browserInternalResources: q('visBrowser')?.checked ?? state.uiFilters.resourceVisibility.browserInternalResources,
          devtoolsInternalResources: q('visDevtools')?.checked ?? state.uiFilters.resourceVisibility.devtoolsInternalResources,
          dataBlobResources: q('visDataBlob')?.checked ?? state.uiFilters.resourceVisibility.dataBlobResources,
          unknownResources: q('visUnknown')?.checked ?? state.uiFilters.resourceVisibility.unknownResources
        };
        storage.set({ resourceVisibility: state.uiFilters.resourceVisibility });
        requestFilterRender(sourceNetworkTextFilterIds.includes(id));
      }
      if (cookieFilterIds.includes(id)) {
        state.cookies.filters.search = q('cookieSearch')?.value || '';
        state.cookies.filters.source = q('cookieSource')?.value || 'all';
        state.cookies.filters.findingSeverity = q('cookieSeverity')?.value || 'all';
        state.cookies.filters.firstParty = q('cookieParty')?.value || 'all';
        state.cookies.filters.sessionLikeOnly = !!q('cookieSessionOnly')?.checked;
        state.cookies.filters.findingsOnly = !!q('cookieFindingsOnly')?.checked;
        requestFilterRender(cookieTextFilterIds.includes(id));
      }
      if (applicationFilterIds.includes(id)) {
        state.application.filters.search = q('appSearch')?.value || '';
        state.application.filters.origin = q('appOrigin')?.value || 'all';
        state.application.filters.type = q('appType')?.value || 'all';
        state.application.filters.sensitive = q('appSensitive')?.value || 'all';
        state.application.filters.rawAvailable = q('appRawAvailable')?.value || 'all';
        requestFilterRender(applicationTextFilterIds.includes(id));
      }
      if (id.startsWith('opt')) {
        deferredFilterRender.cancel();
        if (id === 'optRawCookies') {
          const domain = (typeof globalThis !== 'undefined' && globalThis.BackToolsDomain) || {};
          const scope = domain.summarizeRawCookieScope ? domain.summarizeRawCookieScope(state.cookies.observedCookies || []) : { rawCookieCount: 0, domains: [] };
          if (!state.dumpObjectsEnabled) {
            state.export.options.cookieExportMode = 'sanitized_only';
            state.cookies.rawExportConfirmedAt = null;
            state.cookies.rawExportScope = null;
            rerenderPreserveFocus();
            return;
          }
          if (!q('optRawCookies')?.checked) {
            state.export.options.cookieExportMode = 'sanitized_only';
            state.cookies.rawExportConfirmedAt = null;
            state.cookies.rawExportScope = null;
            storage.set({ exportOptions: state.export.options });
            rerenderPreserveFocus();
            return;
          }
          if (scope.rawCookieCount < 1) {
            state.export.options.cookieExportMode = 'sanitized_only';
            state.cookies.rawExportConfirmedAt = null;
            state.cookies.rawExportScope = null;
            rerenderPreserveFocus();
            return;
          }
          q('optRawCookies').checked = false;
          openConfirmModal({
            title: 'Export raw cookies',
            message: `This may expose usable authentication material. Raw cookies: ${scope.rawCookieCount}. Domains: ${scope.domains.join(', ') || 'unknown'}.`,
            phrase: 'EXPORT RAW COOKIES',
            confirmLabel: 'Enable raw cookie export',
            checkboxLabel: 'I understand this export may grant access to an account or session.',
            onConfirm: () => {
              state.export.options.cookieExportMode = 'raw_confirmed';
              state.cookies.rawExportConfirmedAt = new Date().toISOString();
              state.cookies.rawExportScope = scope;
              storage.set({ exportOptions: state.export.options });
              log('INFO', 'Raw cookie export confirmed', `Raw cookies: ${scope.rawCookieCount}; domains: ${scope.domains.join(', ') || 'unknown'}`);
            }
          });
          return;
        }
        if (id === 'optRawApplication') {
          const domain = (typeof globalThis !== 'undefined' && globalThis.BackToolsDomain) || {};
          const scope = domain.summarizeRawApplicationScope ? domain.summarizeRawApplicationScope(state.application || {}) : { rawStorageItemCount: 0, origins: [], storageTypes: [] };
          if (!state.dumpObjectsEnabled) {
            state.export.options.applicationExportMode = 'sanitized_only';
            state.application.rawExportConfirmedAt = null;
            state.application.rawExportScope = null;
            rerenderPreserveFocus();
            return;
          }
          if (!q('optRawApplication')?.checked) {
            state.export.options.applicationExportMode = 'sanitized_only';
            state.application.rawExportConfirmedAt = null;
            state.application.rawExportScope = null;
            storage.set({ exportOptions: state.export.options });
            rerenderPreserveFocus();
            return;
          }
          if (scope.rawStorageItemCount < 1) {
            state.export.options.applicationExportMode = 'sanitized_only';
            state.application.rawExportConfirmedAt = null;
            state.application.rawExportScope = null;
            rerenderPreserveFocus();
            return;
          }
          q('optRawApplication').checked = false;
          openConfirmModal({
            title: 'Export raw Application storage',
            message: `This exports raw localStorage/sessionStorage values. Values: ${scope.rawStorageItemCount}. Origins: ${scope.origins.join(', ') || 'unknown'}.`,
            phrase: 'EXPORT RAW APPLICATION STORAGE',
            confirmLabel: 'Enable raw Application export',
            checkboxLabel: 'I understand this export may include tokens, credentials, or private application data.',
            onConfirm: () => {
              state.export.options.applicationExportMode = 'raw_confirmed';
              state.application.rawExportConfirmedAt = new Date().toISOString();
              state.application.rawExportScope = scope;
              storage.set({ exportOptions: state.export.options });
              log('INFO', 'Raw Application storage export confirmed', `Storage values: ${scope.rawStorageItemCount}; origins: ${scope.origins.join(', ') || 'unknown'}`);
            }
          });
          return;
        }
        state.export.options.includeSources = q('optSources')?.checked ?? state.export.options.includeSources;
        state.export.options.includeDataUrls = q('optDataUrls')?.checked ?? state.export.options.includeDataUrls;
        state.export.options.includeNetwork = q('optNetwork')?.checked ?? state.export.options.includeNetwork;
        state.export.options.includeDiagnostics = q('optDiagnostics')?.checked ?? state.export.options.includeDiagnostics;
        state.export.options.includeApplication = q('optApplication')?.checked ?? state.export.options.includeApplication;
        state.export.options.includeExtensionResources = q('optExtResources')?.checked ?? state.export.options.includeExtensionResources;
        state.export.options.includeBrowserInternalResources = q('optBrowserResources')?.checked ?? state.export.options.includeBrowserInternalResources;
        state.export.options.includeDevtoolsInternalResources = q('optDevtoolsResources')?.checked ?? state.export.options.includeDevtoolsInternalResources;
        state.export.options.includeBrowserInternalMetadata = state.export.options.includeBrowserInternalResources;
        state.export.options.includeExtensionMetadata = state.export.options.includeExtensionResources;
        state.export.options.includeCookiesReport = q('optCookiesReport')?.checked ?? state.export.options.includeCookiesReport;
        storage.set({ exportOptions: state.export.options });
        rerenderPreserveFocus();
      }
    };

    q('moduleContent').onclick = e => {
      const inspectTrigger = e.target.closest('[data-inspect-kind]');
      if (inspectTrigger && typeof openItemDetails === 'function') {
        const row = e.target.closest('.inspectable-row');
        const explicit = e.target.closest('button[data-inspect-kind]');
        if (explicit || (row && !e.target.closest('button,input,select,label,a'))) {
          openItemDetails(inspectTrigger.dataset.inspectKind, Number(inspectTrigger.dataset.inspectIndex || 0));
          return;
        }
      }
      if (!e.target.closest('[data-cookie-actions-root]') && !e.target.dataset.cookieActionsToggle && modalState.cookieActionsFor) {
        modalState.cookieActionsFor = null;
        render();
        return;
      }
      if (e.target.dataset.cookieActionsToggle) {
        const id = e.target.dataset.cookieActionsToggle;
        modalState.cookieActionsFor = modalState.cookieActionsFor === id ? null : id;
        render();
        return;
      }
      if (e.target.dataset.overviewToggle) {
        const k = e.target.dataset.overviewToggle;
        uiState.overviewExpanded[k] = !uiState.overviewExpanded[k];
        render();
        return;
      }
      if (e.target.dataset.showResourceFamily) {
        const key = e.target.dataset.showResourceFamily;
        if (key === 'allAdvanced') {
          state.uiFilters.resourceVisibility.extensionResources = true;
          state.uiFilters.resourceVisibility.browserInternalResources = true;
          state.uiFilters.resourceVisibility.devtoolsInternalResources = true;
        } else if (Object.prototype.hasOwnProperty.call(state.uiFilters.resourceVisibility, key)) {
          state.uiFilters.resourceVisibility[key] = true;
        }
        storage.set({ resourceVisibility: state.uiFilters.resourceVisibility });
        render();
        return;
      }
      if (e.target.dataset.switchModule) {
        state.modules.activeModule = e.target.dataset.switchModule;
        storage.set({ activeModule: state.modules.activeModule });
        render();
        return;
      }
      if (e.target.dataset.cookieActionsItem) {
        const [action, id] = e.target.dataset.cookieActionsItem.split(':');
        const row = state.cookies.observedCookies.find(x => x.id === id);
        if (!row) {
          modalState.cookieActionsFor = null;
          render();
          return;
        }
        if (action === 'view') {
          if (typeof openCookieDetailsById === 'function') openCookieDetailsById(id);
        }
        if (action === 'copySan') {
          navigator.clipboard.writeText(JSON.stringify({ name: row.name, value: '[protected]', domain: row.domain, originHost: row.originHost, path: row.path, sources: row.sources, secure: row.secure, httpOnly: row.httpOnly, sameSite: row.sameSite, findings: row.findings }, null, 2));
        }
        if (action === 'copyVal') {
          if (state.dumpObjectsEnabled && row.rawValue) {
            navigator.clipboard.writeText(String(row.rawValue));
            log('INFO', 'Cookie raw value copied', 'Dump objects mode copy completed');
          } else {
            log('INFO', 'Cookie raw table copy blocked', 'Enable Dump objects to copy raw values.');
          }
        }
        if (action === 'copyPair') {
          if (state.dumpObjectsEnabled && row.rawValue) {
            navigator.clipboard.writeText(`${row.name || ''}=${String(row.rawValue)}`);
            log('INFO', 'Cookie raw pair copied', 'Dump objects mode copy completed');
          } else {
            log('INFO', 'Cookie raw table copy blocked', 'Enable Dump objects to copy raw values.');
          }
        }
        modalState.cookieActionsFor = null;
        render();
        return;
      }
      if (e.target.id === 'copyLogsBtn') navigator.clipboard.writeText(JSON.stringify(state.diagnostics.logs, null, 2));
      if (e.target.id === 'downloadLogsBtn') {
        const b = new Blob([JSON.stringify(state.diagnostics.logs, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(b);
        a.download = 'logs.json';
        a.click();
      }
      if (e.target.id === 'clearLogsBtn') {
        state.diagnostics.logs = [];
        render();
      }
      if (e.target.id === 'downloadDiagBtn') {
        const payload = typeof buildDiagnosticsPayload === 'function'
          ? buildDiagnosticsPayload()
          : { logs: state.diagnostics.logs, reasons: state.diagnostics.reasonGroups };
        const b = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(b);
        a.download = 'diagnostics.json';
        a.click();
      }
      if (e.target.id === 'modalCancelBtn') {
        closeConfirmModal();
        render();
        return;
      }
      if (e.target.id === 'modalConfirmBtn' && modalState.onConfirm) {
        if (q('modalInput').value !== modalState.phrase) return;
        modalState.onConfirm();
        closeConfirmModal();
        render();
        return;
      }
      if (e.target.id === 'clearCookieDataBtn') {
        state.cookies.rawRecords = [];
        state.cookies.observedCookies = state.cookies.observedCookies.map(x => ({ ...x, rawValue: null }));
        resetCookieSessionState();
        log('INFO', 'Cookie data cleared', 'Sanitized clear event');
        render();
        return;
      }
      if (e.target.dataset.cookieMode) {
        const m = e.target.dataset.cookieMode;
        if (m === 'safe') {
          applyCookieMode('safe');
          render();
          return;
        }
        if (!state.cookies.expertModeEnabled) return;
        if (m === 'audit') {
          openConfirmModal({
            title: 'Enable Audit Mode',
            message: 'Audit Mode may expose session cookies or authentication tokens locally in this DevTools session. Use only with data you own or are authorized to inspect.',
            phrase: 'Turn on audit mode',
            confirmLabel: 'Enable Audit Mode',
            onConfirm: () => {
              applyCookieMode('audit');
              state.cookies.needsReanalyze = state.cookies.summary.observedCookies > 0 && !state.cookies.rawValuesAvailable;
            }
          });
          return;
        }
        if (m === 'raw') {
          openConfirmModal({
            title: 'Enable Raw Mode',
            message: 'Raw Mode can display and export active session cookies, tokens, and authentication data. Only continue if this data is yours or you are authorized to inspect it.',
            phrase: 'Turn on raw mode',
            confirmLabel: 'Enable Raw Mode',
            onConfirm: () => {
              applyCookieMode('raw');
              state.cookies.needsReanalyze = state.cookies.summary.observedCookies > 0 && !state.cookies.rawValuesAvailable;
            }
          });
          return;
        }
      }
      if (e.target.id === 'expertModeToggle' && !state.cookies.expertModeEnabled) {
        openConfirmModal({
          title: 'Enable Expert Mode',
          message: 'Expert Mode unlocks Audit and Raw cookie workflows. These workflows may expose session cookies, authentication tokens, or other sensitive browser-side data. Use only with data you own or are authorized to inspect.',
          phrase: 'I understand',
          confirmLabel: 'Enable Expert Mode',
          onConfirm: () => {
            state.cookies.expertModeEnabled = true;
            log('INFO', 'Expert Mode enabled for current DevTools session', 'Cookie workflows unlocked');
          }
        });
        e.preventDefault();
        return;
      }
      if (e.target.dataset.revealCookie) {
        if (state.cookies.mode === 'audit' && state.cookies.rawValuesAvailable) {
          if (!state.cookies.revealedCookieIds.includes(e.target.dataset.revealCookie)) state.cookies.revealedCookieIds.push(e.target.dataset.revealCookie);
          log('INFO', 'Cookie value revealed', 'cookie value reveal action completed');
          render();
        }
        return;
      }
      if (e.target.dataset.copyValue) {
        const row = state.cookies.observedCookies.find(x => x.id === e.target.dataset.copyValue);
        if (row && row.rawValue && state.dumpObjectsEnabled) {
          navigator.clipboard.writeText(String(row.rawValue));
          log('INFO', 'Cookie raw value copied', 'Dump objects mode copy completed');
        } else if (row && row.rawValue) {
          log('INFO', 'Cookie raw table copy blocked', 'Enable Dump objects to copy raw values.');
        }
        return;
      }
      if (e.target.dataset.copyPair) {
        const row = state.cookies.observedCookies.find(x => x.id === e.target.dataset.copyPair);
        if (row && row.rawValue && state.dumpObjectsEnabled) {
          navigator.clipboard.writeText(`${row.name || ''}=${String(row.rawValue)}`);
          log('INFO', 'Cookie raw pair copied', 'Dump objects mode copy completed');
        } else if (row && row.rawValue) {
          log('INFO', 'Cookie raw table copy blocked', 'Enable Dump objects to copy raw values.');
        }
        return;
      }
      if (e.target.dataset.copyCookie) {
        const row = state.cookies.observedCookies.find(x => x.id === e.target.dataset.copyCookie);
        if (row) {
          navigator.clipboard.writeText(JSON.stringify({ name: row.name, value: '[protected]', domain: row.domain, originHost: row.originHost, path: row.path, sources: row.sources, secure: row.secure, httpOnly: row.httpOnly, sameSite: row.sameSite, findings: row.findings }, null, 2));
        }
      }
    };
  }

  return { bindDynamic };
});
