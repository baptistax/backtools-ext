(function(root, factory) {
  const api = factory(root);
  root.BackToolsUI = Object.assign(root.BackToolsUI || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  let domain = root.BackToolsDomain || {};
  if (typeof require === 'function') {
    try {
      domain = Object.assign(
        {},
        require('../../domain/redaction.js'),
        require('../../domain/resourceClassification.js'),
        require('../../domain/cookies.js'),
        require('../../domain/application.js'),
        require('../../domain/bodyPreview.js'),
        domain
      );
    } catch {}
  }

  const MASK_POLICY_LONG = 'prefix4_middle3_when_long';
  const COOKIE_RAW_DISABLED_NOTICE = 'Raw cookie export is not enabled in this build. Showing masked professional view.';
  const PROTECTED_VALUES = new Set(['[protected]', '[redacted]', '[masked]']);

  function text(value, fallback = '-') {
    if (value === undefined || value === null || value === '') return fallback;
    return String(value);
  }

  function boolText(value) {
    if (value === true) return 'true';
    if (value === false) return 'false';
    return text(value);
  }

  function truncate(value, max = 8000) {
    const output = String(value ?? '');
    if (output.length <= max) return output;
    return `${output.slice(0, max)}\n[preview truncated: ${output.length - max} chars hidden]`;
  }

  function redactUrlValue(value) {
    return domain.redactUrl ? domain.redactUrl(value || '') : text(value, '');
  }

  function displayUrlFor(item) {
    return item?.urlRedacted || item?.originalUrlRedacted || redactUrlValue(item?.url || item?.path || '');
  }

  function urlHashFor(item) {
    if (item?.urlHash) return item.urlHash;
    if (domain.hashSensitiveValue) return domain.hashSensitiveValue(item?.url || item?.path || item?.id || '');
    return null;
  }

  function safeHeaders(headers) {
    const redacted = domain.redactHeaders ? domain.redactHeaders(headers || []) : (headers || []);
    if (!Array.isArray(redacted)) return redacted || [];
    return redacted.map(header => ({
      name: text(header?.name || header?.key),
      value: text(header?.value, ''),
      redactionApplied: !!header?.redactionApplied
    }));
  }

  function field(label, value) {
    return { label, value: text(value) };
  }

  function jsonBlock(title, value) {
    return { title, value };
  }

  function detailField(label, value, options = {}) {
    return {
      label,
      value: text(value),
      copyValue: options.copyValue || null,
      title: options.title || null,
      wide: options.wide === true,
      tone: options.tone || null
    };
  }

  function exportField(label, value, tone = 'info') {
    return { label, value: text(value), tone };
  }

  function notice(level, title, message) {
    return { level, title, message: text(message, '') };
  }

  function formatBytes(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) return text(value);
    if (numeric < 1024) return `${numeric} B`;
    const units = ['KB', 'MB', 'GB'];
    let current = numeric / 1024;
    let index = 0;
    while (current >= 1024 && index < units.length - 1) {
      current /= 1024;
      index += 1;
    }
    return `${current.toFixed(current >= 10 ? 1 : 2)} ${units[index]}`;
  }

  function originFrom(value, fallback = '-') {
    try {
      return new URL(value || '').host || fallback;
    } catch {
      return fallback;
    }
  }

  function statusLabel(value) {
    if (value === undefined || value === null || value === '') return '';
    return String(value).replace(/_/g, ' ');
  }

  function getTab(detail, id) {
    return (detail.tabs || []).find(tab => tab.id === id) || null;
  }

  function getTabFields(detail, id) {
    return getTab(detail, id)?.fields || [];
  }

  function getPrimaryUrl(detail) {
    const raw = detail.rawJson || {};
    const fallbackKinds = new Set(['source', 'network', 'application_manifest', 'application_service_worker', 'export_plan_item']);
    const candidate = raw.urlRedacted || raw.request?.urlRedacted || raw.href || raw.scope || (fallbackKinds.has(detail.kind) ? detail.subtitle : '') || '';
    const value = String(candidate || '');
    return value && value !== '-' ? value : '';
  }

  function resourceRole(raw) {
    const category = raw?.resourceCategory || 'unknown';
    if (category === 'site_first_party') return 'first-party site resource';
    if (category === 'site_third_party') return 'third-party resource';
    if (category === 'extension_resource') return 'extension resource';
    if (category === 'browser_internal') return 'browser/internal resource';
    if (category === 'devtools_internal') return 'DevTools/internal resource';
    if (category === 'data_url' || category === 'blob_url') return 'data/blob resource';
    return 'resource with unknown origin relation';
  }

  function resourceKindLabel(raw) {
    const category = raw?.resourceCategory || 'unknown';
    if (category === 'site_first_party') return 'Site resource';
    if (category === 'site_third_party') return 'Third-party resource';
    if (category === 'extension_resource') return 'Extension resource';
    if (category === 'browser_internal') return 'Browser/internal resource';
    if (category === 'devtools_internal') return 'DevTools/internal resource';
    if (category === 'data_url' || category === 'blob_url') return 'Data/blob resource';
    return 'Unknown resource';
  }

  function relationLabel(raw) {
    const category = raw?.resourceCategory || 'unknown';
    if (category === 'site_first_party') return 'First-party';
    if (category === 'site_third_party') return 'Third-party';
    if (category === 'extension_resource') return 'Extension';
    if (category === 'browser_internal') return 'Browser/internal';
    if (category === 'devtools_internal') return 'DevTools/internal';
    if (category === 'data_url' || category === 'blob_url') return 'Data/blob';
    return 'Unknown';
  }

  function categoryBadge(raw) {
    return raw?.resourceCategory ? resourceKindLabel(raw) : null;
  }

  function networkStatusLine(raw) {
    const method = text(raw.method, 'GET');
    const status = text(raw.statusCode, '-');
    return `${method} ${status}`;
  }

  function bodyStateLabel(raw) {
    const value = String(raw?.status || raw?.body?.bodyStatus || '');
    if (value === 'body_captured') return 'captured';
    if (value === 'mime_blocked') return 'MIME blocked';
    if (value === 'platform_unavailable') return 'platform unavailable';
    if (value === 'policy_blocked') return 'policy blocked';
    if (value === 'read_failed') return 'read failed';
    if (value === 'metadata_only') return 'metadata-only';
    return statusLabel(value) || '-';
  }

  function limitationTitle(raw) {
    const value = String(raw?.status || raw?.body?.bodyStatus || '');
    if (value === 'mime_blocked') return 'MIME policy skipped body';
    if (value === 'platform_unavailable') return 'Body unavailable from platform';
    if (value === 'policy_blocked') return 'Body capture policy';
    if (value === 'read_failed') return 'Body read failed';
    if (value === 'metadata_only') return 'Metadata only';
    return 'Body unavailable or partial';
  }

  function buildHeaderKicker(detail) {
    const raw = detail.rawJson || {};
    if (detail.kind === 'source') return `SOURCE - ${text(raw.type, 'resource')}`;
    if (detail.kind === 'network') return `NETWORK - ${text(raw.type, 'request')}`;
    if (detail.kind === 'cookie') return `COOKIE - ${text(raw.classification || raw.valueState, 'metadata')}`;
    if (detail.kind === 'application_storage') return `APPLICATION - ${text(raw.storageType || raw.type, 'storage')}`;
    if (detail.kind === 'application_indexeddb') return 'APPLICATION - indexedDB';
    if (detail.kind === 'application_cache_storage') return 'APPLICATION - cache storage';
    if (detail.kind === 'application_service_worker') return 'APPLICATION - service worker';
    if (detail.kind === 'application_manifest') return 'APPLICATION - manifest';
    if (detail.kind === 'export_plan_item') return 'EXPORT - plan item';
    return String(detail.kind || 'item').replace(/_/g, ' ').toUpperCase();
  }

  function buildDisplayTitle(detail) {
    const raw = detail.rawJson || {};
    const primaryUrl = getPrimaryUrl(detail);
    if (detail.kind === 'network' && primaryUrl) return `${networkStatusLine(raw)} - ${primaryUrl}`;
    if (primaryUrl) return primaryUrl;
    if (detail.kind === 'cookie') return text(raw.name, detail.title || 'Cookie');
    if (detail.kind === 'application_storage') return text(raw.key, detail.title || 'Storage item');
    if (detail.kind === 'application_indexeddb') return text(raw.name, detail.title || 'IndexedDB database');
    if (detail.kind === 'application_cache_storage') return text(raw.name, detail.title || 'Cache Storage');
    return detail.title || 'Item details';
  }

  function buildHeaderBadges(detail) {
    const raw = detail.rawJson || {};
    const badges = [];
    const add = (label, tone = 'info') => {
      if (label && !badges.some(item => item.label === label)) badges.push({ label, tone });
    };
    if (detail.kind !== 'network') add(statusLabel(detail.status || raw.status || raw.valueState), detail.status === 'raw' ? 'risk' : 'info');
    if (raw.exportable === true) add('Exportable', 'success');
    if (raw.exportable === false) add('Not exportable', 'warning');
    if (raw.bodyExportable === true) add('Body captured', 'success');
    if (raw.bodyExportable === false && raw.status) add('Body metadata only', 'warning');
    if (categoryBadge(raw)) add(categoryBadge(raw), 'info');
    if (raw.resourceCategory) add(relationLabel(raw), 'info');
    if (detail.kind === 'network') add('Included in export', 'success');
    if (detail.__dumpObjectsEnabled) add('Raw mode', 'risk');
    return badges.slice(0, 5);
  }

  function buildSummaryFields(detail) {
    const raw = detail.rawJson || {};
    if (detail.kind === 'source') {
      return [
        detailField('Type', raw.type),
        detailField('Category', resourceLabel(raw)),
        detailField('Relation', relationLabel(raw)),
        detailField('Status', raw.status),
        detailField('Exportable', raw.exportable ? 'yes' : 'no'),
        detailField('Origin', raw.host || originFrom(raw.urlRedacted)),
        detailField('Collector', raw.collector),
        detailField('Size', formatBytes(raw.size)),
        detailField('Reason', raw.reason),
        detailField('Encoding', raw.encoding)
      ];
    }
    if (detail.kind === 'network') {
      return [
        detailField('Method', raw.method),
        detailField('Status', raw.statusCode),
        detailField('Type', raw.type),
        detailField('Host', raw.host || originFrom(raw.urlRedacted)),
        detailField('Relation', relationLabel(raw)),
        detailField('Body state', bodyStateLabel(raw)),
        detailField('Captured bytes', formatBytes(raw.bodySizeBytes ?? raw.bodyCapturedBytes)),
        detailField('Reason', raw.reason),
        detailField('MIME', raw.mimeType),
        detailField('Collector', raw.collector)
      ];
    }
    if (detail.kind === 'cookie') {
      return [
        detailField('Name', raw.name),
        detailField('Domain', raw.domain),
        detailField('Path', raw.path),
        detailField('Classification', raw.classification),
        detailField('Value mode', raw.valueState),
        detailField('Raw availability', raw.rawCookieExportEnabled ? 'available' : 'unavailable'),
        detailField('SameSite', raw.sameSite),
        detailField('Secure', boolText(raw.secure)),
        detailField('HttpOnly', boolText(raw.httpOnly))
      ];
    }
    if (detail.kind === 'application_storage') {
      const rawAvailable = raw.value?.rawAvailable ?? raw.rawAvailable ?? detail.rawPayload?.rawAvailable;
      const rawIncluded = raw.value?.rawIncluded === true || raw.rawIncluded === true;
      return [
        detailField('Type', raw.storageType || raw.type),
        detailField('Key', raw.key),
        detailField('Origin', raw.origin),
        detailField('Classification', raw.classification),
        detailField('Sensitive', raw.sensitive ? 'yes' : 'no'),
        detailField('Value mode', rawIncluded ? 'raw' : 'protected'),
        detailField('Raw availability', rawAvailable ? 'available' : 'unavailable'),
        detailField('Length', raw.value?.length ?? raw.valueLength)
      ];
    }
    if (detail.kind === 'application_indexeddb') {
      return [
        detailField('Database', raw.name),
        detailField('Origin', raw.origin),
        detailField('Version', raw.version),
        detailField('Object stores', raw.objectStoreCount),
        detailField('Records', raw.totalRecordCount),
        detailField('Status', raw.error ? 'partial' : 'inventory')
      ];
    }
    if (detail.kind === 'application_cache_storage') {
      return [
        detailField('Cache', raw.name),
        detailField('Origin', raw.origin),
        detailField('Requests', raw.requestCount),
        detailField('Status', raw.error ? 'partial' : 'inventory')
      ];
    }
    if (detail.kind === 'application_service_worker') {
      return [
        detailField('Origin', raw.origin),
        detailField('Scope', raw.scope, { copyValue: raw.scope, wide: true }),
        detailField('Active state', raw.activeState),
        detailField('Waiting state', raw.waitingState),
        detailField('Installing state', raw.installingState)
      ];
    }
    if (detail.kind === 'application_manifest') {
      return [
        detailField('Status', raw.status),
        detailField('Origin', raw.origin),
        detailField('Href', raw.href, { copyValue: raw.href, wide: true }),
        detailField('Rel', raw.rel),
        detailField('Crossorigin', raw.crossorigin)
      ];
    }
    if (detail.kind === 'export_plan_item') {
      return [
        detailField('Bucket', raw.planBucket),
        detailField('Status', raw.exportStatus),
        detailField('ZIP path', raw.zipPath, { copyValue: raw.zipPath, wide: true }),
        detailField('Category', resourceLabel(raw)),
        detailField('Content kind', raw.contentKind),
        detailField('MIME', raw.mimeType)
      ];
    }
    return getTabFields(detail, 'summary').map(item => detailField(item.label, item.value, {
      copyValue: item.copyValue,
      title: item.title,
      wide: item.wide,
      tone: item.tone
    }));
  }

  function buildInterpretation(detail) {
    const raw = detail.rawJson || {};
    const output = [];
    if (detail.kind === 'source') {
      if (raw.content?.state && raw.content.state !== 'not_available') {
        output.push(`This is a ${resourceRole(raw)} collected from the Sources API. It is readable and can be included in the main ZIP export.`);
      } else {
        output.push('This resource was discovered, but full content is not currently available in this view. It can still appear in reports as metadata, but it should not be treated as a complete source capture.');
      }
      output.push('Individual export provides sanitized metadata JSON.');
    } else if (detail.kind === 'network') {
      if (raw.bodyExportable) {
        output.push(`This is a ${resourceRole(raw)} observed in Network capture. The response body was captured and can be previewed or downloaded from this drawer.`);
      } else if (raw.status === 'mime_blocked') {
        output.push('This request was observed, but body capture was skipped by the current MIME policy. Metadata remains available.');
      } else {
        output.push('This request was observed, but the response body is unavailable. The table keeps metadata for analysis, while export will mark the body as unavailable with the recorded reason.');
      }
      if (raw.reason) output.push(`Reason: ${raw.reason}.`);
      output.push('Individual export provides sanitized request metadata JSON.');
    } else if (detail.kind === 'cookie') {
      output.push(`This cookie metadata belongs to ${text(raw.domain, 'an unknown domain')}.`);
      output.push(raw.rawCookieExportEnabled ? 'A raw value exists in memory, so reveal and raw export actions stay guarded.' : 'The raw value is unavailable from the current collector.');
      output.push(detail.__dumpObjectsEnabled ? 'Dump objects is enabled, so raw cookie data may be visible and exportable.' : 'Protected values are shown by default.');
    } else if (detail.kind === 'application_storage') {
      output.push(`This is ${text(raw.storageType || raw.type, 'storage')} data from ${text(raw.origin, 'an unknown origin')}.`);
      output.push(detail.rawPayload?.rawAvailable ? 'A raw value exists in memory and is guarded unless Dump objects is enabled.' : 'Only protected metadata is available for this value.');
      output.push(detail.__dumpObjectsEnabled ? 'Dump objects is enabled, so raw Application data may be visible and exportable.' : 'The normal display keeps storage values protected.');
    } else if (detail.kind && detail.kind.startsWith('application_')) {
      output.push('This Application item is an inventory record from the inspected page context.');
      output.push(raw.error ? 'The record is partial and includes the collector error shown below.' : 'It is included as metadata in the Application report.');
      output.push('Stored values or response bodies are not expanded by this drawer.');
    } else if (detail.kind === 'export_plan_item') {
      output.push('This row shows how one item is treated by the current export plan.');
      output.push(raw.zipPath ? 'A ZIP path has been assigned for the package.' : 'No ZIP content path is available for this item.');
      output.push(raw.reason ? `The current reason is ${raw.reason}.` : 'No blocking reason is attached.');
    } else {
      output.push(detail.reason || 'This detail view summarizes the selected item.');
    }
    return { title: 'What this means', body: output.join(' ') };
  }

  function buildExportState(detail) {
    const raw = detail.rawJson || {};
    if (detail.kind === 'source') {
      return [
        exportField('Main ZIP package', raw.exportable ? 'included' : 'not included', raw.exportable ? 'success' : 'warning'),
        exportField('Individual JSON', 'available', 'success'),
        exportField('Content file', raw.exportable ? 'included' : 'unavailable', raw.exportable ? 'success' : 'warning'),
        exportField('Sanitization', 'enabled', 'success'),
        exportField('Sensitive data risk', 'low', 'success')
      ];
    }
    if (detail.kind === 'network') {
      return [
        exportField('Main ZIP package', 'metadata included', 'success'),
        exportField('Individual JSON', 'available', 'success'),
        exportField('Body file', raw.bodyExportable ? 'included' : 'unavailable', raw.bodyExportable ? 'success' : 'warning'),
        exportField('Body download', raw.bodyExportable ? 'available' : 'unavailable', raw.bodyExportable ? 'success' : 'warning'),
        exportField('Sanitization', 'enabled', 'success'),
        exportField('Sensitive data risk', raw.cookies?.requestCookieHeaderObserved || raw.cookies?.responseSetCookieHeaderObserved ? 'medium' : 'low')
      ];
    }
    if (detail.kind === 'cookie') {
      const risk = raw.sensitive || raw.possibleToken ? 'high' : raw.rawCookieExportEnabled ? 'medium' : 'low';
      return [
        exportField('Main ZIP package', 'cookie reports included', 'success'),
        exportField('Individual JSON', 'available', 'success'),
        exportField('Raw value', detail.__dumpObjectsEnabled && raw.rawCookieExportEnabled ? 'included by Dump objects' : raw.rawCookieExportEnabled ? 'guarded' : 'unavailable', risk === 'high' ? 'risk' : 'warning'),
        exportField('Sanitization', detail.__dumpObjectsEnabled ? 'raw mode active' : 'enabled', detail.__dumpObjectsEnabled ? 'risk' : 'success'),
        exportField('Sensitive data risk', risk, risk === 'high' ? 'risk' : risk === 'medium' ? 'warning' : 'success')
      ];
    }
    if (detail.kind === 'application_storage') {
      const rawIncluded = detail.__dumpObjectsEnabled && detail.rawPayload?.rawAvailable;
      const risk = raw.sensitive || rawIncluded ? 'high' : detail.rawPayload?.rawAvailable ? 'medium' : 'low';
      return [
        exportField('Main ZIP package', 'application report included', 'success'),
        exportField('Individual JSON', 'available', 'success'),
        exportField('Raw value', rawIncluded ? 'included by Dump objects' : detail.rawPayload?.rawAvailable ? 'guarded' : 'unavailable', rawIncluded ? 'risk' : 'warning'),
        exportField('Sanitization', rawIncluded ? 'raw mode active' : 'enabled', rawIncluded ? 'risk' : 'success'),
        exportField('Sensitive data risk', risk, risk === 'high' ? 'risk' : risk === 'medium' ? 'warning' : 'success')
      ];
    }
    if (detail.kind && detail.kind.startsWith('application_')) {
      return [
        exportField('Main ZIP package', 'metadata included', 'success'),
        exportField('Individual JSON', 'available', 'success'),
        exportField('Content values', 'not collected', 'info'),
        exportField('Sensitive data risk', 'low', 'success')
      ];
    }
    return [
      exportField('Individual JSON', 'available', 'success'),
      exportField('Sanitization', 'enabled', 'success')
    ];
  }

  function buildNotices(detail) {
    const raw = detail.rawJson || {};
    const notices = [];
    if (detail.__dumpObjectsEnabled && (raw.value?.rawIncluded || raw.rawIncluded || raw.containsRawApplicationData)) {
      notices.push(notice('critical', 'Raw mode active', 'Dump objects is enabled. This detail may include raw cookie or Application data.'));
    }
    if (detail.kind === 'cookie' && (raw.sensitive || raw.possibleToken)) {
      notices.push(notice('critical', 'Sensitive value risk', 'This cookie looks session-like, auth-like, token-like, or otherwise sensitive. Keep raw reveal and raw export guarded.'));
    }
    if (detail.kind === 'application_storage' && raw.sensitive) {
      notices.push(notice('critical', 'Sensitive storage value', 'This storage entry is classified as sensitive. Raw value handling should stay explicit and guarded.'));
    }
    if (detail.kind === 'source' && raw.content?.state === 'not_available') {
      notices.push(notice('warning', 'Content preview unavailable', raw.reason || 'Content preview is not available for this item.'));
    }
    if (detail.kind === 'network' && raw.status && raw.status !== 'body_captured') {
      notices.push(notice('warning', limitationTitle(raw), raw.reason || 'The body is not available from the current DevTools capture.'));
    }
    if (detail.kind === 'network' && raw.bodyRenderStatus === 'partial_preview') {
      notices.push(notice('warning', 'Preview truncated', 'Only a partial preview is rendered in the drawer. The captured body remains available for download/export.'));
    }
    if (raw.redactionApplied || raw.body?.redactionApplied) {
      notices.push(notice('info', 'Sanitization applied', 'Sensitive URL, header, or body fields were redacted for display/export.'));
    }
    (detail.tabs || []).forEach(tab => {
      if (tab.id === 'export' && tab.type !== 'cookieExport') return;
      if (tab.notice) notices.push(notice('info', tab.label || 'Note', tab.notice));
    });
    return notices;
  }

  function buildSections(detail) {
    const excluded = new Set(['summary', 'raw']);
    const sectionOrder = {
      body: 0,
      content: 0,
      value: 1,
      request: 2,
      response: 3,
      metadata: 4,
      headers: 5,
      cookies: 6
    };
    return (detail.tabs || [])
      .filter(tab => !excluded.has(tab.id))
      .filter(tab => {
        if (tab.id === 'export' && tab.type !== 'cookieExport') return false;
        return true;
      })
      .map(tab => ({
        ...tab,
        type: tab.id === 'content' && (!tab.text || tab.text === 'Content is not available in the current state.') ? 'emptyState' : tab.type,
        message: tab.id === 'content' && (!tab.text || tab.text === 'Content is not available in the current state.')
          ? `Content preview is not available for this item. Reason: ${detail.rawJson?.reason || 'metadata-only'}.`
          : tab.message,
        notice: tab.id === 'content' && tab.text && String(tab.text).includes('[preview truncated:')
          ? 'Preview is truncated for display. Export state is shown separately.'
          : tab.notice,
        title: tab.id === 'export' && tab.type === 'cookieExport' ? 'Advanced cookie export' : tab.label || tab.id
      }))
      .sort((a, b) => (sectionOrder[a.id] ?? 20) - (sectionOrder[b.id] ?? 20));
  }

  function prepareDetailPresentation(detail) {
    const primaryUrl = getPrimaryUrl(detail);
    return {
      ...detail,
      primaryUrl,
      headerKicker: buildHeaderKicker(detail),
      displayTitle: buildDisplayTitle(detail),
      headerSubtitle: detail.kind === 'network' ? '' : detail.subtitle,
      titleFull: buildDisplayTitle(detail),
      headerBadges: buildHeaderBadges(detail),
      summaryFields: buildSummaryFields(detail),
      interpretation: buildInterpretation(detail),
      exportState: buildExportState(detail),
      notices: buildNotices(detail),
      sections: buildSections(detail),
      developerDetailsLabel: detail.__dumpObjectsEnabled ? 'Developer details (raw dump active)' : 'Developer details (sanitized JSON)'
    };
  }

  function safeFilenamePart(value, fallback = 'item') {
    const cleaned = String(value || fallback)
      .replace(/[^a-zA-Z0-9._-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 80);
    return cleaned || fallback;
  }

  function serializeBodyPreview(row) {
    const preview = domain.createBodyPreview
      ? domain.createBodyPreview(row)
      : {
        bodyStatus: row?.bodyCaptureStatus || row?.status || 'metadata_only',
        bodyRenderStatus: 'not_renderable',
        bodyExportStatus: 'not_exportable',
        reason: row?.bodyCaptureReason || row?.reason || 'BODY_NOT_CAPTURED',
        preview: ''
      };
    return {
      state: preview.bodyStatus,
      bodyStatus: preview.bodyStatus,
      bodyRenderStatus: preview.bodyRenderStatus,
      bodyExportStatus: preview.bodyExportStatus,
      encoding: preview.encoding,
      mimeType: preview.mimeType,
      bytes: preview.bodySizeBytes,
      capturedBytes: preview.capturedBytes,
      renderedBytes: preview.renderedBytes,
      renderedChars: preview.renderedChars,
      totalChars: preview.totalChars,
      exportable: !!preview.exportable,
      previewKind: preview.previewKind,
      reason: preview.reason,
      message: preview.message,
      redactionApplied: !!row?.bodyRedactionApplied,
      preview: preview.preview || ''
    };
  }

  function serializeNetworkItem(row) {
    const requestHeaders = safeHeaders(row?.requestHeadersRedacted || row?.requestHeaders || []);
    const responseHeaders = safeHeaders(row?.responseHeadersRedacted || row?.responseHeaders || []);
    const bodyPreview = serializeBodyPreview(row);
    const bodyPayload = {
      id: row?.id || null,
      url: null,
      urlHash: row?.urlHash || urlHashFor(row),
      method: row?.method || null,
      statusCode: row?.statusCode ?? null,
      mimeType: row?.mimeType || row?.bodyMimeType || null,
      bodyMimeType: row?.bodyMimeType || row?.mimeType || null,
      type: row?.type || null,
      bodyStatus: row?.bodyStatus || row?.bodyCaptureStatus || row?.status || null,
      bodyCaptureStatus: row?.bodyCaptureStatus || row?.status || null,
      bodyCaptureReason: row?.bodyCaptureReason || row?.reason || null,
      bodyEncoding: row?.bodyEncoding || row?.encoding || null,
      bodySizeBytes: row?.bodySizeBytes ?? row?.bodyCapturedBytes ?? null,
      bodyCapturedBytes: row?.bodyCapturedBytes || 0,
      bodyRedactionApplied: !!row?.bodyRedactionApplied,
      bodyRenderStatus: row?.bodyRenderStatus || null,
      bodyExportStatus: row?.bodyExportStatus || null,
      content: typeof row?.content === 'string' ? row.content : null,
      encoding: row?.encoding || '',
      contentKind: row?.contentKind || null
    };
    const sanitized = {
      schemaVersion: 'backtools.inspectable-item.v1',
      kind: 'network',
      id: row?.id || null,
      collector: row?.collector || 'network_har',
      urlRedacted: displayUrlFor(row),
      urlHash: urlHashFor(row),
      method: row?.method || null,
      statusCode: row?.statusCode ?? null,
      host: row?.host || null,
      type: row?.type || null,
      mimeType: row?.mimeType || null,
      resourceCategory: row?.resourceCategory || null,
      visibleByDefault: row?.visibleByDefault !== false,
      size: row?.size ?? null,
      bodySize: row?.bodySize ?? null,
      bodySizeBytes: row?.bodySizeBytes ?? row?.bodyCapturedBytes ?? null,
      status: row?.bodyCaptureStatus || row?.status || null,
      reason: row?.bodyCaptureReason || row?.reason || null,
      bodyCapturedBytes: row?.bodyCapturedBytes || 0,
      bodyEncoding: row?.bodyEncoding || row?.encoding || null,
      bodyRenderStatus: bodyPreview.bodyRenderStatus,
      bodyExportStatus: bodyPreview.bodyExportStatus,
      bodyExportable: !!bodyPreview.exportable,
      redactionApplied: !!row?.redactionApplied,
      redactedFields: row?.redactedFields || [],
      request: {
        method: row?.method || null,
        urlRedacted: displayUrlFor(row),
        headers: requestHeaders
      },
      response: {
        statusCode: row?.statusCode ?? null,
        headers: responseHeaders
      },
      body: bodyPreview,
      cookies: {
        requestCookieHeaderObserved: requestHeaders.some(h => h.name.toLowerCase() === 'cookie'),
        responseSetCookieHeaderObserved: responseHeaders.some(h => h.name.toLowerCase() === 'set-cookie')
      }
    };

    return {
      kind: 'network',
      title: `Network request ${text(row?.method, 'GET')} ${text(row?.statusCode, '-')}`,
      subtitle: sanitized.urlRedacted,
      status: sanitized.status,
      reason: sanitized.reason,
      rawJson: sanitized,
      exportJson: sanitized,
      exportFilename: `network-request-${safeFilenamePart(row?.urlHash || row?.id || 'request')}.json`,
      bodyPayload,
      tabs: [
        { id: 'summary', label: 'Summary', type: 'fields', fields: [
          field('Method', sanitized.method),
          field('Status', sanitized.statusCode),
          field('URL', sanitized.urlRedacted),
          field('Host', sanitized.host),
          field('MIME', sanitized.mimeType),
          field('Category', resourceLabel(row)),
          field('Capture status', sanitized.status),
          field('Render status', sanitized.bodyRenderStatus),
          field('Body exportable', sanitized.bodyExportable ? 'yes' : 'no'),
          field('Reason', sanitized.reason)
        ] },
        { id: 'request', label: 'Request', type: 'fields', fields: [
          field('Method', sanitized.method),
          field('URL', sanitized.urlRedacted),
          field('Request headers', requestHeaders.length)
        ] },
        { id: 'response', label: 'Response', type: 'fields', fields: [
          field('Status code', sanitized.statusCode),
          field('MIME', sanitized.mimeType),
          field('Body status', sanitized.status),
          field('Encoding', sanitized.bodyEncoding),
          field('Captured bytes', sanitized.bodySizeBytes ?? sanitized.bodyCapturedBytes),
          field('Rendered bytes/chars', `${bodyPreview.renderedBytes || 0} bytes / ${bodyPreview.renderedChars || 0} chars`),
          field('Exportable', sanitized.bodyExportable ? 'yes' : 'no'),
          field('Reason', sanitized.reason)
        ] },
        { id: 'headers', label: 'Headers', type: 'jsonBlocks', blocks: [
          jsonBlock('Request headers', requestHeaders),
          jsonBlock('Response headers', responseHeaders)
        ] },
        { id: 'body', label: 'Body Preview', type: 'bodyPreview', body: bodyPreview },
        { id: 'cookies', label: 'Cookies', type: 'fields', fields: [
          field('Cookie header observed', sanitized.cookies.requestCookieHeaderObserved ? 'yes' : 'no'),
          field('Set-Cookie observed', sanitized.cookies.responseSetCookieHeaderObserved ? 'yes' : 'no')
        ] },
        { id: 'raw', label: 'Raw JSON', type: 'rawJson' },
        { id: 'export', label: 'Export', type: 'fields', fields: [
          field('Individual export', 'Sanitized JSON download'),
          field('Individual body download', bodyPreview.exportable ? 'Available in Body Preview' : 'Not available'),
          field('Filename', `network-request-${safeFilenamePart(row?.urlHash || row?.id || 'request')}.json`)
        ] }
      ]
    };
  }

  function serializeSourceItem(row) {
    const isBase64 = row?.encoding === 'base64';
    const hasContent = typeof row?.content === 'string' && row.content.length > 0;
    const contentPreview = hasContent
      ? (isBase64 ? '[base64 source content captured; preview omitted]' : truncate(row.content))
      : '';
    const sanitized = {
      schemaVersion: 'backtools.inspectable-item.v1',
      kind: 'source',
      id: row?.id || null,
      collector: row?.collector || 'chrome_sources',
      urlRedacted: displayUrlFor(row),
      urlHash: urlHashFor(row),
      path: row?.path || null,
      host: row?.host || null,
      type: row?.type || null,
      status: row?.status || null,
      reason: row?.reason || null,
      size: row?.size ?? null,
      encoding: row?.encoding || null,
      exportable: !!row?.exportable,
      resourceCategory: row?.resourceCategory || null,
      visibleByDefault: row?.visibleByDefault !== false,
      redactionApplied: !!row?.redactionApplied,
      redactedFields: row?.redactedFields || [],
      content: {
        state: hasContent ? (isBase64 ? 'captured_base64' : 'captured_text') : 'not_available',
        size: row?.size ?? null,
        encoding: row?.encoding || null,
        preview: contentPreview
      }
    };
    const filename = `source-resource-${safeFilenamePart(row?.urlHash || row?.id || 'resource')}.json`;
    return {
      kind: 'source',
      title: `Source resource ${text(row?.type, 'resource')}`,
      subtitle: sanitized.urlRedacted,
      status: sanitized.status,
      reason: sanitized.reason,
      rawJson: sanitized,
      exportJson: sanitized,
      exportFilename: filename,
      tabs: [
        { id: 'summary', label: 'Summary', type: 'fields', fields: [
          field('URL', sanitized.urlRedacted),
          field('Type', sanitized.type),
          field('Status', sanitized.status),
          field('Reason', sanitized.reason),
          field('Exportable', sanitized.exportable ? 'yes' : 'no'),
          field('Category', resourceLabel(row))
        ] },
        { id: 'content', label: 'Content Preview', type: 'text', text: contentPreview || 'Content is not available in the current state.' },
        { id: 'metadata', label: 'Metadata', type: 'fields', fields: [
          field('Collector', sanitized.collector),
          field('Host', sanitized.host),
          field('Path', sanitized.path),
          field('Size', sanitized.size),
          field('Encoding', sanitized.encoding),
          field('Redaction applied', sanitized.redactionApplied ? 'yes' : 'no')
        ] },
        { id: 'raw', label: 'Raw JSON', type: 'rawJson' },
        { id: 'export', label: 'Export', type: 'fields', fields: [
          field('Individual export', 'Sanitized JSON download'),
          field('Filename', filename),
          field('Content file export', 'Planned')
        ], notice: 'Individual source export currently downloads sanitized metadata and preview JSON only. Full source content remains handled by the main ZIP pipeline.' }
      ]
    };
  }

  function getCookieRawValue(cookie) {
    const candidate = cookie?.rawValue ?? cookie?.value?.rawValue ?? cookie?.value;
    if (candidate === undefined || candidate === null) return null;
    const value = String(candidate);
    if (PROTECTED_VALUES.has(value.toLowerCase())) return null;
    return value;
  }

  function maskCookieValue(value, cookie = {}) {
    const masked = domain.maskCookieValue
      ? domain.maskCookieValue(value, cookie)
      : {
        rawAvailable: value !== undefined && value !== null,
        masked: value == null ? 'not_available' : '[masked]',
        length: value == null ? null : String(value).length,
        maskPolicy: value == null ? 'not_available' : MASK_POLICY_LONG
      };
    return {
      ...masked,
      valueState: masked.rawAvailable ? 'masked' : 'not_available',
      valueMasked: masked.masked,
      valueLength: masked.length,
      visibleRawChars: masked.maskPolicy === 'full_mask_when_short' || masked.maskPolicy === 'not_available'
        ? 0
        : masked.maskPolicy === 'prefix4_middle3_when_long'
          ? 7
          : 4,
      maskPolicy: masked.maskPolicy
    };
  }

  function isPossibleJwt(value) {
    return domain.isPossibleJwt ? domain.isPossibleJwt(value) : /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(String(value || ''));
  }

  function classifyCookieSensitivity(cookie, rawValue) {
    const reasons = [];
    const name = String(cookie?.name || '').toLowerCase();
    const classification = domain.classifyCookieValue ? domain.classifyCookieValue(cookie?.name, rawValue) : 'general';
    if (/(session|sess|sid|auth|token|access|refresh|jwt|id_token|bearer|secret|password|credential|csrf|xsrf|login)/.test(name)) reasons.push('sensitive_name');
    if (rawValue && isPossibleJwt(rawValue)) reasons.push('possible_jwt');
    if (rawValue && /bearer\s+/i.test(rawValue)) reasons.push('possible_bearer_token');
    if (rawValue && String(rawValue).length >= 32 && /(token|auth|session|sid|jwt)/.test(name)) reasons.push('long_session_like_value');
    return {
      sensitive: reasons.length > 0,
      possibleToken: reasons.length > 0,
      sensitivityReasons: reasons,
      classification
    };
  }

  async function fingerprintValue(value) {
    if (value === undefined || value === null) return null;
    if (domain.buildCookieFingerprint) return domain.buildCookieFingerprint(value);
    return null;
  }

  async function serializeCookieItem(cookie, context = {}) {
    const rawValue = getCookieRawValue(cookie);
    const dumpObjectsEnabled = context?.state?.dumpObjectsEnabled === true || context?.dumpObjectsEnabled === true;
    const sanitizedCookie = domain.buildSanitizedCookie
      ? domain.buildSanitizedCookie(cookie)
      : null;
    const masked = sanitizedCookie?.value || maskCookieValue(rawValue, cookie);
    const sensitivity = classifyCookieSensitivity(cookie, rawValue);
    const fingerprint = masked.fingerprint || (rawValue == null ? null : await fingerprintValue(rawValue));
    const observedIn = sanitizedCookie?.observedIn || (cookie?.observedIn || []).map(item => ({
      ...item,
      url: redactUrlValue(item?.url || item?.urlRedacted || '')
    }));
    const sanitized = {
      schemaVersion: 'backtools.inspectable-item.v1',
      kind: 'cookie',
      id: cookie?.id || null,
      name: cookie?.name || null,
      domain: cookie?.domain || cookie?.originHost || null,
      originHost: cookie?.originHost || null,
      hostOnly: cookie?.hostOnly ?? null,
      path: cookie?.path || null,
      source: cookie?.source || 'unknown',
      httpOnly: cookie?.httpOnly ?? null,
      secure: cookie?.secure ?? null,
      sameSite: cookie?.sameSite || null,
      expires: cookie?.expires || null,
      expirationDate: cookie?.expirationDate || null,
      maxAge: cookie?.maxAge || null,
      session: cookie?.session ?? null,
      partitionKey: cookie?.partitionKey || null,
      storeId: cookie?.storeId || null,
      value: {
        ...masked,
        rawIncluded: false
      },
      valueState: masked.rawAvailable ? 'masked' : 'not_available',
      valueMasked: masked.masked || masked.valueMasked || 'not_available',
      valueLength: masked.length ?? masked.valueLength ?? null,
      visibleRawChars: masked.visibleRawChars,
      valueFingerprint: fingerprint,
      maskPolicy: masked.maskPolicy,
      sensitive: sensitivity.sensitive,
      possibleToken: sensitivity.possibleToken,
      sensitivityReasons: sensitivity.sensitivityReasons,
      classification: sanitizedCookie?.classification || sensitivity.classification,
      risk: sanitizedCookie?.risk || cookie?.risk || [],
      exportability: sanitizedCookie?.exportability || cookie?.exportability || {
        sanitizedJson: true,
        html: true,
        netscapeSanitized: true,
        rawJson: rawValue != null,
        rawNetscape: rawValue != null,
        rawUnavailableReason: rawValue == null ? 'Raw value is not available from the current collector.' : null
      },
      sources: cookie?.sources || [],
      observedIn,
      sourceUrls: (cookie?.sourceUrls || []).map(redactUrlValue),
      observedInResponse: !!cookie?.observedInResponse,
      observedInRequest: !!cookie?.observedInRequest,
      isFirstParty: cookie?.isFirstParty ?? null,
      isThirdParty: cookie?.isThirdParty ?? null,
      findings: cookie?.findings || [],
      rawCookieExportEnabled: rawValue != null,
      rawNotice: rawValue == null ? 'Raw value is not available from the current collector.' : dumpObjectsEnabled ? 'Raw value is visible because Dump objects is enabled for this DevTools session.' : 'Raw value is available only after explicit confirmation.'
    };
    if (dumpObjectsEnabled && rawValue != null) {
      sanitized.value.rawIncluded = true;
      sanitized.value.rawValue = rawValue;
      sanitized.valueState = 'raw';
    } else {
      delete sanitized.value.rawValue;
    }
    const filename = `cookie-${safeFilenamePart(cookie?.name || 'cookie')}-${safeFilenamePart(cookie?.domain || cookie?.originHost || 'unknown')}.json`;
    const valueFields = dumpObjectsEnabled && rawValue != null
      ? [
        field('Raw value', rawValue),
        field('Length', sanitized.valueLength),
        field('Fingerprint', sanitized.valueFingerprint || 'not_available'),
        field('Fingerprint algorithm', sanitized.valueFingerprint?.algorithm || sanitized.value?.fingerprintAlgorithm || 'not_available'),
        field('Raw availability', 'available'),
        field('Value mode', 'raw')
      ]
      : [
        field('Protected value', sanitized.valueMasked || 'not_available'),
        field('Length', sanitized.valueLength),
        field('Fingerprint', sanitized.valueFingerprint || 'not_available'),
        field('Fingerprint algorithm', sanitized.valueFingerprint?.algorithm || sanitized.value?.fingerprintAlgorithm || 'not_available'),
        field('Raw availability', rawValue != null ? 'available' : 'unavailable'),
        field('Mask policy', sanitized.maskPolicy),
        field('Redaction reason', sanitized.value?.redactionReason || sanitized.rawNotice)
      ];
    return {
      kind: 'cookie',
      title: `Cookie ${text(cookie?.name, 'unknown')}`,
      subtitle: text(sanitized.domain),
      status: sanitized.valueState,
      reason: sanitized.rawNotice,
      rawJson: sanitized,
      exportJson: sanitized,
      exportFilename: filename,
      __dumpObjectsEnabled: dumpObjectsEnabled,
      rawPayload: {
        rawAvailable: rawValue != null,
        rawValue,
        name: cookie?.name || null,
        domain: sanitized.domain,
        source: sanitized.source
      },
      tabs: [
        { id: 'summary', label: 'Summary', type: 'fields', fields: [
          field('Name', sanitized.name),
          field('Domain', sanitized.domain),
          field('Path', sanitized.path),
          field('Source', sanitized.source),
          field('Classification', sanitized.classification),
          field('Risk', sanitized.risk.join(', ') || '-'),
          field('Findings', sanitized.findings.join(', ') || '-')
        ] },
        { id: 'scope', label: 'Scope', type: 'fields', fields: [
          field('Domain', sanitized.domain),
          field('Host only', boolText(sanitized.hostOnly)),
          field('Path', sanitized.path),
          field('SameSite', sanitized.sameSite),
          field('Partition key', sanitized.partitionKey),
          field('Store ID', sanitized.storeId),
          field('Expires', sanitized.expires || sanitized.expirationDate || (sanitized.session ? 'session' : '-'))
        ] },
        { id: 'security', label: 'Security', type: 'fields', fields: [
          field('Secure', boolText(sanitized.secure)),
          field('HttpOnly', boolText(sanitized.httpOnly)),
          field('SameSite', sanitized.sameSite),
          field('Session or persistent', sanitized.session ? 'session' : 'persistent'),
          field('Auth-like', sanitized.possibleToken ? 'yes' : 'no'),
          field('Replay risk if raw', rawValue != null ? 'yes' : 'unavailable'),
          field('Sensitivity reasons', sanitized.sensitivityReasons.join(', ') || '-'),
          field('Findings', sanitized.findings.join(', ') || '-')
        ] },
        { id: 'observed', label: 'Observed In', type: 'jsonBlocks', blocks: [
          jsonBlock('Observed entries', sanitized.observedIn),
          jsonBlock('Sources', sanitized.sources)
        ] },
        { id: 'value', label: 'Value', type: 'cookieValue', fields: valueFields },
        { id: 'raw', label: 'Raw JSON', type: 'rawJson' },
        { id: 'export', label: 'Export', type: 'cookieExport', fields: [
          field('Export sanitized cookie JSON', filename),
          field('Export all sanitized cookies JSON', 'Available in main ZIP as cookies/cookies.sanitized.json'),
          field('Export cookies HTML', 'Available in main ZIP as cookies/cookies.html'),
          field('Export Netscape sanitized', 'Available in main ZIP as cookies/cookies.netscape.sanitized.txt'),
          field('Advanced raw cookie JSON', rawValue != null ? 'available after confirmation' : 'unavailable'),
          field('Advanced raw Netscape cookie jar', rawValue != null ? 'available after confirmation' : 'unavailable')
        ], notice: sanitized.rawNotice }
      ]
    };
  }

  function serializeApplicationStorageItem(row, context = {}) {
    const dumpObjectsEnabled = context?.state?.dumpObjectsEnabled === true || context?.dumpObjectsEnabled === true;
    const sanitized = domain.buildSanitizedStorageEntry
      ? domain.buildSanitizedStorageEntry(row)
      : {
        ...row,
        value: { ...(row?.value || {}), rawIncluded: false },
        rawIncluded: false
      };
    const rawAvailable = !!row?.value?.rawAvailable && row?.rawValue !== undefined && row?.rawValue !== null;
    if (dumpObjectsEnabled && rawAvailable) {
      sanitized.rawValue = String(row.rawValue);
      sanitized.rawIncluded = true;
      sanitized.containsRawApplicationData = true;
      sanitized.value = {
        ...(sanitized.value || {}),
        rawIncluded: true,
        rawValue: String(row.rawValue)
      };
    } else {
      delete sanitized.rawValue;
      if (sanitized.value) delete sanitized.value.rawValue;
    }
    const filename = `application-${safeFilenamePart(row?.storageType || row?.type || 'storage')}-${safeFilenamePart(row?.key || 'key')}.json`;
    const valueFields = dumpObjectsEnabled && rawAvailable
      ? [
        field('Raw value', String(row.rawValue)),
        field('Length', row?.value?.length ?? row?.valueLength),
        field('Type', row?.storageType || row?.type),
        field('Fingerprint', row?.value?.fingerprint || 'not_available'),
        field('Value mode', 'raw'),
        field('Sensitivity reasons', (row?.sensitivityReasons || []).join(', ') || '-')
      ]
      : [
        field('Protected value', row?.value?.masked || 'not_available'),
        field('Length', row?.value?.length ?? row?.valueLength),
        field('Type', row?.storageType || row?.type),
        field('Fingerprint', row?.value?.fingerprint || 'not_available'),
        field('Mask policy', row?.value?.maskPolicy),
        field('Redaction reason', row?.value?.redactionReason),
        field('Sensitivity reasons', (row?.sensitivityReasons || []).join(', ') || '-')
      ];
    return {
      kind: 'application_storage',
      title: `${text(row?.storageType || row?.type, 'Storage')} ${text(row?.key, 'key')}`,
      subtitle: text(row?.origin || row?.frameUrl),
      status: dumpObjectsEnabled && rawAvailable ? 'raw' : row?.sensitive ? 'sensitive_masked' : 'masked',
      reason: dumpObjectsEnabled && rawAvailable ? 'Raw value is visible because Dump objects is enabled for this DevTools session.' : row?.value?.redactionReason || 'Storage value masked by default.',
      rawJson: sanitized,
      exportJson: sanitized,
      exportFilename: filename,
      __dumpObjectsEnabled: dumpObjectsEnabled,
      rawPayload: {
        rawAvailable,
        rawValue: row?.rawValue ?? null,
        key: row?.key || null,
        storageType: row?.storageType || row?.type || null,
        origin: row?.origin || null
      },
      tabs: [
        { id: 'summary', label: 'Summary', type: 'fields', fields: [
          field('Type', row?.storageType || row?.type),
          field('Key', row?.key),
          field('Classification', row?.classification),
          field('Sensitive', row?.sensitive ? 'yes' : 'no'),
          field('Raw availability', row?.value?.rawAvailable ? 'available' : 'unavailable')
        ] },
        { id: 'scope', label: 'Scope', type: 'fields', fields: [
          field('Origin', row?.origin),
          field('Frame URL', row?.frameUrl),
          field('Storage type', row?.storageType || row?.type)
        ] },
        { id: 'value', label: 'Value', type: 'storageValue', fields: valueFields },
        { id: 'raw', label: 'Raw JSON', type: 'rawJson' },
        { id: 'export', label: 'Export', type: 'fields', fields: [
          field('Individual export', 'Sanitized JSON download'),
          field('Main sanitized export', 'Available in main ZIP as application/storage.sanitized.json'),
          field('Raw export', row?.value?.rawAvailable ? 'Available only in main ZIP after explicit confirmation' : 'Unavailable')
        ] }
      ]
    };
  }

  function serializeApplicationIndexedDbItem(row) {
    const sanitized = {
      schemaVersion: 'backtools.inspectable-item.v1',
      kind: 'application_indexeddb',
      type: 'indexedDB',
      id: row?.id || null,
      origin: row?.origin || null,
      name: row?.name || null,
      version: row?.version ?? null,
      objectStoreCount: row?.objectStoreCount || 0,
      totalRecordCount: row?.totalRecordCount || 0,
      objectStores: row?.objectStores || [],
      error: row?.error || null,
      containsRawApplicationData: false
    };
    const filename = `application-indexeddb-${safeFilenamePart(row?.name || row?.id || 'database')}.json`;
    return {
      kind: 'application_indexeddb',
      title: `IndexedDB ${text(row?.name, 'database')}`,
      subtitle: text(row?.origin),
      status: row?.error ? 'partial' : 'inventory',
      reason: row?.error || 'Inventory only; stored values are not collected.',
      rawJson: sanitized,
      exportJson: sanitized,
      exportFilename: filename,
      tabs: [
        { id: 'summary', label: 'Summary', type: 'fields', fields: [
          field('Database', sanitized.name),
          field('Version', sanitized.version),
          field('Object stores', sanitized.objectStoreCount),
          field('Record count', sanitized.totalRecordCount),
          field('Error', sanitized.error)
        ] },
        { id: 'scope', label: 'Scope', type: 'fields', fields: [
          field('Origin', sanitized.origin),
          field('Type', sanitized.type)
        ] },
        { id: 'inventory', label: 'Inventory', type: 'jsonBlocks', blocks: [
          jsonBlock('Object stores', sanitized.objectStores)
        ] },
        { id: 'raw', label: 'Raw JSON', type: 'rawJson' },
        { id: 'export', label: 'Export', type: 'fields', fields: [
          field('Main export', 'Available in main ZIP as application/indexeddb.inventory.json'),
          field('Values', 'Not collected by the MVP')
        ] }
      ]
    };
  }

  function serializeApplicationCacheStorageItem(row) {
    const sanitized = {
      schemaVersion: 'backtools.inspectable-item.v1',
      kind: 'application_cache_storage',
      type: 'cacheStorage',
      id: row?.id || null,
      origin: row?.origin || null,
      name: row?.name || null,
      requestCount: row?.requestCount || 0,
      requests: row?.requests || [],
      error: row?.error || null,
      containsRawApplicationData: false
    };
    const filename = `application-cache-${safeFilenamePart(row?.name || row?.id || 'cache')}.json`;
    return {
      kind: 'application_cache_storage',
      title: `Cache Storage ${text(row?.name, 'cache')}`,
      subtitle: text(row?.origin),
      status: row?.error ? 'partial' : 'inventory',
      reason: row?.error || 'Inventory only; response bodies are not collected.',
      rawJson: sanitized,
      exportJson: sanitized,
      exportFilename: filename,
      tabs: [
        { id: 'summary', label: 'Summary', type: 'fields', fields: [
          field('Cache name', sanitized.name),
          field('Requests', sanitized.requestCount),
          field('Error', sanitized.error)
        ] },
        { id: 'scope', label: 'Scope', type: 'fields', fields: [
          field('Origin', sanitized.origin),
          field('Type', sanitized.type)
        ] },
        { id: 'inventory', label: 'Inventory', type: 'jsonBlocks', blocks: [
          jsonBlock('Requests', sanitized.requests)
        ] },
        { id: 'raw', label: 'Raw JSON', type: 'rawJson' },
        { id: 'export', label: 'Export', type: 'fields', fields: [
          field('Main export', 'Available in main ZIP as application/cache-storage.inventory.json'),
          field('Response bodies', 'Not collected by the MVP')
        ] }
      ]
    };
  }

  function serializeApplicationServiceWorkerItem(row) {
    const sanitized = {
      schemaVersion: 'backtools.inspectable-item.v1',
      kind: 'application_service_worker',
      type: 'serviceWorker',
      ...row,
      containsRawApplicationData: false
    };
    const filename = `application-service-worker-${safeFilenamePart(row?.scopeHash || row?.id || 'registration')}.json`;
    return {
      kind: 'application_service_worker',
      title: 'Service Worker registration',
      subtitle: text(row?.scope),
      status: row?.activeState || row?.waitingState || row?.installingState || 'inventory',
      reason: 'Registration metadata only.',
      rawJson: sanitized,
      exportJson: sanitized,
      exportFilename: filename,
      tabs: [
        { id: 'summary', label: 'Summary', type: 'fields', fields: [
          field('Scope', row?.scope),
          field('Active state', row?.activeState),
          field('Waiting state', row?.waitingState),
          field('Installing state', row?.installingState)
        ] },
        { id: 'scope', label: 'Scope', type: 'fields', fields: [
          field('Origin', row?.origin),
          field('Scope', row?.scope),
          field('Update via cache', row?.updateViaCache)
        ] },
        { id: 'inventory', label: 'Inventory', type: 'fields', fields: [
          field('Active script', row?.activeScriptUrl),
          field('Waiting script', row?.waitingScriptUrl),
          field('Installing script', row?.installingScriptUrl)
        ] },
        { id: 'raw', label: 'Raw JSON', type: 'rawJson' },
        { id: 'export', label: 'Export', type: 'fields', fields: [
          field('Main export', 'Included in application/APPLICATION_REPORT.json')
        ] }
      ]
    };
  }

  function serializeApplicationManifestItem(row) {
    const sanitized = {
      schemaVersion: 'backtools.inspectable-item.v1',
      kind: 'application_manifest',
      type: 'manifest',
      ...row,
      containsRawApplicationData: false
    };
    const filename = `application-manifest-${safeFilenamePart(row?.hrefHash || row?.id || 'manifest')}.json`;
    return {
      kind: 'application_manifest',
      title: 'Manifest metadata',
      subtitle: text(row?.href),
      status: row?.status || 'not_found',
      reason: row?.note || row?.error || 'Manifest body is not fetched by the MVP collector.',
      rawJson: sanitized,
      exportJson: sanitized,
      exportFilename: filename,
      tabs: [
        { id: 'summary', label: 'Summary', type: 'fields', fields: [
          field('Status', row?.status),
          field('Href', row?.href),
          field('Rel', row?.rel),
          field('Crossorigin', row?.crossorigin)
        ] },
        { id: 'scope', label: 'Scope', type: 'fields', fields: [
          field('Origin', row?.origin),
          field('Href hash', row?.hrefHash)
        ] },
        { id: 'inventory', label: 'Inventory', type: 'fields', fields: [
          field('Note', row?.note),
          field('Error', row?.error)
        ] },
        { id: 'raw', label: 'Raw JSON', type: 'rawJson' },
        { id: 'export', label: 'Export', type: 'fields', fields: [
          field('Main export', 'Included in application/APPLICATION_REPORT.json')
        ] }
      ]
    };
  }

  function serializeDiagnosticItem(item) {
    const sanitized = {
      schemaVersion: 'backtools.inspectable-item.v1',
      kind: 'diagnostic',
      type: item?.type || 'reason_group',
      reason: item?.reason || item?.event || null,
      count: item?.count ?? null,
      level: item?.level || null,
      detail: redactUrlValue(item?.detail || ''),
      logs: (item?.logs || []).map(log => ({
        timestamp: log.timestamp || null,
        level: log.level || null,
        event: log.event || null,
        detail: redactUrlValue(log.detail || '')
      }))
    };
    return {
      kind: 'diagnostic',
      title: `Diagnostic ${text(sanitized.reason, 'item')}`,
      subtitle: text(sanitized.type),
      status: sanitized.level || sanitized.type,
      reason: sanitized.reason,
      rawJson: sanitized,
      exportJson: sanitized,
      exportFilename: `diagnostic-${safeFilenamePart(sanitized.reason || sanitized.type || 'item')}.json`,
      tabs: [
        { id: 'summary', label: 'Summary', type: 'fields', fields: [
          field('Type', sanitized.type),
          field('Reason', sanitized.reason),
          field('Count', sanitized.count),
          field('Level', sanitized.level)
        ] },
        { id: 'details', label: 'Details', type: 'jsonBlocks', blocks: [
          jsonBlock('Matching logs', sanitized.logs)
        ] },
        { id: 'raw', label: 'Raw JSON', type: 'rawJson' }
      ]
    };
  }

  function serializeExportPlanItem(item) {
    const source = item?.resource || item || {};
    const sanitized = {
      schemaVersion: 'backtools.inspectable-item.v1',
      kind: 'export_plan_item',
      planBucket: item?.planBucket || null,
      id: source.id || item?.id || null,
      collector: source.collector || item?.collector || null,
      urlRedacted: displayUrlFor(source),
      urlHash: urlHashFor(source),
      zipPath: item?.zipPath || source.zipPath || null,
      exportStatus: item?.exportStatus || source.exportStatus || (item?.planBucket === 'planned_file' ? 'planned' : null),
      reason: item?.reason || source.reason || null,
      resourceCategory: source.resourceCategory || item?.resourceCategory || null,
      visibleByDefault: source.visibleByDefault !== false,
      contentKind: item?.contentKind || source.contentKind || null,
      mimeType: item?.mimeType || source.mimeType || null
    };
    return {
      kind: 'export_plan_item',
      title: `Export plan item ${text(sanitized.exportStatus, 'planned')}`,
      subtitle: sanitized.urlRedacted,
      status: sanitized.exportStatus,
      reason: sanitized.reason,
      rawJson: sanitized,
      exportJson: sanitized,
      exportFilename: `export-plan-item-${safeFilenamePart(sanitized.urlHash || sanitized.id || 'item')}.json`,
      tabs: [
        { id: 'summary', label: 'Summary', type: 'fields', fields: [
          field('Bucket', sanitized.planBucket),
          field('Status', sanitized.exportStatus),
          field('URL', sanitized.urlRedacted),
          field('ZIP path', sanitized.zipPath),
          field('Reason', sanitized.reason)
        ] },
        { id: 'details', label: 'Details', type: 'fields', fields: [
          field('Collector', sanitized.collector),
          field('Category', resourceLabel(source)),
          field('Visible by default', sanitized.visibleByDefault ? 'yes' : 'no'),
          field('Content kind', sanitized.contentKind),
          field('MIME', sanitized.mimeType)
        ] },
        { id: 'raw', label: 'Raw JSON', type: 'rawJson' },
        { id: 'export', label: 'Export', type: 'fields', fields: [
          field('Individual export', 'Sanitized JSON download')
        ] }
      ]
    };
  }

  function resourceLabel(resource) {
    if (domain.resourceCategoryLabel) return domain.resourceCategoryLabel(resource?.resourceCategory);
    return text(resource?.resourceCategory);
  }

  async function serializeInspectableItem(kind, item, context = {}) {
    let detail = null;
    if (kind === 'network') detail = serializeNetworkItem(item, context);
    if (kind === 'source') detail = serializeSourceItem(item, context);
    if (kind === 'cookie') detail = await serializeCookieItem(item, context);
    if (kind === 'application_storage') detail = serializeApplicationStorageItem(item, context);
    if (kind === 'application_indexeddb') detail = serializeApplicationIndexedDbItem(item, context);
    if (kind === 'application_cache_storage') detail = serializeApplicationCacheStorageItem(item, context);
    if (kind === 'application_service_worker') detail = serializeApplicationServiceWorkerItem(item, context);
    if (kind === 'application_manifest') detail = serializeApplicationManifestItem(item, context);
    if (kind === 'diagnostic') detail = serializeDiagnosticItem(item, context);
    if (kind === 'export_plan_item') detail = serializeExportPlanItem(item, context);
    return prepareDetailPresentation(detail || serializeDiagnosticItem({ type: 'unknown', reason: `Unsupported item kind: ${kind}` }));
  }

  return {
    COOKIE_RAW_DISABLED_NOTICE,
    MASK_POLICY_LONG,
    maskCookieValue,
    classifyCookieSensitivity,
    fingerprintValue,
    serializeInspectableItem,
    serializeNetworkItem,
    serializeSourceItem,
    serializeCookieItem,
    serializeApplicationStorageItem,
    serializeApplicationIndexedDbItem,
    serializeApplicationCacheStorageItem,
    serializeApplicationServiceWorkerItem,
    serializeApplicationManifestItem,
    serializeDiagnosticItem,
    serializeExportPlanItem,
    prepareDetailPresentation,
    safeFilenamePart
  };
});
