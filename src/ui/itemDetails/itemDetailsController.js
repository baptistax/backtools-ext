(function(root, factory) {
  const api = factory(root);
  root.BackToolsUI = Object.assign(root.BackToolsUI || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function(root) {
  async function openItemDetails(payload) {
    const ui = root.BackToolsUI || {};
    if (!ui.serializeInspectableItem || !ui.renderItemDetailsView) {
      throw new Error('Item details UI is not available.');
    }
    const detail = await ui.serializeInspectableItem(payload.kind, payload.item, payload.context || {});
    ui.renderItemDetailsView(detail, {
      onClose: closeItemDetails,
      onCopyUrl: copyDetailUrl,
      onCopy: copyDetailJson,
      onExport: exportDetailJson
    });
    return detail;
  }

  function closeItemDetails() {
    root.BackToolsUI?.closeItemDetailsView?.();
  }

  async function copyDetailJson(detail) {
    const json = JSON.stringify(detail.rawJson || {}, null, 2);
    if (root.navigator?.clipboard?.writeText) {
      await root.navigator.clipboard.writeText(json);
    }
  }

  async function copyDetailUrl(detail) {
    const value = detail.primaryUrl || detail.rawJson?.urlRedacted || detail.subtitle || '';
    if (!value || !root.navigator?.clipboard?.writeText) return false;
    try {
      await root.navigator.clipboard.writeText(String(value));
      return true;
    } catch {
      return false;
    }
  }

  function exportDetailJson(detail) {
    const payload = detail.exportJson || detail.rawJson || {};
    const json = JSON.stringify(payload, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = root.document.createElement('a');
    link.href = url;
    link.download = detail.exportFilename || 'back-tools-item.json';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  return {
    openItemDetails,
    closeItemDetails,
    copyDetailUrl,
    copyDetailJson,
    exportDetailJson
  };
});
