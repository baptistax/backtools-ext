
(function (root, factory) {
  const api = factory(root);
  root.BackToolsExportStorage = Object.assign(root.BackToolsExportStorage || {}, api);
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : window, function (root) {
  const STORAGE_KEYS = [
    "theme",
    "exportOptions",
    "dumpObjectsEnabled",
    "evidenceGroupBy",
    "evidenceFilterText",
    "evidenceExpandedPaths",
    "exportOptionsOpen",
    "scanDurationSeconds"
  ];
  const memoryStore = {};

  function storageArea() {
    return root.chrome?.storage?.local || null;
  }

  function getMany(keys = STORAGE_KEYS) {
    const area = storageArea();
    if (!area || typeof area.get !== "function") {
      return Promise.resolve(keys.reduce((result, key) => {
        result[key] = memoryStore[key];
        return result;
      }, {}));
    }
    return new Promise((resolve) => {
      area.get(keys, (value) => {
        resolve(value || {});
      });
    });
  }

  function setMany(values) {
    const payload = values && typeof values === "object" ? values : {};
    Object.assign(memoryStore, payload);
    const area = storageArea();
    if (!area || typeof area.set !== "function") {
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      area.set(payload, () => resolve());
    });
  }

  return {
    STORAGE_KEYS,
    getMany,
    setMany
  };
});
