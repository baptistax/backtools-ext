(function(root, factory) {
  const api = factory();
  root.BackToolsDomain = Object.assign(root.BackToolsDomain || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window, function() {
  const ResourceCategory = {
    SITE_FIRST_PARTY: 'site_first_party',
    SITE_THIRD_PARTY: 'site_third_party',
    EXTENSION_RESOURCE: 'extension_resource',
    BROWSER_INTERNAL: 'browser_internal',
    DEVTOOLS_INTERNAL: 'devtools_internal',
    DATA_URL: 'data_url',
    BLOB_URL: 'blob_url',
    UNKNOWN: 'unknown'
  };

  const HIDDEN_BY_DEFAULT = new Set([
    ResourceCategory.EXTENSION_RESOURCE,
    ResourceCategory.BROWSER_INTERNAL,
    ResourceCategory.DEVTOOLS_INTERNAL
  ]);

  const CATEGORY_LABELS = {
    [ResourceCategory.SITE_FIRST_PARTY]: 'Site',
    [ResourceCategory.SITE_THIRD_PARTY]: 'Third-party',
    [ResourceCategory.EXTENSION_RESOURCE]: 'Extension',
    [ResourceCategory.BROWSER_INTERNAL]: 'Browser internal',
    [ResourceCategory.DEVTOOLS_INTERNAL]: 'DevTools',
    [ResourceCategory.DATA_URL]: 'Data URL',
    [ResourceCategory.BLOB_URL]: 'Blob URL',
    [ResourceCategory.UNKNOWN]: 'Unknown'
  };

  function parseUrlMaybe(value) {
    try {
      return new URL(value);
    } catch {
      return null;
    }
  }

  function classifyResourceUrl(url, inspectedUrl) {
    const parsed = parseUrlMaybe(url || '');
    if (!parsed) return ResourceCategory.UNKNOWN;

    const scheme = parsed.protocol.replace(':', '').toLowerCase();
    if (scheme === 'http' || scheme === 'https') {
      const target = parseUrlMaybe(inspectedUrl || '');
      if (target && (target.protocol === 'http:' || target.protocol === 'https:')) {
        if (parsed.origin === target.origin || parsed.hostname === target.hostname) {
          return ResourceCategory.SITE_FIRST_PARTY;
        }
      }
      return ResourceCategory.SITE_THIRD_PARTY;
    }
    if (['chrome-extension', 'moz-extension', 'safari-web-extension', 'edge-extension'].includes(scheme)) {
      return ResourceCategory.EXTENSION_RESOURCE;
    }
    if (['chrome', 'edge', 'brave', 'opera', 'about'].includes(scheme)) {
      return ResourceCategory.BROWSER_INTERNAL;
    }
    if (['devtools', 'chrome-devtools'].includes(scheme)) {
      return ResourceCategory.DEVTOOLS_INTERNAL;
    }
    if (scheme === 'data') return ResourceCategory.DATA_URL;
    if (scheme === 'blob') return ResourceCategory.BLOB_URL;
    return ResourceCategory.UNKNOWN;
  }

  function isHiddenByDefaultCategory(category) {
    return HIDDEN_BY_DEFAULT.has(category);
  }

  function getDefaultVisibilityForCategory(category) {
    return !isHiddenByDefaultCategory(category);
  }

  function classifyResourceRecord(resource, inspectedUrl) {
    const resourceCategory = classifyResourceUrl(resource?.url || resource?.path || '', inspectedUrl);
    const visibleByDefault = getDefaultVisibilityForCategory(resourceCategory);
    return {
      ...resource,
      resourceCategory,
      visibleByDefault,
      hiddenByDefaultReason: visibleByDefault ? null : resourceCategory,
      userIncludedAdvanced: false
    };
  }

  function createDefaultResourceVisibilityFilters() {
    return {
      siteResources: true,
      thirdPartyResources: true,
      extensionResources: false,
      browserInternalResources: false,
      devtoolsInternalResources: false,
      dataBlobResources: true,
      unknownResources: true
    };
  }

  function getVisibilityFilterKey(category) {
    if (category === ResourceCategory.SITE_FIRST_PARTY) return 'siteResources';
    if (category === ResourceCategory.SITE_THIRD_PARTY) return 'thirdPartyResources';
    if (category === ResourceCategory.EXTENSION_RESOURCE) return 'extensionResources';
    if (category === ResourceCategory.BROWSER_INTERNAL) return 'browserInternalResources';
    if (category === ResourceCategory.DEVTOOLS_INTERNAL) return 'devtoolsInternalResources';
    if (category === ResourceCategory.DATA_URL || category === ResourceCategory.BLOB_URL) return 'dataBlobResources';
    return 'unknownResources';
  }

  function shouldShowResource(resource, filters) {
    const category = resource?.resourceCategory || ResourceCategory.UNKNOWN;
    const key = getVisibilityFilterKey(category);
    const effective = { ...createDefaultResourceVisibilityFilters(), ...(filters || {}) };
    return effective[key] !== false;
  }

  function getAdvancedExportOptionKey(category) {
    if (category === ResourceCategory.EXTENSION_RESOURCE) return 'includeExtensionResources';
    if (category === ResourceCategory.BROWSER_INTERNAL) return 'includeBrowserInternalResources';
    if (category === ResourceCategory.DEVTOOLS_INTERNAL) return 'includeDevtoolsInternalResources';
    return null;
  }

  function isIncludedByExportPolicy(resource, options) {
    const category = resource?.resourceCategory || ResourceCategory.UNKNOWN;
    const key = getAdvancedExportOptionKey(category);
    if (!key) return true;
    return !!(options && options[key]);
  }

  function getResourceUserIncludedAdvanced(resource, options) {
    const category = resource?.resourceCategory || ResourceCategory.UNKNOWN;
    return isHiddenByDefaultCategory(category) && isIncludedByExportPolicy(resource, options);
  }

  function buildCategoryTotals(resources) {
    const totals = {};
    Object.values(ResourceCategory).forEach(category => {
      totals[category] = 0;
    });
    (resources || []).forEach(resource => {
      const category = resource?.resourceCategory || ResourceCategory.UNKNOWN;
      totals[totals[category] == null ? ResourceCategory.UNKNOWN : category]++;
    });
    return totals;
  }

  function countHiddenByDefault(resources) {
    return (resources || []).filter(r => r?.visibleByDefault === false).length;
  }

  function countHiddenByCurrentFilters(resources, filters) {
    return (resources || []).filter(r => !shouldShowResource(r, filters)).length;
  }

  function resourceCategoryLabel(category) {
    return CATEGORY_LABELS[category] || CATEGORY_LABELS[ResourceCategory.UNKNOWN];
  }

  return {
    ResourceCategory,
    classifyResourceUrl,
    classifyResourceRecord,
    createDefaultResourceVisibilityFilters,
    shouldShowResource,
    getVisibilityFilterKey,
    isHiddenByDefaultCategory,
    isIncludedByExportPolicy,
    getAdvancedExportOptionKey,
    getResourceUserIncludedAdvanced,
    buildCategoryTotals,
    countHiddenByDefault,
    countHiddenByCurrentFilters,
    resourceCategoryLabel
  };
});
