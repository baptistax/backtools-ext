/**
 * Shared JSDoc contracts for the current Back Tools runtime.
 *
 * These are documentation-only typedefs. They intentionally mirror the
 * current JavaScript data shapes instead of enforcing the future capture
 * schema.
 */

/**
 * @typedef {Object} ResourceRecord
 * @property {string} id
 * @property {string|null} url
 * @property {string|null} host
 * @property {string|null} scheme
 * @property {string} type
 * @property {'readable'|'metadata_only'|'unavailable'} status
 * @property {boolean} exportable
 * @property {string|null} reason
 * @property {string|null|undefined} content
 * @property {string|null|undefined} encoding
 * @property {string} collector
 */

/**
 * @typedef {Object} ExportPlan
 * @property {Array<Object>} plannedFiles
 * @property {Array<Object>} manifestOnlyResources
 * @property {Array<Object>} skippedResources
 * @property {Array<Object>} failedResources
 * @property {Object} counts
 */

/**
 * @typedef {Object} CookieObservation
 * @property {string} id
 * @property {string} key
 * @property {string} name
 * @property {'protected'} valueRepresentation
 * @property {Array<string>} sources
 * @property {Array<string>} findings
 */

/**
 * @typedef {Object} CurrentManifest
 * @property {string} generatedAt
 * @property {string|null} inspectedUrl
 * @property {Object} exportOptions
 * @property {Object} totals
 * @property {Array<Object>} exportedFiles
 * @property {Array<Object>} manifestOnlyResources
 * @property {Array<Object>} skippedResources
 * @property {Array<Object>} failedResources
 * @property {Object} reasonGroups
 * @property {Object} cookies
 */

(function(root) {
  root.BackToolsDomain = Object.assign(root.BackToolsDomain || {}, {});
  if (typeof module !== 'undefined' && module.exports) module.exports = {};
})(typeof globalThis !== 'undefined' ? globalThis : window);

