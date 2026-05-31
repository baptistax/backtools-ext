(function () {
const SITE_RELATION = Object.freeze({
  FIRST_PARTY: "first_party",
  THIRD_PARTY: "third_party",
  BROWSER_INTERNAL: "browser_internal",
  EXTENSION: "extension",
  DEVTOOLS_INTERNAL: "devtools_internal",
  DATA: "data",
  UNKNOWN: "unknown"
});

const SENSITIVITY = Object.freeze({
  NONE: "none",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  SECRET_CANDIDATE: "secret_candidate"
});

const CONFIDENCE = Object.freeze({
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  UNKNOWN: "unknown"
});

const SEVERITY = Object.freeze({
  INFO: "info",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical"
});

const BODY_STATUS = Object.freeze({
  NOT_APPLICABLE: "not_applicable",
  NOT_REQUESTED: "not_requested",
  CAPTURED: "captured",
  UNAVAILABLE: "unavailable",
  TRUNCATED: "truncated",
  REDACTED: "redacted",
  FAILED: "failed"
});

const VISIBILITY = Object.freeze({
  DEFAULT_VISIBLE: "default_visible",
  HIDDEN_BY_DEFAULT: "hidden_by_default",
  ADVANCED_ONLY: "advanced_only",
  RAW_ONLY: "raw_only"
});

const ENTITY_TYPE = Object.freeze({
  TARGET: "target",
  ORIGIN: "origin",
  REQUEST: "request",
  RESPONSE_BODY: "response_body",
  RESOURCE: "resource",
  COOKIE: "cookie",
  STORAGE_ITEM: "storage_item",
  DIAGNOSTIC_ISSUE: "diagnostic_issue",
  EXPORT_ITEM: "export_item",
  FINDING: "finding",
  CONSOLE_EVENT: "console_event",
  USER_INTERACTION: "user_interaction",
  SECURITY_SIGNAL: "security_signal"
});

const RELATIONSHIP_TYPE = Object.freeze({
  TARGET_HAS_ORIGIN: "target_has_origin",
  ORIGIN_HAS_REQUEST: "origin_has_request",
  ORIGIN_HAS_RESOURCE: "origin_has_resource",
  ORIGIN_HAS_COOKIE: "origin_has_cookie",
  ORIGIN_HAS_STORAGE_ITEM: "origin_has_storage_item",
  REQUEST_HAS_RESPONSE_BODY: "request_has_response_body",
  REQUEST_BODY_AFFECTS_EXPORT: "request_body_affects_export",
  DIAGNOSTIC_AFFECTS_CAPABILITY: "diagnostic_affects_capability",
  FINDING_SUPPORTED_BY_EVIDENCE: "finding_supported_by_evidence",
  FINDING_AFFECTS_EXPORT: "finding_affects_export"
});

const VALIDATION_STATUS = Object.freeze({
  CANDIDATE: "candidate",
  OBSERVED: "observed",
  PARTIAL: "partial",
  LIMITED: "limited",
  NEEDS_VALIDATION: "needs_validation",
  UNKNOWN: "unknown"
});

const api = {
  BODY_STATUS,
  CONFIDENCE,
  ENTITY_TYPE,
  RELATIONSHIP_TYPE,
  SENSITIVITY,
  SEVERITY,
  SITE_RELATION,
  VALIDATION_STATUS,
  VISIBILITY
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = api;
}

globalThis.BackToolsEvidenceConstants = api;
})();
