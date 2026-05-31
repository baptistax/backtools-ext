(function () {
function requireApi(path) {
  if (typeof require !== "function") {
    return null;
  }
  try {
    return require(path);
  } catch (_error) {
    return null;
  }
}

const evidence = requireApi("./evidenceTypes.js") || globalThis.BackToolsEvidenceTypes;
const redactionDomain = requireApi("../../domain/redaction.js") || globalThis.BackToolsDomain || {};

const {
  BODY_STATUS,
  CONFIDENCE,
  ENTITY_TYPE,
  RELATIONSHIP_TYPE,
  SENSITIVITY,
  SEVERITY,
  SITE_RELATION,
  VALIDATION_STATUS,
  VISIBILITY,
  createEntity,
  createEntityRef,
  createFinding,
  createRelationship
} = evidence;

const MODEL_VERSION = "backtools.evidence.v1";

const FINDING_CATEGORY = Object.freeze({
  CAPTURE_COMPLETENESS: "capture_completeness",
  BODY_AVAILABILITY: "body_availability",
  COOKIE_STORAGE_POSTURE: "cookie_storage_posture",
  THIRD_PARTY_ACTIVITY: "third_party_activity",
  EXPORT_IMPACT: "export_impact",
  TARGET_PLATFORM_LIMITATION: "target_platform_limitation",
  RAW_MODE_RISK: "raw_mode_risk"
});

const WORKFLOW_KEYS = Object.freeze([
  "development",
  "debugging",
  "security",
  "export",
  "explore"
]);

const WORKFLOW_RANK_BY_CATEGORY = Object.freeze({
  [FINDING_CATEGORY.CAPTURE_COMPLETENESS]: freezeRank(70, 80, 45, 85, 55),
  [FINDING_CATEGORY.BODY_AVAILABILITY]: freezeRank(60, 75, 45, 90, 50),
  [FINDING_CATEGORY.COOKIE_STORAGE_POSTURE]: freezeRank(35, 45, 75, 65, 55),
  [FINDING_CATEGORY.THIRD_PARTY_ACTIVITY]: freezeRank(35, 35, 80, 55, 65),
  [FINDING_CATEGORY.EXPORT_IMPACT]: freezeRank(50, 65, 45, 95, 55),
  [FINDING_CATEGORY.TARGET_PLATFORM_LIMITATION]: freezeRank(65, 70, 45, 80, 50),
  [FINDING_CATEGORY.RAW_MODE_RISK]: freezeRank(25, 35, 90, 85, 45)
});

const BODY_UNAVAILABLE_STATUSES = new Set([
  BODY_STATUS.NOT_REQUESTED,
  BODY_STATUS.UNAVAILABLE,
  BODY_STATUS.TRUNCATED,
  BODY_STATUS.REDACTED,
  BODY_STATUS.FAILED
]);

function freezeRank(development, debugging, security, exportRank, explore) {
  return Object.freeze({
    development,
    debugging,
    security,
    export: exportRank,
    explore
  });
}

function safeString(value) {
  return value === null || value === undefined ? "" : String(value);
}

function safeNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : 0;
}

function toArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function firstValue(...values) {
  for (const value of values) {
    const text = safeString(value).trim();
    if (text && text !== "Unavailable") {
      return text;
    }
  }
  return "";
}

function truncateText(value, limit = 180) {
  const text = redactText(value).replace(/\s+/g, " ").trim();
  if (text.length <= limit) {
    return text;
  }
  return `${text.slice(0, limit - 1)}...`;
}

function redactText(value) {
  const text = safeString(value);
  return text
    .replace(/https?:\/\/[^\s"'<>]+/g, (match) => redactUrl(match))
    .replace(/chrome-extension:\/\/[^\s"'<>]+/g, "chrome-extension://[extension]");
}

function redactUrl(value) {
  const text = safeString(value).trim();
  if (!text) {
    return "";
  }
  try {
    if (typeof redactionDomain.redactUrl === "function") {
      return redactionDomain.redactUrl(text);
    }
  } catch (_error) {}
  return text.replace(/([?&])([^=&?#]+)=([^&#]*)/g, (match, separator, key) => {
    return /token|auth|password|pass|secret|session|key|code|state/i.test(key)
      ? `${separator}${key}=[redacted]`
      : match;
  });
}

function stableHash(value) {
  try {
    if (typeof redactionDomain.hashSensitiveValue === "function") {
      return redactionDomain.hashSensitiveValue(value);
    }
  } catch (_error) {}

  const text = safeString(value);
  let hash = 0x811c9dc5;
  for (let index = 0; index < text.length; index++) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

function parseUrl(value) {
  try {
    return new URL(value);
  } catch (_error) {
    return null;
  }
}

function parseOrigin(value) {
  const text = safeString(value).trim();
  if (!text) {
    return null;
  }
  const parsed = parseUrl(text);
  if (parsed) {
    if (parsed.protocol === "data:") {
      return {
        origin: "data:",
        scheme: "data",
        host: null
      };
    }
    if (parsed.protocol === "blob:") {
      const inner = parseUrl(parsed.pathname);
      if (inner) {
        return {
          origin: inner.origin,
          scheme: inner.protocol.replace(/:$/, ""),
          host: inner.host || null
        };
      }
      return {
        origin: "blob:",
        scheme: "blob",
        host: null
      };
    }
    if (parsed.protocol === "chrome-extension:") {
      return {
        origin: "chrome-extension://[extension]",
        scheme: "chrome-extension",
        host: stableHash(parsed.host)
      };
    }
    return {
      origin: parsed.origin,
      scheme: parsed.protocol.replace(/:$/, ""),
      host: parsed.host || null
    };
  }
  if (/^[a-z][a-z0-9+.-]*:$/i.test(text)) {
    return {
      origin: text,
      scheme: text.replace(/:$/, "").toLowerCase(),
      host: null
    };
  }
  return null;
}

function originFromHost(host, targetOrigin) {
  const value = safeString(host).trim().replace(/^\./, "");
  if (!value || value === "unknown") {
    return null;
  }
  const target = parseOrigin(targetOrigin || "");
  const scheme = target && (target.scheme === "http" || target.scheme === "https") ? target.scheme : "https";
  return parseOrigin(`${scheme}://${value}`);
}

function classifySiteRelation(originInfo, targetOrigin, override) {
  const direct = safeString(override);
  if (Object.values(SITE_RELATION).includes(direct)) {
    return direct;
  }
  if (!originInfo) {
    return SITE_RELATION.UNKNOWN;
  }
  const scheme = safeString(originInfo.scheme).toLowerCase();
  if (scheme === "data" || scheme === "blob") {
    return SITE_RELATION.DATA;
  }
  if (scheme === "chrome-extension" || scheme === "moz-extension" || scheme === "safari-web-extension" || scheme === "edge-extension") {
    return SITE_RELATION.EXTENSION;
  }
  if (scheme === "devtools" || scheme === "chrome-devtools") {
    return SITE_RELATION.DEVTOOLS_INTERNAL;
  }
  if (scheme === "chrome" || scheme === "edge" || scheme === "brave" || scheme === "opera" || scheme === "about") {
    return SITE_RELATION.BROWSER_INTERNAL;
  }
  const target = parseOrigin(targetOrigin || "");
  if ((scheme === "http" || scheme === "https") && target && (target.scheme === "http" || target.scheme === "https")) {
    return originInfo.origin === target.origin || originInfo.host === target.host
      ? SITE_RELATION.FIRST_PARTY
      : SITE_RELATION.THIRD_PARTY;
  }
  return SITE_RELATION.UNKNOWN;
}

function relationOverrideFromCategory(value) {
  const category = safeString(value);
  if (category === "site_first_party") {
    return SITE_RELATION.FIRST_PARTY;
  }
  if (category === "site_third_party") {
    return SITE_RELATION.THIRD_PARTY;
  }
  if (category === "extension_resource") {
    return SITE_RELATION.EXTENSION;
  }
  if (category === "browser_internal") {
    return SITE_RELATION.BROWSER_INTERNAL;
  }
  if (category === "devtools_internal") {
    return SITE_RELATION.DEVTOOLS_INTERNAL;
  }
  if (category === "data_url" || category === "blob_url") {
    return SITE_RELATION.DATA;
  }
  return "";
}

function entityRef(entity) {
  return createEntityRef(entity);
}

function normalizeInput(input) {
  if (!input || typeof input !== "object") {
    return {};
  }
  if (input.snapshot && typeof input.snapshot === "object") {
    return input.snapshot;
  }
  if (input.runtimeSnapshot && typeof input.runtimeSnapshot === "object") {
    return input.runtimeSnapshot;
  }
  return input;
}

function sourceObservedAt(source) {
  return firstValue(source.updatedAt, source.analysis && source.analysis.lastRunAt, source.lastRunAt);
}

function buildEvidenceModel(input = {}, options = {}) {
  const source = normalizeInput(input);
  const observedAt = sourceObservedAt(source) || null;
  const entities = [];
  const relationships = [];
  const findings = [];
  const diagnostics = [];
  const relationshipKeys = new Set();
  const originEntities = new Map();
  const captureSummary = normalizeObject(source.captureSummary);
  const targetInfo = readTargetInfo(source);
  const targetOrigin = targetInfo ? targetInfo.origin : null;
  const targetEntity = targetInfo ? addEntity(entities, ENTITY_TYPE.TARGET, `target:${stableHash(targetInfo.urlRedacted || targetInfo.targetType || "target")}`, {
    label: targetInfo.label,
    urlRedacted: targetInfo.urlRedacted || null,
    targetType: targetInfo.targetType || "unknown",
    targetTypeLabel: targetInfo.targetTypeLabel || "Unknown",
    captureMode: targetInfo.captureMode || null,
    captureLabel: targetInfo.captureLabel || null,
    siteRelation: SITE_RELATION.FIRST_PARTY,
    isLimitedTarget: targetInfo.isLimitedTarget,
    isOutOfSync: targetInfo.isOutOfSync
  }, {
    sourceCapability: "target_classification",
    confidence: targetInfo.urlRedacted ? CONFIDENCE.HIGH : CONFIDENCE.MEDIUM,
    observedAt
  }) : null;

  if (targetInfo && targetInfo.originInfo) {
    getOrCreateOrigin(originEntities, entities, targetInfo.originInfo, SITE_RELATION.FIRST_PARTY, observedAt);
  }

  const exportEntity = readExportReadiness(source) ? addEntity(entities, ENTITY_TYPE.EXPORT_ITEM, `export:${stableHash(JSON.stringify(readExportReadiness(source)))}`, readExportReadiness(source), {
    sourceCapability: "safe_export_package",
    confidence: CONFIDENCE.HIGH,
    observedAt
  }) : null;

  const requestEntities = readNetworkEntries(source).map((row, index) => {
    const requestUrl = firstValue(row.urlRedacted, row.url, row.request && row.request.url);
    const originInfo = parseOrigin(requestUrl) || originFromHost(row.host, targetOrigin);
    const siteRelation = classifySiteRelation(originInfo, targetOrigin, relationOverrideFromCategory(row.resourceCategory));
    const originEntity = originInfo ? getOrCreateOrigin(originEntities, entities, originInfo, siteRelation, observedAt) : null;
    const bodyStatus = normalizeBodyStatus(row.bodyCaptureStatus || row.bodyStatus || row.status);
    const entity = addEntity(entities, ENTITY_TYPE.REQUEST, `request:${stableHash(row.id || row.dedupeKey || requestUrl || index)}`, {
      method: truncateText(row.method || "GET", 24) || null,
      urlRedacted: redactUrl(requestUrl),
      statusCode: row.statusCode ?? row.status ?? null,
      resourceType: truncateText(row.type || row.resourceType || "", 48) || null,
      mimeType: truncateText(row.mimeType || row.bodyMimeType || "", 96) || null,
      bodyStatus,
      bodyCaptureReason: truncateText(row.bodyCaptureReason || row.reason || "", 96) || null,
      bodyCapturedBytes: safeNumber(row.bodyCapturedBytes || row.bodySizeBytes),
      bodySizeBytes: safeNumber(row.bodySize || row.size),
      originRef: originEntity ? entityRef(originEntity) : null
    }, {
      sourceCapability: "network_har_capture",
      confidence: CONFIDENCE.HIGH,
      observedAt: firstValue(row.startedDateTime, observedAt) || null
    });
    if (originEntity) {
      addRelationship(relationships, relationshipKeys, RELATIONSHIP_TYPE.ORIGIN_HAS_REQUEST, originEntity, entity, "Observed request summary belongs to this origin.", CONFIDENCE.HIGH);
    }
    return entity;
  });

  const resourceEntities = readResourceEntries(source).map((row, index) => {
    const resourceUrl = firstValue(row.urlRedacted, row.url, row.path, row.href, row.scope);
    const originInfo = parseOrigin(resourceUrl) || originFromHost(row.host, targetOrigin);
    const siteRelation = classifySiteRelation(originInfo, targetOrigin, relationOverrideFromCategory(row.resourceCategory));
    const originEntity = originInfo ? getOrCreateOrigin(originEntities, entities, originInfo, siteRelation, observedAt) : null;
    const entity = addEntity(entities, ENTITY_TYPE.RESOURCE, `resource:${stableHash(row.id || resourceUrl || index)}`, {
      urlRedacted: redactUrl(resourceUrl),
      resourceType: truncateText(row.type || row.resourceType || row.kind || "", 48) || null,
      status: truncateText(row.status || "", 48) || null,
      exportable: Boolean(row.exportable || row.isExportable),
      reason: truncateText(row.reason || row.hiddenByDefaultReason || "", 96) || null,
      sizeBytes: safeNumber(row.size || row.bodySize),
      siteRelation,
      originRef: originEntity ? entityRef(originEntity) : null
    }, {
      sourceCapability: "source_resource_inventory",
      confidence: CONFIDENCE.HIGH,
      visibility: siteRelation === SITE_RELATION.EXTENSION || siteRelation === SITE_RELATION.BROWSER_INTERNAL || siteRelation === SITE_RELATION.DEVTOOLS_INTERNAL
        ? VISIBILITY.HIDDEN_BY_DEFAULT
        : VISIBILITY.DEFAULT_VISIBLE,
      observedAt
    });
    if (originEntity) {
      addRelationship(relationships, relationshipKeys, RELATIONSHIP_TYPE.ORIGIN_HAS_RESOURCE, originEntity, entity, "Observed resource summary belongs to this origin.", CONFIDENCE.HIGH);
    }
    return entity;
  });

  const cookieEntities = readCookieEntries(source).map((cookie, index) => {
    const originInfo = cookieOrigin(cookie, targetOrigin);
    const siteRelation = classifySiteRelation(originInfo, targetOrigin, cookie.isThirdParty === true ? SITE_RELATION.THIRD_PARTY : cookie.isFirstParty === true ? SITE_RELATION.FIRST_PARTY : "");
    const originEntity = originInfo ? getOrCreateOrigin(originEntities, entities, originInfo, siteRelation, observedAt) : null;
    const name = firstValue(cookie.name, cookie.normalizedName, cookie.cookieName);
    const entity = addEntity(entities, ENTITY_TYPE.COOKIE, `cookie:${stableHash(cookie.id || cookie.key || [name, cookie.domain, cookie.path, index].join("|"))}`, {
      nameHash: name ? stableHash(name) : null,
      domain: truncateText(cookie.domain || cookie.originHost || "", 120) || null,
      path: truncateText(cookie.path || "", 120) || null,
      siteRelation,
      flags: {
        secure: cookie.secure ?? null,
        httpOnly: cookie.httpOnly ?? null,
        sameSite: truncateText(cookie.sameSite || "", 48) || null,
        session: cookie.session ?? null
      },
      source: truncateText(cookie.source || "", 64) || null,
      classification: truncateText(cookie.classification || "", 64) || null,
      rawAvailable: Boolean(cookie.rawAvailable || cookie.value && cookie.value.rawAvailable),
      originRef: originEntity ? entityRef(originEntity) : null
    }, {
      sourceCapability: "cookie_observed_from_network",
      sensitivity: cookie.rawAvailable || cookie.value && cookie.value.rawAvailable ? SENSITIVITY.HIGH : SENSITIVITY.MEDIUM,
      confidence: CONFIDENCE.MEDIUM,
      observedAt
    });
    if (originEntity) {
      addRelationship(relationships, relationshipKeys, RELATIONSHIP_TYPE.ORIGIN_HAS_COOKIE, originEntity, entity, "Observed cookie summary belongs to this origin.", CONFIDENCE.MEDIUM);
    }
    return entity;
  });

  const storageEntities = readStorageEntries(source).map((item, index) => {
    const originInfo = storageOrigin(item, source.application, targetOrigin);
    const siteRelation = classifySiteRelation(originInfo, targetOrigin, "");
    const originEntity = originInfo ? getOrCreateOrigin(originEntities, entities, originInfo, siteRelation, observedAt) : null;
    const key = firstValue(item.key, item.name, item.id, item.href, item.scope);
    const entity = addEntity(entities, ENTITY_TYPE.STORAGE_ITEM, `storage:${stableHash(item.id || [item.storageType, item.type, key, index].join("|"))}`, {
      keyHash: key ? stableHash(key) : null,
      storageType: truncateText(item.storageType || item.type || item.kind || "storage", 64),
      itemKind: truncateText(item.kind || item.type || "storage_item", 64),
      sizeBytes: safeNumber(item.valueLength || item.sizeBytes || item.requestCount || item.totalRecordCount),
      classification: truncateText(item.classification || "", 64) || null,
      sensitive: Boolean(item.sensitive),
      rawAvailable: Boolean(item.rawAvailable || item.value && item.value.rawAvailable),
      originRef: originEntity ? entityRef(originEntity) : null
    }, {
      sourceCapability: "application_storage_inventory",
      sensitivity: item.sensitive ? SENSITIVITY.HIGH : SENSITIVITY.MEDIUM,
      confidence: CONFIDENCE.MEDIUM,
      observedAt
    });
    if (originEntity) {
      addRelationship(relationships, relationshipKeys, RELATIONSHIP_TYPE.ORIGIN_HAS_STORAGE_ITEM, originEntity, entity, "Observed storage item summary belongs to this origin.", CONFIDENCE.MEDIUM);
    }
    return entity;
  });

  const diagnosticEntities = readDiagnosticIssues(source).map((issue, index) => {
    const entity = addEntity(entities, ENTITY_TYPE.DIAGNOSTIC_ISSUE, `diagnostic:${stableHash(issue.id || [issue.category, issue.reason, issue.affectedCapability, index].join("|"))}`, {
      category: issue.category,
      severity: issue.severity,
      affectedCapability: issue.affectedCapability,
      reason: issue.reason,
      message: issue.message,
      count: issue.count
    }, {
      sourceCapability: "diagnostics_reason_groups",
      confidence: CONFIDENCE.MEDIUM,
      observedAt
    });
    diagnostics.push({
      id: entity.id,
      category: issue.category,
      severity: issue.severity,
      affectedCapability: issue.affectedCapability,
      reason: issue.reason,
      count: issue.count,
      entityRef: entityRef(entity)
    });
    if (exportEntity && affectsExport(issue)) {
      addRelationship(relationships, relationshipKeys, RELATIONSHIP_TYPE.DIAGNOSTIC_AFFECTS_CAPABILITY, entity, exportEntity, "Diagnostic issue affects export readiness.", CONFIDENCE.MEDIUM);
    }
    return entity;
  });

  if (targetEntity) {
    for (const originEntity of originEntities.values()) {
      addRelationship(relationships, relationshipKeys, RELATIONSHIP_TYPE.TARGET_HAS_ORIGIN, targetEntity, originEntity, "Origin was observed in the current target summary.", CONFIDENCE.MEDIUM);
    }
  }

  const bodyCapturedCount = Math.max(requestEntities.filter((entity) => entity.details.bodyStatus === BODY_STATUS.CAPTURED).length, safeNumber(captureSummary.capturedBodyCount));
  const bodyUnavailableRequests = requestEntities.filter((entity) => BODY_UNAVAILABLE_STATUSES.has(entity.details.bodyStatus));
  const bodyUnavailableCount = Math.max(bodyUnavailableRequests.length, safeNumber(captureSummary.unavailableBodyCount));

  if (exportEntity) {
    for (const requestEntity of bodyUnavailableRequests) {
      addRelationship(relationships, relationshipKeys, RELATIONSHIP_TYPE.REQUEST_BODY_AFFECTS_EXPORT, requestEntity, exportEntity, "Request body availability affects export completeness.", CONFIDENCE.MEDIUM);
    }
  }

  const exportState = exportEntity ? exportEntity.details : readExportReadiness(source) || {};
  const summary = {
    originCount: originEntities.size,
    requestCount: Math.max(requestEntities.length, safeNumber(captureSummary.networkRequestCount)),
    resourceCount: Math.max(resourceEntities.length, safeNumber(captureSummary.sourceCount)),
    cookieCount: Math.max(cookieEntities.length, safeNumber(captureSummary.cookieCount)),
    storageItemCount: Math.max(storageEntities.length, safeNumber(captureSummary.applicationItemCount)),
    diagnosticIssueCount: Math.max(diagnosticEntities.length, safeNumber(captureSummary.diagnosticWarningCount)),
    findingCount: 0,
    bodyCapturedCount,
    bodyUnavailableCount,
    exportBlocked: Boolean(exportState.blocked),
    safeExportReady: Boolean(exportState.safeReady)
  };

  buildFindings({
    findings,
    targetEntity,
    exportEntity,
    requestEntities,
    cookieEntities,
    storageEntities,
    diagnosticEntities,
    originEntities: Array.from(originEntities.values()),
    summary,
    source
  });

  summary.findingCount = findings.length;

  return {
    schemaVersion: MODEL_VERSION,
    entities,
    relationships,
    findings,
    diagnostics,
    summary
  };
}

function addEntity(entities, type, id, details, options = {}) {
  const entity = createEntity(type, {
    id,
    source: "back_tools_evidence_model_v1",
    sourceCapability: options.sourceCapability || null,
    captureSessionId: options.captureSessionId || null,
    provenance: {
      builder: "buildEvidenceModel",
      input: "safe_runtime_state"
    },
    visibility: options.visibility || VISIBILITY.DEFAULT_VISIBLE,
    sensitivity: options.sensitivity || SENSITIVITY.LOW,
    confidence: options.confidence || CONFIDENCE.UNKNOWN,
    observedAt: options.observedAt || null,
    details
  });
  entities.push(entity);
  return entity;
}

function addRelationship(relationships, relationshipKeys, type, fromEntity, toEntity, explanation, confidence) {
  const fromRef = entityRef(fromEntity);
  const toRef = entityRef(toEntity);
  const key = `${type}:${fromRef.id}:${toRef.id}`;
  if (relationshipKeys.has(key)) {
    return null;
  }
  relationshipKeys.add(key);
  const relationship = createRelationship({
    id: `rel:${stableHash(key)}`,
    type,
    fromRef,
    toRef,
    confidence: confidence || CONFIDENCE.UNKNOWN,
    source: "back_tools_evidence_model_v1",
    explanation
  });
  relationships.push(relationship);
  return relationship;
}

function getOrCreateOrigin(originEntities, entities, originInfo, siteRelation, observedAt) {
  const normalized = normalizeOriginInfo(originInfo);
  if (!normalized) {
    return null;
  }
  const key = `${normalized.origin}|${siteRelation || SITE_RELATION.UNKNOWN}`;
  const existing = originEntities.get(key);
  if (existing) {
    return existing;
  }
  const entity = addEntity(entities, ENTITY_TYPE.ORIGIN, `origin:${stableHash(key)}`, {
    origin: normalized.origin,
    scheme: normalized.scheme || null,
    host: normalized.host || null,
    siteRelation: siteRelation || SITE_RELATION.UNKNOWN
  }, {
    sourceCapability: "target_classification",
    confidence: CONFIDENCE.MEDIUM,
    observedAt
  });
  originEntities.set(key, entity);
  return entity;
}

function normalizeOriginInfo(originInfo) {
  if (!originInfo || !originInfo.origin) {
    return null;
  }
  const parsed = parseOrigin(originInfo.origin);
  if (parsed) {
    return {
      origin: parsed.origin,
      scheme: parsed.scheme,
      host: parsed.host
    };
  }
  return {
    origin: truncateText(originInfo.origin, 160),
    scheme: truncateText(originInfo.scheme || "", 48) || null,
    host: truncateText(originInfo.host || "", 120) || null
  };
}

function readTargetInfo(source) {
  const target = normalizeObject(source.target);
  const url = firstValue(
    source.targetUrl,
    source.url,
    source.currentUrl,
    source.analyzedUrl,
    target.urlRedacted,
    target.redactedUrl,
    target.url,
    target.currentUrl,
    target.analyzedUrl,
    target.targetUrl,
    target.displayUrl
  );
  const targetType = firstValue(target.targetType, source.targetType);
  if (!url && !targetType && target.connected !== true && source.connected !== true) {
    return null;
  }
  const urlRedacted = url ? redactUrl(url) : "";
  const originInfo = parseOrigin(urlRedacted);
  return {
    urlRedacted,
    origin: originInfo ? originInfo.origin : null,
    originInfo,
    targetType: targetType || "unknown",
    targetTypeLabel: truncateText(target.targetTypeLabel || "", 80) || null,
    captureMode: truncateText(target.captureMode || "", 80) || null,
    captureLabel: truncateText(target.captureLabel || target.captureModeLabel || "", 120) || null,
    label: truncateText(target.displayUrl || target.statusLabel || target.targetTypeLabel || "Target", 160),
    isLimitedTarget: Boolean(target.isLimitedTarget),
    isOutOfSync: Boolean(target.isOutOfSync)
  };
}

function readExportReadiness(source) {
  const direct = normalizeObject(source.exportReadiness);
  const exportState = normalizeObject(source.export);
  if (!Object.keys(direct).length && !Object.keys(exportState).length) {
    return null;
  }
  const options = normalizeObject(exportState.options);
  const dumpObjectsEnabled = isRawModeEnabled(source);
  const blocked = Boolean(direct.blocked || exportState.blocked || source.target && source.target.isOutOfSync);
  const safeReady = direct.safeReady !== undefined ? Boolean(direct.safeReady) : !blocked && !dumpObjectsEnabled;
  return {
    exportType: "safe_export_readiness",
    status: blocked ? "blocked" : safeReady ? "ready" : "partial",
    blocked,
    safeReady,
    limitedReport: Boolean(direct.limitedReport),
    reason: truncateText(direct.reason || exportState.reason || exportState.lastStatus || "", 160) || null,
    rawCookieExport: options.cookieExportMode && options.cookieExportMode !== "sanitized_only" ? "enabled" : "protected",
    rawApplicationExport: options.applicationExportMode && options.applicationExportMode !== "sanitized_only" ? "enabled" : "protected",
    dumpObjectsEnabled
  };
}

function readNetworkEntries(source) {
  const network = source.network;
  if (Array.isArray(network)) {
    return network;
  }
  if (network && Array.isArray(network.entries)) {
    return network.entries;
  }
  if (Array.isArray(source.networkEntries)) {
    return source.networkEntries;
  }
  if (Array.isArray(source.requests)) {
    return source.requests;
  }
  return [];
}

function readResourceEntries(source) {
  const sources = source.sources;
  if (Array.isArray(sources)) {
    return sources;
  }
  if (sources && Array.isArray(sources.resources)) {
    return sources.resources;
  }
  if (Array.isArray(source.resources)) {
    return source.resources;
  }
  return [];
}

function readCookieEntries(source) {
  const cookies = source.cookies;
  if (Array.isArray(cookies)) {
    return cookies;
  }
  if (cookies && Array.isArray(cookies.observedCookies)) {
    return cookies.observedCookies;
  }
  if (Array.isArray(source.observedCookies)) {
    return source.observedCookies;
  }
  return [];
}

function readStorageEntries(source) {
  const application = normalizeObject(source.application);
  const rows = [];
  toArray(application.localStorage && application.localStorage.entries).forEach((item) => rows.push({ ...item, storageType: "localStorage" }));
  toArray(application.sessionStorage && application.sessionStorage.entries).forEach((item) => rows.push({ ...item, storageType: "sessionStorage" }));
  toArray(application.indexedDB && application.indexedDB.databases).forEach((item) => rows.push({ ...item, storageType: "indexedDB", kind: "application_indexeddb" }));
  toArray(application.cacheStorage && application.cacheStorage.caches).forEach((item) => rows.push({ ...item, storageType: "cacheStorage", kind: "application_cache_storage" }));
  toArray(application.serviceWorkers && application.serviceWorkers.registrations).forEach((item) => rows.push({ ...item, storageType: "serviceWorker", kind: "application_service_worker" }));
  if (application.manifest && application.manifest.href) {
    rows.push({ ...application.manifest, storageType: "manifest", kind: "application_manifest" });
  }
  if (Array.isArray(source.storageItems)) {
    rows.push(...source.storageItems);
  }
  return rows;
}

function readDiagnosticIssues(source) {
  const diagnostics = normalizeObject(source.diagnostics);
  const moduleHealth = normalizeObject(source.moduleHealth);
  const issues = [];
  Object.entries(normalizeObject(diagnostics.reasonGroups)).forEach(([reason, count]) => {
    issues.push({
      category: "reason_group",
      severity: SEVERITY.INFO,
      affectedCapability: capabilityFromReason(reason),
      reason: truncateText(reason, 96),
      message: "Diagnostic reason group observed.",
      count: safeNumber(count)
    });
  });
  Object.entries(moduleHealth).forEach(([moduleName, item]) => {
    const normalized = normalizeObject(item);
    const status = safeString(normalized.status);
    const reason = firstValue(normalized.reason, status && status !== "ready" && status !== "collected" && status !== "not_collected" ? status : "");
    if (!reason) {
      return;
    }
    issues.push({
      category: truncateText(moduleName, 64) || "module",
      severity: status === "failed" || status === "error" ? SEVERITY.MEDIUM : SEVERITY.INFO,
      affectedCapability: capabilityFromModule(moduleName),
      reason: truncateText(reason, 96),
      message: "Module diagnostic state observed.",
      count: safeNumber(normalized.count)
    });
  });
  toArray(diagnostics.logs).forEach((log, index) => {
    const reason = firstValue(log.reason, log.event, log.code);
    if (!reason) {
      return;
    }
    issues.push({
      id: log.id || `log-${index}`,
      category: "log",
      severity: severityFromLevel(log.level),
      affectedCapability: capabilityFromReason(reason),
      reason: truncateText(reason, 96),
      message: "Diagnostic log event observed.",
      count: 1
    });
  });
  toArray(source.application && source.application.observations).forEach((observation, index) => {
    const reason = firstValue(observation.reason, observation.section, observation.status);
    if (!reason) {
      return;
    }
    issues.push({
      id: observation.id || `application-observation-${index}`,
      category: "application",
      severity: SEVERITY.INFO,
      affectedCapability: "application_storage_inventory",
      reason: truncateText(reason, 96),
      message: "Application inventory diagnostic observed.",
      count: 1
    });
  });
  return dedupeIssues(issues);
}

function dedupeIssues(issues) {
  const seen = new Set();
  return issues.filter((issue) => {
    const key = [issue.category, issue.affectedCapability, issue.reason].join("|");
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function severityFromLevel(level) {
  const value = safeString(level).toLowerCase();
  if (value === "error") {
    return SEVERITY.MEDIUM;
  }
  if (value === "warn" || value === "warning") {
    return SEVERITY.LOW;
  }
  return SEVERITY.INFO;
}

function capabilityFromModule(moduleName) {
  const value = safeString(moduleName);
  if (value === "sources") {
    return "source_resource_inventory";
  }
  if (value === "network") {
    return "network_har_capture";
  }
  if (value === "cookies") {
    return "cookie_observed_from_network";
  }
  if (value === "application") {
    return "application_storage_inventory";
  }
  if (value === "diagnostics") {
    return "diagnostics_reason_groups";
  }
  if (value === "export") {
    return "safe_export_package";
  }
  return "diagnostics_reason_groups";
}

function capabilityFromReason(reason) {
  const value = safeString(reason).toLowerCase();
  if (value.includes("body") || value.includes("network") || value.includes("har")) {
    return "network_body_capture";
  }
  if (value.includes("source") || value.includes("resource")) {
    return "source_resource_inventory";
  }
  if (value.includes("cookie")) {
    return "cookie_observed_from_network";
  }
  if (value.includes("storage") || value.includes("application") || value.includes("indexed") || value.includes("cache")) {
    return "application_storage_inventory";
  }
  if (value.includes("export")) {
    return "safe_export_package";
  }
  return "diagnostics_reason_groups";
}

function affectsExport(issue) {
  const value = [issue.affectedCapability, issue.reason, issue.category].map(safeString).join(" ").toLowerCase();
  return value.includes("export") || value.includes("body") || value.includes("network") || value.includes("storage") || value.includes("cookie");
}

function normalizeBodyStatus(status) {
  const value = safeString(status);
  if (value === "body_captured" || value === "captured") {
    return BODY_STATUS.CAPTURED;
  }
  if (value === "not_applicable") {
    return BODY_STATUS.NOT_APPLICABLE;
  }
  if (value === "size_limit_exceeded" || value === "truncated") {
    return BODY_STATUS.TRUNCATED;
  }
  if (value === "policy_blocked" || value === "not_requested") {
    return BODY_STATUS.NOT_REQUESTED;
  }
  if (value === "read_failed" || value === "failed" || value === "error") {
    return BODY_STATUS.FAILED;
  }
  if (value === "redacted") {
    return BODY_STATUS.REDACTED;
  }
  if (value === "metadata_only" || value === "mime_blocked" || value === "platform_unavailable" || value === "encoding_unsupported" || value === "hidden_by_default" || value === "unavailable") {
    return BODY_STATUS.UNAVAILABLE;
  }
  return BODY_STATUS.NOT_REQUESTED;
}

function cookieOrigin(cookie, targetOrigin) {
  const sourceUrl = firstValue(cookie.urlRedacted, cookie.url, cookie.sourceUrls && cookie.sourceUrls[0], cookie.observedIn && cookie.observedIn[0] && (cookie.observedIn[0].urlRedacted || cookie.observedIn[0].url));
  return parseOrigin(sourceUrl) || originFromHost(cookie.originHost || cookie.domain, targetOrigin);
}

function storageOrigin(item, application, targetOrigin) {
  const direct = firstValue(item.origin, application && application.targetOrigin);
  return parseOrigin(direct) || parseOrigin(item.frameUrl || item.href || item.scope || "") || parseOrigin(targetOrigin || "");
}

function isRawModeEnabled(source) {
  const exportOptions = normalizeObject(source.export && source.export.options);
  const diagnostics = normalizeObject(source.diagnostics);
  const objectDump = normalizeObject(source.objectDump || diagnostics.objectDump || diagnostics.metadata && diagnostics.metadata.objectDump);
  return Boolean(
    source.dumpObjectsEnabled === true ||
    source.rawObjectDumpEnabled === true ||
    objectDump.dumpObjectsEnabled === true ||
    exportOptions.cookieExportMode && exportOptions.cookieExportMode !== "sanitized_only" ||
    exportOptions.applicationExportMode && exportOptions.applicationExportMode !== "sanitized_only"
  );
}

function buildFindings(context) {
  const {
    findings,
    targetEntity,
    exportEntity,
    requestEntities,
    cookieEntities,
    storageEntities,
    diagnosticEntities,
    originEntities,
    summary,
    source
  } = context;

  if (summary.bodyUnavailableCount > 0) {
    addFinding(findings, FINDING_CATEGORY.BODY_AVAILABILITY, "Body availability is partial", SEVERITY.MEDIUM, CONFIDENCE.MEDIUM, requestEntities.filter((entity) => BODY_UNAVAILABLE_STATUSES.has(entity.details.bodyStatus)), "Observed request summaries include unavailable, blocked, truncated, or failed body states. Export and payload review may be partial.", ["Body absence can be normal when DevTools did not retain content or policy blocked capture."], ["Reload with capture before repeating the flow when fuller body evidence is needed."], VALIDATION_STATUS.PARTIAL);
  }

  if (summary.diagnosticIssueCount > 0 || summary.bodyUnavailableCount > 0) {
    addFinding(findings, FINDING_CATEGORY.CAPTURE_COMPLETENESS, "Capture completeness is limited", SEVERITY.LOW, CONFIDENCE.MEDIUM, [...diagnosticEntities, ...requestEntities.filter((entity) => BODY_UNAVAILABLE_STATUSES.has(entity.details.bodyStatus))], "The current model contains partial capture indicators from diagnostics or body availability summaries.", ["This is an evidence quality signal, not a statement about application behavior."], ["Review Diagnostics before using the capture as a complete handoff package."], VALIDATION_STATUS.LIMITED);
  }

  if (summary.cookieCount > 0 || summary.storageItemCount > 0) {
    addFinding(findings, FINDING_CATEGORY.COOKIE_STORAGE_POSTURE, "Cookie or storage posture candidate observed", SEVERITY.LOW, CONFIDENCE.MEDIUM, [...cookieEntities, ...storageEntities], "Cookie or storage metadata is present and may affect security, debugging, or export review depending on workflow.", ["Only summaries, hashes, flags, and classifications are included in this model."], ["Review protected cookie and Application summaries before enabling any raw workflow."], VALIDATION_STATUS.CANDIDATE);
  }

  const thirdPartyOrigins = originEntities.filter((entity) => entity.details.siteRelation === SITE_RELATION.THIRD_PARTY);
  if (thirdPartyOrigins.length) {
    addFinding(findings, FINDING_CATEGORY.THIRD_PARTY_ACTIVITY, "Third-party activity observed", SEVERITY.LOW, CONFIDENCE.MEDIUM, thirdPartyOrigins, "One or more observed origins are outside the target origin. Treat this as a candidate review signal.", ["Origin classification is based on available URL summaries only."], ["Review third-party requests and resources in context before drawing conclusions."], VALIDATION_STATUS.OBSERVED);
  }

  if ((exportEntity && (summary.exportBlocked || !summary.safeExportReady)) || summary.bodyUnavailableCount > 0) {
    addFinding(findings, FINDING_CATEGORY.EXPORT_IMPACT, "Export readiness is limited", SEVERITY.MEDIUM, CONFIDENCE.MEDIUM, [exportEntity, ...requestEntities.filter((entity) => BODY_UNAVAILABLE_STATUSES.has(entity.details.bodyStatus))].filter(Boolean), "Safe export readiness is blocked, partial, or affected by unavailable request bodies.", ["This does not mean export data is unsafe; it indicates current package completeness limits."], ["Resolve export readiness or capture gaps before relying on the package as complete evidence."], VALIDATION_STATUS.PARTIAL);
  }

  if (targetEntity && (targetEntity.details.isLimitedTarget || targetEntity.details.isOutOfSync)) {
    addFinding(findings, FINDING_CATEGORY.TARGET_PLATFORM_LIMITATION, "Target platform capability is limited", SEVERITY.LOW, CONFIDENCE.MEDIUM, [targetEntity], "The target summary indicates a limited or out-of-sync target state. Some collectors may only provide a limited report.", ["Limited target behavior is expected for browser-managed, extension, file, empty, or changed targets."], ["Re-run analysis on a normal HTTP or HTTPS page when full capture is required."], VALIDATION_STATUS.LIMITED);
  }

  if (isRawModeEnabled(source)) {
    addFinding(findings, FINDING_CATEGORY.RAW_MODE_RISK, "Raw object mode risk candidate", SEVERITY.MEDIUM, CONFIDENCE.MEDIUM, [exportEntity, ...cookieEntities, ...storageEntities].filter(Boolean), "Dump objects or raw export posture is active. Raw cookie or Application values may be visible or exportable elsewhere in the current session.", ["The Evidence Model keeps only safe summaries and does not include raw values."], ["Return to sanitized mode before sharing exports unless raw evidence was explicitly approved."], VALIDATION_STATUS.CANDIDATE);
  }
}

function addFinding(findings, category, title, severity, confidence, evidenceEntities, explanation, limitations, recommendedNextSteps, validationStatus) {
  const evidenceRefs = toArray(evidenceEntities).filter(Boolean).slice(0, 12).map(entityRef);
  const workflowRank = { ...WORKFLOW_RANK_BY_CATEGORY[category] };
  WORKFLOW_KEYS.forEach((key) => {
    if (workflowRank[key] === undefined) {
      workflowRank[key] = 0;
    }
  });
  findings.push(createFinding({
    id: `finding:${category}:${stableHash(evidenceRefs.map((ref) => ref.id).join("|") || title)}`,
    title,
    category,
    severity,
    confidence,
    workflowRank,
    evidenceRefs,
    explanation,
    limitations,
    recommendedNextSteps,
    validationStatus
  }));
}

const api = {
  FINDING_CATEGORY,
  MODEL_VERSION,
  WORKFLOW_KEYS,
  WORKFLOW_RANK_BY_CATEGORY,
  buildEvidenceModel
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = api;
}

globalThis.BackToolsEvidenceModelBuilder = api;
})();
