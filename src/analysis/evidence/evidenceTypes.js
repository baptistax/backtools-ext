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

const constants = requireApi("./evidenceConstants.js") || globalThis.BackToolsEvidenceConstants;
const {
  BODY_STATUS,
  CONFIDENCE,
  ENTITY_TYPE,
  RELATIONSHIP_TYPE,
  SENSITIVITY,
  SEVERITY,
  SITE_RELATION,
  VALIDATION_STATUS,
  VISIBILITY
} = constants;

const SHARED_ENTITY_FIELDS = Object.freeze([
  "id",
  "type",
  "source",
  "sourceCapability",
  "captureSessionId",
  "provenance",
  "visibility",
  "sensitivity",
  "confidence",
  "observedAt"
]);

const FINDING_FIELDS = Object.freeze([
  "id",
  "title",
  "category",
  "severity",
  "confidence",
  "workflowRank",
  "evidenceRefs",
  "explanation",
  "limitations",
  "recommendedNextSteps",
  "validationStatus"
]);

const RELATIONSHIP_FIELDS = Object.freeze([
  "id",
  "type",
  "fromRef",
  "toRef",
  "confidence",
  "source",
  "explanation"
]);

const RAW_VALUE_FIELD_NAMES = Object.freeze([
  "value",
  "rawValue",
  "body",
  "requestBody",
  "responseBody",
  "content",
  "sourceContent",
  "headers",
  "requestHeaders",
  "responseHeaders"
]);

const ENTITY_CONTRACTS = Object.freeze({
  TargetEntity: freezeContract(ENTITY_TYPE.TARGET, ["label", "urlRedacted", "targetType", "siteRelation"]),
  OriginEntity: freezeContract(ENTITY_TYPE.ORIGIN, ["origin", "scheme", "host", "siteRelation"]),
  RequestEntity: freezeContract(ENTITY_TYPE.REQUEST, ["method", "urlRedacted", "statusCode", "bodyStatus", "originRef"]),
  ResponseBodyEntity: freezeContract(ENTITY_TYPE.RESPONSE_BODY, ["requestRef", "bodyStatus", "mimeType", "sizeBytes", "encoding"]),
  ResourceEntity: freezeContract(ENTITY_TYPE.RESOURCE, ["urlRedacted", "resourceType", "status", "originRef"]),
  CookieEntity: freezeContract(ENTITY_TYPE.COOKIE, ["nameHash", "domain", "path", "siteRelation", "flags", "originRef"]),
  StorageItemEntity: freezeContract(ENTITY_TYPE.STORAGE_ITEM, ["keyHash", "storageType", "sizeBytes", "originRef"]),
  DiagnosticIssueEntity: freezeContract(ENTITY_TYPE.DIAGNOSTIC_ISSUE, ["category", "severity", "affectedCapability", "message"]),
  ExportItemEntity: freezeContract(ENTITY_TYPE.EXPORT_ITEM, ["exportType", "path", "status", "bodyStatus", "evidenceRefs"]),
  FindingEntity: Object.freeze({
    type: ENTITY_TYPE.FINDING,
    requiredFields: FINDING_FIELDS,
    optionalFields: Object.freeze(["source", "sourceCapability", "captureSessionId", "provenance", "visibility", "sensitivity", "observedAt"])
  }),
  ConsoleEventEntity: freezeContract(ENTITY_TYPE.CONSOLE_EVENT, ["level", "message", "originRef", "requestRef"]),
  UserInteractionEntity: freezeContract(ENTITY_TYPE.USER_INTERACTION, ["interactionType", "targetLabel", "targetRef"]),
  SecuritySignalEntity: freezeContract(ENTITY_TYPE.SECURITY_SIGNAL, ["category", "siteRelation", "affectedRef", "message"])
});

const entityContractByType = new Map(Object.values(ENTITY_CONTRACTS).map((contract) => [contract.type, contract]));
const entityTypes = new Set(Object.values(ENTITY_TYPE));
const relationshipTypes = new Set(Object.values(RELATIONSHIP_TYPE));

function freezeContract(type, optionalFields) {
  return Object.freeze({
    type,
    requiredFields: SHARED_ENTITY_FIELDS,
    optionalFields: Object.freeze(optionalFields.slice())
  });
}

function normalizeId(value) {
  return value === null || value === undefined ? "" : String(value).trim();
}

function requireId(value, label) {
  const id = normalizeId(value);
  if (!id) {
    throw new TypeError(`${label || "Evidence"} id is required.`);
  }
  return id;
}

function normalizeEnum(value, fallback, allowedValues) {
  const normalized = value === null || value === undefined ? "" : String(value).trim();
  return allowedValues.includes(normalized) ? normalized : fallback;
}

function normalizeArray(value) {
  return Array.isArray(value) ? value.slice() : [];
}

function normalizeObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? { ...value } : {};
}

function cloneRef(ref) {
  return {
    id: requireId(ref && ref.id, "Evidence reference"),
    type: normalizeEntityType(ref && ref.type)
  };
}

function normalizeEntityType(type) {
  const value = normalizeId(type);
  if (!entityTypes.has(value)) {
    throw new TypeError("Evidence entity type is not supported.");
  }
  return value;
}

function normalizeRelationshipType(type) {
  const value = normalizeId(type);
  if (!relationshipTypes.has(value)) {
    throw new TypeError("Evidence relationship type is not supported.");
  }
  return value;
}

function createEntityRef(entityOrId, type) {
  if (entityOrId && typeof entityOrId === "object") {
    return cloneRef(entityOrId);
  }
  return {
    id: requireId(entityOrId, "Evidence reference"),
    type: normalizeEntityType(type)
  };
}

function createBaseEntity(type, input = {}) {
  const entityType = normalizeEntityType(type);
  return {
    id: requireId(input.id, "Evidence entity"),
    type: entityType,
    source: normalizeId(input.source) || null,
    sourceCapability: normalizeId(input.sourceCapability) || null,
    captureSessionId: normalizeId(input.captureSessionId) || null,
    provenance: normalizeObject(input.provenance),
    visibility: normalizeEnum(input.visibility, VISIBILITY.DEFAULT_VISIBLE, Object.values(VISIBILITY)),
    sensitivity: normalizeEnum(input.sensitivity, SENSITIVITY.NONE, Object.values(SENSITIVITY)),
    confidence: normalizeEnum(input.confidence, CONFIDENCE.UNKNOWN, Object.values(CONFIDENCE)),
    observedAt: normalizeId(input.observedAt) || null
  };
}

function createEntity(type, input = {}) {
  return {
    ...createBaseEntity(type, input),
    details: normalizeObject(input.details)
  };
}

function createFinding(input = {}) {
  const evidenceRefs = normalizeArray(input.evidenceRefs).map((ref) => createEntityRef(ref));
  return {
    id: requireId(input.id, "Finding"),
    type: ENTITY_TYPE.FINDING,
    title: normalizeId(input.title) || "Untitled finding",
    category: normalizeId(input.category) || "unknown",
    severity: normalizeEnum(input.severity, SEVERITY.INFO, Object.values(SEVERITY)),
    confidence: normalizeEnum(input.confidence, CONFIDENCE.UNKNOWN, Object.values(CONFIDENCE)),
    workflowRank: normalizeObject(input.workflowRank),
    evidenceRefs,
    explanation: normalizeId(input.explanation) || "",
    limitations: normalizeArray(input.limitations).map(String),
    recommendedNextSteps: normalizeArray(input.recommendedNextSteps).map(String),
    validationStatus: normalizeEnum(input.validationStatus, VALIDATION_STATUS.UNKNOWN, Object.values(VALIDATION_STATUS))
  };
}

function createRelationship(input = {}) {
  return {
    id: requireId(input.id, "Relationship"),
    type: normalizeRelationshipType(input.type),
    fromRef: createEntityRef(input.fromRef),
    toRef: createEntityRef(input.toRef),
    confidence: normalizeEnum(input.confidence, CONFIDENCE.UNKNOWN, Object.values(CONFIDENCE)),
    source: normalizeId(input.source) || null,
    explanation: normalizeId(input.explanation) || ""
  };
}

function getEntityContract(nameOrType) {
  const key = normalizeId(nameOrType);
  return ENTITY_CONTRACTS[key] || entityContractByType.get(key) || null;
}

function listEntityContracts() {
  return Object.keys(ENTITY_CONTRACTS).map((key) => ENTITY_CONTRACTS[key]);
}

const api = {
  BODY_STATUS,
  CONFIDENCE,
  ENTITY_CONTRACTS,
  ENTITY_TYPE,
  FINDING_FIELDS,
  RAW_VALUE_FIELD_NAMES,
  RELATIONSHIP_FIELDS,
  RELATIONSHIP_TYPE,
  SENSITIVITY,
  SEVERITY,
  SHARED_ENTITY_FIELDS,
  SITE_RELATION,
  VALIDATION_STATUS,
  VISIBILITY,
  createBaseEntity,
  createEntity,
  createEntityRef,
  createFinding,
  createRelationship,
  getEntityContract,
  listEntityContracts,
  normalizeId
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = api;
}

globalThis.BackToolsEvidenceTypes = api;
})();
