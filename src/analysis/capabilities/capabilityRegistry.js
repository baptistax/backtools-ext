(function(root, factory) {
  const api = factory();
  root.BackToolsAnalysisCapabilityRegistry = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : window, function() {
  const capabilityStates = Object.freeze([
    "supported",
    "partial",
    "experimental",
    "manual",
    "unavailable",
    "unknown"
  ]);

  const capabilities = Object.freeze([
    capability({
      id: "target_classification",
      displayName: "Target classification",
      state: "supported",
      sourceType: "devtools_target",
      apis: ["chrome.devtools.inspectedWindow", "runtime target polling"],
      requiredPermissions: [],
      requiredOptionalPermissions: [],
      knownLimits: [
        "Initial target URL can be empty until DevTools reports the inspected target.",
        "Limited targets are classified for reporting, not full collection."
      ],
      sensitivityImpact: "Uses target URL metadata and must keep redacted URL handling for user-facing surfaces.",
      exportImpact: "Drives limited-target report mode and target metadata in export manifests.",
      diagnosticCategories: ["target", "capture_mode"],
      defaultEnabled: true,
      developmentOnly: false
    }),
    capability({
      id: "network_har_capture",
      displayName: "Network HAR capture",
      state: "supported",
      sourceType: "devtools_network",
      apis: ["chrome.devtools.network.getHAR", "chrome.devtools.network.onRequestFinished"],
      requiredPermissions: [],
      requiredOptionalPermissions: [],
      knownLimits: [
        "Requests that occurred before the panel opened can be incomplete.",
        "DevTools HAR data can omit body content and some timing details."
      ],
      sensitivityImpact: "Includes request and response metadata, headers, URLs, and cookie-related observations that require redaction in safe surfaces.",
      exportImpact: "Feeds network reports, body file planning, cookie observations, diagnostics, and export manifests.",
      diagnosticCategories: ["network", "capture_window", "export"],
      defaultEnabled: true,
      developmentOnly: false
    }),
    capability({
      id: "network_body_capture",
      displayName: "Network body capture",
      state: "partial",
      sourceType: "devtools_network",
      apis: ["HAR inline response content", "chrome.devtools.network.Request.getContent"],
      requiredPermissions: [],
      requiredOptionalPermissions: [],
      knownLimits: [
        "Response bodies can be missing when the request predates capture or the platform evicts content.",
        "Unsupported encodings, size policy, binary handling, and platform failures can reduce body availability.",
        "Preview limits do not mean an available captured body is missing from export."
      ],
      sensitivityImpact: "Captured bodies can include credentials, tokens, personal data, source maps, or business payloads and must stay behind safe previews and redaction rules.",
      exportImpact: "Export can include captured body files when available; metadata-only resources must record missing body status and bodyCaptureReason.",
      diagnosticCategories: ["network", "body_capture", "export_gap"],
      defaultEnabled: true,
      developmentOnly: false
    }),
    capability({
      id: "source_resource_inventory",
      displayName: "Source resource inventory",
      state: "supported",
      sourceType: "devtools_sources",
      apis: ["chrome.devtools.inspectedWindow.getResources", "resource.getContent"],
      requiredPermissions: [],
      requiredOptionalPermissions: [],
      knownLimits: [
        "Chrome can return no resources for limited targets or before resources are available.",
        "Individual resource content reads can fail or return empty content."
      ],
      sensitivityImpact: "Source text can contain secrets or sensitive implementation details and should use safe summaries before raw inspection.",
      exportImpact: "Feeds source inventories, captured source files, skipped-resource reasons, and manifest entries.",
      diagnosticCategories: ["sources", "resource_content", "export"],
      defaultEnabled: true,
      developmentOnly: false
    }),
    capability({
      id: "application_storage_inventory",
      displayName: "Application storage inventory",
      state: "partial",
      sourceType: "inspected_page",
      apis: ["chrome.devtools.inspectedWindow.eval", "localStorage", "sessionStorage", "indexedDB.databases", "caches.keys", "navigator.serviceWorker"],
      requiredPermissions: ["host_permissions:<all_urls>"],
      requiredOptionalPermissions: [],
      knownLimits: [
        "Collection runs in the inspected page context and can be unavailable on limited targets.",
        "Cross-origin frames, browser restrictions, collector timeouts, and platform failures can make inventory partial.",
        "IndexedDB values and Cache Storage response bodies are inventoried, not exported."
      ],
      sensitivityImpact: "Storage keys, names, sizes, classifications, fingerprints, and available local/session values can reveal sensitive session or account data.",
      exportImpact: "Safe exports include sanitized storage reports and inventories; raw local/session storage export is separate and gated.",
      diagnosticCategories: ["application", "storage", "platform_limit"],
      defaultEnabled: true,
      developmentOnly: false
    }),
    capability({
      id: "cookie_observed_from_network",
      displayName: "Cookie observations from Network",
      state: "partial",
      sourceType: "derived_network",
      apis: ["HAR request cookies", "HAR response cookies", "Cookie header", "Set-Cookie header"],
      requiredPermissions: [],
      requiredOptionalPermissions: [],
      knownLimits: [
        "This does not read the browser cookie store.",
        "Only cookies visible in current Network data can be modeled.",
        "Raw values depend on what the current collector observed."
      ],
      sensitivityImpact: "Cookie names, metadata, classifications, and raw values where available can expose session, auth, CSRF, tracking, or replay risk.",
      exportImpact: "Safe cookie reports are masked; raw cookie files are separate, session-scoped, and gated.",
      diagnosticCategories: ["cookies", "network", "raw_value_scope"],
      defaultEnabled: true,
      developmentOnly: false
    }),
    capability({
      id: "diagnostics_reason_groups",
      displayName: "Diagnostics reason groups",
      state: "supported",
      sourceType: "runtime_diagnostics",
      apis: ["module status reasons", "diagnostic logs", "target classification reasons"],
      requiredPermissions: [],
      requiredOptionalPermissions: [],
      knownLimits: [
        "Reason groups explain known controlled states and may not cover every browser or extension failure.",
        "Technical details must remain safe for normal UI and exports."
      ],
      sensitivityImpact: "Diagnostics can reveal target structure and capture limitations but should avoid raw page values.",
      exportImpact: "Feeds diagnostics downloads, logs.json, target/module metadata, and export readiness explanations.",
      diagnosticCategories: ["diagnostics", "module_status", "export"],
      defaultEnabled: true,
      developmentOnly: false
    }),
    capability({
      id: "safe_export_package",
      displayName: "Safe export package",
      state: "supported",
      sourceType: "export_pipeline",
      apis: ["Blob", "JSZip-compatible writer", "manifest builder", "report builders"],
      requiredPermissions: [],
      requiredOptionalPermissions: [],
      knownLimits: [
        "ZIP generation is in memory and does not stream.",
        "Export completeness depends on the current captured evidence and target sync state.",
        "Downloads use local Blob links, not the browser downloads API."
      ],
      sensitivityImpact: "Safe package generation must preserve default redaction, masking, and raw-value separation.",
      exportImpact: "Creates MANIFEST.json, reports, captured files, diagnostics metadata, and safe package status.",
      diagnosticCategories: ["export", "manifest", "readiness"],
      defaultEnabled: true,
      developmentOnly: false
    }),
    capability({
      id: "raw_cookie_export",
      displayName: "Raw cookie export",
      state: "manual",
      sourceType: "network_observed_raw_values",
      apis: ["current session cookie model", "raw cookie export builders"],
      requiredPermissions: [],
      requiredOptionalPermissions: [],
      knownLimits: [
        "Raw cookie export only includes raw values already observed in the current session.",
        "This does not read or recover values from the browser cookie store.",
        "Dump objects and explicit confirmation are required by current product policy."
      ],
      sensitivityImpact: "Can expose session, auth, token, CSRF, tracking, and replayable cookie values.",
      exportImpact: "Can add cookies/cookies.raw.json and cookies/cookies.raw.netscape.txt when raw values exist and the user has confirmed the raw workflow.",
      diagnosticCategories: ["cookies", "raw_export", "security"],
      defaultEnabled: false,
      developmentOnly: false
    }),
    capability({
      id: "raw_application_export",
      displayName: "Raw Application export",
      state: "manual",
      sourceType: "application_raw_values",
      apis: ["current session Application model", "raw storage export builders"],
      requiredPermissions: ["host_permissions:<all_urls>"],
      requiredOptionalPermissions: [],
      knownLimits: [
        "Raw export is limited to localStorage and sessionStorage values already captured in memory.",
        "IndexedDB values and Cache Storage response bodies are not exported.",
        "Dump objects and explicit confirmation are required by current product policy."
      ],
      sensitivityImpact: "Can expose session, auth, token, credential, profile, and application state values.",
      exportImpact: "Can add application/storage.raw.json when raw local/session storage values exist and the user has confirmed the raw workflow.",
      diagnosticCategories: ["application", "raw_export", "security"],
      defaultEnabled: false,
      developmentOnly: false
    }),
    capability({
      id: "element_lens",
      displayName: "Element Lens",
      state: "unavailable",
      sourceType: "future_live_page_context",
      apis: ["not wired", "future isolated content script"],
      requiredPermissions: [],
      requiredOptionalPermissions: ["scripting", "activeTab_or_host_access"],
      knownLimits: [
        "The UI v2 workbench currently has an inactive placeholder only.",
        "No inspected-page live element observer is wired.",
        "Future implementation must avoid hidden collection, page mutation, raw input values, and password values."
      ],
      sensitivityImpact: "Future metadata could reveal page structure, interaction context, and form metadata, so it must stay explicit and safe by default.",
      exportImpact: "No current export impact; future evidence persistence requires a separate explicit design and privacy review.",
      diagnosticCategories: ["element_lens", "capability_unavailable"],
      defaultEnabled: false,
      developmentOnly: true
    }),
    capability({
      id: "payload_shape_analysis",
      displayName: "Payload shape analysis",
      state: "experimental",
      sourceType: "derived_body_summary",
      apis: ["captured body metadata", "future safe payload analyzer"],
      requiredPermissions: [],
      requiredOptionalPermissions: [],
      knownLimits: [
        "No dedicated shared payload-shape analyzer is wired into UI v2 yet.",
        "Analysis depends on captured body availability and safe parsing limits.",
        "Raw payload content should not be surfaced by default."
      ],
      sensitivityImpact: "Payload structure can reveal domain objects, identifiers, and data categories even without raw values.",
      exportImpact: "Future exports may include safe shape summaries only when derived from available captured evidence.",
      diagnosticCategories: ["payload", "body_capture", "experimental"],
      defaultEnabled: false,
      developmentOnly: false
    }),
    capability({
      id: "sensitive_exposure_audit",
      displayName: "Sensitive exposure audit",
      state: "experimental",
      sourceType: "derived_safe_summaries",
      apis: ["cookie classifications", "storage classifications", "redacted network summaries", "future exposure audit model"],
      requiredPermissions: [],
      requiredOptionalPermissions: [],
      knownLimits: [
        "Current code has sensitive indicators, but no complete audit workflow is implemented.",
        "Findings must stay probabilistic and avoid claiming secret extraction.",
        "Raw values should remain protected unless a separate raw workflow is explicitly confirmed."
      ],
      sensitivityImpact: "Can flag high-risk locations and categories without dumping secrets; false positives and incomplete evidence are expected.",
      exportImpact: "Future exports may include safe exposure findings, confidence, and missing-evidence notes.",
      diagnosticCategories: ["security", "sensitive_exposure", "experimental"],
      defaultEnabled: false,
      developmentOnly: false
    }),
    capability({
      id: "request_replay_draft",
      displayName: "Request replay draft",
      state: "unavailable",
      sourceType: "future_redacted_network_draft",
      apis: ["not wired", "future request draft builder"],
      requiredPermissions: [],
      requiredOptionalPermissions: [],
      knownLimits: [
        "No replay draft builder is implemented.",
        "Back Tools must not send replay traffic from this capability.",
        "Captured metadata can be incomplete or redacted."
      ],
      sensitivityImpact: "Replay-oriented metadata can expose authentication, CSRF, headers, payload shape, and target behavior if not aggressively redacted.",
      exportImpact: "No current export impact; future draft export must be non-sending and clearly marked as redacted and incomplete.",
      diagnosticCategories: ["network", "replay_draft", "capability_unavailable"],
      defaultEnabled: false,
      developmentOnly: true
    }),
    capability({
      id: "cdp_deep_collectors",
      displayName: "CDP deep collectors",
      state: "experimental",
      sourceType: "future_cdp",
      apis: ["chrome.debugger", "Chrome DevTools Protocol"],
      requiredPermissions: [],
      requiredOptionalPermissions: ["debugger"],
      knownLimits: [
        "No CDP attachment path is implemented in Back Tools.",
        "CDP collection would require explicit user trust and separate permission review.",
        "Deep collectors could collect more data than current safe DevTools APIs."
      ],
      sensitivityImpact: "Could substantially increase access to request bodies, response bodies, cookies, storage, frames, and runtime data.",
      exportImpact: "No current export impact; future CDP evidence would need explicit package labeling, redaction, and diagnostics.",
      diagnosticCategories: ["cdp", "experimental", "permission_review"],
      defaultEnabled: false,
      developmentOnly: true
    })
  ]);

  const capabilitiesById = new Map(capabilities.map((item) => [item.id, item]));
  const statesById = new Set(capabilityStates);

  function capability(input) {
    return Object.freeze({
      id: normalizeId(input.id),
      displayName: String(input.displayName || ""),
      state: normalizeState(input.state),
      sourceType: String(input.sourceType || "unknown"),
      apis: freezeStringArray(input.apis),
      requiredPermissions: freezeStringArray(input.requiredPermissions),
      requiredOptionalPermissions: freezeStringArray(input.requiredOptionalPermissions),
      knownLimits: freezeStringArray(input.knownLimits),
      sensitivityImpact: String(input.sensitivityImpact || ""),
      exportImpact: String(input.exportImpact || ""),
      diagnosticCategories: freezeStringArray(input.diagnosticCategories),
      defaultEnabled: input.defaultEnabled === true,
      developmentOnly: input.developmentOnly === true
    });
  }

  function freezeStringArray(value) {
    return Object.freeze((Array.isArray(value) ? value : []).map((item) => String(item)).filter(Boolean));
  }

  function normalizeId(value) {
    return value === null || value === undefined ? "" : String(value);
  }

  function normalizeState(value) {
    const state = normalizeId(value);
    return capabilityStates.includes(state) ? state : "unknown";
  }

  function contextValues(context, firstKey, secondKey) {
    const source = context || {};
    const value = source[firstKey] || source[secondKey];
    if (Array.isArray(value)) {
      return value.map(normalizeId);
    }
    if (value instanceof Set) {
      return Array.from(value).map(normalizeId);
    }
    return [];
  }

  function contextHasCapability(context, firstKey, secondKey, capabilityId) {
    return contextValues(context, firstKey, secondKey).includes(capabilityId);
  }

  function isDevelopmentContext(context) {
    const source = context || {};
    return source.developmentMode === true || source.environment === "development" || source.mode === "development";
  }

  function isExperimentalAllowed(capabilityId, context) {
    const source = context || {};
    return source.allowExperimentalCapabilities === true
      || contextHasCapability(context, "experimentalCapabilities", "experimentalCapabilityIds", capabilityId);
  }

  function getCapability(id) {
    return capabilitiesById.get(normalizeId(id)) || null;
  }

  function listCapabilities() {
    return capabilities.slice();
  }

  function listCapabilitiesByState(state) {
    const normalized = normalizeId(state);
    if (!statesById.has(normalized)) {
      return [];
    }
    return capabilities.filter((item) => item.state === normalized);
  }

  function isCapabilityEnabled(id, context) {
    const item = getCapability(id);
    if (!item) {
      return false;
    }
    if (item.developmentOnly && !isDevelopmentContext(context)) {
      return false;
    }
    if (contextHasCapability(context, "disabledCapabilities", "disabledCapabilityIds", item.id)) {
      return false;
    }

    const explicitlyEnabled = contextHasCapability(context, "enabledCapabilities", "enabledCapabilityIds", item.id);

    if (item.state === "unavailable" || item.state === "unknown") {
      return false;
    }
    if (item.state === "experimental") {
      return explicitlyEnabled && isExperimentalAllowed(item.id, context);
    }
    if (item.state === "manual") {
      return explicitlyEnabled;
    }

    return item.defaultEnabled || explicitlyEnabled;
  }

  function getCapabilityDiagnostics(id) {
    const item = getCapability(id);
    if (!item) {
      return null;
    }
    return Object.freeze({
      id: item.id,
      state: item.state,
      diagnosticCategories: item.diagnosticCategories.slice(),
      knownLimits: item.knownLimits.slice(),
      sensitivityImpact: item.sensitivityImpact,
      exportImpact: item.exportImpact
    });
  }

  const api = {
    capabilityStates,
    getCapability,
    getCapabilityDiagnostics,
    isCapabilityEnabled,
    listCapabilities,
    listCapabilitiesByState
  };

  return api;
});
