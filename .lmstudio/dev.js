"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/config.ts
var import_sdk, globalConfigSchematics;
var init_config = __esm({
  "src/config.ts"() {
    "use strict";
    import_sdk = require("@lmstudio/sdk");
    globalConfigSchematics = (0, import_sdk.createConfigSchematics)().field(
      "piiModel",
      "string",
      {
        displayName: "PII Detection Model",
        subtitle: "Model identifier used to detect PII. Leave blank to use the currently loaded model. Example: qwen2.5-7b-instruct",
        placeholder: "e.g. qwen2.5-7b-instruct"
      },
      ""
    ).field(
      "assistantModel",
      "string",
      {
        displayName: "Assistant Model",
        subtitle: "Model ID sent to the OpenAI-compatible endpoint for generating responses. Examples: gpt-4o-mini (OpenAI), openai/gpt-4o-mini (OpenRouter).",
        placeholder: "e.g. gpt-4o-mini"
      },
      ""
    ).field(
      "skipConfirmation",
      "boolean",
      {
        displayName: "Skip Confirmation",
        subtitle: "When enabled, redacted prompts are forwarded immediately without requiring '--c'. The redaction preview is still shown in the status panel."
      },
      false
    ).field(
      "apiKey",
      "string",
      {
        displayName: "API Key",
        subtitle: "API key for the OpenAI-compatible endpoint (e.g. sk-... for OpenAI, sk-or-... for OpenRouter). Stored as a protected field.",
        isProtected: true,
        placeholder: "sk-..."
      },
      ""
    ).field(
      "baseUrl",
      "string",
      {
        displayName: "Base URL",
        subtitle: "Base URL of the OpenAI-compatible endpoint. Examples: https://api.openai.com/v1, https://openrouter.ai/api/v1",
        placeholder: "https://api.openai.com/v1"
      },
      "https://api.openai.com/v1"
    ).build();
  }
});

// src/redactor.ts
function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function buildPlaceholder(identifier) {
  return `[[[${identifier}]]]`;
}
function buildIdentifier(type, n) {
  return `${type}_${n}`;
}
function startingCounters(existing) {
  const maxima = /* @__PURE__ */ new Map();
  for (const identifier of existing.values()) {
    const match = /^([A-Z]+)_(\d+)$/.exec(identifier);
    if (match === null) {
      continue;
    }
    const type = match[1];
    const n = parseInt(match[2], 10);
    maxima.set(type, Math.max(maxima.get(type) ?? 0, n));
  }
  return [...maxima];
}
function redact(text, rawEntities, existing) {
  const counters = new Map(existing ? startingCounters(existing) : []);
  const canonicalMap = /* @__PURE__ */ new Map();
  const entities2 = [];
  for (const raw of rawEntities) {
    const key = raw.original.toLowerCase().trim();
    if (canonicalMap.has(key)) {
      continue;
    }
    const existingIdentifier = existing?.get(key);
    if (existingIdentifier !== void 0) {
      canonicalMap.set(key, existingIdentifier);
      entities2.push({ identifier: existingIdentifier, type: raw.type, original: raw.original });
      continue;
    }
    const n = (counters.get(raw.type) ?? 0) + 1;
    counters.set(raw.type, n);
    const identifier = buildIdentifier(raw.type, n);
    canonicalMap.set(key, identifier);
    entities2.push({ identifier, type: raw.type, original: raw.original });
  }
  const replacements = entities2.map((e) => ({
    original: e.original,
    placeholder: buildPlaceholder(e.identifier)
  })).sort((a, b) => b.original.length - a.original.length);
  let redacted = text;
  for (const { original, placeholder } of replacements) {
    const escaped = escapeRegExp(original);
    redacted = redacted.replace(new RegExp(escaped, "g"), placeholder);
  }
  return { redacted_text: redacted, entities: entities2 };
}
function validatePlaceholders(result) {
  for (const entity of result.entities) {
    const placeholder = buildPlaceholder(entity.identifier);
    if (!result.redacted_text.includes(placeholder)) {
      return false;
    }
  }
  return true;
}
var init_redactor = __esm({
  "src/redactor.ts"() {
    "use strict";
  }
});

// src/entityStore.ts
function normalize(text) {
  return text.toLowerCase().trim();
}
function addEntities(newEntities) {
  for (const entity of newEntities) {
    const key = normalize(entity.original);
    if (!entities.has(key)) {
      entities.set(key, entity);
    }
  }
}
function existingIdentifiers() {
  const map = /* @__PURE__ */ new Map();
  for (const [key, entity] of entities) {
    map.set(key, entity.identifier);
  }
  return map;
}
function unredactText(text) {
  let result = text;
  for (const entity of entities.values()) {
    const placeholder = escapeRegExp(buildPlaceholder(entity.identifier));
    const pattern = new RegExp(`\\[*${placeholder}\\]*`, "g");
    result = result.replace(pattern, entity.original);
  }
  return result;
}
function redactText(text) {
  const sorted = [...entities.values()].sort(
    (a, b) => b.original.length - a.original.length
  );
  let result = text;
  for (const entity of sorted) {
    const pattern = new RegExp(escapeRegExp(entity.original), "g");
    result = result.replace(pattern, buildPlaceholder(entity.identifier));
  }
  return result;
}
var entities;
var init_entityStore = __esm({
  "src/entityStore.ts"() {
    "use strict";
    init_redactor();
    entities = /* @__PURE__ */ new Map();
  }
});

// src/generator.ts
function toOpenAIMessages(history) {
  const messages = [];
  for (const message of history) {
    const role = message.getRole();
    if (role === "tool") {
      continue;
    }
    messages.push({ role, content: redactText(message.getText()) });
  }
  return messages;
}
async function generate(ctl, history) {
  const globalConfig = ctl.getGlobalPluginConfig(globalConfigSchematics);
  const assistantModel = globalConfig.get("assistantModel").trim();
  if (assistantModel.length === 0) {
    throw new Error(
      "Assistant Model is not configured. Set it in the plugin settings (e.g. gpt-4o-mini for OpenAI, openai/gpt-4o-mini for OpenRouter)."
    );
  }
  const apiKey = globalConfig.get("apiKey").trim();
  if (apiKey.length === 0) {
    throw new Error(
      "API Key is not configured. Set it in the plugin's global settings."
    );
  }
  const baseUrl2 = globalConfig.get("baseUrl").trim() || DEFAULT_BASE_URL;
  const client2 = new import_openai.default({ apiKey, baseURL: baseUrl2 });
  const stream = await client2.chat.completions.create({
    model: assistantModel,
    messages: toOpenAIMessages(history),
    stream: true
  });
  ctl.onAborted(() => {
    stream.controller.abort();
  });
  let full = "";
  for await (const chunk of stream) {
    ctl.abortSignal.throwIfAborted();
    const delta = chunk.choices[0]?.delta?.content;
    if (delta) {
      full += delta;
    }
  }
  if (full.length === 0) {
    console.info("pii-redact: assistant model returned an empty response.");
  }
  const unredacted = unredactText(full);
  const unmatched = unredacted.match(PLACEHOLDER_PATTERN);
  if (unmatched !== null) {
    console.info(
      "pii-redact: response still contains placeholders with no known original:",
      [...new Set(unmatched)]
    );
  }
  ctl.fragmentGenerated(unredacted);
}
var import_openai, DEFAULT_BASE_URL, PLACEHOLDER_PATTERN;
var init_generator = __esm({
  "src/generator.ts"() {
    "use strict";
    import_openai = __toESM(require("openai"));
    init_config();
    init_entityStore();
    DEFAULT_BASE_URL = "https://api.openai.com/v1";
    PLACEHOLDER_PATTERN = /\[\[\[[A-Z]+_\d+\]\]\]/g;
  }
});

// src/types.ts
var import_zod, PII_TYPES, piiTypeSchema, piiEntitySchema, llmDetectionResponseSchema, redactionResultSchema, CONFIRM_SUFFIX;
var init_types = __esm({
  "src/types.ts"() {
    "use strict";
    import_zod = require("zod");
    PII_TYPES = ["PERSON", "EMAIL", "PHONE", "ORG", "LOCATION", "OTHER"];
    piiTypeSchema = import_zod.z.enum(PII_TYPES);
    piiEntitySchema = import_zod.z.object({
      /** The raw text span found in the prompt */
      original: import_zod.z.string().min(1),
      /** Semantic category */
      type: piiTypeSchema
    });
    llmDetectionResponseSchema = import_zod.z.object({
      entities: import_zod.z.array(piiEntitySchema)
    });
    redactionResultSchema = import_zod.z.object({
      redacted_text: import_zod.z.string(),
      entities: import_zod.z.array(
        import_zod.z.object({
          identifier: import_zod.z.string().regex(/^[A-Z]+_\d+$/),
          type: piiTypeSchema,
          original: import_zod.z.string().min(1)
        })
      )
    });
    CONFIRM_SUFFIX = "--c";
  }
});

// src/piiDetector.ts
function countDigits(s) {
  return (s.match(/\d/g) ?? []).length;
}
function regexDetect(text) {
  const spans = [];
  const seen = /* @__PURE__ */ new Set();
  for (const match of text.matchAll(EMAIL_REGEX)) {
    const original = match[0];
    if (!seen.has(original)) {
      seen.add(original);
      spans.push({ original, type: "EMAIL" });
    }
  }
  for (const match of text.matchAll(PHONE_REGEX)) {
    const original = match[0].trim();
    if (countDigits(original) >= MIN_PHONE_DIGITS && !seen.has(original)) {
      seen.add(original);
      spans.push({ original, type: "PHONE" });
    }
  }
  return spans;
}
async function llmDetect(model, text, abortSignal) {
  const result = await model.respond(
    [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: text }
    ],
    {
      structured: llmDetectionResponseSchema,
      // Generous but bounded — prevents the model getting stuck on large inputs
      maxTokens: 2048,
      temperature: 0,
      signal: abortSignal
    }
  );
  return result.parsed;
}
function mergeDetections(llmEntities, regexSpans) {
  const covered = new Set(llmEntities.map((e) => e.original.toLowerCase()));
  const merged = [...llmEntities];
  for (const span of regexSpans) {
    if (!covered.has(span.original.toLowerCase())) {
      covered.add(span.original.toLowerCase());
      merged.push(span);
    }
  }
  return merged;
}
var SYSTEM_PROMPT, EMAIL_REGEX, PHONE_REGEX, MIN_PHONE_DIGITS;
var init_piiDetector = __esm({
  "src/piiDetector.ts"() {
    "use strict";
    init_types();
    SYSTEM_PROMPT = `You are a privacy-focused PII (Personally Identifiable Information) detector.

Your task: analyse the user's text and return a JSON object listing every PII entity found.

Rules:
1. Detect the following entity types:
   - PERSON   \u2014 full names, first names, last names, nicknames
   - EMAIL    \u2014 email addresses
   - PHONE    \u2014 phone numbers (any format)
   - ORG      \u2014 company, organisation, institution names
   - LOCATION \u2014 street addresses, cities, countries, postcodes
   - OTHER    \u2014 any other PII not covered above (e.g. national ID, passport, credit card)

2. For each entity return the EXACT substring as it appears in the text (preserve case and spacing).

3. Coreference resolution: if a shortened or repeated reference (e.g. "Micky" after "Mickey Mouse")
   unambiguously refers to the same entity, include it as a SEPARATE entry with the same type so the
   caller can merge them. Only do this when the reference is unambiguous.

4. Do NOT invent entities. Only return entities that are actually present in the text.

5. Return ONLY valid JSON matching this schema \u2014 no markdown, no explanation:
{
  "entities": [
    { "original": "<exact text span>", "type": "<TYPE>" },
    ...
  ]
}

If no PII is found, return: { "entities": [] }`;
    EMAIL_REGEX = /[\w.+\-]+@[\w\-]+\.[a-zA-Z]{2,}/g;
    PHONE_REGEX = /(?:\+?\d{1,3}[\s\-.]?)?\(?\d{1,4}\)?[\s\-.]?\d{1,4}[\s\-.]?\d{1,9}(?:[\s\-.]?\d{1,4})?/g;
    MIN_PHONE_DIGITS = 7;
  }
});

// src/promptPreprocessor.ts
async function attemptDetection(ctl, text) {
  const globalConfig = ctl.getGlobalPluginConfig(globalConfigSchematics);
  const modelId = globalConfig.get("piiModel").trim();
  const model = modelId.length > 0 ? await ctl.client.llm.model(modelId, { signal: ctl.abortSignal }) : await ctl.client.llm.model();
  const llmResponse = await llmDetect(model, text, ctl.abortSignal);
  const regexSpans = regexDetect(text);
  const merged = mergeDetections(llmResponse.entities, regexSpans);
  const result = redact(text, merged, existingIdentifiers());
  const parseResult = redactionResultSchema.safeParse(result);
  if (!parseResult.success) {
    ctl.debug("RedactionResult schema validation failed", parseResult.error.format());
    return null;
  }
  if (!validatePlaceholders(result)) {
    ctl.debug("Placeholder integrity check failed \u2014 some placeholders are missing from redacted text");
    return null;
  }
  return result;
}
function formatEntitySummary(result) {
  if (result.entities.length === 0) {
    return "No PII detected.";
  }
  const lines = result.entities.map(
    (e) => `  \u2022 [[[${e.identifier}]]]  \u2190  "${e.original}"  (${e.type})`
  );
  return `Detected ${result.entities.length} PII entity(ies):
${lines.join("\n")}`;
}
async function preprocess(ctl, userMessage) {
  const rawText = userMessage.getText();
  if (rawText === CONFIRM_SUFFIX) {
    if (pendingRedactedPrompt === null) {
      ctl.createStatus({
        status: "error",
        text: "No pending redaction to confirm. Please send your prompt first."
      });
      throw new Error(
        "No pending redaction to confirm. Please send your prompt first."
      );
    }
    const redactedText = pendingRedactedPrompt;
    pendingRedactedPrompt = null;
    const confirmStatus = ctl.createStatus({
      status: "done",
      text: "PII redaction confirmed \u2014 forwarding redacted prompt."
    });
    ctl.debug("User confirmed redacted prompt. Forwarding saved redacted text.");
    return redactedText;
  }
  const globalConfig = ctl.getGlobalPluginConfig(globalConfigSchematics);
  const skipConfirmation = globalConfig.get("skipConfirmation");
  const detectionStatus = ctl.createStatus({
    status: "loading",
    text: "Detecting PII in prompt\u2026"
  });
  let result = null;
  try {
    result = await attemptDetection(ctl, rawText);
  } catch (err) {
    ctl.debug("PII detection attempt 1 failed", err);
  }
  if (result === null) {
    detectionStatus.setState({
      status: "loading",
      text: "PII detection failed \u2014 retrying\u2026"
    });
    try {
      result = await attemptDetection(ctl, rawText);
    } catch (err) {
      ctl.debug("PII detection attempt 2 failed", err);
    }
  }
  if (result === null) {
    detectionStatus.setState({
      status: "error",
      text: "PII detection failed after retry. Request aborted. Check that a model is loaded and try again."
    });
    throw new Error(
      "PII detection failed after one retry. Request aborted \u2014 the original prompt is never forwarded."
    );
  }
  const entitySummary = formatEntitySummary(result);
  if (result.entities.length === 0) {
    detectionStatus.setState({
      status: "done",
      text: "No PII detected \u2014 forwarding original prompt."
    });
    return userMessage;
  }
  addEntities(result.entities);
  if (skipConfirmation) {
    detectionStatus.setState({
      status: "done",
      text: `PII redacted successfully \u2014 forwarding without confirmation.

${entitySummary}`
    });
    ctl.debug("Redaction result", result);
    return result.redacted_text;
  }
  pendingRedactedPrompt = result.redacted_text;
  const preview = result.redacted_text.length > 500 ? result.redacted_text.slice(0, 500) + "\u2026" : result.redacted_text;
  detectionStatus.setState({
    status: "canceled",
    text: `PII detected \u2014 redaction preview shown below. Send another message containing '--c' to confirm and proceed.

--- Redacted prompt ---
${preview}

--- Entity map ---
${entitySummary}`
  });
  throw new Error(
    "Prompt contains PII. Review the redacted preview in the status panel, then confirm your message with --c to proceed."
  );
}
var pendingRedactedPrompt;
var init_promptPreprocessor = __esm({
  "src/promptPreprocessor.ts"() {
    "use strict";
    init_config();
    init_entityStore();
    init_piiDetector();
    init_redactor();
    init_types();
    pendingRedactedPrompt = null;
  }
});

// src/index.ts
var src_exports = {};
__export(src_exports, {
  main: () => main
});
async function main(context) {
  context.withGlobalConfigSchematics(globalConfigSchematics);
  context.withPromptPreprocessor(preprocess);
  context.withGenerator(generate);
}
var init_src = __esm({
  "src/index.ts"() {
    "use strict";
    init_config();
    init_generator();
    init_promptPreprocessor();
  }
});

// .lmstudio/entry.ts
var import_sdk2 = require("@lmstudio/sdk");
var clientIdentifier = process.env.LMS_PLUGIN_CLIENT_IDENTIFIER;
var clientPasskey = process.env.LMS_PLUGIN_CLIENT_PASSKEY;
var baseUrl = process.env.LMS_PLUGIN_BASE_URL;
var client = new import_sdk2.LMStudioClient({
  clientIdentifier,
  clientPasskey,
  baseUrl
});
globalThis.__LMS_PLUGIN_CONTEXT = true;
var predictionLoopHandlerSet = false;
var promptPreprocessorSet = false;
var configSchematicsSet = false;
var globalConfigSchematicsSet = false;
var toolsProviderSet = false;
var generatorSet = false;
var selfRegistrationHost = client.plugins.getSelfRegistrationHost();
var pluginContext = {
  withPredictionLoopHandler: (generate2) => {
    if (predictionLoopHandlerSet) {
      throw new Error("PredictionLoopHandler already registered");
    }
    if (toolsProviderSet) {
      throw new Error("PredictionLoopHandler cannot be used with a tools provider");
    }
    predictionLoopHandlerSet = true;
    selfRegistrationHost.setPredictionLoopHandler(generate2);
    return pluginContext;
  },
  withPromptPreprocessor: (preprocess2) => {
    if (promptPreprocessorSet) {
      throw new Error("PromptPreprocessor already registered");
    }
    promptPreprocessorSet = true;
    selfRegistrationHost.setPromptPreprocessor(preprocess2);
    return pluginContext;
  },
  withConfigSchematics: (configSchematics) => {
    if (configSchematicsSet) {
      throw new Error("Config schematics already registered");
    }
    configSchematicsSet = true;
    selfRegistrationHost.setConfigSchematics(configSchematics);
    return pluginContext;
  },
  withGlobalConfigSchematics: (globalConfigSchematics2) => {
    if (globalConfigSchematicsSet) {
      throw new Error("Global config schematics already registered");
    }
    globalConfigSchematicsSet = true;
    selfRegistrationHost.setGlobalConfigSchematics(globalConfigSchematics2);
    return pluginContext;
  },
  withToolsProvider: (toolsProvider) => {
    if (toolsProviderSet) {
      throw new Error("Tools provider already registered");
    }
    if (predictionLoopHandlerSet) {
      throw new Error("Tools provider cannot be used with a predictionLoopHandler");
    }
    toolsProviderSet = true;
    selfRegistrationHost.setToolsProvider(toolsProvider);
    return pluginContext;
  },
  withGenerator: (generator) => {
    if (generatorSet) {
      throw new Error("Generator already registered");
    }
    generatorSet = true;
    selfRegistrationHost.setGenerator(generator);
    return pluginContext;
  }
};
Promise.resolve().then(() => (init_src(), src_exports)).then(async (module2) => {
  return await module2.main(pluginContext);
}).then(() => {
  selfRegistrationHost.initCompleted();
}).catch((error) => {
  console.error("Failed to execute the main function of the plugin.");
  console.error(error);
});
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vc3JjL2NvbmZpZy50cyIsICIuLi9zcmMvcmVkYWN0b3IudHMiLCAiLi4vc3JjL2VudGl0eVN0b3JlLnRzIiwgIi4uL3NyYy9nZW5lcmF0b3IudHMiLCAiLi4vc3JjL3R5cGVzLnRzIiwgIi4uL3NyYy9waWlEZXRlY3Rvci50cyIsICIuLi9zcmMvcHJvbXB0UHJlcHJvY2Vzc29yLnRzIiwgIi4uL3NyYy9pbmRleC50cyIsICJlbnRyeS50cyJdLAogICJzb3VyY2VzQ29udGVudCI6IFsiaW1wb3J0IHsgY3JlYXRlQ29uZmlnU2NoZW1hdGljcyB9IGZyb20gXCJAbG1zdHVkaW8vc2RrXCI7XG5cbi8qKlxuICogR2xvYmFsIGNvbmZpZ3VyYXRpb24gXHUyMDE0IHNoYXJlZCBhY3Jvc3MgYWxsIGNoYXRzLCBzbyB2YWx1ZXMgcGVyc2lzdCB3aGVuXG4gKiBzdGFydGluZyBhIG5ldyBjb252ZXJzYXRpb24uXG4gKi9cbmV4cG9ydCBjb25zdCBnbG9iYWxDb25maWdTY2hlbWF0aWNzID0gY3JlYXRlQ29uZmlnU2NoZW1hdGljcygpXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgLy8gUElJIGRldGVjdGlvbiBtb2RlbFxuICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC5maWVsZChcbiAgICBcInBpaU1vZGVsXCIsXG4gICAgXCJzdHJpbmdcIixcbiAgICB7XG4gICAgICBkaXNwbGF5TmFtZTogXCJQSUkgRGV0ZWN0aW9uIE1vZGVsXCIsXG4gICAgICBzdWJ0aXRsZTpcbiAgICAgICAgXCJNb2RlbCBpZGVudGlmaWVyIHVzZWQgdG8gZGV0ZWN0IFBJSS4gTGVhdmUgYmxhbmsgdG8gdXNlIHRoZSBjdXJyZW50bHkgbG9hZGVkIG1vZGVsLiBcIiArXG4gICAgICAgIFwiRXhhbXBsZTogcXdlbjIuNS03Yi1pbnN0cnVjdFwiLFxuICAgICAgcGxhY2Vob2xkZXI6IFwiZS5nLiBxd2VuMi41LTdiLWluc3RydWN0XCIsXG4gICAgfSxcbiAgICBcIlwiLFxuICApXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgLy8gQXNzaXN0YW50IG1vZGVsICh0aGUgdGhpcmQtcGFydHkgbW9kZWwgdGhhdCByZWNlaXZlcyB0aGUgcmVkYWN0ZWQgcHJvbXB0KVxuICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC5maWVsZChcbiAgICBcImFzc2lzdGFudE1vZGVsXCIsXG4gICAgXCJzdHJpbmdcIixcbiAgICB7XG4gICAgICBkaXNwbGF5TmFtZTogXCJBc3Npc3RhbnQgTW9kZWxcIixcbiAgICAgIHN1YnRpdGxlOlxuICAgICAgICBcIk1vZGVsIElEIHNlbnQgdG8gdGhlIE9wZW5BSS1jb21wYXRpYmxlIGVuZHBvaW50IGZvciBnZW5lcmF0aW5nIHJlc3BvbnNlcy4gXCIgK1xuICAgICAgICBcIkV4YW1wbGVzOiBncHQtNG8tbWluaSAoT3BlbkFJKSwgb3BlbmFpL2dwdC00by1taW5pIChPcGVuUm91dGVyKS5cIixcbiAgICAgIHBsYWNlaG9sZGVyOiBcImUuZy4gZ3B0LTRvLW1pbmlcIixcbiAgICB9LFxuICAgIFwiXCIsXG4gIClcbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAvLyBDb25maXJtYXRpb24gZ2F0ZVxuICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC5maWVsZChcbiAgICBcInNraXBDb25maXJtYXRpb25cIixcbiAgICBcImJvb2xlYW5cIixcbiAgICB7XG4gICAgICBkaXNwbGF5TmFtZTogXCJTa2lwIENvbmZpcm1hdGlvblwiLFxuICAgICAgc3VidGl0bGU6XG4gICAgICAgIFwiV2hlbiBlbmFibGVkLCByZWRhY3RlZCBwcm9tcHRzIGFyZSBmb3J3YXJkZWQgaW1tZWRpYXRlbHkgd2l0aG91dCByZXF1aXJpbmcgJy0tYycuIFwiICtcbiAgICAgICAgXCJUaGUgcmVkYWN0aW9uIHByZXZpZXcgaXMgc3RpbGwgc2hvd24gaW4gdGhlIHN0YXR1cyBwYW5lbC5cIixcbiAgICB9LFxuICAgIGZhbHNlLFxuICApXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgLy8gQVBJIGtleSBmb3IgdGhlIE9wZW5BSS1jb21wYXRpYmxlIGVuZHBvaW50XG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgLmZpZWxkKFxuICAgIFwiYXBpS2V5XCIsXG4gICAgXCJzdHJpbmdcIixcbiAgICB7XG4gICAgICBkaXNwbGF5TmFtZTogXCJBUEkgS2V5XCIsXG4gICAgICBzdWJ0aXRsZTpcbiAgICAgICAgXCJBUEkga2V5IGZvciB0aGUgT3BlbkFJLWNvbXBhdGlibGUgZW5kcG9pbnQgKGUuZy4gc2stLi4uIGZvciBPcGVuQUksIFwiICtcbiAgICAgICAgXCJzay1vci0uLi4gZm9yIE9wZW5Sb3V0ZXIpLiBTdG9yZWQgYXMgYSBwcm90ZWN0ZWQgZmllbGQuXCIsXG4gICAgICBpc1Byb3RlY3RlZDogdHJ1ZSxcbiAgICAgIHBsYWNlaG9sZGVyOiBcInNrLS4uLlwiLFxuICAgIH0sXG4gICAgXCJcIixcbiAgKVxuICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC8vIEJhc2UgVVJMIG9mIHRoZSBPcGVuQUktY29tcGF0aWJsZSBlbmRwb2ludFxuICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC5maWVsZChcbiAgICBcImJhc2VVcmxcIixcbiAgICBcInN0cmluZ1wiLFxuICAgIHtcbiAgICAgIGRpc3BsYXlOYW1lOiBcIkJhc2UgVVJMXCIsXG4gICAgICBzdWJ0aXRsZTpcbiAgICAgICAgXCJCYXNlIFVSTCBvZiB0aGUgT3BlbkFJLWNvbXBhdGlibGUgZW5kcG9pbnQuIFwiICtcbiAgICAgICAgXCJFeGFtcGxlczogaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS92MSwgaHR0cHM6Ly9vcGVucm91dGVyLmFpL2FwaS92MVwiLFxuICAgICAgcGxhY2Vob2xkZXI6IFwiaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS92MVwiLFxuICAgIH0sXG4gICAgXCJodHRwczovL2FwaS5vcGVuYWkuY29tL3YxXCIsXG4gIClcbiAgLmJ1aWxkKCk7XG4iLCAiaW1wb3J0IHR5cGUgeyBQaWlFbnRpdHksIFBpaVR5cGUsIFJlZGFjdGlvblJlc3VsdCB9IGZyb20gXCIuL3R5cGVzXCI7XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gUGxhY2Vob2xkZXIgaGVscGVyc1xuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbi8qKiBFc2NhcGUgc3BlY2lhbCByZWdleCBjaGFyYWN0ZXJzIGluIGEgbGl0ZXJhbCBzdHJpbmcuICovXG5leHBvcnQgZnVuY3Rpb24gZXNjYXBlUmVnRXhwKHRleHQ6IHN0cmluZyk6IHN0cmluZyB7XG4gIHJldHVybiB0ZXh0LnJlcGxhY2UoL1suKis/XiR7fSgpfFtcXF1cXFxcXS9nLCBcIlxcXFwkJlwiKTtcbn1cblxuLyoqXG4gKiBCdWlsZCB0aGUgcGxhY2Vob2xkZXIgc3RyaW5nIGZvciBhIGdpdmVuIGlkZW50aWZpZXIuXG4gKiBGb3JtYXQ6IFtbW1RZUEVfTl1dXVxuICovXG5leHBvcnQgZnVuY3Rpb24gYnVpbGRQbGFjZWhvbGRlcihpZGVudGlmaWVyOiBzdHJpbmcpOiBzdHJpbmcge1xuICByZXR1cm4gYFtbWyR7aWRlbnRpZmllcn1dXV1gO1xufVxuXG4vKipcbiAqIEJ1aWxkIGEgZGV0ZXJtaW5pc3RpYyBpZGVudGlmaWVyIGtleSBmb3IgYSAodHlwZSwgY291bnRlcikgcGFpci5cbiAqIGUuZy4gKFwiUEVSU09OXCIsIDEpIFx1MjE5MiBcIlBFUlNPTl8xXCJcbiAqL1xuZnVuY3Rpb24gYnVpbGRJZGVudGlmaWVyKHR5cGU6IFBpaVR5cGUsIG46IG51bWJlcik6IHN0cmluZyB7XG4gIHJldHVybiBgJHt0eXBlfV8ke259YDtcbn1cblxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4vLyBTcGFuLWJhc2VkIGVudGl0eSAoaW50ZXJuYWwsIGJlZm9yZSBpZGVudGlmaWVyIGFzc2lnbm1lbnQpXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuaW50ZXJmYWNlIFJhd0VudGl0eSB7XG4gIG9yaWdpbmFsOiBzdHJpbmc7XG4gIHR5cGU6IFBpaVR5cGU7XG59XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gUmVkYWN0b3Jcbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4vKipcbiAqIEJ1aWxkIHRoZSBzdGFydGluZyBjb3VudGVyIHBlciB0eXBlIHNvIHRoYXQgbmV3IGlkZW50aWZpZXJzIGNvbnRpbnVlIGFmdGVyXG4gKiB0aGUgaGlnaGVzdCBudW1iZXIgYWxyZWFkeSBhc3NpZ25lZCAoYXZvaWRzIGNvbGxpc2lvbnMgYWNyb3NzIHR1cm5zKS5cbiAqL1xuZnVuY3Rpb24gc3RhcnRpbmdDb3VudGVycyhleGlzdGluZzogTWFwPHN0cmluZywgc3RyaW5nPik6IEFycmF5PFtQaWlUeXBlLCBudW1iZXJdPiB7XG4gIGNvbnN0IG1heGltYSA9IG5ldyBNYXA8UGlpVHlwZSwgbnVtYmVyPigpO1xuICBmb3IgKGNvbnN0IGlkZW50aWZpZXIgb2YgZXhpc3RpbmcudmFsdWVzKCkpIHtcbiAgICBjb25zdCBtYXRjaCA9IC9eKFtBLVpdKylfKFxcZCspJC8uZXhlYyhpZGVudGlmaWVyKTtcbiAgICBpZiAobWF0Y2ggPT09IG51bGwpIHtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgICBjb25zdCB0eXBlID0gbWF0Y2hbMV0gYXMgUGlpVHlwZTtcbiAgICBjb25zdCBuID0gcGFyc2VJbnQobWF0Y2hbMl0sIDEwKTtcbiAgICBtYXhpbWEuc2V0KHR5cGUsIE1hdGgubWF4KG1heGltYS5nZXQodHlwZSkgPz8gMCwgbikpO1xuICB9XG4gIHJldHVybiBbLi4ubWF4aW1hXTtcbn1cblxuLyoqXG4gKiBHaXZlbiB0aGUgb3JpZ2luYWwgdGV4dCBhbmQgYSBsaXN0IG9mIHJhdyBkZXRlY3RlZCBlbnRpdGllcyAob3JkZXJlZCBieVxuICogZmlyc3QgYXBwZWFyYW5jZSksIGFzc2lnbiB1bmlxdWUgaWRlbnRpZmllcnMsIHJlc29sdmUgY29yZWZlcmVuY2VzLCBhbmRcbiAqIHN1YnN0aXR1dGUgYWxsIG9jY3VycmVuY2VzIGluIHRoZSB0ZXh0LlxuICpcbiAqIFJ1bGVzOlxuICogLSBFbnRpdGllcyBhcmUgbnVtYmVyZWQgcGVyLXR5cGUgc3RhcnRpbmcgYXQgMS5cbiAqIC0gQ29yZWZlcmVuY2U6IGlmIHR3byByYXcgZW50aXRpZXMgaGF2ZSB0aGUgc2FtZSBgb3JpZ2luYWxgIHZhbHVlIChjYXNlLVxuICogICBpbnNlbnNpdGl2ZSksIHRoZXkgc2hhcmUgdGhlIHNhbWUgaWRlbnRpZmllci5cbiAqIC0gSWYgYGV4aXN0aW5nYCBpcyBwcm92aWRlZCAobm9ybWFsaXplZCBvcmlnaW5hbCBcdTIxOTIgaWRlbnRpZmllciksIGVudGl0aWVzXG4gKiAgIHNlZW4gaW4gZWFybGllciB0dXJucyByZXVzZSB0aGVpciBwcmV2aW91cyBpZGVudGlmaWVyLCBhbmQgbmV3IGNvdW50ZXJzXG4gKiAgIGNvbnRpbnVlIGFmdGVyIHRoZSBoaWdoZXN0IGV4aXN0aW5nIG51bWJlciBwZXIgdHlwZS5cbiAqIC0gU3Vic3RpdHV0aW9uIGlzIHBlcmZvcm1lZCBsb25nZXN0LW1hdGNoLWZpcnN0IHRvIGF2b2lkIHBhcnRpYWwgb3ZlcmxhcHNcbiAqICAgKGUuZy4gXCJKb2huIFNtaXRoXCIgYmVmb3JlIFwiSm9oblwiKS5cbiAqIC0gUGxhY2Vob2xkZXJzIGFyZSB0cmlwbGUtYnJhY2tldCB3cmFwcGVkIHNvIGRvd25zdHJlYW0gbW9kZWxzIGFyZSB1bmxpa2VseVxuICogICB0byBhbHRlciB0aGVtLlxuICovXG5leHBvcnQgZnVuY3Rpb24gcmVkYWN0KFxuICB0ZXh0OiBzdHJpbmcsXG4gIHJhd0VudGl0aWVzOiBSYXdFbnRpdHlbXSxcbiAgZXhpc3Rpbmc/OiBNYXA8c3RyaW5nLCBzdHJpbmc+LFxuKTogUmVkYWN0aW9uUmVzdWx0IHtcbiAgLy8gU3RlcCAxOiBEZWR1cGxpY2F0ZSBhbmQgYXNzaWduIGlkZW50aWZpZXJzLlxuICAvLyBXZSBwcmVzZXJ2ZSBmaXJzdC1hcHBlYXJhbmNlIG9yZGVyIGFuZCBtZXJnZSBpZGVudGljYWwgb3JpZ2luYWxzLlxuICBjb25zdCBjb3VudGVycyA9IG5ldyBNYXA8UGlpVHlwZSwgbnVtYmVyPihleGlzdGluZyA/IHN0YXJ0aW5nQ291bnRlcnMoZXhpc3RpbmcpIDogW10pO1xuICAvLyBNYXAgZnJvbSBub3JtYWxpc2VkIG9yaWdpbmFsIHRleHQgXHUyMTkyIGFzc2lnbmVkIGlkZW50aWZpZXJcbiAgY29uc3QgY2Fub25pY2FsTWFwID0gbmV3IE1hcDxzdHJpbmcsIHN0cmluZz4oKTtcbiAgLy8gRmluYWwgb3JkZXJlZCBlbnRpdHkgbGlzdCAobm8gZHVwbGljYXRlcylcbiAgY29uc3QgZW50aXRpZXM6IFBpaUVudGl0eVtdID0gW107XG5cbiAgZm9yIChjb25zdCByYXcgb2YgcmF3RW50aXRpZXMpIHtcbiAgICBjb25zdCBrZXkgPSByYXcub3JpZ2luYWwudG9Mb3dlckNhc2UoKS50cmltKCk7XG4gICAgaWYgKGNhbm9uaWNhbE1hcC5oYXMoa2V5KSkge1xuICAgICAgLy8gQWxyZWFkeSBhc3NpZ25lZCBcdTIwMTQgY29yZWZlcmVuY2UgcmVzb2x2ZWRcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgICBjb25zdCBleGlzdGluZ0lkZW50aWZpZXIgPSBleGlzdGluZz8uZ2V0KGtleSk7XG4gICAgaWYgKGV4aXN0aW5nSWRlbnRpZmllciAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAvLyBTZWVuIGluIGFuIGVhcmxpZXIgdHVybiBcdTIwMTQgcmV1c2UgdGhlIHByZXZpb3VzIGlkZW50aWZpZXJcbiAgICAgIGNhbm9uaWNhbE1hcC5zZXQoa2V5LCBleGlzdGluZ0lkZW50aWZpZXIpO1xuICAgICAgZW50aXRpZXMucHVzaCh7IGlkZW50aWZpZXI6IGV4aXN0aW5nSWRlbnRpZmllciwgdHlwZTogcmF3LnR5cGUsIG9yaWdpbmFsOiByYXcub3JpZ2luYWwgfSk7XG4gICAgICBjb250aW51ZTtcbiAgICB9XG4gICAgY29uc3QgbiA9IChjb3VudGVycy5nZXQocmF3LnR5cGUpID8/IDApICsgMTtcbiAgICBjb3VudGVycy5zZXQocmF3LnR5cGUsIG4pO1xuICAgIGNvbnN0IGlkZW50aWZpZXIgPSBidWlsZElkZW50aWZpZXIocmF3LnR5cGUsIG4pO1xuICAgIGNhbm9uaWNhbE1hcC5zZXQoa2V5LCBpZGVudGlmaWVyKTtcbiAgICBlbnRpdGllcy5wdXNoKHsgaWRlbnRpZmllciwgdHlwZTogcmF3LnR5cGUsIG9yaWdpbmFsOiByYXcub3JpZ2luYWwgfSk7XG4gIH1cblxuICAvLyBTdGVwIDI6IEJ1aWxkIHJlcGxhY2VtZW50IHBhaXJzIHNvcnRlZCBieSBsZW5ndGggZGVzY2VuZGluZyAobG9uZ2VzdCBmaXJzdClcbiAgLy8gdG8gYXZvaWQgcmVwbGFjaW5nIHN1YnN0cmluZ3Mgb2YgbG9uZ2VyIG1hdGNoZXMuXG4gIGNvbnN0IHJlcGxhY2VtZW50czogQXJyYXk8eyBvcmlnaW5hbDogc3RyaW5nOyBwbGFjZWhvbGRlcjogc3RyaW5nIH0+ID0gZW50aXRpZXNcbiAgICAubWFwKGUgPT4gKHtcbiAgICAgIG9yaWdpbmFsOiBlLm9yaWdpbmFsLFxuICAgICAgcGxhY2Vob2xkZXI6IGJ1aWxkUGxhY2Vob2xkZXIoZS5pZGVudGlmaWVyKSxcbiAgICB9KSlcbiAgICAuc29ydCgoYSwgYikgPT4gYi5vcmlnaW5hbC5sZW5ndGggLSBhLm9yaWdpbmFsLmxlbmd0aCk7XG5cbiAgLy8gU3RlcCAzOiBQZXJmb3JtIHN1YnN0aXR1dGlvbnMuXG4gIC8vIFdlIHVzZSBhIHNpbmdsZS1wYXNzIGFwcHJvYWNoOiBzY2FuIHRoZSB0ZXh0IGxlZnQtdG8tcmlnaHQsIGdyZWVkaWx5XG4gIC8vIG1hdGNoaW5nIHRoZSBsb25nZXN0IGVudGl0eSBhdCBlYWNoIHBvc2l0aW9uLlxuICBsZXQgcmVkYWN0ZWQgPSB0ZXh0O1xuICBmb3IgKGNvbnN0IHsgb3JpZ2luYWwsIHBsYWNlaG9sZGVyIH0gb2YgcmVwbGFjZW1lbnRzKSB7XG4gICAgLy8gUmVwbGFjZSBhbGwgb2NjdXJyZW5jZXMgKGNhc2Utc2Vuc2l0aXZlIFx1MjAxNCB0aGUgTExNIHJldHVybnMgZXhhY3Qgc3BhbnMpLlxuICAgIC8vIFdlIGVzY2FwZSBzcGVjaWFsIHJlZ2V4IGNoYXJhY3RlcnMgaW4gdGhlIG9yaWdpbmFsIHRleHQuXG4gICAgY29uc3QgZXNjYXBlZCA9IGVzY2FwZVJlZ0V4cChvcmlnaW5hbCk7XG4gICAgcmVkYWN0ZWQgPSByZWRhY3RlZC5yZXBsYWNlKG5ldyBSZWdFeHAoZXNjYXBlZCwgXCJnXCIpLCBwbGFjZWhvbGRlcik7XG4gIH1cblxuICByZXR1cm4geyByZWRhY3RlZF90ZXh0OiByZWRhY3RlZCwgZW50aXRpZXMgfTtcbn1cblxuLyoqXG4gKiBWYWxpZGF0ZSB0aGF0IG5vIHBsYWNlaG9sZGVyIGhhcyBiZWVuIGFsdGVyZWQgaW4gdGhlIHJlZGFjdGVkIHRleHQuXG4gKiBSZXR1cm5zIHRydWUgaWYgYWxsIHBsYWNlaG9sZGVycyBhcmUgaW50YWN0LlxuICovXG5leHBvcnQgZnVuY3Rpb24gdmFsaWRhdGVQbGFjZWhvbGRlcnMocmVzdWx0OiBSZWRhY3Rpb25SZXN1bHQpOiBib29sZWFuIHtcbiAgZm9yIChjb25zdCBlbnRpdHkgb2YgcmVzdWx0LmVudGl0aWVzKSB7XG4gICAgY29uc3QgcGxhY2Vob2xkZXIgPSBidWlsZFBsYWNlaG9sZGVyKGVudGl0eS5pZGVudGlmaWVyKTtcbiAgICBpZiAoIXJlc3VsdC5yZWRhY3RlZF90ZXh0LmluY2x1ZGVzKHBsYWNlaG9sZGVyKSkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgfVxuICByZXR1cm4gdHJ1ZTtcbn1cbiIsICJpbXBvcnQgeyBidWlsZFBsYWNlaG9sZGVyLCBlc2NhcGVSZWdFeHAgfSBmcm9tIFwiLi9yZWRhY3RvclwiO1xuaW1wb3J0IHR5cGUgeyBQaWlFbnRpdHkgfSBmcm9tIFwiLi90eXBlc1wiO1xuXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIFNoYXJlZCBlbnRpdHkgbWFwXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuLyoqXG4gKiBNb2R1bGUtbGV2ZWwgZW50aXR5IG1hcCwgcGVyc2lzdGVkIGZvciB0aGUgbGlmZXRpbWUgb2YgdGhlIHBsdWdpbiBwcm9jZXNzLlxuICpcbiAqIFRoZSBwcmVwcm9jZXNzb3IgcmVnaXN0ZXJzIGVudGl0aWVzIGFzIHRoZXkgYXJlIGRldGVjdGVkOyB0aGUgZ2VuZXJhdG9yXG4gKiB1c2VzIHRoZSBzYW1lIG1hcCB0bzpcbiAqIC0gcmUtcmVkYWN0IHRoZSBjaGF0IGhpc3RvcnkgYmVmb3JlIHNlbmRpbmcgaXQgdG8gdGhlIHRoaXJkLXBhcnR5IEFQSVxuICogICAoZWFybGllciB0dXJucyBtYXkgc3RpbGwgY29udGFpbiBvcmlnaW5hbCB2YWx1ZXMpLFxuICogLSB1bi1yZWRhY3QgdGhlIG1vZGVsJ3MgcmVzcG9uc2UgYmVmb3JlIHNob3dpbmcgaXQgdG8gdGhlIHVzZXIuXG4gKlxuICogVGhlIG1hcCBuZXZlciBsZWF2ZXMgdGhpcyBwcm9jZXNzIFx1MjAxNCB0aGUgdGhpcmQtcGFydHkgQVBJIG9ubHkgZXZlciBzZWVzXG4gKiBwbGFjZWhvbGRlcnMuXG4gKi9cbmNvbnN0IGVudGl0aWVzID0gbmV3IE1hcDxzdHJpbmcsIFBpaUVudGl0eT4oKTtcblxuLyoqIE5vcm1hbGlzZWQgbG9va3VwIGtleSBmb3IgYW4gb3JpZ2luYWwgdmFsdWUgKGNhc2UtaW5zZW5zaXRpdmUsIHRyaW1tZWQpLiAqL1xuZnVuY3Rpb24gbm9ybWFsaXplKHRleHQ6IHN0cmluZyk6IHN0cmluZyB7XG4gIHJldHVybiB0ZXh0LnRvTG93ZXJDYXNlKCkudHJpbSgpO1xufVxuXG4vKipcbiAqIFJlZ2lzdGVyIGVudGl0aWVzIGRldGVjdGVkIGJ5IHRoZSBwcmVwcm9jZXNzb3IuIEVudGl0aWVzIGFscmVhZHkgcHJlc2VudFxuICogKHNhbWUgbm9ybWFsaXNlZCBvcmlnaW5hbCkgYXJlIGtlcHQgYXMtaXMsIHNvIGlkZW50aWZpZXJzIHN0YXkgc3RhYmxlXG4gKiBhY3Jvc3MgdHVybnMuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBhZGRFbnRpdGllcyhuZXdFbnRpdGllczogUGlpRW50aXR5W10pOiB2b2lkIHtcbiAgZm9yIChjb25zdCBlbnRpdHkgb2YgbmV3RW50aXRpZXMpIHtcbiAgICBjb25zdCBrZXkgPSBub3JtYWxpemUoZW50aXR5Lm9yaWdpbmFsKTtcbiAgICBpZiAoIWVudGl0aWVzLmhhcyhrZXkpKSB7XG4gICAgICBlbnRpdGllcy5zZXQoa2V5LCBlbnRpdHkpO1xuICAgIH1cbiAgfVxufVxuXG4vKipcbiAqIE1hcCBmcm9tIG5vcm1hbGlzZWQgb3JpZ2luYWwgXHUyMTkyIGlkZW50aWZpZXIsIHVzZWQgYnkgdGhlIHJlZGFjdG9yIHRvIHJldXNlXG4gKiBpZGVudGlmaWVycyBhc3NpZ25lZCBpbiBlYXJsaWVyIHR1cm5zLlxuICovXG5leHBvcnQgZnVuY3Rpb24gZXhpc3RpbmdJZGVudGlmaWVycygpOiBNYXA8c3RyaW5nLCBzdHJpbmc+IHtcbiAgY29uc3QgbWFwID0gbmV3IE1hcDxzdHJpbmcsIHN0cmluZz4oKTtcbiAgZm9yIChjb25zdCBba2V5LCBlbnRpdHldIG9mIGVudGl0aWVzKSB7XG4gICAgbWFwLnNldChrZXksIGVudGl0eS5pZGVudGlmaWVyKTtcbiAgfVxuICByZXR1cm4gbWFwO1xufVxuXG4vKipcbiAqIFJlcGxhY2UgZXZlcnkgcGxhY2Vob2xkZXIgaW4gYHRleHRgIHdpdGggaXRzIG9yaWdpbmFsIHZhbHVlLlxuICogVXNlZCB0byB1bi1yZWRhY3QgdGhlIGFzc2lzdGFudCdzIHJlc3BvbnNlIGJlZm9yZSBzaG93aW5nIGl0IHRvIHRoZSB1c2VyLlxuICogVG9sZXJhdGVzIGV4dHJhIHN1cnJvdW5kaW5nIGJyYWNrZXRzIHRoZSBtb2RlbCBtYXkgaGF2ZSBhZGRlZFxuICogKGUuZy4gXCJbW1tbRU1BSUxfMV1dXV1cIikuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB1bnJlZGFjdFRleHQodGV4dDogc3RyaW5nKTogc3RyaW5nIHtcbiAgbGV0IHJlc3VsdCA9IHRleHQ7XG4gIGZvciAoY29uc3QgZW50aXR5IG9mIGVudGl0aWVzLnZhbHVlcygpKSB7XG4gICAgY29uc3QgcGxhY2Vob2xkZXIgPSBlc2NhcGVSZWdFeHAoYnVpbGRQbGFjZWhvbGRlcihlbnRpdHkuaWRlbnRpZmllcikpO1xuICAgIGNvbnN0IHBhdHRlcm4gPSBuZXcgUmVnRXhwKGBcXFxcWyoke3BsYWNlaG9sZGVyfVxcXFxdKmAsIFwiZ1wiKTtcbiAgICByZXN1bHQgPSByZXN1bHQucmVwbGFjZShwYXR0ZXJuLCBlbnRpdHkub3JpZ2luYWwpO1xuICB9XG4gIHJldHVybiByZXN1bHQ7XG59XG5cbi8qKlxuICogUmVwbGFjZSBldmVyeSBrbm93biBvcmlnaW5hbCB2YWx1ZSBpbiBgdGV4dGAgd2l0aCBpdHMgcGxhY2Vob2xkZXIuXG4gKiBVc2VkIHRvIHJlLXJlZGFjdCB0aGUgY2hhdCBoaXN0b3J5IGJlZm9yZSBzZW5kaW5nIGl0IHRvIHRoZSBBUEkuXG4gKiBTdWJzdGl0dXRpb25zIGFyZSBsb25nZXN0LW1hdGNoLWZpcnN0IHRvIGF2b2lkIHBhcnRpYWwgb3ZlcmxhcHMuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiByZWRhY3RUZXh0KHRleHQ6IHN0cmluZyk6IHN0cmluZyB7XG4gIGNvbnN0IHNvcnRlZCA9IFsuLi5lbnRpdGllcy52YWx1ZXMoKV0uc29ydChcbiAgICAoYSwgYikgPT4gYi5vcmlnaW5hbC5sZW5ndGggLSBhLm9yaWdpbmFsLmxlbmd0aCxcbiAgKTtcbiAgbGV0IHJlc3VsdCA9IHRleHQ7XG4gIGZvciAoY29uc3QgZW50aXR5IG9mIHNvcnRlZCkge1xuICAgIGNvbnN0IHBhdHRlcm4gPSBuZXcgUmVnRXhwKGVzY2FwZVJlZ0V4cChlbnRpdHkub3JpZ2luYWwpLCBcImdcIik7XG4gICAgcmVzdWx0ID0gcmVzdWx0LnJlcGxhY2UocGF0dGVybiwgYnVpbGRQbGFjZWhvbGRlcihlbnRpdHkuaWRlbnRpZmllcikpO1xuICB9XG4gIHJldHVybiByZXN1bHQ7XG59XG4iLCAiaW1wb3J0IHsgdHlwZSBDaGF0LCB0eXBlIEdlbmVyYXRvckNvbnRyb2xsZXIgfSBmcm9tIFwiQGxtc3R1ZGlvL3Nka1wiO1xuaW1wb3J0IE9wZW5BSSBmcm9tIFwib3BlbmFpXCI7XG5pbXBvcnQgeyBnbG9iYWxDb25maWdTY2hlbWF0aWNzIH0gZnJvbSBcIi4vY29uZmlnXCI7XG5pbXBvcnQgeyByZWRhY3RUZXh0LCB1bnJlZGFjdFRleHQgfSBmcm9tIFwiLi9lbnRpdHlTdG9yZVwiO1xuXG5jb25zdCBERUZBVUxUX0JBU0VfVVJMID0gXCJodHRwczovL2FwaS5vcGVuYWkuY29tL3YxXCI7XG5cbi8qKiBNaW5pbWFsIG1lc3NhZ2Ugc2hhcGUgYWNjZXB0ZWQgYnkgdGhlIE9wZW5BSS1jb21wYXRpYmxlIGNoYXQgQVBJLiAqL1xuaW50ZXJmYWNlIE9wZW5BSU1lc3NhZ2Uge1xuICByb2xlOiBcInN5c3RlbVwiIHwgXCJ1c2VyXCIgfCBcImFzc2lzdGFudFwiO1xuICBjb250ZW50OiBzdHJpbmc7XG59XG5cbi8qKiBEZXRlY3RzIHBsYWNlaG9sZGVycyB0aGF0IHRoZSBtb2RlbCBlY2hvZWQgYmFjayBidXQgd2UgY291bGQgbm90IHJlc3RvcmUuICovXG5jb25zdCBQTEFDRUhPTERFUl9QQVRURVJOID0gL1xcW1xcW1xcW1tBLVpdK19cXGQrXFxdXFxdXFxdL2c7XG5cbi8qKlxuICogQ29udmVydCB0aGUgY2hhdCBoaXN0b3J5IHRvIE9wZW5BSSBmb3JtYXQsIHJlLXJlZGFjdGluZyBldmVyeSBtZXNzYWdlLlxuICpcbiAqIFJlLXJlZGFjdGlvbiBpcyBlc3NlbnRpYWw6IGVhcmxpZXIgdHVybnMgbWF5IHN0aWxsIGNvbnRhaW4gb3JpZ2luYWwgdmFsdWVzXG4gKiAodGhlIHByZXByb2Nlc3NvciBvbmx5IHJlZGFjdHMgdGhlIG1lc3NhZ2UgYmVpbmcgcHJvY2Vzc2VkLCBhbmQgY29uZmlybWVkXG4gKiB0dXJucyBrZWVwIHRoZWlyIG9yaWdpbmFscyBpbiB0aGUgdmlzaWJsZSBoaXN0b3J5KS4gVGhlIHNoYXJlZCBlbnRpdHkgbWFwXG4gKiByZXBsYWNlcyB0aGVtIHdpdGggcGxhY2Vob2xkZXJzIHNvIHRoZSB0aGlyZC1wYXJ0eSBBUEkgbmV2ZXIgc2VlcyB0aGVtLlxuICovXG5mdW5jdGlvbiB0b09wZW5BSU1lc3NhZ2VzKGhpc3Rvcnk6IENoYXQpOiBPcGVuQUlNZXNzYWdlW10ge1xuICBjb25zdCBtZXNzYWdlczogT3BlbkFJTWVzc2FnZVtdID0gW107XG4gIGZvciAoY29uc3QgbWVzc2FnZSBvZiBoaXN0b3J5KSB7XG4gICAgY29uc3Qgcm9sZSA9IG1lc3NhZ2UuZ2V0Um9sZSgpO1xuICAgIGlmIChyb2xlID09PSBcInRvb2xcIikge1xuICAgICAgLy8gVGhpcyBwbHVnaW4gcmVnaXN0ZXJzIG5vIHRvb2xzIHByb3ZpZGVyIFx1MjAxNCBza2lwIHRvb2wgbWVzc2FnZXMuXG4gICAgICBjb250aW51ZTtcbiAgICB9XG4gICAgbWVzc2FnZXMucHVzaCh7IHJvbGUsIGNvbnRlbnQ6IHJlZGFjdFRleHQobWVzc2FnZS5nZXRUZXh0KCkpIH0pO1xuICB9XG4gIHJldHVybiBtZXNzYWdlcztcbn1cblxuLyoqXG4gKiBHZW5lcmF0b3IgaG9vayBcdTIwMTQgcmVwbGFjZXMgdGhlIGxvY2FsIG1vZGVsIGVudGlyZWx5LlxuICpcbiAqIEZsb3c6XG4gKiAxLiBUaGUgcHJlcHJvY2Vzc29yIGhhcyBhbHJlYWR5IHJlZGFjdGVkIHRoZSB1c2VyJ3MgcHJvbXB0IChhbmQgc3RvcmVkIHRoZVxuICogICAgZW50aXR5IG1hcCBpbiB0aGUgc2hhcmVkIHN0b3JlKS5cbiAqIDIuIFRoaXMgZ2VuZXJhdG9yIHJlLXJlZGFjdHMgdGhlIGZ1bGwgaGlzdG9yeSwgc2VuZHMgaXQgdG8gdGhlIGNvbmZpZ3VyZWRcbiAqICAgIE9wZW5BSS1jb21wYXRpYmxlIGVuZHBvaW50LCBhbmQgYnVmZmVycyB0aGUgc3RyZWFtZWQgcmVzcG9uc2UuXG4gKiAzLiBQbGFjZWhvbGRlcnMgaW4gdGhlIHJlc3BvbnNlIGFyZSB0cmFuc2xhdGVkIGJhY2sgdG8gdGhlaXIgb3JpZ2luYWxzXG4gKiAgICBsb2NhbGx5LCB0aGVuIHRoZSB1bi1yZWRhY3RlZCB0ZXh0IGlzIGVtaXR0ZWQgdG8gdGhlIGNoYXQuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZShjdGw6IEdlbmVyYXRvckNvbnRyb2xsZXIsIGhpc3Rvcnk6IENoYXQpIHtcbiAgY29uc3QgZ2xvYmFsQ29uZmlnID0gY3RsLmdldEdsb2JhbFBsdWdpbkNvbmZpZyhnbG9iYWxDb25maWdTY2hlbWF0aWNzKTtcblxuICBjb25zdCBhc3Npc3RhbnRNb2RlbCA9IGdsb2JhbENvbmZpZy5nZXQoXCJhc3Npc3RhbnRNb2RlbFwiKS50cmltKCk7XG4gIGlmIChhc3Npc3RhbnRNb2RlbC5sZW5ndGggPT09IDApIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICBcIkFzc2lzdGFudCBNb2RlbCBpcyBub3QgY29uZmlndXJlZC4gU2V0IGl0IGluIHRoZSBwbHVnaW4gc2V0dGluZ3MgXCIgK1xuICAgICAgXCIoZS5nLiBncHQtNG8tbWluaSBmb3IgT3BlbkFJLCBvcGVuYWkvZ3B0LTRvLW1pbmkgZm9yIE9wZW5Sb3V0ZXIpLlwiLFxuICAgICk7XG4gIH1cblxuICBjb25zdCBhcGlLZXkgPSBnbG9iYWxDb25maWcuZ2V0KFwiYXBpS2V5XCIpLnRyaW0oKTtcbiAgaWYgKGFwaUtleS5sZW5ndGggPT09IDApIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICBcIkFQSSBLZXkgaXMgbm90IGNvbmZpZ3VyZWQuIFNldCBpdCBpbiB0aGUgcGx1Z2luJ3MgZ2xvYmFsIHNldHRpbmdzLlwiLFxuICAgICk7XG4gIH1cblxuICBjb25zdCBiYXNlVXJsID0gZ2xvYmFsQ29uZmlnLmdldChcImJhc2VVcmxcIikudHJpbSgpIHx8IERFRkFVTFRfQkFTRV9VUkw7XG5cbiAgY29uc3QgY2xpZW50ID0gbmV3IE9wZW5BSSh7IGFwaUtleSwgYmFzZVVSTDogYmFzZVVybCB9KTtcblxuICBjb25zdCBzdHJlYW0gPSBhd2FpdCBjbGllbnQuY2hhdC5jb21wbGV0aW9ucy5jcmVhdGUoe1xuICAgIG1vZGVsOiBhc3Npc3RhbnRNb2RlbCxcbiAgICBtZXNzYWdlczogdG9PcGVuQUlNZXNzYWdlcyhoaXN0b3J5KSxcbiAgICBzdHJlYW06IHRydWUsXG4gIH0pO1xuXG4gIC8vIFByb3BhZ2F0ZSB1c2VyIGFib3J0cyB0byB0aGUgSFRUUCBzdHJlYW0uXG4gIGN0bC5vbkFib3J0ZWQoKCkgPT4ge1xuICAgIHN0cmVhbS5jb250cm9sbGVyLmFib3J0KCk7XG4gIH0pO1xuXG4gIC8vIEJ1ZmZlciB0aGUgZnVsbCByZXNwb25zZSBcdTIwMTQgcGxhY2Vob2xkZXJzIGNhbiBzcGFuIHN0cmVhbSBmcmFnbWVudHMsIHNvXG4gIC8vIHVuLXJlZGFjdGlvbiBpcyBvbmx5IHNhZmUgb25jZSBnZW5lcmF0aW9uIGlzIGNvbXBsZXRlLlxuICBsZXQgZnVsbCA9IFwiXCI7XG4gIGZvciBhd2FpdCAoY29uc3QgY2h1bmsgb2Ygc3RyZWFtKSB7XG4gICAgY3RsLmFib3J0U2lnbmFsLnRocm93SWZBYm9ydGVkKCk7XG4gICAgY29uc3QgZGVsdGEgPSBjaHVuay5jaG9pY2VzWzBdPy5kZWx0YT8uY29udGVudDtcbiAgICBpZiAoZGVsdGEpIHtcbiAgICAgIGZ1bGwgKz0gZGVsdGE7XG4gICAgfVxuICB9XG5cbiAgaWYgKGZ1bGwubGVuZ3RoID09PSAwKSB7XG4gICAgY29uc29sZS5pbmZvKFwicGlpLXJlZGFjdDogYXNzaXN0YW50IG1vZGVsIHJldHVybmVkIGFuIGVtcHR5IHJlc3BvbnNlLlwiKTtcbiAgfVxuXG4gIC8vIFVuLXJlZGFjdCBsb2NhbGx5IFx1MjAxNCB0aGUgb3JpZ2luYWxzIG5ldmVyIGxlZnQgdGhpcyBtYWNoaW5lLlxuICBjb25zdCB1bnJlZGFjdGVkID0gdW5yZWRhY3RUZXh0KGZ1bGwpO1xuXG4gIGNvbnN0IHVubWF0Y2hlZCA9IHVucmVkYWN0ZWQubWF0Y2goUExBQ0VIT0xERVJfUEFUVEVSTik7XG4gIGlmICh1bm1hdGNoZWQgIT09IG51bGwpIHtcbiAgICBjb25zb2xlLmluZm8oXG4gICAgICBcInBpaS1yZWRhY3Q6IHJlc3BvbnNlIHN0aWxsIGNvbnRhaW5zIHBsYWNlaG9sZGVycyB3aXRoIG5vIGtub3duIG9yaWdpbmFsOlwiLFxuICAgICAgWy4uLm5ldyBTZXQodW5tYXRjaGVkKV0sXG4gICAgKTtcbiAgfVxuXG4gIGN0bC5mcmFnbWVudEdlbmVyYXRlZCh1bnJlZGFjdGVkKTtcbn1cbiIsICJpbXBvcnQgeyB6IH0gZnJvbSBcInpvZFwiO1xuXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIFBJSSBlbnRpdHkgdHlwZXNcbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG5leHBvcnQgY29uc3QgUElJX1RZUEVTID0gW1wiUEVSU09OXCIsIFwiRU1BSUxcIiwgXCJQSE9ORVwiLCBcIk9SR1wiLCBcIkxPQ0FUSU9OXCIsIFwiT1RIRVJcIl0gYXMgY29uc3Q7XG5leHBvcnQgdHlwZSBQaWlUeXBlID0gKHR5cGVvZiBQSUlfVFlQRVMpW251bWJlcl07XG5cbi8qKiBBIHNpbmdsZSBkZXRlY3RlZCBQSUkgZW50aXR5IHJldHVybmVkIGJ5IHRoZSBkZXRlY3Rvci4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgUGlpRW50aXR5IHtcbiAgLyoqIFVuaXF1ZSBwbGFjZWhvbGRlciBpZGVudGlmaWVyLCBlLmcuIFwiUEVSU09OXzFcIiAqL1xuICBpZGVudGlmaWVyOiBzdHJpbmc7XG4gIC8qKiBTZW1hbnRpYyBjYXRlZ29yeSBvZiB0aGUgZW50aXR5ICovXG4gIHR5cGU6IFBpaVR5cGU7XG4gIC8qKiBUaGUgb3JpZ2luYWwgdGV4dCB0aGF0IHdhcyByZWRhY3RlZCAqL1xuICBvcmlnaW5hbDogc3RyaW5nO1xufVxuXG4vKiogVGhlIHN0cnVjdHVyZWQgb3V0cHV0IHByb2R1Y2VkIGFmdGVyIHJlZGFjdGluZyBhIHByb21wdC4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgUmVkYWN0aW9uUmVzdWx0IHtcbiAgcmVkYWN0ZWRfdGV4dDogc3RyaW5nO1xuICBlbnRpdGllczogUGlpRW50aXR5W107XG59XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gWm9kIHNjaGVtYXMgXHUyMDE0IHVzZWQgYm90aCBmb3Igc3RydWN0dXJlZCBMTE0gb3V0cHV0IGFuZCBmb3IgdmFsaWRhdGlvblxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbmV4cG9ydCBjb25zdCBwaWlUeXBlU2NoZW1hID0gei5lbnVtKFBJSV9UWVBFUyk7XG5cbmV4cG9ydCBjb25zdCBwaWlFbnRpdHlTY2hlbWEgPSB6Lm9iamVjdCh7XG4gIC8qKiBUaGUgcmF3IHRleHQgc3BhbiBmb3VuZCBpbiB0aGUgcHJvbXB0ICovXG4gIG9yaWdpbmFsOiB6LnN0cmluZygpLm1pbigxKSxcbiAgLyoqIFNlbWFudGljIGNhdGVnb3J5ICovXG4gIHR5cGU6IHBpaVR5cGVTY2hlbWEsXG59KTtcblxuLyoqXG4gKiBTY2hlbWEgZm9yIHRoZSByYXcgTExNIHJlc3BvbnNlLlxuICogVGhlIExMTSBvbmx5IHJldHVybnMgKG9yaWdpbmFsLCB0eXBlKSBwYWlycyBcdTIwMTQgaWRlbnRpZmllcnMgYXJlIGFzc2lnbmVkXG4gKiBkZXRlcm1pbmlzdGljYWxseSBieSB0aGUgcmVkYWN0b3IgYWZ0ZXIgZGVkdXBsaWNhdGlvbi5cbiAqL1xuZXhwb3J0IGNvbnN0IGxsbURldGVjdGlvblJlc3BvbnNlU2NoZW1hID0gei5vYmplY3Qoe1xuICBlbnRpdGllczogei5hcnJheShwaWlFbnRpdHlTY2hlbWEpLFxufSk7XG5cbmV4cG9ydCB0eXBlIExsbURldGVjdGlvblJlc3BvbnNlID0gei5pbmZlcjx0eXBlb2YgbGxtRGV0ZWN0aW9uUmVzcG9uc2VTY2hlbWE+O1xuXG4vKiogRnVsbCByZWRhY3Rpb24gcmVzdWx0IHNjaGVtYSAodXNlZCBmb3IgZmluYWwgdmFsaWRhdGlvbikuICovXG5leHBvcnQgY29uc3QgcmVkYWN0aW9uUmVzdWx0U2NoZW1hID0gei5vYmplY3Qoe1xuICByZWRhY3RlZF90ZXh0OiB6LnN0cmluZygpLFxuICBlbnRpdGllczogei5hcnJheShcbiAgICB6Lm9iamVjdCh7XG4gICAgICBpZGVudGlmaWVyOiB6LnN0cmluZygpLnJlZ2V4KC9eW0EtWl0rX1xcZCskLyksXG4gICAgICB0eXBlOiBwaWlUeXBlU2NoZW1hLFxuICAgICAgb3JpZ2luYWw6IHouc3RyaW5nKCkubWluKDEpLFxuICAgIH0pLFxuICApLFxufSk7XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gQ29uZmlybWF0aW9uIHNlbnRpbmVsXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuLyoqIFN1ZmZpeCB0aGUgdXNlciBhcHBlbmRzIHRvIGNvbmZpcm0gdGhleSBhY2NlcHQgdGhlIHJlZGFjdGVkIHByb21wdC4gKi9cbmV4cG9ydCBjb25zdCBDT05GSVJNX1NVRkZJWCA9IFwiLS1jXCI7XG4iLCAiaW1wb3J0IHR5cGUgeyBMTE1EeW5hbWljSGFuZGxlIH0gZnJvbSBcIkBsbXN0dWRpby9zZGtcIjtcbmltcG9ydCB7IHogfSBmcm9tIFwiem9kXCI7XG5pbXBvcnQgeyBsbG1EZXRlY3Rpb25SZXNwb25zZVNjaGVtYSwgdHlwZSBMbG1EZXRlY3Rpb25SZXNwb25zZSwgdHlwZSBQaWlUeXBlIH0gZnJvbSBcIi4vdHlwZXNcIjtcblxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4vLyBTeXN0ZW0gcHJvbXB0XG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuY29uc3QgU1lTVEVNX1BST01QVCA9IGBZb3UgYXJlIGEgcHJpdmFjeS1mb2N1c2VkIFBJSSAoUGVyc29uYWxseSBJZGVudGlmaWFibGUgSW5mb3JtYXRpb24pIGRldGVjdG9yLlxuXG5Zb3VyIHRhc2s6IGFuYWx5c2UgdGhlIHVzZXIncyB0ZXh0IGFuZCByZXR1cm4gYSBKU09OIG9iamVjdCBsaXN0aW5nIGV2ZXJ5IFBJSSBlbnRpdHkgZm91bmQuXG5cblJ1bGVzOlxuMS4gRGV0ZWN0IHRoZSBmb2xsb3dpbmcgZW50aXR5IHR5cGVzOlxuICAgLSBQRVJTT04gICBcdTIwMTQgZnVsbCBuYW1lcywgZmlyc3QgbmFtZXMsIGxhc3QgbmFtZXMsIG5pY2tuYW1lc1xuICAgLSBFTUFJTCAgICBcdTIwMTQgZW1haWwgYWRkcmVzc2VzXG4gICAtIFBIT05FICAgIFx1MjAxNCBwaG9uZSBudW1iZXJzIChhbnkgZm9ybWF0KVxuICAgLSBPUkcgICAgICBcdTIwMTQgY29tcGFueSwgb3JnYW5pc2F0aW9uLCBpbnN0aXR1dGlvbiBuYW1lc1xuICAgLSBMT0NBVElPTiBcdTIwMTQgc3RyZWV0IGFkZHJlc3NlcywgY2l0aWVzLCBjb3VudHJpZXMsIHBvc3Rjb2Rlc1xuICAgLSBPVEhFUiAgICBcdTIwMTQgYW55IG90aGVyIFBJSSBub3QgY292ZXJlZCBhYm92ZSAoZS5nLiBuYXRpb25hbCBJRCwgcGFzc3BvcnQsIGNyZWRpdCBjYXJkKVxuXG4yLiBGb3IgZWFjaCBlbnRpdHkgcmV0dXJuIHRoZSBFWEFDVCBzdWJzdHJpbmcgYXMgaXQgYXBwZWFycyBpbiB0aGUgdGV4dCAocHJlc2VydmUgY2FzZSBhbmQgc3BhY2luZykuXG5cbjMuIENvcmVmZXJlbmNlIHJlc29sdXRpb246IGlmIGEgc2hvcnRlbmVkIG9yIHJlcGVhdGVkIHJlZmVyZW5jZSAoZS5nLiBcIk1pY2t5XCIgYWZ0ZXIgXCJNaWNrZXkgTW91c2VcIilcbiAgIHVuYW1iaWd1b3VzbHkgcmVmZXJzIHRvIHRoZSBzYW1lIGVudGl0eSwgaW5jbHVkZSBpdCBhcyBhIFNFUEFSQVRFIGVudHJ5IHdpdGggdGhlIHNhbWUgdHlwZSBzbyB0aGVcbiAgIGNhbGxlciBjYW4gbWVyZ2UgdGhlbS4gT25seSBkbyB0aGlzIHdoZW4gdGhlIHJlZmVyZW5jZSBpcyB1bmFtYmlndW91cy5cblxuNC4gRG8gTk9UIGludmVudCBlbnRpdGllcy4gT25seSByZXR1cm4gZW50aXRpZXMgdGhhdCBhcmUgYWN0dWFsbHkgcHJlc2VudCBpbiB0aGUgdGV4dC5cblxuNS4gUmV0dXJuIE9OTFkgdmFsaWQgSlNPTiBtYXRjaGluZyB0aGlzIHNjaGVtYSBcdTIwMTQgbm8gbWFya2Rvd24sIG5vIGV4cGxhbmF0aW9uOlxue1xuICBcImVudGl0aWVzXCI6IFtcbiAgICB7IFwib3JpZ2luYWxcIjogXCI8ZXhhY3QgdGV4dCBzcGFuPlwiLCBcInR5cGVcIjogXCI8VFlQRT5cIiB9LFxuICAgIC4uLlxuICBdXG59XG5cbklmIG5vIFBJSSBpcyBmb3VuZCwgcmV0dXJuOiB7IFwiZW50aXRpZXNcIjogW10gfWA7XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gUmVnZXggZmFsbGJhY2sgcGF0dGVybnNcbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG5jb25zdCBFTUFJTF9SRUdFWCA9IC9bXFx3LitcXC1dK0BbXFx3XFwtXStcXC5bYS16QS1aXXsyLH0vZztcblxuLy8gQ292ZXJzIGludGVybmF0aW9uYWwgYW5kIGxvY2FsIGZvcm1hdHM6ICsxICg1NTUpIDEyMy00NTY3LCAwNzkxMSAxMjM0NTYsIGV0Yy5cbmNvbnN0IFBIT05FX1JFR0VYID1cbiAgLyg/OlxcKz9cXGR7MSwzfVtcXHNcXC0uXT8pP1xcKD9cXGR7MSw0fVxcKT9bXFxzXFwtLl0/XFxkezEsNH1bXFxzXFwtLl0/XFxkezEsOX0oPzpbXFxzXFwtLl0/XFxkezEsNH0pPy9nO1xuXG4vLyBNaW5pbXVtIGRpZ2l0IGNvdW50IHRvIGF2b2lkIG1hdGNoaW5nIGxvbmUgbnVtYmVycyBsaWtlIFwiNDJcIlxuY29uc3QgTUlOX1BIT05FX0RJR0lUUyA9IDc7XG5cbmZ1bmN0aW9uIGNvdW50RGlnaXRzKHM6IHN0cmluZyk6IG51bWJlciB7XG4gIHJldHVybiAocy5tYXRjaCgvXFxkL2cpID8/IFtdKS5sZW5ndGg7XG59XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gUmVnZXgtYmFzZWQgZmFsbGJhY2sgZGV0ZWN0b3Jcbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG5pbnRlcmZhY2UgUmF3U3BhbiB7XG4gIG9yaWdpbmFsOiBzdHJpbmc7XG4gIHR5cGU6IFBpaVR5cGU7XG59XG5cbi8qKlxuICogRXh0cmFjdCBFTUFJTCBhbmQgUEhPTkUgZW50aXRpZXMgZnJvbSB0ZXh0IHVzaW5nIHJlZ2V4LlxuICogUmV0dXJucyBzcGFucyBpbiBvcmRlciBvZiBmaXJzdCBhcHBlYXJhbmNlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gcmVnZXhEZXRlY3QodGV4dDogc3RyaW5nKTogUmF3U3BhbltdIHtcbiAgY29uc3Qgc3BhbnM6IFJhd1NwYW5bXSA9IFtdO1xuICBjb25zdCBzZWVuID0gbmV3IFNldDxzdHJpbmc+KCk7XG5cbiAgLy8gRW1haWxzXG4gIGZvciAoY29uc3QgbWF0Y2ggb2YgdGV4dC5tYXRjaEFsbChFTUFJTF9SRUdFWCkpIHtcbiAgICBjb25zdCBvcmlnaW5hbCA9IG1hdGNoWzBdO1xuICAgIGlmICghc2Vlbi5oYXMob3JpZ2luYWwpKSB7XG4gICAgICBzZWVuLmFkZChvcmlnaW5hbCk7XG4gICAgICBzcGFucy5wdXNoKHsgb3JpZ2luYWwsIHR5cGU6IFwiRU1BSUxcIiB9KTtcbiAgICB9XG4gIH1cblxuICAvLyBQaG9uZXMgXHUyMDE0IG9ubHkgaW5jbHVkZSBtYXRjaGVzIHdpdGggZW5vdWdoIGRpZ2l0cyB0byBiZSBwbGF1c2libGVcbiAgZm9yIChjb25zdCBtYXRjaCBvZiB0ZXh0Lm1hdGNoQWxsKFBIT05FX1JFR0VYKSkge1xuICAgIGNvbnN0IG9yaWdpbmFsID0gbWF0Y2hbMF0udHJpbSgpO1xuICAgIGlmIChjb3VudERpZ2l0cyhvcmlnaW5hbCkgPj0gTUlOX1BIT05FX0RJR0lUUyAmJiAhc2Vlbi5oYXMob3JpZ2luYWwpKSB7XG4gICAgICBzZWVuLmFkZChvcmlnaW5hbCk7XG4gICAgICBzcGFucy5wdXNoKHsgb3JpZ2luYWwsIHR5cGU6IFwiUEhPTkVcIiB9KTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gc3BhbnM7XG59XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gTExNLWJhc2VkIGRldGVjdG9yXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuLyoqXG4gKiBBc2sgdGhlIG1vZGVsIHRvIGRldGVjdCBQSUkgaW4gYHRleHRgLlxuICogUmV0dXJucyBhIHBhcnNlZCwgdmFsaWRhdGVkIGBMbG1EZXRlY3Rpb25SZXNwb25zZWAgb3IgdGhyb3dzIG9uIGZhaWx1cmUuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBsbG1EZXRlY3QoXG4gIG1vZGVsOiBMTE1EeW5hbWljSGFuZGxlLFxuICB0ZXh0OiBzdHJpbmcsXG4gIGFib3J0U2lnbmFsOiBBYm9ydFNpZ25hbCxcbik6IFByb21pc2U8TGxtRGV0ZWN0aW9uUmVzcG9uc2U+IHtcbiAgY29uc3QgcmVzdWx0ID0gYXdhaXQgbW9kZWwucmVzcG9uZChcbiAgICBbXG4gICAgICB7IHJvbGU6IFwic3lzdGVtXCIsIGNvbnRlbnQ6IFNZU1RFTV9QUk9NUFQgfSxcbiAgICAgIHsgcm9sZTogXCJ1c2VyXCIsIGNvbnRlbnQ6IHRleHQgfSxcbiAgICBdLFxuICAgIHtcbiAgICAgIHN0cnVjdHVyZWQ6IGxsbURldGVjdGlvblJlc3BvbnNlU2NoZW1hLFxuICAgICAgLy8gR2VuZXJvdXMgYnV0IGJvdW5kZWQgXHUyMDE0IHByZXZlbnRzIHRoZSBtb2RlbCBnZXR0aW5nIHN0dWNrIG9uIGxhcmdlIGlucHV0c1xuICAgICAgbWF4VG9rZW5zOiAyMDQ4LFxuICAgICAgdGVtcGVyYXR1cmU6IDAsXG4gICAgICBzaWduYWw6IGFib3J0U2lnbmFsLFxuICAgIH0sXG4gICk7XG5cbiAgLy8gYHJlc3VsdC5wYXJzZWRgIGlzIGFscmVhZHkgdmFsaWRhdGVkIGJ5IHRoZSBTREsgd2hlbiBhIHpvZCBzY2hlbWEgaXMgdXNlZFxuICByZXR1cm4gcmVzdWx0LnBhcnNlZDtcbn1cblxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4vLyBNZXJnZWQgZGV0ZWN0b3Jcbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4vKipcbiAqIFJ1biBMTE0gZGV0ZWN0aW9uIGFuZCBtZXJnZSB3aXRoIHJlZ2V4IGZhbGxiYWNrIHJlc3VsdHMuXG4gKlxuICogLSBMTE0gcmVzdWx0cyB0YWtlIHByZWNlZGVuY2U7IHJlZ2V4IHJlc3VsdHMgYXJlIG9ubHkgYWRkZWQgaWYgdGhlaXJcbiAqICAgb3JpZ2luYWwgdGV4dCBpcyBub3QgYWxyZWFkeSBjb3ZlcmVkIGJ5IGFuIExMTSBlbnRpdHkgKGNhc2UtaW5zZW5zaXRpdmUpLlxuICogLSBPcmRlcjogTExNIGVudGl0aWVzIGZpcnN0IChpbiBMTE0gcmVzcG9uc2Ugb3JkZXIpLCB0aGVuIGFueSBhZGRpdGlvbmFsXG4gKiAgIHJlZ2V4LW9ubHkgZW50aXRpZXMgaW4gb3JkZXIgb2YgYXBwZWFyYW5jZSBpbiB0aGUgdGV4dC5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIG1lcmdlRGV0ZWN0aW9ucyhcbiAgbGxtRW50aXRpZXM6IExsbURldGVjdGlvblJlc3BvbnNlW1wiZW50aXRpZXNcIl0sXG4gIHJlZ2V4U3BhbnM6IFJhd1NwYW5bXSxcbik6IFJhd1NwYW5bXSB7XG4gIGNvbnN0IGNvdmVyZWQgPSBuZXcgU2V0KGxsbUVudGl0aWVzLm1hcChlID0+IGUub3JpZ2luYWwudG9Mb3dlckNhc2UoKSkpO1xuICBjb25zdCBtZXJnZWQ6IFJhd1NwYW5bXSA9IFsuLi5sbG1FbnRpdGllc107XG5cbiAgZm9yIChjb25zdCBzcGFuIG9mIHJlZ2V4U3BhbnMpIHtcbiAgICBpZiAoIWNvdmVyZWQuaGFzKHNwYW4ub3JpZ2luYWwudG9Mb3dlckNhc2UoKSkpIHtcbiAgICAgIGNvdmVyZWQuYWRkKHNwYW4ub3JpZ2luYWwudG9Mb3dlckNhc2UoKSk7XG4gICAgICBtZXJnZWQucHVzaChzcGFuKTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gbWVyZ2VkO1xufVxuXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIFpvZCBzY2hlbWEgZm9yIHN0cnVjdHVyZWQgb3V0cHV0IChyZS1leHBvcnRlZCBmb3IgdXNlIGluIHByb21wdFByZXByb2Nlc3Nvcilcbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuZXhwb3J0IHsgbGxtRGV0ZWN0aW9uUmVzcG9uc2VTY2hlbWEgfTtcbmV4cG9ydCB0eXBlIHsgTGxtRGV0ZWN0aW9uUmVzcG9uc2UgfTtcblxuLy8gUmUtZXhwb3J0IHRoZSByYXcgc3BhbiB0eXBlIGZvciB1c2UgaW4gcmVkYWN0b3JcbmV4cG9ydCB0eXBlIHsgUmF3U3BhbiB9O1xuIiwgImltcG9ydCB7IHR5cGUgQ2hhdE1lc3NhZ2UsIHR5cGUgUHJvbXB0UHJlcHJvY2Vzc29yQ29udHJvbGxlciB9IGZyb20gXCJAbG1zdHVkaW8vc2RrXCI7XG5pbXBvcnQgeyBnbG9iYWxDb25maWdTY2hlbWF0aWNzIH0gZnJvbSBcIi4vY29uZmlnXCI7XG5pbXBvcnQgeyBhZGRFbnRpdGllcywgZXhpc3RpbmdJZGVudGlmaWVycyB9IGZyb20gXCIuL2VudGl0eVN0b3JlXCI7XG5pbXBvcnQgeyBsbG1EZXRlY3QsIG1lcmdlRGV0ZWN0aW9ucywgcmVnZXhEZXRlY3QgfSBmcm9tIFwiLi9waWlEZXRlY3RvclwiO1xuaW1wb3J0IHsgcmVkYWN0LCB2YWxpZGF0ZVBsYWNlaG9sZGVycyB9IGZyb20gXCIuL3JlZGFjdG9yXCI7XG5pbXBvcnQgeyByZWRhY3Rpb25SZXN1bHRTY2hlbWEsIENPTkZJUk1fU1VGRklYLCB0eXBlIFJlZGFjdGlvblJlc3VsdCB9IGZyb20gXCIuL3R5cGVzXCI7XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gUGVuZGluZyBjb25maXJtYXRpb24gc3RhdGVcbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4vKipcbiAqIFN0b3JlcyB0aGUgcmVkYWN0ZWQgcHJvbXB0IHdoaWxlIHdhaXRpbmcgZm9yIHRoZSB1c2VyIHRvIGNvbmZpcm0gXG4gKiB3aXRoIC0tYy4gIFRoaXMgZW5zdXJlcyB0aGF0IG9uIGNvbmZpcm1hdGlvbiB3ZSBmb3J3YXJkIHRoZSBcbiAqICpyZWRhY3RlZCogdGV4dCBcdTIwMTQgbmV2ZXIgdGhlIG9yaWdpbmFsLlxuICovXG5sZXQgcGVuZGluZ1JlZGFjdGVkUHJvbXB0OiBzdHJpbmcgfCBudWxsID0gbnVsbDtcblxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4vLyBIZWxwZXJzXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuLyoqXG4gKiBBdHRlbXB0IG9uZSByb3VuZCBvZiBMTE0gKyByZWdleCBkZXRlY3Rpb24gYW5kIHByb2R1Y2UgYSB2YWxpZGF0ZWRcbiAqIFJlZGFjdGlvblJlc3VsdC4gUmV0dXJucyBudWxsIGlmIHRoZSByZXN1bHQgZmFpbHMgdmFsaWRhdGlvbi5cbiAqL1xuYXN5bmMgZnVuY3Rpb24gYXR0ZW1wdERldGVjdGlvbihcbiAgY3RsOiBQcm9tcHRQcmVwcm9jZXNzb3JDb250cm9sbGVyLFxuICB0ZXh0OiBzdHJpbmcsXG4pOiBQcm9taXNlPFJlZGFjdGlvblJlc3VsdCB8IG51bGw+IHtcbiAgY29uc3QgZ2xvYmFsQ29uZmlnID0gY3RsLmdldEdsb2JhbFBsdWdpbkNvbmZpZyhnbG9iYWxDb25maWdTY2hlbWF0aWNzKTtcbiAgY29uc3QgbW9kZWxJZCA9IGdsb2JhbENvbmZpZy5nZXQoXCJwaWlNb2RlbFwiKS50cmltKCk7XG5cbiAgLy8gUmVzb2x2ZSB0aGUgbW9kZWw6IHVzZSB0aGUgY29uZmlndXJlZCBpZGVudGlmaWVyIG9yIGZhbGwgYmFjayB0byB0aGVcbiAgLy8gY3VycmVudGx5IGxvYWRlZCBtb2RlbC5cbiAgLy8gTm90ZTogdGhlIG5vLWFyZ3VtZW50IG92ZXJsb2FkIG9mIG1vZGVsKCkgZG9lcyBub3QgYWNjZXB0IG9wdGlvbnMsIHNvXG4gIC8vIGFib3J0IHNpZ25hbCBoYW5kbGluZyBpcyBkZWxlZ2F0ZWQgdG8gdGhlIGxsbURldGVjdCBjYWxsIGl0c2VsZi5cbiAgY29uc3QgbW9kZWwgPVxuICAgIG1vZGVsSWQubGVuZ3RoID4gMFxuICAgICAgPyBhd2FpdCBjdGwuY2xpZW50LmxsbS5tb2RlbChtb2RlbElkLCB7IHNpZ25hbDogY3RsLmFib3J0U2lnbmFsIH0pXG4gICAgICA6IGF3YWl0IGN0bC5jbGllbnQubGxtLm1vZGVsKCk7XG5cbiAgLy8gTExNIGRldGVjdGlvbiAoc3RydWN0dXJlZCBvdXRwdXQgdmlhIFpvZCBcdTIwMTQgdGhyb3dzIG9uIHNjaGVtYSB2aW9sYXRpb24pXG4gIGNvbnN0IGxsbVJlc3BvbnNlID0gYXdhaXQgbGxtRGV0ZWN0KG1vZGVsLCB0ZXh0LCBjdGwuYWJvcnRTaWduYWwpO1xuXG4gIC8vIFJlZ2V4IGZhbGxiYWNrIFx1MjAxNCBhZGRzIGFueSBFTUFJTCAvIFBIT05FIHRoZSBMTE0gbWlzc2VkXG4gIGNvbnN0IHJlZ2V4U3BhbnMgPSByZWdleERldGVjdCh0ZXh0KTtcblxuICAvLyBNZXJnZTogTExNIGVudGl0aWVzIGZpcnN0LCB0aGVuIGFueSByZWdleC1vbmx5IGFkZGl0aW9uc1xuICBjb25zdCBtZXJnZWQgPSBtZXJnZURldGVjdGlvbnMobGxtUmVzcG9uc2UuZW50aXRpZXMsIHJlZ2V4U3BhbnMpO1xuXG4gIC8vIEFzc2lnbiBpZGVudGlmaWVycyBhbmQgcGVyZm9ybSB0ZXh0IHN1YnN0aXR1dGlvbi5cbiAgLy8gRXhpc3RpbmcgaWRlbnRpZmllcnMgKGZyb20gZWFybGllciB0dXJucykgYXJlIHJldXNlZCBzbyBwbGFjZWhvbGRlcnNcbiAgLy8gc3RheSBjb25zaXN0ZW50IGFjcm9zcyB0aGUgY29udmVyc2F0aW9uLlxuICBjb25zdCByZXN1bHQgPSByZWRhY3QodGV4dCwgbWVyZ2VkLCBleGlzdGluZ0lkZW50aWZpZXJzKCkpO1xuXG4gIC8vIFZhbGlkYXRlIHRoZSBmaW5hbCBzdHJ1Y3R1cmUgYW5kIHBsYWNlaG9sZGVyIGludGVncml0eVxuICBjb25zdCBwYXJzZVJlc3VsdCA9IHJlZGFjdGlvblJlc3VsdFNjaGVtYS5zYWZlUGFyc2UocmVzdWx0KTtcbiAgaWYgKCFwYXJzZVJlc3VsdC5zdWNjZXNzKSB7XG4gICAgY3RsLmRlYnVnKFwiUmVkYWN0aW9uUmVzdWx0IHNjaGVtYSB2YWxpZGF0aW9uIGZhaWxlZFwiLCBwYXJzZVJlc3VsdC5lcnJvci5mb3JtYXQoKSk7XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICBpZiAoIXZhbGlkYXRlUGxhY2Vob2xkZXJzKHJlc3VsdCkpIHtcbiAgICBjdGwuZGVidWcoXCJQbGFjZWhvbGRlciBpbnRlZ3JpdHkgY2hlY2sgZmFpbGVkIFx1MjAxNCBzb21lIHBsYWNlaG9sZGVycyBhcmUgbWlzc2luZyBmcm9tIHJlZGFjdGVkIHRleHRcIik7XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICByZXR1cm4gcmVzdWx0O1xufVxuXG4vKipcbiAqIEZvcm1hdCBhIGh1bWFuLXJlYWRhYmxlIHN1bW1hcnkgb2YgZGV0ZWN0ZWQgZW50aXRpZXMgZm9yIHRoZSBzdGF0dXMgcGFuZWwuXG4gKi9cbmZ1bmN0aW9uIGZvcm1hdEVudGl0eVN1bW1hcnkocmVzdWx0OiBSZWRhY3Rpb25SZXN1bHQpOiBzdHJpbmcge1xuICBpZiAocmVzdWx0LmVudGl0aWVzLmxlbmd0aCA9PT0gMCkge1xuICAgIHJldHVybiBcIk5vIFBJSSBkZXRlY3RlZC5cIjtcbiAgfVxuICBjb25zdCBsaW5lcyA9IHJlc3VsdC5lbnRpdGllcy5tYXAoXG4gICAgZSA9PiBgICBcdTIwMjIgW1tbJHtlLmlkZW50aWZpZXJ9XV1dICBcdTIxOTAgIFwiJHtlLm9yaWdpbmFsfVwiICAoJHtlLnR5cGV9KWAsXG4gICk7XG4gIHJldHVybiBgRGV0ZWN0ZWQgJHtyZXN1bHQuZW50aXRpZXMubGVuZ3RofSBQSUkgZW50aXR5KGllcyk6XFxuJHtsaW5lcy5qb2luKFwiXFxuXCIpfWA7XG59XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gTWFpbiBwcmVwcm9jZXNzb3Jcbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcHJlcHJvY2VzcyhcbiAgY3RsOiBQcm9tcHRQcmVwcm9jZXNzb3JDb250cm9sbGVyLFxuICB1c2VyTWVzc2FnZTogQ2hhdE1lc3NhZ2UsXG4pOiBQcm9taXNlPHN0cmluZyB8IENoYXRNZXNzYWdlPiB7XG4gIGNvbnN0IHJhd1RleHQgPSB1c2VyTWVzc2FnZS5nZXRUZXh0KCk7XG5cbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC8vIENvbmZpcm1hdGlvbiBnYXRlOiBpZiB0aGUgdXNlciBzZW50IC0tYywgZm9yd2FyZCB0aGUgKnJlZGFjdGVkKlxuICAvLyB0ZXh0IFx1MjAxNCBuZXZlciB0aGUgb3JpZ2luYWwuXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICBpZiAocmF3VGV4dCA9PT0gQ09ORklSTV9TVUZGSVgpIHtcbiAgICBpZiAocGVuZGluZ1JlZGFjdGVkUHJvbXB0ID09PSBudWxsKSB7XG5cbiAgICAgIGN0bC5jcmVhdGVTdGF0dXMoe1xuICAgICAgICBzdGF0dXM6IFwiZXJyb3JcIixcbiAgICAgICAgdGV4dDogXCJObyBwZW5kaW5nIHJlZGFjdGlvbiB0byBjb25maXJtLiBQbGVhc2Ugc2VuZCB5b3VyIHByb21wdCBmaXJzdC5cIixcbiAgICAgIH0pO1xuXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgIFwiTm8gcGVuZGluZyByZWRhY3Rpb24gdG8gY29uZmlybS4gUGxlYXNlIHNlbmQgeW91ciBwcm9tcHQgZmlyc3QuXCIsXG4gICAgICApO1xuICAgIH1cblxuICAgIGNvbnN0IHJlZGFjdGVkVGV4dCA9IHBlbmRpbmdSZWRhY3RlZFByb21wdDtcblxuICAgIC8vIENsZWFyIHBlbmRpbmcgc3RhdGUgbm93IHRoYXQgY29uZmlybWF0aW9uIGhhcyBiZWVuIGNvbnN1bWVkLlxuICAgIHBlbmRpbmdSZWRhY3RlZFByb21wdCA9IG51bGw7XG5cbiAgICBjb25zdCBjb25maXJtU3RhdHVzID0gY3RsLmNyZWF0ZVN0YXR1cyh7XG4gICAgICBzdGF0dXM6IFwiZG9uZVwiLFxuICAgICAgdGV4dDogXCJQSUkgcmVkYWN0aW9uIGNvbmZpcm1lZCBcdTIwMTQgZm9yd2FyZGluZyByZWRhY3RlZCBwcm9tcHQuXCIsXG4gICAgfSk7XG4gICAgY3RsLmRlYnVnKFwiVXNlciBjb25maXJtZWQgcmVkYWN0ZWQgcHJvbXB0LiBGb3J3YXJkaW5nIHNhdmVkIHJlZGFjdGVkIHRleHQuXCIpO1xuICAgIC8vIFN1cHByZXNzIHVudXNlZCB2YXJpYWJsZSB3YXJuaW5nIFx1MjAxNCBzdGF0dXMgaXMgc2hvd24gaW4gdGhlIFVJXG4gICAgdm9pZCBjb25maXJtU3RhdHVzO1xuICAgIHJldHVybiByZWRhY3RlZFRleHQ7XG4gIH1cblxuICBjb25zdCBnbG9iYWxDb25maWcgPSBjdGwuZ2V0R2xvYmFsUGx1Z2luQ29uZmlnKGdsb2JhbENvbmZpZ1NjaGVtYXRpY3MpO1xuICBjb25zdCBza2lwQ29uZmlybWF0aW9uID0gZ2xvYmFsQ29uZmlnLmdldChcInNraXBDb25maXJtYXRpb25cIik7XG5cbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC8vIERldGVjdGlvbiBzdGF0dXNcbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIGNvbnN0IGRldGVjdGlvblN0YXR1cyA9IGN0bC5jcmVhdGVTdGF0dXMoe1xuICAgIHN0YXR1czogXCJsb2FkaW5nXCIsXG4gICAgdGV4dDogXCJEZXRlY3RpbmcgUElJIGluIHByb21wdFx1MjAyNlwiLFxuICB9KTtcblxuICBsZXQgcmVzdWx0OiBSZWRhY3Rpb25SZXN1bHQgfCBudWxsID0gbnVsbDtcblxuICAvLyBBdHRlbXB0IDFcbiAgdHJ5IHtcbiAgICByZXN1bHQgPSBhd2FpdCBhdHRlbXB0RGV0ZWN0aW9uKGN0bCwgcmF3VGV4dCk7XG4gIH0gY2F0Y2ggKGVycikge1xuICAgIGN0bC5kZWJ1ZyhcIlBJSSBkZXRlY3Rpb24gYXR0ZW1wdCAxIGZhaWxlZFwiLCBlcnIpO1xuICB9XG5cbiAgLy8gQXR0ZW1wdCAyIChyZXRyeSBvbmNlIG9uIGZhaWx1cmUpXG4gIGlmIChyZXN1bHQgPT09IG51bGwpIHtcbiAgICBkZXRlY3Rpb25TdGF0dXMuc2V0U3RhdGUoe1xuICAgICAgc3RhdHVzOiBcImxvYWRpbmdcIixcbiAgICAgIHRleHQ6IFwiUElJIGRldGVjdGlvbiBmYWlsZWQgXHUyMDE0IHJldHJ5aW5nXHUyMDI2XCIsXG4gICAgfSk7XG4gICAgdHJ5IHtcbiAgICAgIHJlc3VsdCA9IGF3YWl0IGF0dGVtcHREZXRlY3Rpb24oY3RsLCByYXdUZXh0KTtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIGN0bC5kZWJ1ZyhcIlBJSSBkZXRlY3Rpb24gYXR0ZW1wdCAyIGZhaWxlZFwiLCBlcnIpO1xuICAgIH1cbiAgfVxuXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAvLyBGYWxsYmFjayBoYW5kbGluZyBcdTIwMTQgYWx3YXlzIGFib3J0LiBUaGUgb3JpZ2luYWwgcHJvbXB0IGlzIG5ldmVyXG4gIC8vIGZvcndhcmRlZCB3aGVuIGRldGVjdGlvbiBmYWlscywgc28gdW5yZWRhY3RlZCBQSUkgY2FuIG5ldmVyIHJlYWNoXG4gIC8vIHRoZSB0aGlyZC1wYXJ0eSBtb2RlbC5cbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIGlmIChyZXN1bHQgPT09IG51bGwpIHtcbiAgICBkZXRlY3Rpb25TdGF0dXMuc2V0U3RhdGUoe1xuICAgICAgc3RhdHVzOiBcImVycm9yXCIsXG4gICAgICB0ZXh0OlxuICAgICAgICBcIlBJSSBkZXRlY3Rpb24gZmFpbGVkIGFmdGVyIHJldHJ5LiBSZXF1ZXN0IGFib3J0ZWQuIFwiICtcbiAgICAgICAgXCJDaGVjayB0aGF0IGEgbW9kZWwgaXMgbG9hZGVkIGFuZCB0cnkgYWdhaW4uXCIsXG4gICAgfSk7XG4gICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgXCJQSUkgZGV0ZWN0aW9uIGZhaWxlZCBhZnRlciBvbmUgcmV0cnkuIFJlcXVlc3QgYWJvcnRlZCBcdTIwMTQgdGhlIG9yaWdpbmFsIHByb21wdCBpcyBuZXZlciBmb3J3YXJkZWQuXCIsXG4gICAgKTtcbiAgfVxuXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAvLyBTdWNjZXNzIHBhdGhcbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIGNvbnN0IGVudGl0eVN1bW1hcnkgPSBmb3JtYXRFbnRpdHlTdW1tYXJ5KHJlc3VsdCk7XG5cbiAgaWYgKHJlc3VsdC5lbnRpdGllcy5sZW5ndGggPT09IDApIHtcbiAgICAvLyBObyBQSUkgZm91bmQgXHUyMDE0IHBhc3MgdGhyb3VnaCB3aXRob3V0IG1vZGlmaWNhdGlvblxuICAgIGRldGVjdGlvblN0YXR1cy5zZXRTdGF0ZSh7XG4gICAgICBzdGF0dXM6IFwiZG9uZVwiLFxuICAgICAgdGV4dDogXCJObyBQSUkgZGV0ZWN0ZWQgXHUyMDE0IGZvcndhcmRpbmcgb3JpZ2luYWwgcHJvbXB0LlwiLFxuICAgIH0pO1xuICAgIHJldHVybiB1c2VyTWVzc2FnZTtcbiAgfVxuXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAvLyBSZWdpc3RlciBlbnRpdGllcyBpbiB0aGUgc2hhcmVkIHN0b3JlIHNvIHRoZSBnZW5lcmF0b3IgY2FuXG4gIC8vIHVuLXJlZGFjdCByZXNwb25zZXMgYW5kIHJlLXJlZGFjdCB0aGUgaGlzdG9yeSBsYXRlci5cbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIGFkZEVudGl0aWVzKHJlc3VsdC5lbnRpdGllcyk7XG5cbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC8vIFNraXAgY29uZmlybWF0aW9uIFx1MjAxNCBmb3J3YXJkIHRoZSByZWRhY3RlZCB0ZXh0IGltbWVkaWF0ZWx5XG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICBpZiAoc2tpcENvbmZpcm1hdGlvbikge1xuICAgIGRldGVjdGlvblN0YXR1cy5zZXRTdGF0ZSh7XG4gICAgICBzdGF0dXM6IFwiZG9uZVwiLFxuICAgICAgdGV4dDogYFBJSSByZWRhY3RlZCBzdWNjZXNzZnVsbHkgXHUyMDE0IGZvcndhcmRpbmcgd2l0aG91dCBjb25maXJtYXRpb24uXFxuXFxuJHtlbnRpdHlTdW1tYXJ5fWAsXG4gICAgfSk7XG4gICAgY3RsLmRlYnVnKFwiUmVkYWN0aW9uIHJlc3VsdFwiLCByZXN1bHQpO1xuICAgIHJldHVybiByZXN1bHQucmVkYWN0ZWRfdGV4dDtcbiAgfVxuXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAvLyBDb25maXJtYXRpb24gZ2F0ZSAoZGVmYXVsdClcbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC8vIFNhdmUgdGhlIHJlZGFjdGVkIHByb21wdCBzbyB0aGUgLS1jIGhhbmRsZXIgY2FuIGZvcndhcmRcbiAgLy8gdGhlIHJlZGFjdGVkIHZlcnNpb24gKG5ldmVyIHRoZSBvcmlnaW5hbCkuXG4gIHBlbmRpbmdSZWRhY3RlZFByb21wdCA9IHJlc3VsdC5yZWRhY3RlZF90ZXh0O1xuXG4gIC8vIFRydW5jYXRlIHRoZSByZWRhY3RlZCB0ZXh0IHByZXZpZXcgdG8gYXZvaWQgZmxvb2RpbmcgdGhlIHN0YXR1cyBwYW5lbFxuICBjb25zdCBwcmV2aWV3ID1cbiAgICByZXN1bHQucmVkYWN0ZWRfdGV4dC5sZW5ndGggPiA1MDBcbiAgICAgID8gcmVzdWx0LnJlZGFjdGVkX3RleHQuc2xpY2UoMCwgNTAwKSArIFwiXHUyMDI2XCJcbiAgICAgIDogcmVzdWx0LnJlZGFjdGVkX3RleHQ7XG5cbiAgZGV0ZWN0aW9uU3RhdHVzLnNldFN0YXRlKHtcbiAgICBzdGF0dXM6IFwiY2FuY2VsZWRcIixcbiAgICB0ZXh0OlxuICAgICAgYFBJSSBkZXRlY3RlZCBcdTIwMTQgcmVkYWN0aW9uIHByZXZpZXcgc2hvd24gYmVsb3cuIGAgK1xuICAgICAgYFNlbmQgYW5vdGhlciBtZXNzYWdlIGNvbnRhaW5pbmcgJy0tYycgdG8gY29uZmlybSBhbmQgcHJvY2VlZC5cXG5cXG5gICtcbiAgICAgIGAtLS0gUmVkYWN0ZWQgcHJvbXB0IC0tLVxcbiR7cHJldmlld31cXG5cXG5gICtcbiAgICAgIGAtLS0gRW50aXR5IG1hcCAtLS1cXG4ke2VudGl0eVN1bW1hcnl9YCxcbiAgfSk7XG5cbiAgdGhyb3cgbmV3IEVycm9yKFxuICAgIFwiUHJvbXB0IGNvbnRhaW5zIFBJSS4gUmV2aWV3IHRoZSByZWRhY3RlZCBwcmV2aWV3IGluIHRoZSBzdGF0dXMgcGFuZWwsIHRoZW4gY29uZmlybSBcIiArXG4gICAgXCJ5b3VyIG1lc3NhZ2Ugd2l0aCAtLWMgdG8gcHJvY2VlZC5cIixcbiAgKTtcbn1cbiIsICJpbXBvcnQgeyB0eXBlIFBsdWdpbkNvbnRleHQgfSBmcm9tIFwiQGxtc3R1ZGlvL3Nka1wiO1xuaW1wb3J0IHsgZ2xvYmFsQ29uZmlnU2NoZW1hdGljcyB9IGZyb20gXCIuL2NvbmZpZ1wiO1xuaW1wb3J0IHsgZ2VuZXJhdGUgfSBmcm9tIFwiLi9nZW5lcmF0b3JcIjtcbmltcG9ydCB7IHByZXByb2Nlc3MgfSBmcm9tIFwiLi9wcm9tcHRQcmVwcm9jZXNzb3JcIjtcblxuLyoqXG4gKiBQbHVnaW4gZW50cnkgcG9pbnQuXG4gKlxuICogUmVnaXN0ZXJzOlxuICogLSBHbG9iYWwgY29uZmlndXJhdGlvbiBzY2hlbWEgKGRldGVjdGlvbi9hc3Npc3RhbnQgbW9kZWxzLCBjb25maXJtYXRpb25cbiAqICAgZ2F0ZSwgQVBJIGtleSwgYmFzZSBVUkwgXHUyMDE0IHNoYXJlZCBhY3Jvc3MgYWxsIGNoYXRzKVxuICogLSBQcm9tcHQgcHJlcHJvY2Vzc29yIChQSUkgZGV0ZWN0aW9uICsgcmVkYWN0aW9uICsgY29uZmlybWF0aW9uIGdhdGUpXG4gKiAtIEdlbmVyYXRvciAoc2VuZHMgdGhlIHJlZGFjdGVkIGhpc3RvcnkgdG8gdGhlIHRoaXJkLXBhcnR5IEFQSSBhbmRcbiAqICAgdW4tcmVkYWN0cyB0aGUgcmVzcG9uc2UgbG9jYWxseSlcbiAqXG4gKiBCZWNhdXNlIHRoZSBwbHVnaW4gY29udGFpbnMgYSBnZW5lcmF0b3IsIGl0IGFwcGVhcnMgaW4gdGhlIG1vZGVsIGRyb3Bkb3duXG4gKiAoaW5zdGVhZCBvZiB0aGUgcGx1Z2lucyBsaXN0KSBhbmQgYWN0cyBhcyBhIG1vZGVsLiBUaGUgcHJlcHJvY2Vzc29yIHJ1bnNcbiAqIHdoZW5ldmVyIHRoaXMgcGx1Z2luLW1vZGVsIGlzIHNlbGVjdGVkLlxuICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gbWFpbihjb250ZXh0OiBQbHVnaW5Db250ZXh0KSB7XG4gIGNvbnRleHQud2l0aEdsb2JhbENvbmZpZ1NjaGVtYXRpY3MoZ2xvYmFsQ29uZmlnU2NoZW1hdGljcyk7XG4gIGNvbnRleHQud2l0aFByb21wdFByZXByb2Nlc3NvcihwcmVwcm9jZXNzKTtcbiAgY29udGV4dC53aXRoR2VuZXJhdG9yKGdlbmVyYXRlKTtcbn1cbiIsICJpbXBvcnQgeyBMTVN0dWRpb0NsaWVudCwgdHlwZSBQbHVnaW5Db250ZXh0IH0gZnJvbSBcIkBsbXN0dWRpby9zZGtcIjtcblxuZGVjbGFyZSB2YXIgcHJvY2VzczogYW55O1xuXG4vLyBXZSByZWNlaXZlIHJ1bnRpbWUgaW5mb3JtYXRpb24gaW4gdGhlIGVudmlyb25tZW50IHZhcmlhYmxlcy5cbmNvbnN0IGNsaWVudElkZW50aWZpZXIgPSBwcm9jZXNzLmVudi5MTVNfUExVR0lOX0NMSUVOVF9JREVOVElGSUVSO1xuY29uc3QgY2xpZW50UGFzc2tleSA9IHByb2Nlc3MuZW52LkxNU19QTFVHSU5fQ0xJRU5UX1BBU1NLRVk7XG5jb25zdCBiYXNlVXJsID0gcHJvY2Vzcy5lbnYuTE1TX1BMVUdJTl9CQVNFX1VSTDtcblxuY29uc3QgY2xpZW50ID0gbmV3IExNU3R1ZGlvQ2xpZW50KHtcbiAgY2xpZW50SWRlbnRpZmllcixcbiAgY2xpZW50UGFzc2tleSxcbiAgYmFzZVVybCxcbn0pO1xuXG4oZ2xvYmFsVGhpcyBhcyBhbnkpLl9fTE1TX1BMVUdJTl9DT05URVhUID0gdHJ1ZTtcblxubGV0IHByZWRpY3Rpb25Mb29wSGFuZGxlclNldCA9IGZhbHNlO1xubGV0IHByb21wdFByZXByb2Nlc3NvclNldCA9IGZhbHNlO1xubGV0IGNvbmZpZ1NjaGVtYXRpY3NTZXQgPSBmYWxzZTtcbmxldCBnbG9iYWxDb25maWdTY2hlbWF0aWNzU2V0ID0gZmFsc2U7XG5sZXQgdG9vbHNQcm92aWRlclNldCA9IGZhbHNlO1xubGV0IGdlbmVyYXRvclNldCA9IGZhbHNlO1xuXG5jb25zdCBzZWxmUmVnaXN0cmF0aW9uSG9zdCA9IGNsaWVudC5wbHVnaW5zLmdldFNlbGZSZWdpc3RyYXRpb25Ib3N0KCk7XG5cbmNvbnN0IHBsdWdpbkNvbnRleHQ6IFBsdWdpbkNvbnRleHQgPSB7XG4gIHdpdGhQcmVkaWN0aW9uTG9vcEhhbmRsZXI6IChnZW5lcmF0ZSkgPT4ge1xuICAgIGlmIChwcmVkaWN0aW9uTG9vcEhhbmRsZXJTZXQpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIlByZWRpY3Rpb25Mb29wSGFuZGxlciBhbHJlYWR5IHJlZ2lzdGVyZWRcIik7XG4gICAgfVxuICAgIGlmICh0b29sc1Byb3ZpZGVyU2V0KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJQcmVkaWN0aW9uTG9vcEhhbmRsZXIgY2Fubm90IGJlIHVzZWQgd2l0aCBhIHRvb2xzIHByb3ZpZGVyXCIpO1xuICAgIH1cblxuICAgIHByZWRpY3Rpb25Mb29wSGFuZGxlclNldCA9IHRydWU7XG4gICAgc2VsZlJlZ2lzdHJhdGlvbkhvc3Quc2V0UHJlZGljdGlvbkxvb3BIYW5kbGVyKGdlbmVyYXRlKTtcbiAgICByZXR1cm4gcGx1Z2luQ29udGV4dDtcbiAgfSxcbiAgd2l0aFByb21wdFByZXByb2Nlc3NvcjogKHByZXByb2Nlc3MpID0+IHtcbiAgICBpZiAocHJvbXB0UHJlcHJvY2Vzc29yU2V0KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJQcm9tcHRQcmVwcm9jZXNzb3IgYWxyZWFkeSByZWdpc3RlcmVkXCIpO1xuICAgIH1cbiAgICBwcm9tcHRQcmVwcm9jZXNzb3JTZXQgPSB0cnVlO1xuICAgIHNlbGZSZWdpc3RyYXRpb25Ib3N0LnNldFByb21wdFByZXByb2Nlc3NvcihwcmVwcm9jZXNzKTtcbiAgICByZXR1cm4gcGx1Z2luQ29udGV4dDtcbiAgfSxcbiAgd2l0aENvbmZpZ1NjaGVtYXRpY3M6IChjb25maWdTY2hlbWF0aWNzKSA9PiB7XG4gICAgaWYgKGNvbmZpZ1NjaGVtYXRpY3NTZXQpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIkNvbmZpZyBzY2hlbWF0aWNzIGFscmVhZHkgcmVnaXN0ZXJlZFwiKTtcbiAgICB9XG4gICAgY29uZmlnU2NoZW1hdGljc1NldCA9IHRydWU7XG4gICAgc2VsZlJlZ2lzdHJhdGlvbkhvc3Quc2V0Q29uZmlnU2NoZW1hdGljcyhjb25maWdTY2hlbWF0aWNzKTtcbiAgICByZXR1cm4gcGx1Z2luQ29udGV4dDtcbiAgfSxcbiAgd2l0aEdsb2JhbENvbmZpZ1NjaGVtYXRpY3M6IChnbG9iYWxDb25maWdTY2hlbWF0aWNzKSA9PiB7XG4gICAgaWYgKGdsb2JhbENvbmZpZ1NjaGVtYXRpY3NTZXQpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIkdsb2JhbCBjb25maWcgc2NoZW1hdGljcyBhbHJlYWR5IHJlZ2lzdGVyZWRcIik7XG4gICAgfVxuICAgIGdsb2JhbENvbmZpZ1NjaGVtYXRpY3NTZXQgPSB0cnVlO1xuICAgIHNlbGZSZWdpc3RyYXRpb25Ib3N0LnNldEdsb2JhbENvbmZpZ1NjaGVtYXRpY3MoZ2xvYmFsQ29uZmlnU2NoZW1hdGljcyk7XG4gICAgcmV0dXJuIHBsdWdpbkNvbnRleHQ7XG4gIH0sXG4gIHdpdGhUb29sc1Byb3ZpZGVyOiAodG9vbHNQcm92aWRlcikgPT4ge1xuICAgIGlmICh0b29sc1Byb3ZpZGVyU2V0KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJUb29scyBwcm92aWRlciBhbHJlYWR5IHJlZ2lzdGVyZWRcIik7XG4gICAgfVxuICAgIGlmIChwcmVkaWN0aW9uTG9vcEhhbmRsZXJTZXQpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIlRvb2xzIHByb3ZpZGVyIGNhbm5vdCBiZSB1c2VkIHdpdGggYSBwcmVkaWN0aW9uTG9vcEhhbmRsZXJcIik7XG4gICAgfVxuXG4gICAgdG9vbHNQcm92aWRlclNldCA9IHRydWU7XG4gICAgc2VsZlJlZ2lzdHJhdGlvbkhvc3Quc2V0VG9vbHNQcm92aWRlcih0b29sc1Byb3ZpZGVyKTtcbiAgICByZXR1cm4gcGx1Z2luQ29udGV4dDtcbiAgfSxcbiAgd2l0aEdlbmVyYXRvcjogKGdlbmVyYXRvcikgPT4ge1xuICAgIGlmIChnZW5lcmF0b3JTZXQpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIkdlbmVyYXRvciBhbHJlYWR5IHJlZ2lzdGVyZWRcIik7XG4gICAgfVxuXG4gICAgZ2VuZXJhdG9yU2V0ID0gdHJ1ZTtcbiAgICBzZWxmUmVnaXN0cmF0aW9uSG9zdC5zZXRHZW5lcmF0b3IoZ2VuZXJhdG9yKTtcbiAgICByZXR1cm4gcGx1Z2luQ29udGV4dDtcbiAgfSxcbn07XG5cbmltcG9ydChcIi4vLi4vc3JjL2luZGV4LnRzXCIpLnRoZW4oYXN5bmMgbW9kdWxlID0+IHtcbiAgcmV0dXJuIGF3YWl0IG1vZHVsZS5tYWluKHBsdWdpbkNvbnRleHQpO1xufSkudGhlbigoKSA9PiB7XG4gIHNlbGZSZWdpc3RyYXRpb25Ib3N0LmluaXRDb21wbGV0ZWQoKTtcbn0pLmNhdGNoKChlcnJvcikgPT4ge1xuICBjb25zb2xlLmVycm9yKFwiRmFpbGVkIHRvIGV4ZWN1dGUgdGhlIG1haW4gZnVuY3Rpb24gb2YgdGhlIHBsdWdpbi5cIik7XG4gIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xufSk7XG4iXSwKICAibWFwcGluZ3MiOiAiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLGdCQU1hO0FBTmI7QUFBQTtBQUFBO0FBQUEsaUJBQXVDO0FBTWhDLElBQU0sNkJBQXlCLG1DQUF1QixFQUkxRDtBQUFBLE1BQ0M7QUFBQSxNQUNBO0FBQUEsTUFDQTtBQUFBLFFBQ0UsYUFBYTtBQUFB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QUFDQSxnQ0FBNEI7QUFDNUIseUJBQXFCLDBCQUEwQkEsdUJBQXNCO0FBQ3JFLFdBQU87QUFBQSxFQUNUO0FBQUEsRUFDQSxtQkFBbUIsQ0FBQyxrQkFBa0I7QUFDcEMsUUFBSSxrQkFBa0I7QUFDcEIsWUFBTSxJQUFJLE1BQU0sbUNBQW1DO0FBQUEsSUFDckQ7QUFDQSxRQUFJLDBCQUEwQjtBQUM1QixZQUFNLElBQUksTUFBTSw0REFBNEQ7QUFBQSxJQUM5RTtBQUVBLHVCQUFtQjtBQUNuQix5QkFBcUIsaUJBQWlCLGFBQWE7QUFDbkQsV0FBTztBQUFBLEVBQ1Q7QUFBQSxFQUNBLGVBQWUsQ0FBQyxjQUFjO0FBQzVCLFFBQUksY0FBYztBQUNoQixZQUFNLElBQUksTUFBTSw4QkFBOEI7QUFBQSxJQUNoRDtBQUVBLG1CQUFlO0FBQ2YseUJBQXFCLGFBQWEsU0FBUztBQUMzQyxXQUFPO0FBQUEsRUFDVDtBQUNGO0FBRUEsd0RBQTRCLEtBQUssT0FBTUMsWUFBVTtBQUMvQyxTQUFPLE1BQU1BLFFBQU8sS0FBSyxhQUFhO0FBQ3hDLENBQUMsRUFBRSxLQUFLLE1BQU07QUFDWix1QkFBcUIsY0FBYztBQUNyQyxDQUFDLEVBQUUsTUFBTSxDQUFDLFVBQVU7QUFDbEIsVUFBUSxNQUFNLG9EQUFvRDtBQUNsRSxVQUFRLE1BQU0sS0FBSztBQUNyQixDQUFDOyIsCiAgIm5hbWVzIjogWyJlbnRpdGllcyIsICJiYXNlVXJsIiwgImNsaWVudCIsICJPcGVuQUkiLCAiaW1wb3J0X3NkayIsICJnZW5lcmF0ZSIsICJwcmVwcm9jZXNzIiwgImdsb2JhbENvbmZpZ1NjaGVtYXRpY3MiLCAibW9kdWxlIl0KfQo=
