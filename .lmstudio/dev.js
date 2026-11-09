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
      "detectionEngine",
      "select",
      {
        displayName: "Detection Engine",
        subtitle: "'redact' uses the on-device Desert Ant Redact model (recommended \u2014 no LLM needed, weights download on first use). 'llm' uses the PII Detection Model for detection.",
        options: [
          { value: "redact", displayName: "Redact (on-device model)" },
          { value: "llm", displayName: "LLM (PII Detection Model)" }
        ]
      },
      "redact"
    ).field(
      "piiModel",
      "string",
      {
        displayName: "PII Detection Model",
        subtitle: "Only used when Detection Engine is 'llm'. Model identifier used to detect PII. Leave blank to use the currently loaded model. Example: qwen2.5-7b-instruct",
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
    const match = /^([A-Z_]+)_(\d+)$/.exec(identifier);
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

// src/sidecar.ts
function pluginRoot() {
  const candidates = [__dirname, import_node_path.default.join(__dirname, "..")];
  for (const dir of candidates) {
    if (import_node_fs.default.existsSync(import_node_path.default.join(dir, "sidecar", "worker.mjs"))) {
      return dir;
    }
  }
  throw new Error(
    `sidecar worker script not found (tried: ${candidates.map((c) => import_node_path.default.join(c, "sidecar", "worker.mjs")).join(", ")})`
  );
}
function ensureRunner() {
  const source = process.execPath;
  const srcStat = import_node_fs.default.statSync(source);
  let needsRebuild = true;
  try {
    const dstStat = import_node_fs.default.statSync(RUNNER_PATH);
    needsRebuild = dstStat.size !== srcStat.size || Math.floor(dstStat.mtimeMs) !== Math.floor(srcStat.mtimeMs);
  } catch {
  }
  if (needsRebuild) {
    import_node_fs.default.mkdirSync(CACHE_DIR, { recursive: true });
    import_node_fs.default.copyFileSync(source, RUNNER_PATH);
    import_node_fs.default.chmodSync(RUNNER_PATH, 493);
    (0, import_node_child_process.execFileSync)("/usr/bin/xattr", ["-c", RUNNER_PATH]);
    try {
      (0, import_node_child_process.execFileSync)("/usr/bin/codesign", ["--force", "--sign", "-", RUNNER_PATH], {
        stdio: ["ignore", "ignore", "pipe"]
      });
    } catch (err) {
      const stderr = err.stderr?.toString().trim();
      throw new Error(
        `failed to re-sign the sidecar runner copy (${RUNNER_PATH}): ` + (stderr || String(err))
      );
    }
  }
  return RUNNER_PATH;
}
function spawnWorker() {
  const runner = ensureRunner();
  const child = (0, import_node_child_process.spawn)(runner, [WORKER_PATH], {
    cwd: pluginRoot(),
    stdio: ["pipe", "pipe", "pipe"]
  });
  child.on("exit", () => {
    for (const p of pending.values()) {
      p.reject(new Error("sidecar worker exited unexpectedly"));
    }
    pending.clear();
    worker = null;
  });
  child.stderr.on("data", (chunk) => {
    process.stderr.write(chunk);
  });
  let outBuf = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    outBuf += chunk;
    let idx;
    while ((idx = outBuf.indexOf("\n")) !== -1) {
      const line = outBuf.slice(0, idx);
      outBuf = outBuf.slice(idx + 1);
      if (line.trim() === "") continue;
      handleWorkerMessage(line);
    }
  });
  return child;
}
function handleWorkerMessage(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    process.stderr.write(`[pii-redact] sidecar sent invalid JSON: ${line}
`);
    return;
  }
  if (msg.id === null || msg.id === void 0) {
    process.stderr.write(`[pii-redact] sidecar error: ${msg.message ?? "unknown"}
`);
    return;
  }
  const p = pending.get(msg.id);
  if (p === void 0) {
    return;
  }
  pending.delete(msg.id);
  if (msg.type === "result" && msg.spans !== void 0) {
    p.resolve(msg.spans);
  } else if (msg.type === "ready") {
    p.resolve(void 0);
  } else {
    p.reject(new Error(msg.message ?? "sidecar request failed"));
  }
}
function getWorker() {
  if (worker === null) {
    worker = spawnWorker();
  }
  return worker;
}
function request(type, text) {
  const child = getWorker();
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    child.stdin.write(JSON.stringify({ type, id, text }) + "\n");
  });
}
async function detectViaSidecar(text) {
  return await request("detect", text);
}
async function warmSidecar() {
  await request("warmup");
}
var import_node_child_process, import_node_fs, import_node_os, import_node_path, WORKER_PATH, CACHE_DIR, RUNNER_PATH, worker, nextId, pending;
var init_sidecar = __esm({
  "src/sidecar.ts"() {
    "use strict";
    import_node_child_process = require("node:child_process");
    import_node_fs = __toESM(require("node:fs"));
    import_node_os = __toESM(require("node:os"));
    import_node_path = __toESM(require("node:path"));
    WORKER_PATH = import_node_path.default.join(pluginRoot(), "sidecar", "worker.mjs");
    CACHE_DIR = import_node_path.default.join(import_node_os.default.homedir(), ".cache", "pii-redact");
    RUNNER_PATH = import_node_path.default.join(CACHE_DIR, "pii-redact-node");
    worker = null;
    nextId = 1;
    pending = /* @__PURE__ */ new Map();
  }
});

// src/types.ts
var import_zod, import_native, PII_TYPES, piiTypeSchema, piiEntitySchema, llmDetectionResponseSchema, redactionResultSchema, CONFIRM_SUFFIX;
var init_types = __esm({
  "src/types.ts"() {
    "use strict";
    import_zod = require("zod");
    import_native = require("@desert-ant-labs/redact/native");
    PII_TYPES = import_native.ALL_LABELS;
    piiTypeSchema = import_zod.z.enum([...PII_TYPES]);
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
          // Labels may contain underscores (e.g. "GIVEN_NAME_1"), so the type
          // part is matched with [A-Z_]+ and the trailing counter with _\d+.
          identifier: import_zod.z.string().regex(/^[A-Z_]+_\d+$/),
          type: piiTypeSchema,
          original: import_zod.z.string().min(1)
        })
      )
    });
    CONFIRM_SUFFIX = "--c";
  }
});

// src/piiDetector.ts
async function getRedact() {
  if (redactInstance !== null) {
    return redactInstance;
  }
  if (redactLoadPromise === null) {
    redactLoadPromise = import_native2.Redact.load().then((instance) => {
      redactInstance = instance;
      return instance;
    });
    redactLoadPromise.catch(() => {
      redactLoadPromise = null;
    });
  }
  return redactLoadPromise;
}
async function preloadRedact() {
  if (!useSidecar) {
    try {
      await getRedact();
      return;
    } catch (err) {
      if (isDlopenError(err)) {
        useSidecar = true;
      } else {
        throw err;
      }
    }
  }
  await warmSidecar();
}
async function redactDetect(text) {
  if (!useSidecar) {
    try {
      const redact2 = await getRedact();
      const result = await redact2.redaction(text, { labels: [...ALL_LABELS_SET] });
      return result.items.map((item) => ({
        original: item.original,
        type: item.label
      }));
    } catch (err) {
      if (isDlopenError(err)) {
        useSidecar = true;
      } else {
        throw err;
      }
    }
  }
  return detectViaSidecar(text);
}
function isDlopenError(err) {
  const message = err instanceof Error ? err.message : String(err);
  return err?.code === "ERR_DLOPEN_FAILED" || message.includes("different Team IDs") || message.includes("code signature");
}
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
var import_native2, ALL_LABELS_SET, SYSTEM_PROMPT, redactInstance, redactLoadPromise, useSidecar, EMAIL_REGEX, PHONE_REGEX, MIN_PHONE_DIGITS;
var init_piiDetector = __esm({
  "src/piiDetector.ts"() {
    "use strict";
    import_native2 = require("@desert-ant-labs/redact/native");
    init_sidecar();
    init_types();
    ALL_LABELS_SET = new Set(import_native2.ALL_LABELS);
    SYSTEM_PROMPT = `You are a privacy-focused PII (Personally Identifiable Information) detector.

Your task: analyse the user's text and return a JSON object listing every PII entity found.

Rules:
1. Detect the following entity types:
   - GIVEN_NAME        \u2014 first names, given names
   - SURNAME           \u2014 last names, family names
   - STREET_NAME       \u2014 street names
   - BUILDING_NUMBER   \u2014 house or building numbers
   - SECONDARY_ADDRESS \u2014 apartment, suite, floor, PO box
   - CITY              \u2014 cities and towns
   - STATE             \u2014 states, provinces, regions
   - ZIP_CODE          \u2014 postal codes
   - EMAIL             \u2014 email addresses
   - PHONE             \u2014 phone numbers (any format)
   - CREDIT_CARD       \u2014 credit card numbers
   - BANK_ACCOUNT      \u2014 bank account numbers, IBANs
   - ROUTING_NUMBER    \u2014 bank routing numbers
   - IP_ADDRESS        \u2014 IP addresses
   - URL               \u2014 URLs
   - GOVERNMENT_ID     \u2014 national ID numbers
   - PASSPORT          \u2014 passport numbers
   - DRIVERS_LICENSE   \u2014 driver's license numbers
   - TAX_ID            \u2014 tax identification numbers
   - SSN               \u2014 social security numbers
   - IMEI              \u2014 device identifiers
   - ORG               \u2014 company, organisation, institution names

2. For each entity return the EXACT substring as it appears in the text (preserve case and spacing).

3. Do NOT invent entities. Only return entities that are actually present in the text.

4. Return ONLY valid JSON matching this schema \u2014 no markdown, no extra keys:
{
  "entities": [
    { "original": "<exact text span>", "type": "<TYPE>" },
    ...
  ]
}

If no PII is found, return: { "entities": [] }`;
    redactInstance = null;
    redactLoadPromise = null;
    useSidecar = false;
    EMAIL_REGEX = /[\w.+\-]+@[\w\-]+\.[a-zA-Z]{2,}/g;
    PHONE_REGEX = /(?:\+?\d{1,3}[\s\-.]?)?\(?\d{1,4}\)?[\s\-.]?\d{1,4}[\s\-.]?\d{1,4}(?:[\s\-.]?\d{1,4})*/g;
    MIN_PHONE_DIGITS = 7;
  }
});

// src/promptPreprocessor.ts
async function attemptDetection(ctl, text) {
  const globalConfig = ctl.getGlobalPluginConfig(globalConfigSchematics);
  const detectionEngine = globalConfig.get("detectionEngine");
  let spans;
  if (detectionEngine === "llm") {
    const modelId = globalConfig.get("piiModel").trim();
    const model = modelId.length > 0 ? await ctl.client.llm.model(modelId, { signal: ctl.abortSignal }) : await ctl.client.llm.model();
    const llmResponse = await llmDetect(model, text, ctl.abortSignal);
    const regexSpans = regexDetect(text);
    spans = mergeDetections(llmResponse.entities, regexSpans);
  } else {
    spans = await redactDetect(text);
  }
  const result = redact(text, spans, existingIdentifiers());
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
  let lastError = null;
  try {
    result = await attemptDetection(ctl, rawText);
  } catch (err) {
    lastError = err;
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
      lastError = err;
      ctl.debug("PII detection attempt 2 failed", err);
    }
  }
  if (result === null) {
    const detail = lastError instanceof Error ? lastError.message : lastError !== null ? String(lastError) : "detection returned an invalid result (see debug logs)";
    detectionStatus.setState({
      status: "error",
      text: `PII detection failed after retry. Request aborted.
Engine: ${globalConfig.get("detectionEngine")}
Reason: ${detail}`
    });
    throw new Error(
      `PII detection failed after one retry. Request aborted \u2014 the original prompt is never forwarded. Reason: ${detail}`
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
  void preloadRedact().catch((err) => {
    console.error("[pii-redact] Redact model pre-load failed:", err);
  });
  context.withPromptPreprocessor(preprocess);
  context.withGenerator(generate);
}
var init_src = __esm({
  "src/index.ts"() {
    "use strict";
    init_config();
    init_generator();
    init_piiDetector();
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vc3JjL2NvbmZpZy50cyIsICIuLi9zcmMvcmVkYWN0b3IudHMiLCAiLi4vc3JjL2VudGl0eVN0b3JlLnRzIiwgIi4uL3NyYy9nZW5lcmF0b3IudHMiLCAiLi4vc3JjL3NpZGVjYXIudHMiLCAiLi4vc3JjL3R5cGVzLnRzIiwgIi4uL3NyYy9waWlEZXRlY3Rvci50cyIsICIuLi9zcmMvcHJvbXB0UHJlcHJvY2Vzc29yLnRzIiwgIi4uL3NyYy9pbmRleC50cyIsICJlbnRyeS50cyJdLAogICJzb3VyY2VzQ29udGVudCI6IFsiaW1wb3J0IHsgY3JlYXRlQ29uZmlnU2NoZW1hdGljcyB9IGZyb20gXCJAbG1zdHVkaW8vc2RrXCI7XG5cbi8qKlxuICogR2xvYmFsIGNvbmZpZ3VyYXRpb24gXHUyMDE0IHNoYXJlZCBhY3Jvc3MgYWxsIGNoYXRzLCBzbyB2YWx1ZXMgcGVyc2lzdCB3aGVuXG4gKiBzdGFydGluZyBhIG5ldyBjb252ZXJzYXRpb24uXG4gKi9cbmV4cG9ydCBjb25zdCBnbG9iYWxDb25maWdTY2hlbWF0aWNzID0gY3JlYXRlQ29uZmlnU2NoZW1hdGljcygpXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgLy8gRGV0ZWN0aW9uIGVuZ2luZVxuICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC5maWVsZChcbiAgICBcImRldGVjdGlvbkVuZ2luZVwiLFxuICAgIFwic2VsZWN0XCIsXG4gICAge1xuICAgICAgZGlzcGxheU5hbWU6IFwiRGV0ZWN0aW9uIEVuZ2luZVwiLFxuICAgICAgc3VidGl0bGU6XG4gICAgICAgIFwiJ3JlZGFjdCcgdXNlcyB0aGUgb24tZGV2aWNlIERlc2VydCBBbnQgUmVkYWN0IG1vZGVsIChyZWNvbW1lbmRlZCBcdTIwMTQgbm8gTExNIG5lZWRlZCwgXCIgK1xuICAgICAgICBcIndlaWdodHMgZG93bmxvYWQgb24gZmlyc3QgdXNlKS4gJ2xsbScgdXNlcyB0aGUgUElJIERldGVjdGlvbiBNb2RlbCBmb3IgZGV0ZWN0aW9uLlwiLFxuICAgICAgb3B0aW9uczogW1xuICAgICAgICB7IHZhbHVlOiBcInJlZGFjdFwiLCBkaXNwbGF5TmFtZTogXCJSZWRhY3QgKG9uLWRldmljZSBtb2RlbClcIiB9LFxuICAgICAgICB7IHZhbHVlOiBcImxsbVwiLCBkaXNwbGF5TmFtZTogXCJMTE0gKFBJSSBEZXRlY3Rpb24gTW9kZWwpXCIgfSxcbiAgICAgIF0sXG4gICAgfSxcbiAgICBcInJlZGFjdFwiLFxuICApXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgLy8gUElJIGRldGVjdGlvbiBtb2RlbFxuICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC5maWVsZChcbiAgICBcInBpaU1vZGVsXCIsXG4gICAgXCJzdHJpbmdcIixcbiAgICB7XG4gICAgICBkaXNwbGF5TmFtZTogXCJQSUkgRGV0ZWN0aW9uIE1vZGVsXCIsXG4gICAgICBzdWJ0aXRsZTpcbiAgICAgICAgXCJPbmx5IHVzZWQgd2hlbiBEZXRlY3Rpb24gRW5naW5lIGlzICdsbG0nLiBNb2RlbCBpZGVudGlmaWVyIHVzZWQgdG8gZGV0ZWN0IFBJSS4gXCIgK1xuICAgICAgICBcIkxlYXZlIGJsYW5rIHRvIHVzZSB0aGUgY3VycmVudGx5IGxvYWRlZCBtb2RlbC4gRXhhbXBsZTogcXdlbjIuNS03Yi1pbnN0cnVjdFwiLFxuICAgICAgcGxhY2Vob2xkZXI6IFwiZS5nLiBxd2VuMi41LTdiLWluc3RydWN0XCIsXG4gICAgfSxcbiAgICBcIlwiLFxuICApXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgLy8gQXNzaXN0YW50IG1vZGVsICh0aGUgdGhpcmQtcGFydHkgbW9kZWwgdGhhdCByZWNlaXZlcyB0aGUgcmVkYWN0ZWQgcHJvbXB0KVxuICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC5maWVsZChcbiAgICBcImFzc2lzdGFudE1vZGVsXCIsXG4gICAgXCJzdHJpbmdcIixcbiAgICB7XG4gICAgICBkaXNwbGF5TmFtZTogXCJBc3Npc3RhbnQgTW9kZWxcIixcbiAgICAgIHN1YnRpdGxlOlxuICAgICAgICBcIk1vZGVsIElEIHNlbnQgdG8gdGhlIE9wZW5BSS1jb21wYXRpYmxlIGVuZHBvaW50IGZvciBnZW5lcmF0aW5nIHJlc3BvbnNlcy4gXCIgK1xuICAgICAgICBcIkV4YW1wbGVzOiBncHQtNG8tbWluaSAoT3BlbkFJKSwgb3BlbmFpL2dwdC00by1taW5pIChPcGVuUm91dGVyKS5cIixcbiAgICAgIHBsYWNlaG9sZGVyOiBcImUuZy4gZ3B0LTRvLW1pbmlcIixcbiAgICB9LFxuICAgIFwiXCIsXG4gIClcbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAvLyBDb25maXJtYXRpb24gZ2F0ZVxuICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC5maWVsZChcbiAgICBcInNraXBDb25maXJtYXRpb25cIixcbiAgICBcImJvb2xlYW5cIixcbiAgICB7XG4gICAgICBkaXNwbGF5TmFtZTogXCJTa2lwIENvbmZpcm1hdGlvblwiLFxuICAgICAgc3VidGl0bGU6XG4gICAgICAgIFwiV2hlbiBlbmFibGVkLCByZWRhY3RlZCBwcm9tcHRzIGFyZSBmb3J3YXJkZWQgaW1tZWRpYXRlbHkgd2l0aG91dCByZXF1aXJpbmcgJy0tYycuIFwiICtcbiAgICAgICAgXCJUaGUgcmVkYWN0aW9uIHByZXZpZXcgaXMgc3RpbGwgc2hvd24gaW4gdGhlIHN0YXR1cyBwYW5lbC5cIixcbiAgICB9LFxuICAgIGZhbHNlLFxuICApXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgLy8gQVBJIGtleSBmb3IgdGhlIE9wZW5BSS1jb21wYXRpYmxlIGVuZHBvaW50XG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgLmZpZWxkKFxuICAgIFwiYXBpS2V5XCIsXG4gICAgXCJzdHJpbmdcIixcbiAgICB7XG4gICAgICBkaXNwbGF5TmFtZTogXCJBUEkgS2V5XCIsXG4gICAgICBzdWJ0aXRsZTpcbiAgICAgICAgXCJBUEkga2V5IGZvciB0aGUgT3BlbkFJLWNvbXBhdGlibGUgZW5kcG9pbnQgKGUuZy4gc2stLi4uIGZvciBPcGVuQUksIFwiICtcbiAgICAgICAgXCJzay1vci0uLi4gZm9yIE9wZW5Sb3V0ZXIpLiBTdG9yZWQgYXMgYSBwcm90ZWN0ZWQgZmllbGQuXCIsXG4gICAgICBpc1Byb3RlY3RlZDogdHJ1ZSxcbiAgICAgIHBsYWNlaG9sZGVyOiBcInNrLS4uLlwiLFxuICAgIH0sXG4gICAgXCJcIixcbiAgKVxuICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC8vIEJhc2UgVVJMIG9mIHRoZSBPcGVuQUktY29tcGF0aWJsZSBlbmRwb2ludFxuICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC5maWVsZChcbiAgICBcImJhc2VVcmxcIixcbiAgICBcInN0cmluZ1wiLFxuICAgIHtcbiAgICAgIGRpc3BsYXlOYW1lOiBcIkJhc2UgVVJMXCIsXG4gICAgICBzdWJ0aXRsZTpcbiAgICAgICAgXCJCYXNlIFVSTCBvZiB0aGUgT3BlbkFJLWNvbXBhdGlibGUgZW5kcG9pbnQuIFwiICtcbiAgICAgICAgXCJFeGFtcGxlczogaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS92MSwgaHR0cHM6Ly9vcGVucm91dGVyLmFpL2FwaS92MVwiLFxuICAgICAgcGxhY2Vob2xkZXI6IFwiaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS92MVwiLFxuICAgIH0sXG4gICAgXCJodHRwczovL2FwaS5vcGVuYWkuY29tL3YxXCIsXG4gIClcbiAgLmJ1aWxkKCk7XG4iLCAiaW1wb3J0IHR5cGUgeyBQaWlFbnRpdHksIFBpaVR5cGUsIFJlZGFjdGlvblJlc3VsdCB9IGZyb20gXCIuL3R5cGVzXCI7XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gUGxhY2Vob2xkZXIgaGVscGVyc1xuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbi8qKiBFc2NhcGUgc3BlY2lhbCByZWdleCBjaGFyYWN0ZXJzIGluIGEgbGl0ZXJhbCBzdHJpbmcuICovXG5leHBvcnQgZnVuY3Rpb24gZXNjYXBlUmVnRXhwKHRleHQ6IHN0cmluZyk6IHN0cmluZyB7XG4gIHJldHVybiB0ZXh0LnJlcGxhY2UoL1suKis/XiR7fSgpfFtcXF1cXFxcXS9nLCBcIlxcXFwkJlwiKTtcbn1cblxuLyoqXG4gKiBCdWlsZCB0aGUgcGxhY2Vob2xkZXIgc3RyaW5nIGZvciBhIGdpdmVuIGlkZW50aWZpZXIuXG4gKiBGb3JtYXQ6IFtbW1RZUEVfTl1dXVxuICovXG5leHBvcnQgZnVuY3Rpb24gYnVpbGRQbGFjZWhvbGRlcihpZGVudGlmaWVyOiBzdHJpbmcpOiBzdHJpbmcge1xuICByZXR1cm4gYFtbWyR7aWRlbnRpZmllcn1dXV1gO1xufVxuXG4vKipcbiAqIEJ1aWxkIGEgZGV0ZXJtaW5pc3RpYyBpZGVudGlmaWVyIGtleSBmb3IgYSAodHlwZSwgY291bnRlcikgcGFpci5cbiAqIGUuZy4gKFwiR0lWRU5fTkFNRVwiLCAxKSBcdTIxOTIgXCJHSVZFTl9OQU1FXzFcIlxuICovXG5mdW5jdGlvbiBidWlsZElkZW50aWZpZXIodHlwZTogUGlpVHlwZSwgbjogbnVtYmVyKTogc3RyaW5nIHtcbiAgcmV0dXJuIGAke3R5cGV9XyR7bn1gO1xufVxuXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIFNwYW4tYmFzZWQgZW50aXR5IChpbnRlcm5hbCwgYmVmb3JlIGlkZW50aWZpZXIgYXNzaWdubWVudClcbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG5pbnRlcmZhY2UgUmF3RW50aXR5IHtcbiAgb3JpZ2luYWw6IHN0cmluZztcbiAgdHlwZTogUGlpVHlwZTtcbn1cblxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4vLyBSZWRhY3RvclxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbi8qKlxuICogQnVpbGQgdGhlIHN0YXJ0aW5nIGNvdW50ZXIgcGVyIHR5cGUgc28gdGhhdCBuZXcgaWRlbnRpZmllcnMgY29udGludWUgYWZ0ZXJcbiAqIHRoZSBoaWdoZXN0IG51bWJlciBhbHJlYWR5IGFzc2lnbmVkIChhdm9pZHMgY29sbGlzaW9ucyBhY3Jvc3MgdHVybnMpLlxuICovXG5mdW5jdGlvbiBzdGFydGluZ0NvdW50ZXJzKGV4aXN0aW5nOiBNYXA8c3RyaW5nLCBzdHJpbmc+KTogQXJyYXk8W1BpaVR5cGUsIG51bWJlcl0+IHtcbiAgY29uc3QgbWF4aW1hID0gbmV3IE1hcDxQaWlUeXBlLCBudW1iZXI+KCk7XG4gIGZvciAoY29uc3QgaWRlbnRpZmllciBvZiBleGlzdGluZy52YWx1ZXMoKSkge1xuICAgIC8vIExhYmVscyBtYXkgY29udGFpbiB1bmRlcnNjb3JlcyAoZS5nLiBcIkdJVkVOX05BTUVfMVwiKSwgc28gdGhlIHR5cGUgcGFydFxuICAgIC8vIGlzIG1hdGNoZWQgd2l0aCBbQS1aX10rIGFuZCB0aGUgdHJhaWxpbmcgY291bnRlciB3aXRoIF9cXGQrLlxuICAgIGNvbnN0IG1hdGNoID0gL14oW0EtWl9dKylfKFxcZCspJC8uZXhlYyhpZGVudGlmaWVyKTtcbiAgICBpZiAobWF0Y2ggPT09IG51bGwpIHtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgICBjb25zdCB0eXBlID0gbWF0Y2hbMV0gYXMgUGlpVHlwZTtcbiAgICBjb25zdCBuID0gcGFyc2VJbnQobWF0Y2hbMl0sIDEwKTtcbiAgICBtYXhpbWEuc2V0KHR5cGUsIE1hdGgubWF4KG1heGltYS5nZXQodHlwZSkgPz8gMCwgbikpO1xuICB9XG4gIHJldHVybiBbLi4ubWF4aW1hXTtcbn1cblxuLyoqXG4gKiBHaXZlbiB0aGUgb3JpZ2luYWwgdGV4dCBhbmQgYSBsaXN0IG9mIHJhdyBkZXRlY3RlZCBlbnRpdGllcyAob3JkZXJlZCBieVxuICogZmlyc3QgYXBwZWFyYW5jZSksIGFzc2lnbiB1bmlxdWUgaWRlbnRpZmllcnMsIHJlc29sdmUgY29yZWZlcmVuY2VzLCBhbmRcbiAqIHN1YnN0aXR1dGUgYWxsIG9jY3VycmVuY2VzIGluIHRoZSB0ZXh0LlxuICpcbiAqIFJ1bGVzOlxuICogLSBFbnRpdGllcyBhcmUgbnVtYmVyZWQgcGVyLXR5cGUgc3RhcnRpbmcgYXQgMS5cbiAqIC0gQ29yZWZlcmVuY2U6IGlmIHR3byByYXcgZW50aXRpZXMgaGF2ZSB0aGUgc2FtZSBgb3JpZ2luYWxgIHZhbHVlIChjYXNlLVxuICogICBpbnNlbnNpdGl2ZSksIHRoZXkgc2hhcmUgdGhlIHNhbWUgaWRlbnRpZmllci5cbiAqIC0gSWYgYGV4aXN0aW5nYCBpcyBwcm92aWRlZCAobm9ybWFsaXplZCBvcmlnaW5hbCBcdTIxOTIgaWRlbnRpZmllciksIGVudGl0aWVzXG4gKiAgIHNlZW4gaW4gZWFybGllciB0dXJucyByZXVzZSB0aGVpciBwcmV2aW91cyBpZGVudGlmaWVyLCBhbmQgbmV3IGNvdW50ZXJzXG4gKiAgIGNvbnRpbnVlIGFmdGVyIHRoZSBoaWdoZXN0IGV4aXN0aW5nIG51bWJlciBwZXIgdHlwZS5cbiAqIC0gU3Vic3RpdHV0aW9uIGlzIHBlcmZvcm1lZCBsb25nZXN0LW1hdGNoLWZpcnN0IHRvIGF2b2lkIHBhcnRpYWwgb3ZlcmxhcHNcbiAqICAgKGUuZy4gXCJKb2huIFNtaXRoXCIgYmVmb3JlIFwiSm9oblwiKS5cbiAqIC0gUGxhY2Vob2xkZXJzIGFyZSB0cmlwbGUtYnJhY2tldCB3cmFwcGVkIHNvIGRvd25zdHJlYW0gbW9kZWxzIGFyZSB1bmxpa2VseVxuICogICB0byBhbHRlciB0aGVtLlxuICovXG5leHBvcnQgZnVuY3Rpb24gcmVkYWN0KFxuICB0ZXh0OiBzdHJpbmcsXG4gIHJhd0VudGl0aWVzOiBSYXdFbnRpdHlbXSxcbiAgZXhpc3Rpbmc/OiBNYXA8c3RyaW5nLCBzdHJpbmc+LFxuKTogUmVkYWN0aW9uUmVzdWx0IHtcbiAgLy8gU3RlcCAxOiBEZWR1cGxpY2F0ZSBhbmQgYXNzaWduIGlkZW50aWZpZXJzLlxuICAvLyBXZSBwcmVzZXJ2ZSBmaXJzdC1hcHBlYXJhbmNlIG9yZGVyIGFuZCBtZXJnZSBpZGVudGljYWwgb3JpZ2luYWxzLlxuICBjb25zdCBjb3VudGVycyA9IG5ldyBNYXA8UGlpVHlwZSwgbnVtYmVyPihleGlzdGluZyA/IHN0YXJ0aW5nQ291bnRlcnMoZXhpc3RpbmcpIDogW10pO1xuICAvLyBNYXAgZnJvbSBub3JtYWxpc2VkIG9yaWdpbmFsIHRleHQgXHUyMTkyIGFzc2lnbmVkIGlkZW50aWZpZXJcbiAgY29uc3QgY2Fub25pY2FsTWFwID0gbmV3IE1hcDxzdHJpbmcsIHN0cmluZz4oKTtcbiAgLy8gRmluYWwgb3JkZXJlZCBlbnRpdHkgbGlzdCAobm8gZHVwbGljYXRlcylcbiAgY29uc3QgZW50aXRpZXM6IFBpaUVudGl0eVtdID0gW107XG5cbiAgZm9yIChjb25zdCByYXcgb2YgcmF3RW50aXRpZXMpIHtcbiAgICBjb25zdCBrZXkgPSByYXcub3JpZ2luYWwudG9Mb3dlckNhc2UoKS50cmltKCk7XG4gICAgaWYgKGNhbm9uaWNhbE1hcC5oYXMoa2V5KSkge1xuICAgICAgLy8gQWxyZWFkeSBhc3NpZ25lZCBcdTIwMTQgY29yZWZlcmVuY2UgcmVzb2x2ZWRcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgICBjb25zdCBleGlzdGluZ0lkZW50aWZpZXIgPSBleGlzdGluZz8uZ2V0KGtleSk7XG4gICAgaWYgKGV4aXN0aW5nSWRlbnRpZmllciAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAvLyBTZWVuIGluIGFuIGVhcmxpZXIgdHVybiBcdTIwMTQgcmV1c2UgdGhlIHByZXZpb3VzIGlkZW50aWZpZXJcbiAgICAgIGNhbm9uaWNhbE1hcC5zZXQoa2V5LCBleGlzdGluZ0lkZW50aWZpZXIpO1xuICAgICAgZW50aXRpZXMucHVzaCh7IGlkZW50aWZpZXI6IGV4aXN0aW5nSWRlbnRpZmllciwgdHlwZTogcmF3LnR5cGUsIG9yaWdpbmFsOiByYXcub3JpZ2luYWwgfSk7XG4gICAgICBjb250aW51ZTtcbiAgICB9XG4gICAgY29uc3QgbiA9IChjb3VudGVycy5nZXQocmF3LnR5cGUpID8/IDApICsgMTtcbiAgICBjb3VudGVycy5zZXQocmF3LnR5cGUsIG4pO1xuICAgIGNvbnN0IGlkZW50aWZpZXIgPSBidWlsZElkZW50aWZpZXIocmF3LnR5cGUsIG4pO1xuICAgIGNhbm9uaWNhbE1hcC5zZXQoa2V5LCBpZGVudGlmaWVyKTtcbiAgICBlbnRpdGllcy5wdXNoKHsgaWRlbnRpZmllciwgdHlwZTogcmF3LnR5cGUsIG9yaWdpbmFsOiByYXcub3JpZ2luYWwgfSk7XG4gIH1cblxuICAvLyBTdGVwIDI6IEJ1aWxkIHJlcGxhY2VtZW50IHBhaXJzIHNvcnRlZCBieSBsZW5ndGggZGVzY2VuZGluZyAobG9uZ2VzdCBmaXJzdClcbiAgLy8gdG8gYXZvaWQgcmVwbGFjaW5nIHN1YnN0cmluZ3Mgb2YgbG9uZ2VyIG1hdGNoZXMuXG4gIGNvbnN0IHJlcGxhY2VtZW50czogQXJyYXk8eyBvcmlnaW5hbDogc3RyaW5nOyBwbGFjZWhvbGRlcjogc3RyaW5nIH0+ID0gZW50aXRpZXNcbiAgICAubWFwKGUgPT4gKHtcbiAgICAgIG9yaWdpbmFsOiBlLm9yaWdpbmFsLFxuICAgICAgcGxhY2Vob2xkZXI6IGJ1aWxkUGxhY2Vob2xkZXIoZS5pZGVudGlmaWVyKSxcbiAgICB9KSlcbiAgICAuc29ydCgoYSwgYikgPT4gYi5vcmlnaW5hbC5sZW5ndGggLSBhLm9yaWdpbmFsLmxlbmd0aCk7XG5cbiAgLy8gU3RlcCAzOiBQZXJmb3JtIHN1YnN0aXR1dGlvbnMuXG4gIC8vIFdlIHVzZSBhIHNpbmdsZS1wYXNzIGFwcHJvYWNoOiBzY2FuIHRoZSB0ZXh0IGxlZnQtdG8tcmlnaHQsIGdyZWVkaWx5XG4gIC8vIG1hdGNoaW5nIHRoZSBsb25nZXN0IGVudGl0eSBhdCBlYWNoIHBvc2l0aW9uLlxuICBsZXQgcmVkYWN0ZWQgPSB0ZXh0O1xuICBmb3IgKGNvbnN0IHsgb3JpZ2luYWwsIHBsYWNlaG9sZGVyIH0gb2YgcmVwbGFjZW1lbnRzKSB7XG4gICAgLy8gUmVwbGFjZSBhbGwgb2NjdXJyZW5jZXMgKGNhc2Utc2Vuc2l0aXZlIFx1MjAxNCB0aGUgTExNIHJldHVybnMgZXhhY3Qgc3BhbnMpLlxuICAgIC8vIFdlIGVzY2FwZSBzcGVjaWFsIHJlZ2V4IGNoYXJhY3RlcnMgaW4gdGhlIG9yaWdpbmFsIHRleHQuXG4gICAgY29uc3QgZXNjYXBlZCA9IGVzY2FwZVJlZ0V4cChvcmlnaW5hbCk7XG4gICAgcmVkYWN0ZWQgPSByZWRhY3RlZC5yZXBsYWNlKG5ldyBSZWdFeHAoZXNjYXBlZCwgXCJnXCIpLCBwbGFjZWhvbGRlcik7XG4gIH1cblxuICByZXR1cm4geyByZWRhY3RlZF90ZXh0OiByZWRhY3RlZCwgZW50aXRpZXMgfTtcbn1cblxuLyoqXG4gKiBWYWxpZGF0ZSB0aGF0IG5vIHBsYWNlaG9sZGVyIGhhcyBiZWVuIGFsdGVyZWQgaW4gdGhlIHJlZGFjdGVkIHRleHQuXG4gKiBSZXR1cm5zIHRydWUgaWYgYWxsIHBsYWNlaG9sZGVycyBhcmUgaW50YWN0LlxuICovXG5leHBvcnQgZnVuY3Rpb24gdmFsaWRhdGVQbGFjZWhvbGRlcnMocmVzdWx0OiBSZWRhY3Rpb25SZXN1bHQpOiBib29sZWFuIHtcbiAgZm9yIChjb25zdCBlbnRpdHkgb2YgcmVzdWx0LmVudGl0aWVzKSB7XG4gICAgY29uc3QgcGxhY2Vob2xkZXIgPSBidWlsZFBsYWNlaG9sZGVyKGVudGl0eS5pZGVudGlmaWVyKTtcbiAgICBpZiAoIXJlc3VsdC5yZWRhY3RlZF90ZXh0LmluY2x1ZGVzKHBsYWNlaG9sZGVyKSkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgfVxuICByZXR1cm4gdHJ1ZTtcbn1cbiIsICJpbXBvcnQgeyBidWlsZFBsYWNlaG9sZGVyLCBlc2NhcGVSZWdFeHAgfSBmcm9tIFwiLi9yZWRhY3RvclwiO1xuaW1wb3J0IHR5cGUgeyBQaWlFbnRpdHkgfSBmcm9tIFwiLi90eXBlc1wiO1xuXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIFNoYXJlZCBlbnRpdHkgbWFwXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuLyoqXG4gKiBNb2R1bGUtbGV2ZWwgZW50aXR5IG1hcCwgcGVyc2lzdGVkIGZvciB0aGUgbGlmZXRpbWUgb2YgdGhlIHBsdWdpbiBwcm9jZXNzLlxuICpcbiAqIFRoZSBwcmVwcm9jZXNzb3IgcmVnaXN0ZXJzIGVudGl0aWVzIGFzIHRoZXkgYXJlIGRldGVjdGVkOyB0aGUgZ2VuZXJhdG9yXG4gKiB1c2VzIHRoZSBzYW1lIG1hcCB0bzpcbiAqIC0gcmUtcmVkYWN0IHRoZSBjaGF0IGhpc3RvcnkgYmVmb3JlIHNlbmRpbmcgaXQgdG8gdGhlIHRoaXJkLXBhcnR5IEFQSVxuICogICAoZWFybGllciB0dXJucyBtYXkgc3RpbGwgY29udGFpbiBvcmlnaW5hbCB2YWx1ZXMpLFxuICogLSB1bi1yZWRhY3QgdGhlIG1vZGVsJ3MgcmVzcG9uc2UgYmVmb3JlIHNob3dpbmcgaXQgdG8gdGhlIHVzZXIuXG4gKlxuICogVGhlIG1hcCBuZXZlciBsZWF2ZXMgdGhpcyBwcm9jZXNzIFx1MjAxNCB0aGUgdGhpcmQtcGFydHkgQVBJIG9ubHkgZXZlciBzZWVzXG4gKiBwbGFjZWhvbGRlcnMuXG4gKi9cbmNvbnN0IGVudGl0aWVzID0gbmV3IE1hcDxzdHJpbmcsIFBpaUVudGl0eT4oKTtcblxuLyoqIE5vcm1hbGlzZWQgbG9va3VwIGtleSBmb3IgYW4gb3JpZ2luYWwgdmFsdWUgKGNhc2UtaW5zZW5zaXRpdmUsIHRyaW1tZWQpLiAqL1xuZnVuY3Rpb24gbm9ybWFsaXplKHRleHQ6IHN0cmluZyk6IHN0cmluZyB7XG4gIHJldHVybiB0ZXh0LnRvTG93ZXJDYXNlKCkudHJpbSgpO1xufVxuXG4vKipcbiAqIFJlZ2lzdGVyIGVudGl0aWVzIGRldGVjdGVkIGJ5IHRoZSBwcmVwcm9jZXNzb3IuIEVudGl0aWVzIGFscmVhZHkgcHJlc2VudFxuICogKHNhbWUgbm9ybWFsaXNlZCBvcmlnaW5hbCkgYXJlIGtlcHQgYXMtaXMsIHNvIGlkZW50aWZpZXJzIHN0YXkgc3RhYmxlXG4gKiBhY3Jvc3MgdHVybnMuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBhZGRFbnRpdGllcyhuZXdFbnRpdGllczogUGlpRW50aXR5W10pOiB2b2lkIHtcbiAgZm9yIChjb25zdCBlbnRpdHkgb2YgbmV3RW50aXRpZXMpIHtcbiAgICBjb25zdCBrZXkgPSBub3JtYWxpemUoZW50aXR5Lm9yaWdpbmFsKTtcbiAgICBpZiAoIWVudGl0aWVzLmhhcyhrZXkpKSB7XG4gICAgICBlbnRpdGllcy5zZXQoa2V5LCBlbnRpdHkpO1xuICAgIH1cbiAgfVxufVxuXG4vKipcbiAqIE1hcCBmcm9tIG5vcm1hbGlzZWQgb3JpZ2luYWwgXHUyMTkyIGlkZW50aWZpZXIsIHVzZWQgYnkgdGhlIHJlZGFjdG9yIHRvIHJldXNlXG4gKiBpZGVudGlmaWVycyBhc3NpZ25lZCBpbiBlYXJsaWVyIHR1cm5zLlxuICovXG5leHBvcnQgZnVuY3Rpb24gZXhpc3RpbmdJZGVudGlmaWVycygpOiBNYXA8c3RyaW5nLCBzdHJpbmc+IHtcbiAgY29uc3QgbWFwID0gbmV3IE1hcDxzdHJpbmcsIHN0cmluZz4oKTtcbiAgZm9yIChjb25zdCBba2V5LCBlbnRpdHldIG9mIGVudGl0aWVzKSB7XG4gICAgbWFwLnNldChrZXksIGVudGl0eS5pZGVudGlmaWVyKTtcbiAgfVxuICByZXR1cm4gbWFwO1xufVxuXG4vKipcbiAqIFJlcGxhY2UgZXZlcnkgcGxhY2Vob2xkZXIgaW4gYHRleHRgIHdpdGggaXRzIG9yaWdpbmFsIHZhbHVlLlxuICogVXNlZCB0byB1bi1yZWRhY3QgdGhlIGFzc2lzdGFudCdzIHJlc3BvbnNlIGJlZm9yZSBzaG93aW5nIGl0IHRvIHRoZSB1c2VyLlxuICogVG9sZXJhdGVzIGV4dHJhIHN1cnJvdW5kaW5nIGJyYWNrZXRzIHRoZSBtb2RlbCBtYXkgaGF2ZSBhZGRlZFxuICogKGUuZy4gXCJbW1tbRU1BSUxfMV1dXV1cIikuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB1bnJlZGFjdFRleHQodGV4dDogc3RyaW5nKTogc3RyaW5nIHtcbiAgbGV0IHJlc3VsdCA9IHRleHQ7XG4gIGZvciAoY29uc3QgZW50aXR5IG9mIGVudGl0aWVzLnZhbHVlcygpKSB7XG4gICAgY29uc3QgcGxhY2Vob2xkZXIgPSBlc2NhcGVSZWdFeHAoYnVpbGRQbGFjZWhvbGRlcihlbnRpdHkuaWRlbnRpZmllcikpO1xuICAgIGNvbnN0IHBhdHRlcm4gPSBuZXcgUmVnRXhwKGBcXFxcWyoke3BsYWNlaG9sZGVyfVxcXFxdKmAsIFwiZ1wiKTtcbiAgICByZXN1bHQgPSByZXN1bHQucmVwbGFjZShwYXR0ZXJuLCBlbnRpdHkub3JpZ2luYWwpO1xuICB9XG4gIHJldHVybiByZXN1bHQ7XG59XG5cbi8qKlxuICogUmVwbGFjZSBldmVyeSBrbm93biBvcmlnaW5hbCB2YWx1ZSBpbiBgdGV4dGAgd2l0aCBpdHMgcGxhY2Vob2xkZXIuXG4gKiBVc2VkIHRvIHJlLXJlZGFjdCB0aGUgY2hhdCBoaXN0b3J5IGJlZm9yZSBzZW5kaW5nIGl0IHRvIHRoZSBBUEkuXG4gKiBTdWJzdGl0dXRpb25zIGFyZSBsb25nZXN0LW1hdGNoLWZpcnN0IHRvIGF2b2lkIHBhcnRpYWwgb3ZlcmxhcHMuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiByZWRhY3RUZXh0KHRleHQ6IHN0cmluZyk6IHN0cmluZyB7XG4gIGNvbnN0IHNvcnRlZCA9IFsuLi5lbnRpdGllcy52YWx1ZXMoKV0uc29ydChcbiAgICAoYSwgYikgPT4gYi5vcmlnaW5hbC5sZW5ndGggLSBhLm9yaWdpbmFsLmxlbmd0aCxcbiAgKTtcbiAgbGV0IHJlc3VsdCA9IHRleHQ7XG4gIGZvciAoY29uc3QgZW50aXR5IG9mIHNvcnRlZCkge1xuICAgIGNvbnN0IHBhdHRlcm4gPSBuZXcgUmVnRXhwKGVzY2FwZVJlZ0V4cChlbnRpdHkub3JpZ2luYWwpLCBcImdcIik7XG4gICAgcmVzdWx0ID0gcmVzdWx0LnJlcGxhY2UocGF0dGVybiwgYnVpbGRQbGFjZWhvbGRlcihlbnRpdHkuaWRlbnRpZmllcikpO1xuICB9XG4gIHJldHVybiByZXN1bHQ7XG59XG4iLCAiaW1wb3J0IHsgdHlwZSBDaGF0LCB0eXBlIEdlbmVyYXRvckNvbnRyb2xsZXIgfSBmcm9tIFwiQGxtc3R1ZGlvL3Nka1wiO1xuaW1wb3J0IE9wZW5BSSBmcm9tIFwib3BlbmFpXCI7XG5pbXBvcnQgeyBnbG9iYWxDb25maWdTY2hlbWF0aWNzIH0gZnJvbSBcIi4vY29uZmlnXCI7XG5pbXBvcnQgeyByZWRhY3RUZXh0LCB1bnJlZGFjdFRleHQgfSBmcm9tIFwiLi9lbnRpdHlTdG9yZVwiO1xuXG5jb25zdCBERUZBVUxUX0JBU0VfVVJMID0gXCJodHRwczovL2FwaS5vcGVuYWkuY29tL3YxXCI7XG5cbi8qKiBNaW5pbWFsIG1lc3NhZ2Ugc2hhcGUgYWNjZXB0ZWQgYnkgdGhlIE9wZW5BSS1jb21wYXRpYmxlIGNoYXQgQVBJLiAqL1xuaW50ZXJmYWNlIE9wZW5BSU1lc3NhZ2Uge1xuICByb2xlOiBcInN5c3RlbVwiIHwgXCJ1c2VyXCIgfCBcImFzc2lzdGFudFwiO1xuICBjb250ZW50OiBzdHJpbmc7XG59XG5cbi8qKiBEZXRlY3RzIHBsYWNlaG9sZGVycyB0aGF0IHRoZSBtb2RlbCBlY2hvZWQgYmFjayBidXQgd2UgY291bGQgbm90IHJlc3RvcmUuICovXG5jb25zdCBQTEFDRUhPTERFUl9QQVRURVJOID0gL1xcW1xcW1xcW1tBLVpdK19cXGQrXFxdXFxdXFxdL2c7XG5cbi8qKlxuICogQ29udmVydCB0aGUgY2hhdCBoaXN0b3J5IHRvIE9wZW5BSSBmb3JtYXQsIHJlLXJlZGFjdGluZyBldmVyeSBtZXNzYWdlLlxuICpcbiAqIFJlLXJlZGFjdGlvbiBpcyBlc3NlbnRpYWw6IGVhcmxpZXIgdHVybnMgbWF5IHN0aWxsIGNvbnRhaW4gb3JpZ2luYWwgdmFsdWVzXG4gKiAodGhlIHByZXByb2Nlc3NvciBvbmx5IHJlZGFjdHMgdGhlIG1lc3NhZ2UgYmVpbmcgcHJvY2Vzc2VkLCBhbmQgY29uZmlybWVkXG4gKiB0dXJucyBrZWVwIHRoZWlyIG9yaWdpbmFscyBpbiB0aGUgdmlzaWJsZSBoaXN0b3J5KS4gVGhlIHNoYXJlZCBlbnRpdHkgbWFwXG4gKiByZXBsYWNlcyB0aGVtIHdpdGggcGxhY2Vob2xkZXJzIHNvIHRoZSB0aGlyZC1wYXJ0eSBBUEkgbmV2ZXIgc2VlcyB0aGVtLlxuICovXG5mdW5jdGlvbiB0b09wZW5BSU1lc3NhZ2VzKGhpc3Rvcnk6IENoYXQpOiBPcGVuQUlNZXNzYWdlW10ge1xuICBjb25zdCBtZXNzYWdlczogT3BlbkFJTWVzc2FnZVtdID0gW107XG4gIGZvciAoY29uc3QgbWVzc2FnZSBvZiBoaXN0b3J5KSB7XG4gICAgY29uc3Qgcm9sZSA9IG1lc3NhZ2UuZ2V0Um9sZSgpO1xuICAgIGlmIChyb2xlID09PSBcInRvb2xcIikge1xuICAgICAgLy8gVGhpcyBwbHVnaW4gcmVnaXN0ZXJzIG5vIHRvb2xzIHByb3ZpZGVyIFx1MjAxNCBza2lwIHRvb2wgbWVzc2FnZXMuXG4gICAgICBjb250aW51ZTtcbiAgICB9XG4gICAgbWVzc2FnZXMucHVzaCh7IHJvbGUsIGNvbnRlbnQ6IHJlZGFjdFRleHQobWVzc2FnZS5nZXRUZXh0KCkpIH0pO1xuICB9XG4gIHJldHVybiBtZXNzYWdlcztcbn1cblxuLyoqXG4gKiBHZW5lcmF0b3IgaG9vayBcdTIwMTQgcmVwbGFjZXMgdGhlIGxvY2FsIG1vZGVsIGVudGlyZWx5LlxuICpcbiAqIEZsb3c6XG4gKiAxLiBUaGUgcHJlcHJvY2Vzc29yIGhhcyBhbHJlYWR5IHJlZGFjdGVkIHRoZSB1c2VyJ3MgcHJvbXB0IChhbmQgc3RvcmVkIHRoZVxuICogICAgZW50aXR5IG1hcCBpbiB0aGUgc2hhcmVkIHN0b3JlKS5cbiAqIDIuIFRoaXMgZ2VuZXJhdG9yIHJlLXJlZGFjdHMgdGhlIGZ1bGwgaGlzdG9yeSwgc2VuZHMgaXQgdG8gdGhlIGNvbmZpZ3VyZWRcbiAqICAgIE9wZW5BSS1jb21wYXRpYmxlIGVuZHBvaW50LCBhbmQgYnVmZmVycyB0aGUgc3RyZWFtZWQgcmVzcG9uc2UuXG4gKiAzLiBQbGFjZWhvbGRlcnMgaW4gdGhlIHJlc3BvbnNlIGFyZSB0cmFuc2xhdGVkIGJhY2sgdG8gdGhlaXIgb3JpZ2luYWxzXG4gKiAgICBsb2NhbGx5LCB0aGVuIHRoZSB1bi1yZWRhY3RlZCB0ZXh0IGlzIGVtaXR0ZWQgdG8gdGhlIGNoYXQuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZShjdGw6IEdlbmVyYXRvckNvbnRyb2xsZXIsIGhpc3Rvcnk6IENoYXQpIHtcbiAgY29uc3QgZ2xvYmFsQ29uZmlnID0gY3RsLmdldEdsb2JhbFBsdWdpbkNvbmZpZyhnbG9iYWxDb25maWdTY2hlbWF0aWNzKTtcblxuICBjb25zdCBhc3Npc3RhbnRNb2RlbCA9IGdsb2JhbENvbmZpZy5nZXQoXCJhc3Npc3RhbnRNb2RlbFwiKS50cmltKCk7XG4gIGlmIChhc3Npc3RhbnRNb2RlbC5sZW5ndGggPT09IDApIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICBcIkFzc2lzdGFudCBNb2RlbCBpcyBub3QgY29uZmlndXJlZC4gU2V0IGl0IGluIHRoZSBwbHVnaW4gc2V0dGluZ3MgXCIgK1xuICAgICAgXCIoZS5nLiBncHQtNG8tbWluaSBmb3IgT3BlbkFJLCBvcGVuYWkvZ3B0LTRvLW1pbmkgZm9yIE9wZW5Sb3V0ZXIpLlwiLFxuICAgICk7XG4gIH1cblxuICBjb25zdCBhcGlLZXkgPSBnbG9iYWxDb25maWcuZ2V0KFwiYXBpS2V5XCIpLnRyaW0oKTtcbiAgaWYgKGFwaUtleS5sZW5ndGggPT09IDApIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICBcIkFQSSBLZXkgaXMgbm90IGNvbmZpZ3VyZWQuIFNldCBpdCBpbiB0aGUgcGx1Z2luJ3MgZ2xvYmFsIHNldHRpbmdzLlwiLFxuICAgICk7XG4gIH1cblxuICBjb25zdCBiYXNlVXJsID0gZ2xvYmFsQ29uZmlnLmdldChcImJhc2VVcmxcIikudHJpbSgpIHx8IERFRkFVTFRfQkFTRV9VUkw7XG5cbiAgY29uc3QgY2xpZW50ID0gbmV3IE9wZW5BSSh7IGFwaUtleSwgYmFzZVVSTDogYmFzZVVybCB9KTtcblxuICBjb25zdCBzdHJlYW0gPSBhd2FpdCBjbGllbnQuY2hhdC5jb21wbGV0aW9ucy5jcmVhdGUoe1xuICAgIG1vZGVsOiBhc3Npc3RhbnRNb2RlbCxcbiAgICBtZXNzYWdlczogdG9PcGVuQUlNZXNzYWdlcyhoaXN0b3J5KSxcbiAgICBzdHJlYW06IHRydWUsXG4gIH0pO1xuXG4gIC8vIFByb3BhZ2F0ZSB1c2VyIGFib3J0cyB0byB0aGUgSFRUUCBzdHJlYW0uXG4gIGN0bC5vbkFib3J0ZWQoKCkgPT4ge1xuICAgIHN0cmVhbS5jb250cm9sbGVyLmFib3J0KCk7XG4gIH0pO1xuXG4gIC8vIEJ1ZmZlciB0aGUgZnVsbCByZXNwb25zZSBcdTIwMTQgcGxhY2Vob2xkZXJzIGNhbiBzcGFuIHN0cmVhbSBmcmFnbWVudHMsIHNvXG4gIC8vIHVuLXJlZGFjdGlvbiBpcyBvbmx5IHNhZmUgb25jZSBnZW5lcmF0aW9uIGlzIGNvbXBsZXRlLlxuICBsZXQgZnVsbCA9IFwiXCI7XG4gIGZvciBhd2FpdCAoY29uc3QgY2h1bmsgb2Ygc3RyZWFtKSB7XG4gICAgY3RsLmFib3J0U2lnbmFsLnRocm93SWZBYm9ydGVkKCk7XG4gICAgY29uc3QgZGVsdGEgPSBjaHVuay5jaG9pY2VzWzBdPy5kZWx0YT8uY29udGVudDtcbiAgICBpZiAoZGVsdGEpIHtcbiAgICAgIGZ1bGwgKz0gZGVsdGE7XG4gICAgfVxuICB9XG5cbiAgaWYgKGZ1bGwubGVuZ3RoID09PSAwKSB7XG4gICAgY29uc29sZS5pbmZvKFwicGlpLXJlZGFjdDogYXNzaXN0YW50IG1vZGVsIHJldHVybmVkIGFuIGVtcHR5IHJlc3BvbnNlLlwiKTtcbiAgfVxuXG4gIC8vIFVuLXJlZGFjdCBsb2NhbGx5IFx1MjAxNCB0aGUgb3JpZ2luYWxzIG5ldmVyIGxlZnQgdGhpcyBtYWNoaW5lLlxuICBjb25zdCB1bnJlZGFjdGVkID0gdW5yZWRhY3RUZXh0KGZ1bGwpO1xuXG4gIGNvbnN0IHVubWF0Y2hlZCA9IHVucmVkYWN0ZWQubWF0Y2goUExBQ0VIT0xERVJfUEFUVEVSTik7XG4gIGlmICh1bm1hdGNoZWQgIT09IG51bGwpIHtcbiAgICBjb25zb2xlLmluZm8oXG4gICAgICBcInBpaS1yZWRhY3Q6IHJlc3BvbnNlIHN0aWxsIGNvbnRhaW5zIHBsYWNlaG9sZGVycyB3aXRoIG5vIGtub3duIG9yaWdpbmFsOlwiLFxuICAgICAgWy4uLm5ldyBTZXQodW5tYXRjaGVkKV0sXG4gICAgKTtcbiAgfVxuXG4gIGN0bC5mcmFnbWVudEdlbmVyYXRlZCh1bnJlZGFjdGVkKTtcbn1cbiIsICJpbXBvcnQgeyBleGVjRmlsZVN5bmMsIHNwYXduLCB0eXBlIENoaWxkUHJvY2Vzc1dpdGhvdXROdWxsU3RyZWFtcyB9IGZyb20gXCJub2RlOmNoaWxkX3Byb2Nlc3NcIjtcbmltcG9ydCBmcyBmcm9tIFwibm9kZTpmc1wiO1xuaW1wb3J0IG9zIGZyb20gXCJub2RlOm9zXCI7XG5pbXBvcnQgcGF0aCBmcm9tIFwibm9kZTpwYXRoXCI7XG5pbXBvcnQgdHlwZSB7IFJhd1NwYW4gfSBmcm9tIFwiLi90eXBlc1wiO1xuXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIFBhdGhzXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuLyoqXG4gKiBUaGUgcGx1Z2luIHJvb3QuIFRoZSBjb21waWxlZCBwbHVnaW4gY29kZSBsaXZlcyBhdCB0aGUgcmVwbyByb290ICh0c2NcbiAqIG91dHB1dCkgb3IgaW4gYC5sbXN0dWRpby9kZXYuanNgIChsbXMgZGV2IGJ1bmRsZSkgXHUyMDE0IHRoZSB3b3JrZXIgc2NyaXB0IGlzXG4gKiBhbHdheXMgYXQgYDxwbHVnaW4gcm9vdD4vc2lkZWNhci93b3JrZXIubWpzYC5cbiAqL1xuZnVuY3Rpb24gcGx1Z2luUm9vdCgpOiBzdHJpbmcge1xuICBjb25zdCBjYW5kaWRhdGVzID0gW19fZGlybmFtZSwgcGF0aC5qb2luKF9fZGlybmFtZSwgXCIuLlwiKV07XG4gIGZvciAoY29uc3QgZGlyIG9mIGNhbmRpZGF0ZXMpIHtcbiAgICBpZiAoZnMuZXhpc3RzU3luYyhwYXRoLmpvaW4oZGlyLCBcInNpZGVjYXJcIiwgXCJ3b3JrZXIubWpzXCIpKSkge1xuICAgICAgcmV0dXJuIGRpcjtcbiAgICB9XG4gIH1cbiAgdGhyb3cgbmV3IEVycm9yKFxuICAgIGBzaWRlY2FyIHdvcmtlciBzY3JpcHQgbm90IGZvdW5kICh0cmllZDogJHtjYW5kaWRhdGVzLm1hcChjID0+IHBhdGguam9pbihjLCBcInNpZGVjYXJcIiwgXCJ3b3JrZXIubWpzXCIpKS5qb2luKFwiLCBcIil9KWAsXG4gICk7XG59XG5cbmNvbnN0IFdPUktFUl9QQVRIID0gcGF0aC5qb2luKHBsdWdpblJvb3QoKSwgXCJzaWRlY2FyXCIsIFwid29ya2VyLm1qc1wiKTtcblxuLyoqXG4gKiBDYWNoZSBkaXJlY3RvcnkgZm9yIHRoZSByZS1zaWduZWQgcnVubmVyIGJpbmFyeS4gVGhlIGNvcHkgaXMgbmFtZWRcbiAqIGBwaWktcmVkYWN0LW5vZGVgIHNvIHRoZSBHYXRla2VlcGVyIHByb21wdCAoaWYgYW55KSBpZGVudGlmaWVzIGl0IGNsZWFybHkuXG4gKi9cbmNvbnN0IENBQ0hFX0RJUiA9IHBhdGguam9pbihvcy5ob21lZGlyKCksIFwiLmNhY2hlXCIsIFwicGlpLXJlZGFjdFwiKTtcbmNvbnN0IFJVTk5FUl9QQVRIID0gcGF0aC5qb2luKENBQ0hFX0RJUiwgXCJwaWktcmVkYWN0LW5vZGVcIik7XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gUnVubmVyIHByZXBhcmF0aW9uXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuLyoqXG4gKiBQcmVwYXJlIGEgcmUtc2lnbmVkIGNvcHkgb2YgdGhlIHBsdWdpbiBydW5uZXIgYmluYXJ5LlxuICpcbiAqIExNIFN0dWRpbydzIHBsdWdpbiBydW5uZXIgaXMgc2lnbmVkIHdpdGggYSBUZWFtIElEIGFuZCBlbmZvcmNlcyBtYWNPU1xuICogbGlicmFyeSB2YWxpZGF0aW9uLCBzbyBuYXRpdmUgYWRkb25zIChrb2ZmaSkgY2Fubm90IGJlIGxvYWRlZCBpbi1wcm9jZXNzXG4gKiAobG1zdHVkaW8tYnVnLXRyYWNrZXIjMTQ5NCkuIEFuIGFkLWhvYyByZS1zaWduZWQgY29weSBkcm9wcyB0aGUgaGFyZGVuZWRcbiAqIHJ1bnRpbWUgZmxhZywgd2hpY2ggZGlzYWJsZXMgbGlicmFyeSB2YWxpZGF0aW9uLlxuICpcbiAqIFN0ZXBzOlxuICogMS4gQ29weSB0aGUgcnVubmVyIGJpbmFyeSBpbnRvIHRoZSBjYWNoZSBkaXIgKHJlLWRvbmUgd2hlbiB0aGUgc291cmNlXG4gKiAgICBiaW5hcnkgY2hhbmdlcywgZS5nLiBhZnRlciBhbiBMTSBTdHVkaW8gdXBkYXRlKS5cbiAqIDIuIFN0cmlwIGFsbCBleHRlbmRlZCBhdHRyaWJ1dGVzIFx1MjAxNCBtYWNPUyBraWxscyByZS1zaWduZWQgYmluYXJpZXMgdGhhdFxuICogICAgc3RpbGwgY2FycnkgYHByb3ZlbmFuY2VgL2BxdWFyYW50aW5lYCB4YXR0cnMgaW5oZXJpdGVkIGZyb20gdGhlIGFwcFxuICogICAgYnVuZGxlLlxuICogMy4gQWQtaG9jIHJlLXNpZ24gKGBjb2Rlc2lnbiAtLWZvcmNlIC0tc2lnbiAtYCkuXG4gKi9cbmZ1bmN0aW9uIGVuc3VyZVJ1bm5lcigpOiBzdHJpbmcge1xuICBjb25zdCBzb3VyY2UgPSBwcm9jZXNzLmV4ZWNQYXRoO1xuICBjb25zdCBzcmNTdGF0ID0gZnMuc3RhdFN5bmMoc291cmNlKTtcblxuICBsZXQgbmVlZHNSZWJ1aWxkID0gdHJ1ZTtcbiAgdHJ5IHtcbiAgICBjb25zdCBkc3RTdGF0ID0gZnMuc3RhdFN5bmMoUlVOTkVSX1BBVEgpO1xuICAgIG5lZWRzUmVidWlsZCA9XG4gICAgICBkc3RTdGF0LnNpemUgIT09IHNyY1N0YXQuc2l6ZSB8fCBNYXRoLmZsb29yKGRzdFN0YXQubXRpbWVNcykgIT09IE1hdGguZmxvb3Ioc3JjU3RhdC5tdGltZU1zKTtcbiAgfSBjYXRjaCB7XG4gICAgLy8gQ29weSBkb2VzIG5vdCBleGlzdCB5ZXRcbiAgfVxuXG4gIGlmIChuZWVkc1JlYnVpbGQpIHtcbiAgICBmcy5ta2RpclN5bmMoQ0FDSEVfRElSLCB7IHJlY3Vyc2l2ZTogdHJ1ZSB9KTtcbiAgICBmcy5jb3B5RmlsZVN5bmMoc291cmNlLCBSVU5ORVJfUEFUSCk7XG4gICAgZnMuY2htb2RTeW5jKFJVTk5FUl9QQVRILCAwbzc1NSk7XG4gICAgLy8gbWFjT1Mtb25seSBoZWxwZXJzIFx1MjAxNCB0aGUgc2lkZWNhciBpcyBvbmx5IHVzZWQgb24gbWFjT1MgKHdoZXJlIGxpYnJhcnlcbiAgICAvLyB2YWxpZGF0aW9uIGJsb2NrcyBuYXRpdmUgYWRkb25zKTsgb24gTGludXgvV2luZG93cyB0aGUgaW4tcHJvY2VzcyBwYXRoXG4gICAgLy8gd29ya3MgYW5kIHRoaXMgY29kZSBpcyBuZXZlciByZWFjaGVkLlxuICAgIGV4ZWNGaWxlU3luYyhcIi91c3IvYmluL3hhdHRyXCIsIFtcIi1jXCIsIFJVTk5FUl9QQVRIXSk7XG4gICAgdHJ5IHtcbiAgICAgIC8vIFN1cHByZXNzIGNvZGVzaWduJ3Mgbm9ybWFsIG91dHB1dCAoXCJyZXBsYWNpbmcgZXhpc3Rpbmcgc2lnbmF0dXJlXCIpIFx1MjAxNFxuICAgICAgLy8gb25seSBmYWlsdXJlcyBhcmUgc3VyZmFjZWQuXG4gICAgICBleGVjRmlsZVN5bmMoXCIvdXNyL2Jpbi9jb2Rlc2lnblwiLCBbXCItLWZvcmNlXCIsIFwiLS1zaWduXCIsIFwiLVwiLCBSVU5ORVJfUEFUSF0sIHtcbiAgICAgICAgc3RkaW86IFtcImlnbm9yZVwiLCBcImlnbm9yZVwiLCBcInBpcGVcIl0sXG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIGNvbnN0IHN0ZGVyciA9IChlcnIgYXMgeyBzdGRlcnI/OiBCdWZmZXIgfSkuc3RkZXJyPy50b1N0cmluZygpLnRyaW0oKTtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgYGZhaWxlZCB0byByZS1zaWduIHRoZSBzaWRlY2FyIHJ1bm5lciBjb3B5ICgke1JVTk5FUl9QQVRIfSk6IGAgK1xuICAgICAgICAgIChzdGRlcnIgfHwgU3RyaW5nKGVycikpLFxuICAgICAgKTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIFJVTk5FUl9QQVRIO1xufVxuXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIFdvcmtlciBsaWZlY3ljbGVcbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG5pbnRlcmZhY2UgUGVuZGluZ1JlcXVlc3Qge1xuICByZXNvbHZlOiAodmFsdWU6IHVua25vd24pID0+IHZvaWQ7XG4gIHJlamVjdDogKGVycjogRXJyb3IpID0+IHZvaWQ7XG59XG5cbmxldCB3b3JrZXI6IENoaWxkUHJvY2Vzc1dpdGhvdXROdWxsU3RyZWFtcyB8IG51bGwgPSBudWxsO1xubGV0IG5leHRJZCA9IDE7XG5jb25zdCBwZW5kaW5nID0gbmV3IE1hcDxudW1iZXIsIFBlbmRpbmdSZXF1ZXN0PigpO1xuXG5mdW5jdGlvbiBzcGF3bldvcmtlcigpOiBDaGlsZFByb2Nlc3NXaXRob3V0TnVsbFN0cmVhbXMge1xuICBjb25zdCBydW5uZXIgPSBlbnN1cmVSdW5uZXIoKTtcbiAgY29uc3QgY2hpbGQgPSBzcGF3bihydW5uZXIsIFtXT1JLRVJfUEFUSF0sIHtcbiAgICBjd2Q6IHBsdWdpblJvb3QoKSxcbiAgICBzdGRpbzogW1wicGlwZVwiLCBcInBpcGVcIiwgXCJwaXBlXCJdLFxuICB9KTtcblxuICBjaGlsZC5vbihcImV4aXRcIiwgKCkgPT4ge1xuICAgIC8vIFJlamVjdCBhbGwgaW4tZmxpZ2h0IHJlcXVlc3RzIGFuZCBkcm9wIHRoZSB3b3JrZXIgc28gdGhlIG5leHRcbiAgICAvLyBkZXRlY3Rpb24gc3Bhd25zIGEgZnJlc2ggb25lLlxuICAgIGZvciAoY29uc3QgcCBvZiBwZW5kaW5nLnZhbHVlcygpKSB7XG4gICAgICBwLnJlamVjdChuZXcgRXJyb3IoXCJzaWRlY2FyIHdvcmtlciBleGl0ZWQgdW5leHBlY3RlZGx5XCIpKTtcbiAgICB9XG4gICAgcGVuZGluZy5jbGVhcigpO1xuICAgIHdvcmtlciA9IG51bGw7XG4gIH0pO1xuXG4gIC8vIFdvcmtlciBzdGRlcnIgXHUyMTkyIHBsdWdpbiBzdGRlcnIgKHNob3dzIHVwIGluIHRoZSBsbXMgZGV2IHRlcm1pbmFsKVxuICBjaGlsZC5zdGRlcnIub24oXCJkYXRhXCIsIGNodW5rID0+IHtcbiAgICBwcm9jZXNzLnN0ZGVyci53cml0ZShjaHVuayk7XG4gIH0pO1xuXG4gIGxldCBvdXRCdWYgPSBcIlwiO1xuICBjaGlsZC5zdGRvdXQuc2V0RW5jb2RpbmcoXCJ1dGY4XCIpO1xuICBjaGlsZC5zdGRvdXQub24oXCJkYXRhXCIsIGNodW5rID0+IHtcbiAgICBvdXRCdWYgKz0gY2h1bms7XG4gICAgbGV0IGlkeDtcbiAgICB3aGlsZSAoKGlkeCA9IG91dEJ1Zi5pbmRleE9mKFwiXFxuXCIpKSAhPT0gLTEpIHtcbiAgICAgIGNvbnN0IGxpbmUgPSBvdXRCdWYuc2xpY2UoMCwgaWR4KTtcbiAgICAgIG91dEJ1ZiA9IG91dEJ1Zi5zbGljZShpZHggKyAxKTtcbiAgICAgIGlmIChsaW5lLnRyaW0oKSA9PT0gXCJcIikgY29udGludWU7XG4gICAgICBoYW5kbGVXb3JrZXJNZXNzYWdlKGxpbmUpO1xuICAgIH1cbiAgfSk7XG5cbiAgcmV0dXJuIGNoaWxkO1xufVxuXG5mdW5jdGlvbiBoYW5kbGVXb3JrZXJNZXNzYWdlKGxpbmU6IHN0cmluZyk6IHZvaWQge1xuICBsZXQgbXNnOiB7XG4gICAgdHlwZTogc3RyaW5nO1xuICAgIGlkOiBudW1iZXIgfCBudWxsO1xuICAgIHNwYW5zPzogUmF3U3BhbltdO1xuICAgIG1lc3NhZ2U/OiBzdHJpbmc7XG4gIH07XG4gIHRyeSB7XG4gICAgbXNnID0gSlNPTi5wYXJzZShsaW5lKTtcbiAgfSBjYXRjaCB7XG4gICAgcHJvY2Vzcy5zdGRlcnIud3JpdGUoYFtwaWktcmVkYWN0XSBzaWRlY2FyIHNlbnQgaW52YWxpZCBKU09OOiAke2xpbmV9XFxuYCk7XG4gICAgcmV0dXJuO1xuICB9XG4gIGlmIChtc2cuaWQgPT09IG51bGwgfHwgbXNnLmlkID09PSB1bmRlZmluZWQpIHtcbiAgICBwcm9jZXNzLnN0ZGVyci53cml0ZShgW3BpaS1yZWRhY3RdIHNpZGVjYXIgZXJyb3I6ICR7bXNnLm1lc3NhZ2UgPz8gXCJ1bmtub3duXCJ9XFxuYCk7XG4gICAgcmV0dXJuO1xuICB9XG4gIGNvbnN0IHAgPSBwZW5kaW5nLmdldChtc2cuaWQpO1xuICBpZiAocCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgLy8gTGF0ZSByZXNwb25zZSAoZS5nLiBhZnRlciBhbiBhYm9ydCkgXHUyMDE0IGlnbm9yZVxuICAgIHJldHVybjtcbiAgfVxuICBwZW5kaW5nLmRlbGV0ZShtc2cuaWQpO1xuICBpZiAobXNnLnR5cGUgPT09IFwicmVzdWx0XCIgJiYgbXNnLnNwYW5zICE9PSB1bmRlZmluZWQpIHtcbiAgICBwLnJlc29sdmUobXNnLnNwYW5zKTtcbiAgfSBlbHNlIGlmIChtc2cudHlwZSA9PT0gXCJyZWFkeVwiKSB7XG4gICAgcC5yZXNvbHZlKHVuZGVmaW5lZCk7XG4gIH0gZWxzZSB7XG4gICAgcC5yZWplY3QobmV3IEVycm9yKG1zZy5tZXNzYWdlID8/IFwic2lkZWNhciByZXF1ZXN0IGZhaWxlZFwiKSk7XG4gIH1cbn1cblxuZnVuY3Rpb24gZ2V0V29ya2VyKCk6IENoaWxkUHJvY2Vzc1dpdGhvdXROdWxsU3RyZWFtcyB7XG4gIGlmICh3b3JrZXIgPT09IG51bGwpIHtcbiAgICB3b3JrZXIgPSBzcGF3bldvcmtlcigpO1xuICB9XG4gIHJldHVybiB3b3JrZXI7XG59XG5cbmZ1bmN0aW9uIHJlcXVlc3QodHlwZTogXCJ3YXJtdXBcIiB8IFwiZGV0ZWN0XCIsIHRleHQ/OiBzdHJpbmcpOiBQcm9taXNlPHVua25vd24+IHtcbiAgY29uc3QgY2hpbGQgPSBnZXRXb3JrZXIoKTtcbiAgY29uc3QgaWQgPSBuZXh0SWQrKztcbiAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICBwZW5kaW5nLnNldChpZCwgeyByZXNvbHZlLCByZWplY3QgfSk7XG4gICAgY2hpbGQuc3RkaW4ud3JpdGUoSlNPTi5zdHJpbmdpZnkoeyB0eXBlLCBpZCwgdGV4dCB9KSArIFwiXFxuXCIpO1xuICB9KTtcbn1cblxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4vLyBQdWJsaWMgQVBJXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuLyoqXG4gKiBEZXRlY3QgUElJIHZpYSB0aGUgc2lkZWNhciB3b3JrZXIuIFJldHVybnMgc3BhbnMgaW4gZG9jdW1lbnQgb3JkZXIsIHVzaW5nXG4gKiBSZWRhY3QncyBvd24gbGFiZWxzLlxuICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGV0ZWN0VmlhU2lkZWNhcih0ZXh0OiBzdHJpbmcpOiBQcm9taXNlPFJhd1NwYW5bXT4ge1xuICByZXR1cm4gKGF3YWl0IHJlcXVlc3QoXCJkZXRlY3RcIiwgdGV4dCkpIGFzIFJhd1NwYW5bXTtcbn1cblxuLyoqXG4gKiBXYXJtIHVwIHRoZSBzaWRlY2FyOiBzcGF3biB0aGUgd29ya2VyIGFuZCB0cmlnZ2VyIHRoZSBSZWRhY3QgbW9kZWwgbG9hZFxuICogKHdlaWdodHMgZG93bmxvYWQgb24gZmlyc3QgdXNlKS4gQ2FsbGVkIGZpcmUtYW5kLWZvcmdldCBmcm9tIG1haW4oKSBzbyB0aGVcbiAqIGZpcnN0IHByZXByb2Nlc3NvciByZXF1ZXN0IGRvZXMgbm90IHBheSB0aGUgc3RhcnR1cCBjb3N0LlxuICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gd2FybVNpZGVjYXIoKTogUHJvbWlzZTx2b2lkPiB7XG4gIGF3YWl0IHJlcXVlc3QoXCJ3YXJtdXBcIik7XG59XG4iLCAiaW1wb3J0IHsgeiB9IGZyb20gXCJ6b2RcIjtcbmltcG9ydCB7IEFMTF9MQUJFTFMsIHR5cGUgUmVkYWN0TGFiZWwgfSBmcm9tIFwiQGRlc2VydC1hbnQtbGFicy9yZWRhY3QvbmF0aXZlXCI7XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gUElJIGVudGl0eSB0eXBlcyBcdTIwMTQgUmVkYWN0J3MgbGFiZWxzLCBzaGFyZWQgYnkgYm90aCBkZXRlY3Rpb24gZW5naW5lc1xuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbi8qKlxuICogVGhlIFBJSSBjYXRlZ29yaWVzIHVzZWQgdGhyb3VnaG91dCB0aGUgcGx1Z2luLiBUYWtlbiBkaXJlY3RseSBmcm9tIHRoZVxuICogRGVzZXJ0IEFudCBSZWRhY3QgbW9kZWwgc28gcGxhY2Vob2xkZXJzIGFyZSBjb25zaXN0ZW50IHJlZ2FyZGxlc3Mgb2ZcbiAqIHdoZXRoZXIgdGhlIG9uLWRldmljZSBSZWRhY3QgbW9kZWwgb3IgYW4gTExNIHBlcmZvcm1lZCB0aGUgZGV0ZWN0aW9uLlxuICovXG5leHBvcnQgY29uc3QgUElJX1RZUEVTID0gQUxMX0xBQkVMUztcbmV4cG9ydCB0eXBlIFBpaVR5cGUgPSBSZWRhY3RMYWJlbDtcblxuLyoqIEEgc2luZ2xlIGRldGVjdGVkIFBJSSBlbnRpdHkgcmV0dXJuZWQgYnkgdGhlIGRldGVjdG9yLiAqL1xuZXhwb3J0IGludGVyZmFjZSBQaWlFbnRpdHkge1xuICAvKiogVW5pcXVlIHBsYWNlaG9sZGVyIGlkZW50aWZpZXIsIGUuZy4gXCJFTUFJTF8xXCIgKi9cbiAgaWRlbnRpZmllcjogc3RyaW5nO1xuICAvKiogU2VtYW50aWMgY2F0ZWdvcnkgb2YgdGhlIGVudGl0eSAqL1xuICB0eXBlOiBQaWlUeXBlO1xuICAvKiogVGhlIG9yaWdpbmFsIHRleHQgdGhhdCB3YXMgcmVkYWN0ZWQgKi9cbiAgb3JpZ2luYWw6IHN0cmluZztcbn1cblxuLyoqIEEgcmF3IGRldGVjdGlvbiBzcGFuLCBiZWZvcmUgaWRlbnRpZmllciBhc3NpZ25tZW50LiAqL1xuZXhwb3J0IGludGVyZmFjZSBSYXdTcGFuIHtcbiAgb3JpZ2luYWw6IHN0cmluZztcbiAgdHlwZTogUGlpVHlwZTtcbn1cblxuLyoqIFRoZSBzdHJ1Y3R1cmVkIG91dHB1dCBwcm9kdWNlZCBhZnRlciByZWRhY3RpbmcgYSBwcm9tcHQuICovXG5leHBvcnQgaW50ZXJmYWNlIFJlZGFjdGlvblJlc3VsdCB7XG4gIHJlZGFjdGVkX3RleHQ6IHN0cmluZztcbiAgZW50aXRpZXM6IFBpaUVudGl0eVtdO1xufVxuXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIFpvZCBzY2hlbWFzIFx1MjAxNCB1c2VkIGJvdGggZm9yIHN0cnVjdHVyZWQgTExNIG91dHB1dCBhbmQgZm9yIHZhbGlkYXRpb25cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG5leHBvcnQgY29uc3QgcGlpVHlwZVNjaGVtYSA9IHouZW51bShbLi4uUElJX1RZUEVTXSBhcyBbUGlpVHlwZSwgLi4uUGlpVHlwZVtdXSk7XG5cbmV4cG9ydCBjb25zdCBwaWlFbnRpdHlTY2hlbWEgPSB6Lm9iamVjdCh7XG4gIC8qKiBUaGUgcmF3IHRleHQgc3BhbiBmb3VuZCBpbiB0aGUgcHJvbXB0ICovXG4gIG9yaWdpbmFsOiB6LnN0cmluZygpLm1pbigxKSxcbiAgLyoqIFNlbWFudGljIGNhdGVnb3J5ICovXG4gIHR5cGU6IHBpaVR5cGVTY2hlbWEsXG59KTtcblxuLyoqXG4gKiBTY2hlbWEgZm9yIHRoZSByYXcgTExNIHJlc3BvbnNlLlxuICogVGhlIExMTSBvbmx5IHJldHVybnMgKG9yaWdpbmFsLCB0eXBlKSBwYWlycyBcdTIwMTQgaWRlbnRpZmllcnMgYXJlIGFzc2lnbmVkXG4gKiBkZXRlcm1pbmlzdGljYWxseSBieSB0aGUgcmVkYWN0b3IgYWZ0ZXIgZGVkdXBsaWNhdGlvbi5cbiAqL1xuZXhwb3J0IGNvbnN0IGxsbURldGVjdGlvblJlc3BvbnNlU2NoZW1hID0gei5vYmplY3Qoe1xuICBlbnRpdGllczogei5hcnJheShwaWlFbnRpdHlTY2hlbWEpLFxufSk7XG5cbmV4cG9ydCB0eXBlIExsbURldGVjdGlvblJlc3BvbnNlID0gei5pbmZlcjx0eXBlb2YgbGxtRGV0ZWN0aW9uUmVzcG9uc2VTY2hlbWE+O1xuXG4vKiogRnVsbCByZWRhY3Rpb24gcmVzdWx0IHNjaGVtYSAodXNlZCBmb3IgZmluYWwgdmFsaWRhdGlvbikuICovXG5leHBvcnQgY29uc3QgcmVkYWN0aW9uUmVzdWx0U2NoZW1hID0gei5vYmplY3Qoe1xuICByZWRhY3RlZF90ZXh0OiB6LnN0cmluZygpLFxuICBlbnRpdGllczogei5hcnJheShcbiAgICB6Lm9iamVjdCh7XG4gICAgICAvLyBMYWJlbHMgbWF5IGNvbnRhaW4gdW5kZXJzY29yZXMgKGUuZy4gXCJHSVZFTl9OQU1FXzFcIiksIHNvIHRoZSB0eXBlXG4gICAgICAvLyBwYXJ0IGlzIG1hdGNoZWQgd2l0aCBbQS1aX10rIGFuZCB0aGUgdHJhaWxpbmcgY291bnRlciB3aXRoIF9cXGQrLlxuICAgICAgaWRlbnRpZmllcjogei5zdHJpbmcoKS5yZWdleCgvXltBLVpfXStfXFxkKyQvKSxcbiAgICAgIHR5cGU6IHBpaVR5cGVTY2hlbWEsXG4gICAgICBvcmlnaW5hbDogei5zdHJpbmcoKS5taW4oMSksXG4gICAgfSksXG4gICksXG59KTtcblxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4vLyBDb25maXJtYXRpb24gc2VudGluZWxcbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4vKiogU3VmZml4IHRoZSB1c2VyIGFwcGVuZHMgdG8gY29uZmlybSB0aGV5IGFjY2VwdCB0aGUgcmVkYWN0ZWQgcHJvbXB0LiAqL1xuZXhwb3J0IGNvbnN0IENPTkZJUk1fU1VGRklYID0gXCItLWNcIjtcbiIsICJpbXBvcnQgdHlwZSB7IExMTUR5bmFtaWNIYW5kbGUgfSBmcm9tIFwiQGxtc3R1ZGlvL3Nka1wiO1xuaW1wb3J0IHsgeiB9IGZyb20gXCJ6b2RcIjtcbmltcG9ydCB7IEFMTF9MQUJFTFMsIFJlZGFjdCB9IGZyb20gXCJAZGVzZXJ0LWFudC1sYWJzL3JlZGFjdC9uYXRpdmVcIjtcbmltcG9ydCB7IGRldGVjdFZpYVNpZGVjYXIsIHdhcm1TaWRlY2FyIH0gZnJvbSBcIi4vc2lkZWNhclwiO1xuaW1wb3J0IHtcbiAgbGxtRGV0ZWN0aW9uUmVzcG9uc2VTY2hlbWEsXG4gIHR5cGUgTGxtRGV0ZWN0aW9uUmVzcG9uc2UsXG4gIHR5cGUgUGlpVHlwZSxcbiAgdHlwZSBSYXdTcGFuLFxufSBmcm9tIFwiLi90eXBlc1wiO1xuXG4vKiogRXZlcnkgUmVkYWN0IGxhYmVsLCBpbmNsdWRpbmcgT1JHIFx1MjAxNCB0aGUgcGx1Z2luIHJlZGFjdHMgb3JnYW5pc2F0aW9ucyB0b28uICovXG5jb25zdCBBTExfTEFCRUxTX1NFVCA9IG5ldyBTZXQoQUxMX0xBQkVMUyk7XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gU3lzdGVtIHByb21wdFxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbmNvbnN0IFNZU1RFTV9QUk9NUFQgPSBgWW91IGFyZSBhIHByaXZhY3ktZm9jdXNlZCBQSUkgKFBlcnNvbmFsbHkgSWRlbnRpZmlhYmxlIEluZm9ybWF0aW9uKSBkZXRlY3Rvci5cblxuWW91ciB0YXNrOiBhbmFseXNlIHRoZSB1c2VyJ3MgdGV4dCBhbmQgcmV0dXJuIGEgSlNPTiBvYmplY3QgbGlzdGluZyBldmVyeSBQSUkgZW50aXR5IGZvdW5kLlxuXG5SdWxlczpcbjEuIERldGVjdCB0aGUgZm9sbG93aW5nIGVudGl0eSB0eXBlczpcbiAgIC0gR0lWRU5fTkFNRSAgICAgICAgXHUyMDE0IGZpcnN0IG5hbWVzLCBnaXZlbiBuYW1lc1xuICAgLSBTVVJOQU1FICAgICAgICAgICBcdTIwMTQgbGFzdCBuYW1lcywgZmFtaWx5IG5hbWVzXG4gICAtIFNUUkVFVF9OQU1FICAgICAgIFx1MjAxNCBzdHJlZXQgbmFtZXNcbiAgIC0gQlVJTERJTkdfTlVNQkVSICAgXHUyMDE0IGhvdXNlIG9yIGJ1aWxkaW5nIG51bWJlcnNcbiAgIC0gU0VDT05EQVJZX0FERFJFU1MgXHUyMDE0IGFwYXJ0bWVudCwgc3VpdGUsIGZsb29yLCBQTyBib3hcbiAgIC0gQ0lUWSAgICAgICAgICAgICAgXHUyMDE0IGNpdGllcyBhbmQgdG93bnNcbiAgIC0gU1RBVEUgICAgICAgICAgICAgXHUyMDE0IHN0YXRlcywgcHJvdmluY2VzLCByZWdpb25zXG4gICAtIFpJUF9DT0RFICAgICAgICAgIFx1MjAxNCBwb3N0YWwgY29kZXNcbiAgIC0gRU1BSUwgICAgICAgICAgICAgXHUyMDE0IGVtYWlsIGFkZHJlc3Nlc1xuICAgLSBQSE9ORSAgICAgICAgICAgICBcdTIwMTQgcGhvbmUgbnVtYmVycyAoYW55IGZvcm1hdClcbiAgIC0gQ1JFRElUX0NBUkQgICAgICAgXHUyMDE0IGNyZWRpdCBjYXJkIG51bWJlcnNcbiAgIC0gQkFOS19BQ0NPVU5UICAgICAgXHUyMDE0IGJhbmsgYWNjb3VudCBudW1iZXJzLCBJQkFOc1xuICAgLSBST1VUSU5HX05VTUJFUiAgICBcdTIwMTQgYmFuayByb3V0aW5nIG51bWJlcnNcbiAgIC0gSVBfQUREUkVTUyAgICAgICAgXHUyMDE0IElQIGFkZHJlc3Nlc1xuICAgLSBVUkwgICAgICAgICAgICAgICBcdTIwMTQgVVJMc1xuICAgLSBHT1ZFUk5NRU5UX0lEICAgICBcdTIwMTQgbmF0aW9uYWwgSUQgbnVtYmVyc1xuICAgLSBQQVNTUE9SVCAgICAgICAgICBcdTIwMTQgcGFzc3BvcnQgbnVtYmVyc1xuICAgLSBEUklWRVJTX0xJQ0VOU0UgICBcdTIwMTQgZHJpdmVyJ3MgbGljZW5zZSBudW1iZXJzXG4gICAtIFRBWF9JRCAgICAgICAgICAgIFx1MjAxNCB0YXggaWRlbnRpZmljYXRpb24gbnVtYmVyc1xuICAgLSBTU04gICAgICAgICAgICAgICBcdTIwMTQgc29jaWFsIHNlY3VyaXR5IG51bWJlcnNcbiAgIC0gSU1FSSAgICAgICAgICAgICAgXHUyMDE0IGRldmljZSBpZGVudGlmaWVyc1xuICAgLSBPUkcgICAgICAgICAgICAgICBcdTIwMTQgY29tcGFueSwgb3JnYW5pc2F0aW9uLCBpbnN0aXR1dGlvbiBuYW1lc1xuXG4yLiBGb3IgZWFjaCBlbnRpdHkgcmV0dXJuIHRoZSBFWEFDVCBzdWJzdHJpbmcgYXMgaXQgYXBwZWFycyBpbiB0aGUgdGV4dCAocHJlc2VydmUgY2FzZSBhbmQgc3BhY2luZykuXG5cbjMuIERvIE5PVCBpbnZlbnQgZW50aXRpZXMuIE9ubHkgcmV0dXJuIGVudGl0aWVzIHRoYXQgYXJlIGFjdHVhbGx5IHByZXNlbnQgaW4gdGhlIHRleHQuXG5cbjQuIFJldHVybiBPTkxZIHZhbGlkIEpTT04gbWF0Y2hpbmcgdGhpcyBzY2hlbWEgXHUyMDE0IG5vIG1hcmtkb3duLCBubyBleHRyYSBrZXlzOlxue1xuICBcImVudGl0aWVzXCI6IFtcbiAgICB7IFwib3JpZ2luYWxcIjogXCI8ZXhhY3QgdGV4dCBzcGFuPlwiLCBcInR5cGVcIjogXCI8VFlQRT5cIiB9LFxuICAgIC4uLlxuICBdXG59XG5cbklmIG5vIFBJSSBpcyBmb3VuZCwgcmV0dXJuOiB7IFwiZW50aXRpZXNcIjogW10gfWA7XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gUmVkYWN0LWJhc2VkIGRldGVjdG9yIChvbi1kZXZpY2UgbW9kZWwpXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuLyoqIExhemlseS1sb2FkZWQgUmVkYWN0IGluc3RhbmNlIFx1MjAxNCB0aGUgbW9kZWwgZG93bmxvYWRzIG9uIGZpcnN0IHVzZSBhbmQgY2FjaGVzLiAqL1xubGV0IHJlZGFjdEluc3RhbmNlOiBSZWRhY3QgfCBudWxsID0gbnVsbDtcbmxldCByZWRhY3RMb2FkUHJvbWlzZTogUHJvbWlzZTxSZWRhY3Q+IHwgbnVsbCA9IG51bGw7XG5cbi8qKlxuICogV2hldGhlciBkZXRlY3Rpb24gaXMgcm91dGVkIHRocm91Z2ggdGhlIHNpZGVjYXIgd29ya2VyLiBTZXQgb25jZSB0aGVcbiAqIGluLXByb2Nlc3MgbG9hZCBmYWlscyB3aXRoIGEgbWFjT1MgbGlicmFyeS12YWxpZGF0aW9uIGVycm9yIFx1MjAxNCB0aGUgc2lkZWNhclxuICogaXMgdGhlbiB1c2VkIGZvciB0aGUgbGlmZXRpbWUgb2YgdGhlIHBsdWdpbi5cbiAqL1xubGV0IHVzZVNpZGVjYXIgPSBmYWxzZTtcblxuLyoqXG4gKiBMb2FkIHRoZSBSZWRhY3QgbW9kZWwgb25jZSBhbmQgcmV1c2UgaXQgZm9yIHRoZSBsaWZldGltZSBvZiB0aGUgcGx1Z2luLlxuICogV2VpZ2h0cyBkb3dubG9hZCBmcm9tIEh1Z2dpbmcgRmFjZSBvbiBmaXJzdCB1c2UgYW5kIGFyZSBjYWNoZWQgbG9jYWxseS5cbiAqL1xuYXN5bmMgZnVuY3Rpb24gZ2V0UmVkYWN0KCk6IFByb21pc2U8UmVkYWN0PiB7XG4gIGlmIChyZWRhY3RJbnN0YW5jZSAhPT0gbnVsbCkge1xuICAgIHJldHVybiByZWRhY3RJbnN0YW5jZTtcbiAgfVxuICBpZiAocmVkYWN0TG9hZFByb21pc2UgPT09IG51bGwpIHtcbiAgICByZWRhY3RMb2FkUHJvbWlzZSA9IFJlZGFjdC5sb2FkKCkudGhlbihpbnN0YW5jZSA9PiB7XG4gICAgICByZWRhY3RJbnN0YW5jZSA9IGluc3RhbmNlO1xuICAgICAgcmV0dXJuIGluc3RhbmNlO1xuICAgIH0pO1xuICAgIC8vIE9uIGZhaWx1cmUsIGNsZWFyIHRoZSBjYWNoZWQgcHJvbWlzZSBzbyBhIGxhdGVyIGNhbGwgY2FuIHJldHJ5IHRoZVxuICAgIC8vIGxvYWQgKGUuZy4gYWZ0ZXIgYSB0cmFuc2llbnQgbmV0d29yayBlcnJvciBkdXJpbmcgdGhlIGZpcnN0LXVzZVxuICAgIC8vIHdlaWdodHMgZG93bmxvYWQpLlxuICAgIHJlZGFjdExvYWRQcm9taXNlLmNhdGNoKCgpID0+IHtcbiAgICAgIHJlZGFjdExvYWRQcm9taXNlID0gbnVsbDtcbiAgICB9KTtcbiAgfVxuICByZXR1cm4gcmVkYWN0TG9hZFByb21pc2U7XG59XG5cbi8qKlxuICogS2ljayBvZmYgdGhlIFJlZGFjdCBtb2RlbCBsb2FkIGF0IHBsdWdpbiBzdGFydHVwLiBDYWxsZWQgZmlyZS1hbmQtZm9yZ2V0XG4gKiBmcm9tIG1haW4oKSBzbyB0aGUgZmlyc3QtdXNlIHdlaWdodHMgZG93bmxvYWQgZG9lcyBub3QgYmxvY2sgdGhlIGZpcnN0XG4gKiBwcmVwcm9jZXNzb3IgcmVxdWVzdC4gRXJyb3JzIGFyZSBoYW5kbGVkIGJ5IHRoZSBjYWxsZXIuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBwcmVsb2FkUmVkYWN0KCk6IFByb21pc2U8dm9pZD4ge1xuICBpZiAoIXVzZVNpZGVjYXIpIHtcbiAgICB0cnkge1xuICAgICAgYXdhaXQgZ2V0UmVkYWN0KCk7XG4gICAgICByZXR1cm47XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICBpZiAoaXNEbG9wZW5FcnJvcihlcnIpKSB7XG4gICAgICAgIHVzZVNpZGVjYXIgPSB0cnVlO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhyb3cgZXJyO1xuICAgICAgfVxuICAgIH1cbiAgfVxuICBhd2FpdCB3YXJtU2lkZWNhcigpO1xufVxuXG4vKipcbiAqIERldGVjdCBQSUkgdXNpbmcgdGhlIG9uLWRldmljZSBSZWRhY3QgbW9kZWwuXG4gKiBSZXR1cm5zIHNwYW5zIGluIGRvY3VtZW50IG9yZGVyLCB1c2luZyBSZWRhY3QncyBvd24gbGFiZWxzLlxuICpcbiAqIFRyaWVzIHRoZSBpbi1wcm9jZXNzIHBhdGggZmlyc3QuIE9uIG1hY09TLCBMTSBTdHVkaW8ncyBwbHVnaW4gcnVubmVyXG4gKiBlbmZvcmNlcyBsaWJyYXJ5IHZhbGlkYXRpb24sIHNvIHRoZSBuYXRpdmUgY29yZSAoa29mZmkpIGNhbm5vdCBiZSBsb2FkZWRcbiAqIGluLXByb2Nlc3MgKGxtc3R1ZGlvLWJ1Zy10cmFja2VyIzE0OTQpIFx1MjAxNCBpbiB0aGF0IGNhc2UgZGV0ZWN0aW9uIGZhbGxzIGJhY2tcbiAqIHRvIHRoZSBzaWRlY2FyIHdvcmtlciBydW5uaW5nIHVuZGVyIGEgcmUtc2lnbmVkIGNvcHkgb2YgdGhlIHJ1bm5lciBiaW5hcnkuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiByZWRhY3REZXRlY3QodGV4dDogc3RyaW5nKTogUHJvbWlzZTxSYXdTcGFuW10+IHtcbiAgaWYgKCF1c2VTaWRlY2FyKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHJlZGFjdCA9IGF3YWl0IGdldFJlZGFjdCgpO1xuICAgICAgLy8gQUxMX0xBQkVMUyBpbmNsdWRlcyBPUkcgXHUyMDE0IHRoZSBwbHVnaW4gcmVkYWN0cyBvcmdhbmlzYXRpb25zIGFzIHdlbGwuXG4gICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCByZWRhY3QucmVkYWN0aW9uKHRleHQsIHsgbGFiZWxzOiBbLi4uQUxMX0xBQkVMU19TRVRdIH0pO1xuICAgICAgcmV0dXJuIHJlc3VsdC5pdGVtcy5tYXAoaXRlbSA9PiAoe1xuICAgICAgICBvcmlnaW5hbDogaXRlbS5vcmlnaW5hbCxcbiAgICAgICAgdHlwZTogaXRlbS5sYWJlbCBhcyBQaWlUeXBlLFxuICAgICAgfSkpO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgaWYgKGlzRGxvcGVuRXJyb3IoZXJyKSkge1xuICAgICAgICB1c2VTaWRlY2FyID0gdHJ1ZTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRocm93IGVycjtcbiAgICAgIH1cbiAgICB9XG4gIH1cbiAgcmV0dXJuIGRldGVjdFZpYVNpZGVjYXIodGV4dCk7XG59XG5cbi8qKlxuICogUmVjb2duaXNlIHRoZSBtYWNPUyBsaWJyYXJ5LXZhbGlkYXRpb24gZmFpbHVyZTogdGhlIHBsdWdpbiBydW5uZXIgcmVmdXNlc1xuICogdG8gZGxvcGVuIG5hdGl2ZSBhZGRvbnMgc2lnbmVkIHdpdGggYSBkaWZmZXJlbnQgVGVhbSBJRC5cbiAqL1xuZnVuY3Rpb24gaXNEbG9wZW5FcnJvcihlcnI6IHVua25vd24pOiBib29sZWFuIHtcbiAgY29uc3QgbWVzc2FnZSA9IGVyciBpbnN0YW5jZW9mIEVycm9yID8gZXJyLm1lc3NhZ2UgOiBTdHJpbmcoZXJyKTtcbiAgcmV0dXJuIChcbiAgICAoZXJyIGFzIE5vZGVKUy5FcnJub0V4Y2VwdGlvbik/LmNvZGUgPT09IFwiRVJSX0RMT1BFTl9GQUlMRURcIiB8fFxuICAgIG1lc3NhZ2UuaW5jbHVkZXMoXCJkaWZmZXJlbnQgVGVhbSBJRHNcIikgfHxcbiAgICBtZXNzYWdlLmluY2x1ZGVzKFwiY29kZSBzaWduYXR1cmVcIilcbiAgKTtcbn1cblxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4vLyBSZWdleCBmYWxsYmFjayBwYXR0ZXJuc1xuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbmNvbnN0IEVNQUlMX1JFR0VYID0gL1tcXHcuK1xcLV0rQFtcXHdcXC1dK1xcLlthLXpBLVpdezIsfS9nO1xuXG4vLyBDb3ZlcnMgaW50ZXJuYXRpb25hbCBhbmQgbG9jYWwgZm9ybWF0czogKzEgKDU1NSkgMTIzLTQ1NjcsIDA3OTExIDEyMyA0NTY3LlxuY29uc3QgUEhPTkVfUkVHRVggPVxuICAvKD86XFwrP1xcZHsxLDN9W1xcc1xcLS5dPyk/XFwoP1xcZHsxLDR9XFwpP1tcXHNcXC0uXT9cXGR7MSw0fVtcXHNcXC0uXT9cXGR7MSw0fSg/OltcXHNcXC0uXT9cXGR7MSw0fSkqL2c7XG5cbi8vIE1pbmltdW0gZGlnaXQgY291bnQgdG8gYXZvaWQgbWF0Y2hpbmcgbG9uZSBudW1iZXJzIGxpa2UgXCI0MlwiXG5jb25zdCBNSU5fUEhPTkVfRElHSVRTID0gNztcblxuZnVuY3Rpb24gY291bnREaWdpdHMoczogc3RyaW5nKTogbnVtYmVyIHtcbiAgcmV0dXJuIChzLm1hdGNoKC9cXGQvZykgPz8gW10pLmxlbmd0aDtcbn1cblxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4vLyBSZWdleC1iYXNlZCBmYWxsYmFjayBkZXRlY3RvclxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbi8qKlxuICogRXh0cmFjdCBFTUFJTCBhbmQgUEhPTkUgZW50aXRpZXMgZnJvbSB0ZXh0IHVzaW5nIHJlZ2V4LlxuICogUmV0dXJucyBzcGFucyBpbiBvcmRlciBvZiBmaXJzdCBhcHBlYXJhbmNlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gcmVnZXhEZXRlY3QodGV4dDogc3RyaW5nKTogUmF3U3BhbltdIHtcbiAgY29uc3Qgc3BhbnM6IFJhd1NwYW5bXSA9IFtdO1xuICBjb25zdCBzZWVuID0gbmV3IFNldDxzdHJpbmc+KCk7XG5cbiAgZm9yIChjb25zdCBtYXRjaCBvZiB0ZXh0Lm1hdGNoQWxsKEVNQUlMX1JFR0VYKSkge1xuICAgIGNvbnN0IG9yaWdpbmFsID0gbWF0Y2hbMF07XG4gICAgaWYgKCFzZWVuLmhhcyhvcmlnaW5hbCkpIHtcbiAgICAgIHNlZW4uYWRkKG9yaWdpbmFsKTtcbiAgICAgIHNwYW5zLnB1c2goeyBvcmlnaW5hbCwgdHlwZTogXCJFTUFJTFwiIH0pO1xuICAgIH1cbiAgfVxuXG4gIGZvciAoY29uc3QgbWF0Y2ggb2YgdGV4dC5tYXRjaEFsbChQSE9ORV9SRUdFWCkpIHtcbiAgICBjb25zdCBvcmlnaW5hbCA9IG1hdGNoWzBdLnRyaW0oKTtcbiAgICBpZiAoY291bnREaWdpdHMob3JpZ2luYWwpID49IE1JTl9QSE9ORV9ESUdJVFMgJiYgIXNlZW4uaGFzKG9yaWdpbmFsKSkge1xuICAgICAgc2Vlbi5hZGQob3JpZ2luYWwpO1xuICAgICAgc3BhbnMucHVzaCh7IG9yaWdpbmFsLCB0eXBlOiBcIlBIT05FXCIgfSk7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIHNwYW5zO1xufVxuXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIExMTS1iYXNlZCBkZXRlY3RvclxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbi8qKlxuICogQXNrIHRoZSBtb2RlbCB0byBkZXRlY3QgUElJIGluIGB0ZXh0YC5cbiAqIFJldHVybnMgYSBwYXJzZWQsIHZhbGlkYXRlZCBgTGxtRGV0ZWN0aW9uUmVzcG9uc2VgIG9yIHRocm93cyBvbiBmYWlsdXJlLlxuICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gbGxtRGV0ZWN0KFxuICBtb2RlbDogTExNRHluYW1pY0hhbmRsZSxcbiAgdGV4dDogc3RyaW5nLFxuICBhYm9ydFNpZ25hbDogQWJvcnRTaWduYWwsXG4pOiBQcm9taXNlPExsbURldGVjdGlvblJlc3BvbnNlPiB7XG4gIGNvbnN0IHJlc3VsdCA9IGF3YWl0IG1vZGVsLnJlc3BvbmQoXG4gICAgW1xuICAgICAgeyByb2xlOiBcInN5c3RlbVwiLCBjb250ZW50OiBTWVNURU1fUFJPTVBUIH0sXG4gICAgICB7IHJvbGU6IFwidXNlclwiLCBjb250ZW50OiB0ZXh0IH0sXG4gICAgXSxcbiAgICB7XG4gICAgICBzdHJ1Y3R1cmVkOiBsbG1EZXRlY3Rpb25SZXNwb25zZVNjaGVtYSxcbiAgICAgIC8vIEdlbmVyb3VzIGJ1dCBib3VuZGVkIFx1MjAxNCBwcmV2ZW50cyB0aGUgbW9kZWwgZ2V0dGluZyBzdHVjayBvbiBsYXJnZSBpbnB1dHNcbiAgICAgIG1heFRva2VuczogMjA0OCxcbiAgICAgIHRlbXBlcmF0dXJlOiAwLFxuICAgICAgc2lnbmFsOiBhYm9ydFNpZ25hbCxcbiAgICB9LFxuICApO1xuXG4gIC8vIGByZXN1bHQucGFyc2VkYCBpcyBhbHJlYWR5IHZhbGlkYXRlZCBieSB0aGUgU0RLIHdoZW4gYSB6b2Qgc2NoZW1hIGlzIHVzZWRcbiAgcmV0dXJuIHJlc3VsdC5wYXJzZWQ7XG59XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gTWVyZ2VkIGRldGVjdG9yXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuLyoqXG4gKiBSdW4gTExNIGRldGVjdGlvbiBhbmQgbWVyZ2Ugd2l0aCByZWdleCBmYWxsYmFjayByZXN1bHRzLlxuICpcbiAqIC0gTExNIHJlc3VsdHMgdGFrZSBwcmVjZWRlbmNlOyByZWdleCByZXN1bHRzIGFyZSBvbmx5IGFkZGVkIGlmIHRoZWlyXG4gKiAgIG9yaWdpbmFsIHRleHQgaXMgbm90IGFscmVhZHkgY292ZXJlZCBieSBhbiBMTE0gZW50aXR5IChjYXNlLWluc2Vuc2l0aXZlKS5cbiAqIC0gT3JkZXI6IExMTSBlbnRpdGllcyBmaXJzdCwgdGhlbiBhbnkgYWRkaXRpb25hbCByZWdleC1vbmx5IGVudGl0aWVzIGluXG4gKiAgIG9yZGVyIG9mIGFwcGVhcmFuY2UgaW4gdGhlIHRleHQuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBtZXJnZURldGVjdGlvbnMoXG4gIGxsbUVudGl0aWVzOiBMbG1EZXRlY3Rpb25SZXNwb25zZVtcImVudGl0aWVzXCJdLFxuICByZWdleFNwYW5zOiBSYXdTcGFuW10sXG4pOiBSYXdTcGFuW10ge1xuICBjb25zdCBjb3ZlcmVkID0gbmV3IFNldChsbG1FbnRpdGllcy5tYXAoZSA9PiBlLm9yaWdpbmFsLnRvTG93ZXJDYXNlKCkpKTtcbiAgY29uc3QgbWVyZ2VkOiBSYXdTcGFuW10gPSBbLi4ubGxtRW50aXRpZXNdO1xuICBmb3IgKGNvbnN0IHNwYW4gb2YgcmVnZXhTcGFucykge1xuICAgIGlmICghY292ZXJlZC5oYXMoc3Bhbi5vcmlnaW5hbC50b0xvd2VyQ2FzZSgpKSkge1xuICAgICAgY292ZXJlZC5hZGQoc3Bhbi5vcmlnaW5hbC50b0xvd2VyQ2FzZSgpKTtcbiAgICAgIG1lcmdlZC5wdXNoKHNwYW4pO1xuICAgIH1cbiAgfVxuICByZXR1cm4gbWVyZ2VkO1xufVxuXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIFpvZCBzY2hlbWEgZm9yIHN0cnVjdHVyZWQgb3V0cHV0IChyZS1leHBvcnRlZCBmb3IgdXNlIGluIHByb21wdFByZXByb2Nlc3Nvcilcbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuZXhwb3J0IHsgbGxtRGV0ZWN0aW9uUmVzcG9uc2VTY2hlbWEgfTtcbmV4cG9ydCB0eXBlIHsgTGxtRGV0ZWN0aW9uUmVzcG9uc2UgfTtcbiIsICJpbXBvcnQgeyB0eXBlIENoYXRNZXNzYWdlLCB0eXBlIFByb21wdFByZXByb2Nlc3NvckNvbnRyb2xsZXIgfSBmcm9tIFwiQGxtc3R1ZGlvL3Nka1wiO1xuaW1wb3J0IHsgZ2xvYmFsQ29uZmlnU2NoZW1hdGljcyB9IGZyb20gXCIuL2NvbmZpZ1wiO1xuaW1wb3J0IHsgYWRkRW50aXRpZXMsIGV4aXN0aW5nSWRlbnRpZmllcnMgfSBmcm9tIFwiLi9lbnRpdHlTdG9yZVwiO1xuaW1wb3J0IHsgbGxtRGV0ZWN0LCBtZXJnZURldGVjdGlvbnMsIHJlZGFjdERldGVjdCwgcmVnZXhEZXRlY3QgfSBmcm9tIFwiLi9waWlEZXRlY3RvclwiO1xuaW1wb3J0IHsgcmVkYWN0LCB2YWxpZGF0ZVBsYWNlaG9sZGVycyB9IGZyb20gXCIuL3JlZGFjdG9yXCI7XG5pbXBvcnQgeyByZWRhY3Rpb25SZXN1bHRTY2hlbWEsIENPTkZJUk1fU1VGRklYLCB0eXBlIFJlZGFjdGlvblJlc3VsdCB9IGZyb20gXCIuL3R5cGVzXCI7XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gUGVuZGluZyBjb25maXJtYXRpb24gc3RhdGVcbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4vKipcbiAqIFN0b3JlcyB0aGUgcmVkYWN0ZWQgcHJvbXB0IHdoaWxlIHdhaXRpbmcgZm9yIHRoZSB1c2VyIHRvIGNvbmZpcm0gXG4gKiB3aXRoIC0tYy4gIFRoaXMgZW5zdXJlcyB0aGF0IG9uIGNvbmZpcm1hdGlvbiB3ZSBmb3J3YXJkIHRoZSBcbiAqICpyZWRhY3RlZCogdGV4dCBcdTIwMTQgbmV2ZXIgdGhlIG9yaWdpbmFsLlxuICovXG5sZXQgcGVuZGluZ1JlZGFjdGVkUHJvbXB0OiBzdHJpbmcgfCBudWxsID0gbnVsbDtcblxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4vLyBIZWxwZXJzXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuLyoqXG4gKiBBdHRlbXB0IG9uZSByb3VuZCBvZiBkZXRlY3Rpb24gYW5kIHByb2R1Y2UgYSB2YWxpZGF0ZWQgUmVkYWN0aW9uUmVzdWx0LlxuICogUmV0dXJucyBudWxsIGlmIHRoZSByZXN1bHQgZmFpbHMgdmFsaWRhdGlvbi5cbiAqL1xuYXN5bmMgZnVuY3Rpb24gYXR0ZW1wdERldGVjdGlvbihcbiAgY3RsOiBQcm9tcHRQcmVwcm9jZXNzb3JDb250cm9sbGVyLFxuICB0ZXh0OiBzdHJpbmcsXG4pOiBQcm9taXNlPFJlZGFjdGlvblJlc3VsdCB8IG51bGw+IHtcbiAgY29uc3QgZ2xvYmFsQ29uZmlnID0gY3RsLmdldEdsb2JhbFBsdWdpbkNvbmZpZyhnbG9iYWxDb25maWdTY2hlbWF0aWNzKTtcbiAgY29uc3QgZGV0ZWN0aW9uRW5naW5lID0gZ2xvYmFsQ29uZmlnLmdldChcImRldGVjdGlvbkVuZ2luZVwiKSBhcyBcInJlZGFjdFwiIHwgXCJsbG1cIjtcblxuICBsZXQgc3BhbnM7XG4gIGlmIChkZXRlY3Rpb25FbmdpbmUgPT09IFwibGxtXCIpIHtcbiAgICBjb25zdCBtb2RlbElkID0gZ2xvYmFsQ29uZmlnLmdldChcInBpaU1vZGVsXCIpLnRyaW0oKTtcblxuICAgIC8vIFJlc29sdmUgdGhlIG1vZGVsOiB1c2UgdGhlIGNvbmZpZ3VyZWQgaWRlbnRpZmllciBvciBmYWxsIGJhY2sgdG8gdGhlXG4gICAgLy8gY3VycmVudGx5IGxvYWRlZCBtb2RlbC5cbiAgICAvLyBOb3RlOiB0aGUgbm8tYXJndW1lbnQgb3ZlcmxvYWQgb2YgbW9kZWwoKSBkb2VzIG5vdCBhY2NlcHQgb3B0aW9ucywgc29cbiAgICAvLyBhYm9ydCBzaWduYWwgaGFuZGxpbmcgaXMgZGVsZWdhdGVkIHRvIHRoZSBsbG1EZXRlY3QgY2FsbCBpdHNlbGYuXG4gICAgY29uc3QgbW9kZWwgPVxuICAgICAgbW9kZWxJZC5sZW5ndGggPiAwXG4gICAgICAgID8gYXdhaXQgY3RsLmNsaWVudC5sbG0ubW9kZWwobW9kZWxJZCwgeyBzaWduYWw6IGN0bC5hYm9ydFNpZ25hbCB9KVxuICAgICAgICA6IGF3YWl0IGN0bC5jbGllbnQubGxtLm1vZGVsKCk7XG5cbiAgICAvLyBMTE0gZGV0ZWN0aW9uIChzdHJ1Y3R1cmVkIG91dHB1dCB2aWEgWm9kIFx1MjAxNCB0aHJvd3Mgb24gc2NoZW1hIHZpb2xhdGlvbilcbiAgICBjb25zdCBsbG1SZXNwb25zZSA9IGF3YWl0IGxsbURldGVjdChtb2RlbCwgdGV4dCwgY3RsLmFib3J0U2lnbmFsKTtcblxuICAgIC8vIFJlZ2V4IGZhbGxiYWNrIFx1MjAxNCBhZGRzIGFueSBFTUFJTCAvIFBIT05FIHRoZSBMTE0gbWlzc2VkXG4gICAgY29uc3QgcmVnZXhTcGFucyA9IHJlZ2V4RGV0ZWN0KHRleHQpO1xuXG4gICAgLy8gTWVyZ2U6IExMTSBlbnRpdGllcyBmaXJzdCwgdGhlbiBhbnkgcmVnZXgtb25seSBhZGRpdGlvbnNcbiAgICBzcGFucyA9IG1lcmdlRGV0ZWN0aW9ucyhsbG1SZXNwb25zZS5lbnRpdGllcywgcmVnZXhTcGFucyk7XG4gIH0gZWxzZSB7XG4gICAgLy8gT24tZGV2aWNlIFJlZGFjdCBtb2RlbCBcdTIwMTQgZGV0ZXJtaW5pc3RpYywgaW5jbHVkZXMgYnVpbHQtaW4gcGF0dGVyblxuICAgIC8vIHJlY29nbmlzZXJzIGZvciBzdHJ1Y3R1cmVkIGRhdGEgKGVtYWlscywgcGhvbmVzLCBjYXJkcywgSUJBTnMpLlxuICAgIHNwYW5zID0gYXdhaXQgcmVkYWN0RGV0ZWN0KHRleHQpO1xuICB9XG5cbiAgLy8gQXNzaWduIGlkZW50aWZpZXJzIGFuZCBwZXJmb3JtIHRleHQgc3Vic3RpdHV0aW9uLlxuICAvLyBFeGlzdGluZyBpZGVudGlmaWVycyAoZnJvbSBlYXJsaWVyIHR1cm5zKSBhcmUgcmV1c2VkIHNvIHBsYWNlaG9sZGVyc1xuICAvLyBzdGF5IGNvbnNpc3RlbnQgYWNyb3NzIHRoZSBjb252ZXJzYXRpb24uXG4gIGNvbnN0IHJlc3VsdCA9IHJlZGFjdCh0ZXh0LCBzcGFucywgZXhpc3RpbmdJZGVudGlmaWVycygpKTtcblxuICAvLyBWYWxpZGF0ZSB0aGUgZmluYWwgc3RydWN0dXJlIGFuZCBwbGFjZWhvbGRlciBpbnRlZ3JpdHlcbiAgY29uc3QgcGFyc2VSZXN1bHQgPSByZWRhY3Rpb25SZXN1bHRTY2hlbWEuc2FmZVBhcnNlKHJlc3VsdCk7XG4gIGlmICghcGFyc2VSZXN1bHQuc3VjY2Vzcykge1xuICAgIGN0bC5kZWJ1ZyhcIlJlZGFjdGlvblJlc3VsdCBzY2hlbWEgdmFsaWRhdGlvbiBmYWlsZWRcIiwgcGFyc2VSZXN1bHQuZXJyb3IuZm9ybWF0KCkpO1xuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAgaWYgKCF2YWxpZGF0ZVBsYWNlaG9sZGVycyhyZXN1bHQpKSB7XG4gICAgY3RsLmRlYnVnKFwiUGxhY2Vob2xkZXIgaW50ZWdyaXR5IGNoZWNrIGZhaWxlZCBcdTIwMTQgc29tZSBwbGFjZWhvbGRlcnMgYXJlIG1pc3NpbmcgZnJvbSByZWRhY3RlZCB0ZXh0XCIpO1xuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAgcmV0dXJuIHJlc3VsdDtcbn1cblxuLyoqXG4gKiBGb3JtYXQgYSBodW1hbi1yZWFkYWJsZSBzdW1tYXJ5IG9mIGRldGVjdGVkIGVudGl0aWVzIGZvciB0aGUgc3RhdHVzIHBhbmVsLlxuICovXG5mdW5jdGlvbiBmb3JtYXRFbnRpdHlTdW1tYXJ5KHJlc3VsdDogUmVkYWN0aW9uUmVzdWx0KTogc3RyaW5nIHtcbiAgaWYgKHJlc3VsdC5lbnRpdGllcy5sZW5ndGggPT09IDApIHtcbiAgICByZXR1cm4gXCJObyBQSUkgZGV0ZWN0ZWQuXCI7XG4gIH1cbiAgY29uc3QgbGluZXMgPSByZXN1bHQuZW50aXRpZXMubWFwKFxuICAgIGUgPT4gYCAgXHUyMDIyIFtbWyR7ZS5pZGVudGlmaWVyfV1dXSAgXHUyMTkwICBcIiR7ZS5vcmlnaW5hbH1cIiAgKCR7ZS50eXBlfSlgLFxuICApO1xuICByZXR1cm4gYERldGVjdGVkICR7cmVzdWx0LmVudGl0aWVzLmxlbmd0aH0gUElJIGVudGl0eShpZXMpOlxcbiR7bGluZXMuam9pbihcIlxcblwiKX1gO1xufVxuXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIE1haW4gcHJlcHJvY2Vzc29yXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHByZXByb2Nlc3MoXG4gIGN0bDogUHJvbXB0UHJlcHJvY2Vzc29yQ29udHJvbGxlcixcbiAgdXNlck1lc3NhZ2U6IENoYXRNZXNzYWdlLFxuKTogUHJvbWlzZTxzdHJpbmcgfCBDaGF0TWVzc2FnZT4ge1xuICBjb25zdCByYXdUZXh0ID0gdXNlck1lc3NhZ2UuZ2V0VGV4dCgpO1xuXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAvLyBDb25maXJtYXRpb24gZ2F0ZTogaWYgdGhlIHVzZXIgc2VudCAtLWMsIGZvcndhcmQgdGhlICpyZWRhY3RlZCpcbiAgLy8gdGV4dCBcdTIwMTQgbmV2ZXIgdGhlIG9yaWdpbmFsLlxuICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgaWYgKHJhd1RleHQgPT09IENPTkZJUk1fU1VGRklYKSB7XG4gICAgaWYgKHBlbmRpbmdSZWRhY3RlZFByb21wdCA9PT0gbnVsbCkge1xuXG4gICAgICBjdGwuY3JlYXRlU3RhdHVzKHtcbiAgICAgICAgc3RhdHVzOiBcImVycm9yXCIsXG4gICAgICAgIHRleHQ6IFwiTm8gcGVuZGluZyByZWRhY3Rpb24gdG8gY29uZmlybS4gUGxlYXNlIHNlbmQgeW91ciBwcm9tcHQgZmlyc3QuXCIsXG4gICAgICB9KTtcblxuICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICBcIk5vIHBlbmRpbmcgcmVkYWN0aW9uIHRvIGNvbmZpcm0uIFBsZWFzZSBzZW5kIHlvdXIgcHJvbXB0IGZpcnN0LlwiLFxuICAgICAgKTtcbiAgICB9XG5cbiAgICBjb25zdCByZWRhY3RlZFRleHQgPSBwZW5kaW5nUmVkYWN0ZWRQcm9tcHQ7XG5cbiAgICAvLyBDbGVhciBwZW5kaW5nIHN0YXRlIG5vdyB0aGF0IGNvbmZpcm1hdGlvbiBoYXMgYmVlbiBjb25zdW1lZC5cbiAgICBwZW5kaW5nUmVkYWN0ZWRQcm9tcHQgPSBudWxsO1xuXG4gICAgY29uc3QgY29uZmlybVN0YXR1cyA9IGN0bC5jcmVhdGVTdGF0dXMoe1xuICAgICAgc3RhdHVzOiBcImRvbmVcIixcbiAgICAgIHRleHQ6IFwiUElJIHJlZGFjdGlvbiBjb25maXJtZWQgXHUyMDE0IGZvcndhcmRpbmcgcmVkYWN0ZWQgcHJvbXB0LlwiLFxuICAgIH0pO1xuICAgIGN0bC5kZWJ1ZyhcIlVzZXIgY29uZmlybWVkIHJlZGFjdGVkIHByb21wdC4gRm9yd2FyZGluZyBzYXZlZCByZWRhY3RlZCB0ZXh0LlwiKTtcbiAgICAvLyBTdXBwcmVzcyB1bnVzZWQgdmFyaWFibGUgd2FybmluZyBcdTIwMTQgc3RhdHVzIGlzIHNob3duIGluIHRoZSBVSVxuICAgIHZvaWQgY29uZmlybVN0YXR1cztcbiAgICByZXR1cm4gcmVkYWN0ZWRUZXh0O1xuICB9XG5cbiAgY29uc3QgZ2xvYmFsQ29uZmlnID0gY3RsLmdldEdsb2JhbFBsdWdpbkNvbmZpZyhnbG9iYWxDb25maWdTY2hlbWF0aWNzKTtcbiAgY29uc3Qgc2tpcENvbmZpcm1hdGlvbiA9IGdsb2JhbENvbmZpZy5nZXQoXCJza2lwQ29uZmlybWF0aW9uXCIpO1xuXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAvLyBEZXRlY3Rpb24gc3RhdHVzXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICBjb25zdCBkZXRlY3Rpb25TdGF0dXMgPSBjdGwuY3JlYXRlU3RhdHVzKHtcbiAgICBzdGF0dXM6IFwibG9hZGluZ1wiLFxuICAgIHRleHQ6IFwiRGV0ZWN0aW5nIFBJSSBpbiBwcm9tcHRcdTIwMjZcIixcbiAgfSk7XG5cbiAgbGV0IHJlc3VsdDogUmVkYWN0aW9uUmVzdWx0IHwgbnVsbCA9IG51bGw7XG4gIGxldCBsYXN0RXJyb3I6IHVua25vd24gPSBudWxsO1xuXG4gIC8vIEF0dGVtcHQgMVxuICB0cnkge1xuICAgIHJlc3VsdCA9IGF3YWl0IGF0dGVtcHREZXRlY3Rpb24oY3RsLCByYXdUZXh0KTtcbiAgfSBjYXRjaCAoZXJyKSB7XG4gICAgbGFzdEVycm9yID0gZXJyO1xuICAgIGN0bC5kZWJ1ZyhcIlBJSSBkZXRlY3Rpb24gYXR0ZW1wdCAxIGZhaWxlZFwiLCBlcnIpO1xuICB9XG5cbiAgLy8gQXR0ZW1wdCAyIChyZXRyeSBvbmNlIG9uIGZhaWx1cmUpXG4gIGlmIChyZXN1bHQgPT09IG51bGwpIHtcbiAgICBkZXRlY3Rpb25TdGF0dXMuc2V0U3RhdGUoe1xuICAgICAgc3RhdHVzOiBcImxvYWRpbmdcIixcbiAgICAgIHRleHQ6IFwiUElJIGRldGVjdGlvbiBmYWlsZWQgXHUyMDE0IHJldHJ5aW5nXHUyMDI2XCIsXG4gICAgfSk7XG4gICAgdHJ5IHtcbiAgICAgIHJlc3VsdCA9IGF3YWl0IGF0dGVtcHREZXRlY3Rpb24oY3RsLCByYXdUZXh0KTtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIGxhc3RFcnJvciA9IGVycjtcbiAgICAgIGN0bC5kZWJ1ZyhcIlBJSSBkZXRlY3Rpb24gYXR0ZW1wdCAyIGZhaWxlZFwiLCBlcnIpO1xuICAgIH1cbiAgfVxuXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAvLyBGYWxsYmFjayBoYW5kbGluZyBcdTIwMTQgYWx3YXlzIGFib3J0LiBUaGUgb3JpZ2luYWwgcHJvbXB0IGlzIG5ldmVyXG4gIC8vIGZvcndhcmRlZCB3aGVuIGRldGVjdGlvbiBmYWlscywgc28gdW5yZWRhY3RlZCBQSUkgY2FuIG5ldmVyIHJlYWNoXG4gIC8vIHRoZSB0aGlyZC1wYXJ0eSBtb2RlbC5cbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIGlmIChyZXN1bHQgPT09IG51bGwpIHtcbiAgICBjb25zdCBkZXRhaWwgPVxuICAgICAgbGFzdEVycm9yIGluc3RhbmNlb2YgRXJyb3JcbiAgICAgICAgPyBsYXN0RXJyb3IubWVzc2FnZVxuICAgICAgICA6IGxhc3RFcnJvciAhPT0gbnVsbFxuICAgICAgICAgID8gU3RyaW5nKGxhc3RFcnJvcilcbiAgICAgICAgICA6IFwiZGV0ZWN0aW9uIHJldHVybmVkIGFuIGludmFsaWQgcmVzdWx0IChzZWUgZGVidWcgbG9ncylcIjtcblxuICAgIGRldGVjdGlvblN0YXR1cy5zZXRTdGF0ZSh7XG4gICAgICBzdGF0dXM6IFwiZXJyb3JcIixcbiAgICAgIHRleHQ6XG4gICAgICAgIGBQSUkgZGV0ZWN0aW9uIGZhaWxlZCBhZnRlciByZXRyeS4gUmVxdWVzdCBhYm9ydGVkLlxcbmAgK1xuICAgICAgICBgRW5naW5lOiAke2dsb2JhbENvbmZpZy5nZXQoXCJkZXRlY3Rpb25FbmdpbmVcIil9XFxuYCArXG4gICAgICAgIGBSZWFzb246ICR7ZGV0YWlsfWAsXG4gICAgfSk7XG4gICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgYFBJSSBkZXRlY3Rpb24gZmFpbGVkIGFmdGVyIG9uZSByZXRyeS4gUmVxdWVzdCBhYm9ydGVkIFx1MjAxNCB0aGUgb3JpZ2luYWwgcHJvbXB0IGlzIG5ldmVyIGZvcndhcmRlZC4gYCArXG4gICAgICAgIGBSZWFzb246ICR7ZGV0YWlsfWAsXG4gICAgKTtcbiAgfVxuXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAvLyBTdWNjZXNzIHBhdGhcbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIGNvbnN0IGVudGl0eVN1bW1hcnkgPSBmb3JtYXRFbnRpdHlTdW1tYXJ5KHJlc3VsdCk7XG5cbiAgaWYgKHJlc3VsdC5lbnRpdGllcy5sZW5ndGggPT09IDApIHtcbiAgICAvLyBObyBQSUkgZm91bmQgXHUyMDE0IHBhc3MgdGhyb3VnaCB3aXRob3V0IG1vZGlmaWNhdGlvblxuICAgIGRldGVjdGlvblN0YXR1cy5zZXRTdGF0ZSh7XG4gICAgICBzdGF0dXM6IFwiZG9uZVwiLFxuICAgICAgdGV4dDogXCJObyBQSUkgZGV0ZWN0ZWQgXHUyMDE0IGZvcndhcmRpbmcgb3JpZ2luYWwgcHJvbXB0LlwiLFxuICAgIH0pO1xuICAgIHJldHVybiB1c2VyTWVzc2FnZTtcbiAgfVxuXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAvLyBSZWdpc3RlciBlbnRpdGllcyBpbiB0aGUgc2hhcmVkIHN0b3JlIHNvIHRoZSBnZW5lcmF0b3IgY2FuXG4gIC8vIHVuLXJlZGFjdCByZXNwb25zZXMgYW5kIHJlLXJlZGFjdCB0aGUgaGlzdG9yeSBsYXRlci5cbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIGFkZEVudGl0aWVzKHJlc3VsdC5lbnRpdGllcyk7XG5cbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC8vIFNraXAgY29uZmlybWF0aW9uIFx1MjAxNCBmb3J3YXJkIHRoZSByZWRhY3RlZCB0ZXh0IGltbWVkaWF0ZWx5XG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICBpZiAoc2tpcENvbmZpcm1hdGlvbikge1xuICAgIGRldGVjdGlvblN0YXR1cy5zZXRTdGF0ZSh7XG4gICAgICBzdGF0dXM6IFwiZG9uZVwiLFxuICAgICAgdGV4dDogYFBJSSByZWRhY3RlZCBzdWNjZXNzZnVsbHkgXHUyMDE0IGZvcndhcmRpbmcgd2l0aG91dCBjb25maXJtYXRpb24uXFxuXFxuJHtlbnRpdHlTdW1tYXJ5fWAsXG4gICAgfSk7XG4gICAgY3RsLmRlYnVnKFwiUmVkYWN0aW9uIHJlc3VsdFwiLCByZXN1bHQpO1xuICAgIHJldHVybiByZXN1bHQucmVkYWN0ZWRfdGV4dDtcbiAgfVxuXG4gIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAvLyBDb25maXJtYXRpb24gZ2F0ZSAoZGVmYXVsdClcbiAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gIC8vIFNhdmUgdGhlIHJlZGFjdGVkIHByb21wdCBzbyB0aGUgLS1jIGhhbmRsZXIgY2FuIGZvcndhcmRcbiAgLy8gdGhlIHJlZGFjdGVkIHZlcnNpb24gKG5ldmVyIHRoZSBvcmlnaW5hbCkuXG4gIHBlbmRpbmdSZWRhY3RlZFByb21wdCA9IHJlc3VsdC5yZWRhY3RlZF90ZXh0O1xuXG4gIC8vIFRydW5jYXRlIHRoZSByZWRhY3RlZCB0ZXh0IHByZXZpZXcgdG8gYXZvaWQgZmxvb2RpbmcgdGhlIHN0YXR1cyBwYW5lbFxuICBjb25zdCBwcmV2aWV3ID1cbiAgICByZXN1bHQucmVkYWN0ZWRfdGV4dC5sZW5ndGggPiA1MDBcbiAgICAgID8gcmVzdWx0LnJlZGFjdGVkX3RleHQuc2xpY2UoMCwgNTAwKSArIFwiXHUyMDI2XCJcbiAgICAgIDogcmVzdWx0LnJlZGFjdGVkX3RleHQ7XG5cbiAgZGV0ZWN0aW9uU3RhdHVzLnNldFN0YXRlKHtcbiAgICBzdGF0dXM6IFwiY2FuY2VsZWRcIixcbiAgICB0ZXh0OlxuICAgICAgYFBJSSBkZXRlY3RlZCBcdTIwMTQgcmVkYWN0aW9uIHByZXZpZXcgc2hvd24gYmVsb3cuIGAgK1xuICAgICAgYFNlbmQgYW5vdGhlciBtZXNzYWdlIGNvbnRhaW5pbmcgJy0tYycgdG8gY29uZmlybSBhbmQgcHJvY2VlZC5cXG5cXG5gICtcbiAgICAgIGAtLS0gUmVkYWN0ZWQgcHJvbXB0IC0tLVxcbiR7cHJldmlld31cXG5cXG5gICtcbiAgICAgIGAtLS0gRW50aXR5IG1hcCAtLS1cXG4ke2VudGl0eVN1bW1hcnl9YCxcbiAgfSk7XG5cbiAgdGhyb3cgbmV3IEVycm9yKFxuICAgIFwiUHJvbXB0IGNvbnRhaW5zIFBJSS4gUmV2aWV3IHRoZSByZWRhY3RlZCBwcmV2aWV3IGluIHRoZSBzdGF0dXMgcGFuZWwsIHRoZW4gY29uZmlybSBcIiArXG4gICAgXCJ5b3VyIG1lc3NhZ2Ugd2l0aCAtLWMgdG8gcHJvY2VlZC5cIixcbiAgKTtcbn1cbiIsICJpbXBvcnQgeyB0eXBlIFBsdWdpbkNvbnRleHQgfSBmcm9tIFwiQGxtc3R1ZGlvL3Nka1wiO1xuaW1wb3J0IHsgZ2xvYmFsQ29uZmlnU2NoZW1hdGljcyB9IGZyb20gXCIuL2NvbmZpZ1wiO1xuaW1wb3J0IHsgZ2VuZXJhdGUgfSBmcm9tIFwiLi9nZW5lcmF0b3JcIjtcbmltcG9ydCB7IHByZWxvYWRSZWRhY3QgfSBmcm9tIFwiLi9waWlEZXRlY3RvclwiO1xuaW1wb3J0IHsgcHJlcHJvY2VzcyB9IGZyb20gXCIuL3Byb21wdFByZXByb2Nlc3NvclwiO1xuXG4vKipcbiAqIFBsdWdpbiBlbnRyeSBwb2ludC5cbiAqXG4gKiBSZWdpc3RlcnM6XG4gKiAtIEdsb2JhbCBjb25maWd1cmF0aW9uIHNjaGVtYSAoZGV0ZWN0aW9uL2Fzc2lzdGFudCBtb2RlbHMsIGNvbmZpcm1hdGlvblxuICogICBnYXRlLCBBUEkga2V5LCBiYXNlIFVSTCBcdTIwMTQgc2hhcmVkIGFjcm9zcyBhbGwgY2hhdHMpXG4gKiAtIFByb21wdCBwcmVwcm9jZXNzb3IgKFBJSSBkZXRlY3Rpb24gKyByZWRhY3Rpb24gKyBjb25maXJtYXRpb24gZ2F0ZSlcbiAqIC0gR2VuZXJhdG9yIChzZW5kcyB0aGUgcmVkYWN0ZWQgaGlzdG9yeSB0byB0aGUgdGhpcmQtcGFydHkgQVBJIGFuZFxuICogICB1bi1yZWRhY3RzIHRoZSByZXNwb25zZSBsb2NhbGx5KVxuICpcbiAqIEJlY2F1c2UgdGhlIHBsdWdpbiBjb250YWlucyBhIGdlbmVyYXRvciwgaXQgYXBwZWFycyBpbiB0aGUgbW9kZWwgZHJvcGRvd25cbiAqIChpbnN0ZWFkIG9mIHRoZSBwbHVnaW5zIGxpc3QpIGFuZCBhY3RzIGFzIGEgbW9kZWwuIFRoZSBwcmVwcm9jZXNzb3IgcnVuc1xuICogd2hlbmV2ZXIgdGhpcyBwbHVnaW4tbW9kZWwgaXMgc2VsZWN0ZWQuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBtYWluKGNvbnRleHQ6IFBsdWdpbkNvbnRleHQpIHtcbiAgY29udGV4dC53aXRoR2xvYmFsQ29uZmlnU2NoZW1hdGljcyhnbG9iYWxDb25maWdTY2hlbWF0aWNzKTtcblxuICAvLyBQcmUtbG9hZCB0aGUgb24tZGV2aWNlIFJlZGFjdCBtb2RlbCBpbiB0aGUgYmFja2dyb3VuZCBzbyB0aGUgMjQuNSBNQlxuICAvLyB3ZWlnaHRzIGRvd25sb2FkIChmaXJzdCB1c2Ugb25seSkgZG9lcyBub3QgaGFwcGVuIGluc2lkZSB0aGUgZmlyc3RcbiAgLy8gcHJlcHJvY2Vzc29yIHJlcXVlc3QuIEZhaWx1cmVzIGFyZSBsb2dnZWQgYnV0IG5vbi1mYXRhbDogdGhlXG4gIC8vIHByZXByb2Nlc3NvciB3aWxsIHJldHJ5IHRoZSBsb2FkIG9uIGRlbWFuZCBhbmQgc3VyZmFjZSB0aGUgZXJyb3IuXG4gIHZvaWQgcHJlbG9hZFJlZGFjdCgpLmNhdGNoKGVyciA9PiB7XG4gICAgY29uc29sZS5lcnJvcihcIltwaWktcmVkYWN0XSBSZWRhY3QgbW9kZWwgcHJlLWxvYWQgZmFpbGVkOlwiLCBlcnIpO1xuICB9KTtcblxuICBjb250ZXh0LndpdGhQcm9tcHRQcmVwcm9jZXNzb3IocHJlcHJvY2Vzcyk7XG4gIGNvbnRleHQud2l0aEdlbmVyYXRvcihnZW5lcmF0ZSk7XG59XG4iLCAiaW1wb3J0IHsgTE1TdHVkaW9DbGllbnQsIHR5cGUgUGx1Z2luQ29udGV4dCB9IGZyb20gXCJAbG1zdHVkaW8vc2RrXCI7XG5cbmRlY2xhcmUgdmFyIHByb2Nlc3M6IGFueTtcblxuLy8gV2UgcmVjZWl2ZSBydW50aW1lIGluZm9ybWF0aW9uIGluIHRoZSBlbnZpcm9ubWVudCB2YXJpYWJsZXMuXG5jb25zdCBjbGllbnRJZGVudGlmaWVyID0gcHJvY2Vzcy5lbnYuTE1TX1BMVUdJTl9DTElFTlRfSURFTlRJRklFUjtcbmNvbnN0IGNsaWVudFBhc3NrZXkgPSBwcm9jZXNzLmVudi5MTVNfUExVR0lOX0NMSUVOVF9QQVNTS0VZO1xuY29uc3QgYmFzZVVybCA9IHByb2Nlc3MuZW52LkxNU19QTFVHSU5fQkFTRV9VUkw7XG5cbmNvbnN0IGNsaWVudCA9IG5ldyBMTVN0dWRpb0NsaWVudCh7XG4gIGNsaWVudElkZW50aWZpZXIsXG4gIGNsaWVudFBhc3NrZXksXG4gIGJhc2VVcmwsXG59KTtcblxuKGdsb2JhbFRoaXMgYXMgYW55KS5fX0xNU19QTFVHSU5fQ09OVEVYVCA9IHRydWU7XG5cbmxldCBwcmVkaWN0aW9uTG9vcEhhbmRsZXJTZXQgPSBmYWxzZTtcbmxldCBwcm9tcHRQcmVwcm9jZXNzb3JTZXQgPSBmYWxzZTtcbmxldCBjb25maWdTY2hlbWF0aWNzU2V0ID0gZmFsc2U7XG5sZXQgZ2xvYmFsQ29uZmlnU2NoZW1hdGljc1NldCA9IGZhbHNlO1xubGV0IHRvb2xzUHJvdmlkZXJTZXQgPSBmYWxzZTtcbmxldCBnZW5lcmF0b3JTZXQgPSBmYWxzZTtcblxuY29uc3Qgc2VsZlJlZ2lzdHJhdGlvbkhvc3QgPSBjbGllbnQucGx1Z2lucy5nZXRTZWxmUmVnaXN0cmF0aW9uSG9zdCgpO1xuXG5jb25zdCBwbHVnaW5Db250ZXh0OiBQbHVnaW5Db250ZXh0ID0ge1xuICB3aXRoUHJlZGljdGlvbkxvb3BIYW5kbGVyOiAoZ2VuZXJhdGUpID0+IHtcbiAgICBpZiAocHJlZGljdGlvbkxvb3BIYW5kbGVyU2V0KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJQcmVkaWN0aW9uTG9vcEhhbmRsZXIgYWxyZWFkeSByZWdpc3RlcmVkXCIpO1xuICAgIH1cbiAgICBpZiAodG9vbHNQcm92aWRlclNldCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiUHJlZGljdGlvbkxvb3BIYW5kbGVyIGNhbm5vdCBiZSB1c2VkIHdpdGggYSB0b29scyBwcm92aWRlclwiKTtcbiAgICB9XG5cbiAgICBwcmVkaWN0aW9uTG9vcEhhbmRsZXJTZXQgPSB0cnVlO1xuICAgIHNlbGZSZWdpc3RyYXRpb25Ib3N0LnNldFByZWRpY3Rpb25Mb29wSGFuZGxlcihnZW5lcmF0ZSk7XG4gICAgcmV0dXJuIHBsdWdpbkNvbnRleHQ7XG4gIH0sXG4gIHdpdGhQcm9tcHRQcmVwcm9jZXNzb3I6IChwcmVwcm9jZXNzKSA9PiB7XG4gICAgaWYgKHByb21wdFByZXByb2Nlc3NvclNldCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiUHJvbXB0UHJlcHJvY2Vzc29yIGFscmVhZHkgcmVnaXN0ZXJlZFwiKTtcbiAgICB9XG4gICAgcHJvbXB0UHJlcHJvY2Vzc29yU2V0ID0gdHJ1ZTtcbiAgICBzZWxmUmVnaXN0cmF0aW9uSG9zdC5zZXRQcm9tcHRQcmVwcm9jZXNzb3IocHJlcHJvY2Vzcyk7XG4gICAgcmV0dXJuIHBsdWdpbkNvbnRleHQ7XG4gIH0sXG4gIHdpdGhDb25maWdTY2hlbWF0aWNzOiAoY29uZmlnU2NoZW1hdGljcykgPT4ge1xuICAgIGlmIChjb25maWdTY2hlbWF0aWNzU2V0KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJDb25maWcgc2NoZW1hdGljcyBhbHJlYWR5IHJlZ2lzdGVyZWRcIik7XG4gICAgfVxuICAgIGNvbmZpZ1NjaGVtYXRpY3NTZXQgPSB0cnVlO1xuICAgIHNlbGZSZWdpc3RyYXRpb25Ib3N0LnNldENvbmZpZ1NjaGVtYXRpY3MoY29uZmlnU2NoZW1hdGljcyk7XG4gICAgcmV0dXJuIHBsdWdpbkNvbnRleHQ7XG4gIH0sXG4gIHdpdGhHbG9iYWxDb25maWdTY2hlbWF0aWNzOiAoZ2xvYmFsQ29uZmlnU2NoZW1hdGljcykgPT4ge1xuICAgIGlmIChnbG9iYWxDb25maWdTY2hlbWF0aWNzU2V0KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJHbG9iYWwgY29uZmlnIHNjaGVtYXRpY3MgYWxyZWFkeSByZWdpc3RlcmVkXCIpO1xuICAgIH1cbiAgICBnbG9iYWxDb25maWdTY2hlbWF0aWNzU2V0ID0gdHJ1ZTtcbiAgICBzZWxmUmVnaXN0cmF0aW9uSG9zdC5zZXRHbG9iYWxDb25maWdTY2hlbWF0aWNzKGdsb2JhbENvbmZpZ1NjaGVtYXRpY3MpO1xuICAgIHJldHVybiBwbHVnaW5Db250ZXh0O1xuICB9LFxuICB3aXRoVG9vbHNQcm92aWRlcjogKHRvb2xzUHJvdmlkZXIpID0+IHtcbiAgICBpZiAodG9vbHNQcm92aWRlclNldCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiVG9vbHMgcHJvdmlkZXIgYWxyZWFkeSByZWdpc3RlcmVkXCIpO1xuICAgIH1cbiAgICBpZiAocHJlZGljdGlvbkxvb3BIYW5kbGVyU2V0KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJUb29scyBwcm92aWRlciBjYW5ub3QgYmUgdXNlZCB3aXRoIGEgcHJlZGljdGlvbkxvb3BIYW5kbGVyXCIpO1xuICAgIH1cblxuICAgIHRvb2xzUHJvdmlkZXJTZXQgPSB0cnVlO1xuICAgIHNlbGZSZWdpc3RyYXRpb25Ib3N0LnNldFRvb2xzUHJvdmlkZXIodG9vbHNQcm92aWRlcik7XG4gICAgcmV0dXJuIHBsdWdpbkNvbnRleHQ7XG4gIH0sXG4gIHdpdGhHZW5lcmF0b3I6IChnZW5lcmF0b3IpID0+IHtcbiAgICBpZiAoZ2VuZXJhdG9yU2V0KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJHZW5lcmF0b3IgYWxyZWFkeSByZWdpc3RlcmVkXCIpO1xuICAgIH1cblxuICAgIGdlbmVyYXRvclNldCA9IHRydWU7XG4gICAgc2VsZlJlZ2lzdHJhdGlvbkhvc3Quc2V0R2VuZXJhdG9yKGdlbmVyYXRvcik7XG4gICAgcmV0dXJuIHBsdWdpbkNvbnRleHQ7XG4gIH0sXG59O1xuXG5pbXBvcnQoXCIuLy4uL3NyYy9pbmRleC50c1wiKS50aGVuKGFzeW5jIG1vZHVsZSA9PiB7XG4gIHJldHVybiBhd2FpdCBtb2R1bGUubWFpbihwbHVnaW5Db250ZXh0KTtcbn0pLnRoZW4oKCkgPT4ge1xuICBzZWxmUmVnaXN0cmF0aW9uSG9zdC5pbml0Q29tcGxldGVkKCk7XG59KS5jYXRjaCgoZXJyb3IpID0+IHtcbiAgY29uc29sZS5lcnJvcihcIkZhaWxlZCB0byBleGVjdXRlIHRoZSBtYWluIGZ1bmN0aW9uIG9mIHRoZSBwbHVnaW4uXCIpO1xuICBjb25zb2xlLmVycm9yKGVycm9yKTtcbn0pO1xuIl0sCiAgIm1hcHBpbmdzIjogIjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFBQSxnQkFNYTtBQU5iO0FBQUE7QUFBQTtBQUFBLGlCQUF1QztBQU1oQyxJQUFNLDZCQUF5QixtQ0FBdUIsRUFJMUQ7QUFBQSxNQUNDO0FBQUEsTUFDQTtBQUFBLE1BQ0E7QUFBQSxRQUNFLGFBQWE7QUFBQSxRQUNiLFVBQ0U7QUFBQSxRQUVGLFNBQVM7QUFBQSxVQUNQLEVBQUUsT0FBTyxVQUFVLGFBQWEsMkJBQTJCO0FBQUEsVUFDM0QsRUFBRSxPQUFPLE9BQU8sYUFBYSw0QkFBNEI7QUFBQSxRQUMzRDtBQUFBLE1BQ0Y7QUFBQSxNQUNBO0FBQUEsSUFDRixFQUlDO0FBQUEsTUFDQztBQUFBLE1BQ0E7QUFBQSxNQUNBO0FBQUEsUUFDRSxhQUFhO0FBQUEsUUFDYixVQUNFO0FBQUEsUUFFRixhQUFhO0FBQUEsTUFDZjtBQUFBLE1BQ0E7QUFBQSxJQUNGLEVBSUM7QUFBQSxNQUNDO0FBQUEsTUFDQTtBQUFBLE1BQ0E7QUFBQSxRQUNFLGFBQWE7QUFBQSxRQUNiLFVBQ0U7QUFBQSxRQUVGLGFBQWE7QUFBQSxNQUNmO0FBQUEsTUFDQTtBQUFBLElBQ0YsRUFJQztBQUFBLE1BQ0M7QUFBQSxNQUNBO0FBQUEsTUFDQTtBQUFBLFFBQ0UsYUFBYTtBQUFBLFFBQ2IsVUFDRTtBQUFBLE1BRUo7QUFBQSxNQUNBO0FBQUEsSUFDRixFQUlDO0FBQUEsTUFDQztBQUFBLE1BQ0E7QUFBQSxNQUNBO0FBQUEsUUFDRSxhQUFhO0FBQUEsUUFD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SSxNQUFNLDhCQUE4QjtBQUFBLElBQ2hEO0FBRUEsbUJBQWU7QUFDZix5QkFBcUIsYUFBYSxTQUFTO0FBQzNDLFdBQU87QUFBQSxFQUNUO0FBQ0Y7QUFFQSx3REFBNEIsS0FBSyxPQUFNQyxZQUFVO0FBQy9DLFNBQU8sTUFBTUEsUUFBTyxLQUFLLGFBQWE7QUFDeEMsQ0FBQyxFQUFFLEtBQUssTUFBTTtBQUNaLHVCQUFxQixjQUFjO0FBQ3JDLENBQUMsRUFBRSxNQUFNLENBQUMsVUFBVTtBQUNsQixVQUFRLE1BQU0sb0RBQW9EO0FBQ2xFLFVBQVEsTUFBTSxLQUFLO0FBQ3JCLENBQUM7IiwKICAibmFtZXMiOiBbImVudGl0aWVzIiwgImJhc2VVcmwiLCAiY2xpZW50IiwgIk9wZW5BSSIsICJwYXRoIiwgImZzIiwgIm9zIiwgInJlZGFjdCIsICJpbXBvcnRfbmF0aXZlIiwgImltcG9ydF9zZGsiLCAiZ2VuZXJhdGUiLCAicHJlcHJvY2VzcyIsICJnbG9iYWxDb25maWdTY2hlbWF0aWNzIiwgIm1vZHVsZSJdCn0K
