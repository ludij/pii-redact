"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.preprocess = preprocess;
const config_1 = require("./config");
const entityStore_1 = require("./entityStore");
const piiDetector_1 = require("./piiDetector");
const redactor_1 = require("./redactor");
const types_1 = require("./types");
// ---------------------------------------------------------------------------
// Pending confirmation state
// ---------------------------------------------------------------------------
/**
 * Stores the redacted prompt while waiting for the user to confirm
 * with --c.  This ensures that on confirmation we forward the
 * *redacted* text — never the original.
 */
let pendingRedactedPrompt = null;
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
/**
 * Attempt one round of detection and produce a validated RedactionResult.
 * Returns null if the result fails validation.
 */
async function attemptDetection(ctl, text) {
    const globalConfig = ctl.getGlobalPluginConfig(config_1.globalConfigSchematics);
    const detectionEngine = globalConfig.get("detectionEngine");
    let spans;
    if (detectionEngine === "llm") {
        const modelId = globalConfig.get("piiModel").trim();
        // Resolve the model: use the configured identifier or fall back to the
        // currently loaded model.
        // Note: the no-argument overload of model() does not accept options, so
        // abort signal handling is delegated to the llmDetect call itself.
        const model = modelId.length > 0
            ? await ctl.client.llm.model(modelId, { signal: ctl.abortSignal })
            : await ctl.client.llm.model();
        // LLM detection (structured output via Zod — throws on schema violation)
        const llmResponse = await (0, piiDetector_1.llmDetect)(model, text, ctl.abortSignal);
        // Regex fallback — adds any EMAIL / PHONE the LLM missed
        const regexSpans = (0, piiDetector_1.regexDetect)(text);
        // Merge: LLM entities first, then any regex-only additions
        spans = (0, piiDetector_1.mergeDetections)(llmResponse.entities, regexSpans);
    }
    else {
        // On-device Redact model — deterministic, includes built-in pattern
        // recognisers for structured data (emails, phones, cards, IBANs).
        spans = await (0, piiDetector_1.redactDetect)(text);
    }
    // Assign identifiers and perform text substitution.
    // Existing identifiers (from earlier turns) are reused so placeholders
    // stay consistent across the conversation.
    const result = (0, redactor_1.redact)(text, spans, (0, entityStore_1.existingIdentifiers)());
    // Validate the final structure and placeholder integrity
    const parseResult = types_1.redactionResultSchema.safeParse(result);
    if (!parseResult.success) {
        ctl.debug("RedactionResult schema validation failed", parseResult.error.format());
        return null;
    }
    if (!(0, redactor_1.validatePlaceholders)(result)) {
        ctl.debug("Placeholder integrity check failed — some placeholders are missing from redacted text");
        return null;
    }
    return result;
}
/**
 * Format a human-readable summary of detected entities for the status panel.
 */
function formatEntitySummary(result) {
    if (result.entities.length === 0) {
        return "No PII detected.";
    }
    const lines = result.entities.map(e => `  • [[[${e.identifier}]]]  ←  "${e.original}"  (${e.type})`);
    return `Detected ${result.entities.length} PII entity(ies):\n${lines.join("\n")}`;
}
// ---------------------------------------------------------------------------
// Main preprocessor
// ---------------------------------------------------------------------------
async function preprocess(ctl, userMessage) {
    const rawText = userMessage.getText();
    // ------------------------------------------------------------------
    // Confirmation gate: if the user sent --c, forward the *redacted*
    // text — never the original.
    // ------------------------------------------------------------------
    if (rawText === types_1.CONFIRM_SUFFIX) {
        if (pendingRedactedPrompt === null) {
            ctl.createStatus({
                status: "error",
                text: "No pending redaction to confirm. Please send your prompt first.",
            });
            throw new Error("No pending redaction to confirm. Please send your prompt first.");
        }
        const redactedText = pendingRedactedPrompt;
        // Clear pending state now that confirmation has been consumed.
        pendingRedactedPrompt = null;
        const confirmStatus = ctl.createStatus({
            status: "done",
            text: "PII redaction confirmed — forwarding redacted prompt.",
        });
        ctl.debug("User confirmed redacted prompt. Forwarding saved redacted text.");
        // Suppress unused variable warning — status is shown in the UI
        void confirmStatus;
        return redactedText;
    }
    const globalConfig = ctl.getGlobalPluginConfig(config_1.globalConfigSchematics);
    const skipConfirmation = globalConfig.get("skipConfirmation");
    // ------------------------------------------------------------------
    // Detection status
    // ------------------------------------------------------------------
    const detectionStatus = ctl.createStatus({
        status: "loading",
        text: "Detecting PII in prompt…",
    });
    let result = null;
    let lastError = null;
    // Attempt 1
    try {
        result = await attemptDetection(ctl, rawText);
    }
    catch (err) {
        lastError = err;
        ctl.debug("PII detection attempt 1 failed", err);
    }
    // Attempt 2 (retry once on failure)
    if (result === null) {
        detectionStatus.setState({
            status: "loading",
            text: "PII detection failed — retrying…",
        });
        try {
            result = await attemptDetection(ctl, rawText);
        }
        catch (err) {
            lastError = err;
            ctl.debug("PII detection attempt 2 failed", err);
        }
    }
    // ------------------------------------------------------------------
    // Fallback handling — always abort. The original prompt is never
    // forwarded when detection fails, so unredacted PII can never reach
    // the third-party model.
    // ------------------------------------------------------------------
    if (result === null) {
        const detail = lastError instanceof Error
            ? lastError.message
            : lastError !== null
                ? String(lastError)
                : "detection returned an invalid result (see debug logs)";
        detectionStatus.setState({
            status: "error",
            text: `PII detection failed after retry. Request aborted.\n` +
                `Engine: ${globalConfig.get("detectionEngine")}\n` +
                `Reason: ${detail}`,
        });
        throw new Error(`PII detection failed after one retry. Request aborted — the original prompt is never forwarded. ` +
            `Reason: ${detail}`);
    }
    // ------------------------------------------------------------------
    // Success path
    // ------------------------------------------------------------------
    const entitySummary = formatEntitySummary(result);
    if (result.entities.length === 0) {
        // No PII found — pass through without modification
        detectionStatus.setState({
            status: "done",
            text: "No PII detected — forwarding original prompt.",
        });
        return userMessage;
    }
    // ------------------------------------------------------------------
    // Register entities in the shared store so the generator can
    // un-redact responses and re-redact the history later.
    // ------------------------------------------------------------------
    (0, entityStore_1.addEntities)(result.entities);
    // ------------------------------------------------------------------
    // Skip confirmation — forward the redacted text immediately
    // ------------------------------------------------------------------
    if (skipConfirmation) {
        detectionStatus.setState({
            status: "done",
            text: `PII redacted successfully — forwarding without confirmation.\n\n${entitySummary}`,
        });
        ctl.debug("Redaction result", result);
        return result.redacted_text;
    }
    // ------------------------------------------------------------------
    // Confirmation gate (default)
    // ------------------------------------------------------------------
    // Save the redacted prompt so the --c handler can forward
    // the redacted version (never the original).
    pendingRedactedPrompt = result.redacted_text;
    // Truncate the redacted text preview to avoid flooding the status panel
    const preview = result.redacted_text.length > 500
        ? result.redacted_text.slice(0, 500) + "…"
        : result.redacted_text;
    detectionStatus.setState({
        status: "canceled",
        text: `PII detected — redaction preview shown below. ` +
            `Send another message containing '--c' to confirm and proceed.\n\n` +
            `--- Redacted prompt ---\n${preview}\n\n` +
            `--- Entity map ---\n${entitySummary}`,
    });
    throw new Error("Prompt contains PII. Review the redacted preview in the status panel, then confirm " +
        "your message with --c to proceed.");
}
