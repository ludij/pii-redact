"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.globalConfigSchematics = void 0;
const sdk_1 = require("@lmstudio/sdk");
/**
 * Global configuration — shared across all chats, so values persist when
 * starting a new conversation.
 */
exports.globalConfigSchematics = (0, sdk_1.createConfigSchematics)()
    // -------------------------------------------------------------------------
    // Detection engine
    // -------------------------------------------------------------------------
    .field("detectionEngine", "select", {
    displayName: "Detection Engine",
    subtitle: "'redact' uses the on-device Desert Ant Redact model (recommended — no LLM needed, " +
        "weights download on first use). 'llm' uses the PII Detection Model for detection.",
    options: [
        { value: "redact", displayName: "Redact (on-device model)" },
        { value: "llm", displayName: "LLM (PII Detection Model)" },
    ],
}, "redact")
    // -------------------------------------------------------------------------
    // PII detection model
    // -------------------------------------------------------------------------
    .field("piiModel", "string", {
    displayName: "PII Detection Model",
    subtitle: "Only used when Detection Engine is 'llm'. Model identifier used to detect PII. " +
        "Leave blank to use the currently loaded model. Example: qwen2.5-7b-instruct",
    placeholder: "e.g. qwen2.5-7b-instruct",
}, "")
    // -------------------------------------------------------------------------
    // Assistant model (the third-party model that receives the redacted prompt)
    // -------------------------------------------------------------------------
    .field("assistantModel", "string", {
    displayName: "Assistant Model",
    subtitle: "Model ID sent to the OpenAI-compatible endpoint for generating responses. " +
        "Examples: gpt-4o-mini (OpenAI), openai/gpt-4o-mini (OpenRouter).",
    placeholder: "e.g. gpt-4o-mini",
}, "")
    // -------------------------------------------------------------------------
    // Confirmation gate
    // -------------------------------------------------------------------------
    .field("skipConfirmation", "boolean", {
    displayName: "Skip Confirmation",
    subtitle: "When enabled, redacted prompts are forwarded immediately without requiring '--c'. " +
        "The redaction preview is still shown in the status panel.",
}, false)
    // -------------------------------------------------------------------------
    // API key for the OpenAI-compatible endpoint
    // -------------------------------------------------------------------------
    .field("apiKey", "string", {
    displayName: "API Key",
    subtitle: "API key for the OpenAI-compatible endpoint (e.g. sk-... for OpenAI, " +
        "sk-or-... for OpenRouter). Stored as a protected field.",
    isProtected: true,
    placeholder: "sk-...",
}, "")
    // -------------------------------------------------------------------------
    // Base URL of the OpenAI-compatible endpoint
    // -------------------------------------------------------------------------
    .field("baseUrl", "string", {
    displayName: "Base URL",
    subtitle: "Base URL of the OpenAI-compatible endpoint. " +
        "Examples: https://api.openai.com/v1, https://openrouter.ai/api/v1",
    placeholder: "https://api.openai.com/v1",
}, "https://api.openai.com/v1")
    .build();
