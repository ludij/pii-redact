"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generate = generate;
const openai_1 = __importDefault(require("openai"));
const config_1 = require("./config");
const entityStore_1 = require("./entityStore");
const DEFAULT_BASE_URL = "https://api.openai.com/v1";
/** Detects placeholders that the model echoed back but we could not restore. */
const PLACEHOLDER_PATTERN = /\[\[\[[A-Z]+_\d+\]\]\]/g;
/**
 * Convert the chat history to OpenAI format, re-redacting every message.
 *
 * Re-redaction is essential: earlier turns may still contain original values
 * (the preprocessor only redacts the message being processed, and confirmed
 * turns keep their originals in the visible history). The shared entity map
 * replaces them with placeholders so the third-party API never sees them.
 */
function toOpenAIMessages(history) {
    const messages = [];
    for (const message of history) {
        const role = message.getRole();
        if (role === "tool") {
            // This plugin registers no tools provider — skip tool messages.
            continue;
        }
        messages.push({ role, content: (0, entityStore_1.redactText)(message.getText()) });
    }
    return messages;
}
/**
 * Generator hook — replaces the local model entirely.
 *
 * Flow:
 * 1. The preprocessor has already redacted the user's prompt (and stored the
 *    entity map in the shared store).
 * 2. This generator re-redacts the full history, sends it to the configured
 *    OpenAI-compatible endpoint, and buffers the streamed response.
 * 3. Placeholders in the response are translated back to their originals
 *    locally, then the un-redacted text is emitted to the chat.
 */
async function generate(ctl, history) {
    const globalConfig = ctl.getGlobalPluginConfig(config_1.globalConfigSchematics);
    const assistantModel = globalConfig.get("assistantModel").trim();
    if (assistantModel.length === 0) {
        throw new Error("Assistant Model is not configured. Set it in the plugin settings " +
            "(e.g. gpt-4o-mini for OpenAI, openai/gpt-4o-mini for OpenRouter).");
    }
    const apiKey = globalConfig.get("apiKey").trim();
    if (apiKey.length === 0) {
        throw new Error("API Key is not configured. Set it in the plugin's global settings.");
    }
    const baseUrl = globalConfig.get("baseUrl").trim() || DEFAULT_BASE_URL;
    const client = new openai_1.default({ apiKey, baseURL: baseUrl });
    const stream = await client.chat.completions.create({
        model: assistantModel,
        messages: toOpenAIMessages(history),
        stream: true,
    });
    // Propagate user aborts to the HTTP stream.
    ctl.onAborted(() => {
        stream.controller.abort();
    });
    // Buffer the full response — placeholders can span stream fragments, so
    // un-redaction is only safe once generation is complete.
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
    // Un-redact locally — the originals never left this machine.
    const unredacted = (0, entityStore_1.unredactText)(full);
    const unmatched = unredacted.match(PLACEHOLDER_PATTERN);
    if (unmatched !== null) {
        console.info("pii-redact: response still contains placeholders with no known original:", [...new Set(unmatched)]);
    }
    ctl.fragmentGenerated(unredacted);
}
