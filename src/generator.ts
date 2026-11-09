import { type Chat, type GeneratorController } from "@lmstudio/sdk";
import OpenAI from "openai";
import { globalConfigSchematics } from "./config";
import { redactText, unredactText } from "./entityStore";

const DEFAULT_BASE_URL = "https://api.openai.com/v1";

/** Minimal message shape accepted by the OpenAI-compatible chat API. */
interface OpenAIMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

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
function toOpenAIMessages(history: Chat): OpenAIMessage[] {
  const messages: OpenAIMessage[] = [];
  for (const message of history) {
    const role = message.getRole();
    if (role === "tool") {
      // This plugin registers no tools provider — skip tool messages.
      continue;
    }
    messages.push({ role, content: redactText(message.getText()) });
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
export async function generate(ctl: GeneratorController, history: Chat) {
  const globalConfig = ctl.getGlobalPluginConfig(globalConfigSchematics);

  const assistantModel = globalConfig.get("assistantModel").trim();
  if (assistantModel.length === 0) {
    throw new Error(
      "Assistant Model is not configured. Set it in the plugin settings " +
      "(e.g. gpt-4o-mini for OpenAI, openai/gpt-4o-mini for OpenRouter).",
    );
  }

  const apiKey = globalConfig.get("apiKey").trim();
  if (apiKey.length === 0) {
    throw new Error(
      "API Key is not configured. Set it in the plugin's global settings.",
    );
  }

  const baseUrl = globalConfig.get("baseUrl").trim() || DEFAULT_BASE_URL;

  const client = new OpenAI({ apiKey, baseURL: baseUrl });

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
  const unredacted = unredactText(full);

  const unmatched = unredacted.match(PLACEHOLDER_PATTERN);
  if (unmatched !== null) {
    console.info(
      "pii-redact: response still contains placeholders with no known original:",
      [...new Set(unmatched)],
    );
  }

  ctl.fragmentGenerated(unredacted);
}
