import { createConfigSchematics } from "@lmstudio/sdk";

/**
 * Global configuration — shared across all chats, so values persist when
 * starting a new conversation.
 */
export const globalConfigSchematics = createConfigSchematics()
  // -------------------------------------------------------------------------
  // PII detection model
  // -------------------------------------------------------------------------
  .field(
    "piiModel",
    "string",
    {
      displayName: "PII Detection Model",
      subtitle:
        "Model identifier used to detect PII. Leave blank to use the currently loaded model. " +
        "Example: qwen2.5-7b-instruct",
      placeholder: "e.g. qwen2.5-7b-instruct",
    },
    "",
  )
  // -------------------------------------------------------------------------
  // Assistant model (the third-party model that receives the redacted prompt)
  // -------------------------------------------------------------------------
  .field(
    "assistantModel",
    "string",
    {
      displayName: "Assistant Model",
      subtitle:
        "Model ID sent to the OpenAI-compatible endpoint for generating responses. " +
        "Examples: gpt-4o-mini (OpenAI), openai/gpt-4o-mini (OpenRouter).",
      placeholder: "e.g. gpt-4o-mini",
    },
    "",
  )
  // -------------------------------------------------------------------------
  // Confirmation gate
  // -------------------------------------------------------------------------
  .field(
    "skipConfirmation",
    "boolean",
    {
      displayName: "Skip Confirmation",
      subtitle:
        "When enabled, redacted prompts are forwarded immediately without requiring '--c'. " +
        "The redaction preview is still shown in the status panel.",
    },
    false,
  )
  // -------------------------------------------------------------------------
  // API key for the OpenAI-compatible endpoint
  // -------------------------------------------------------------------------
  .field(
    "apiKey",
    "string",
    {
      displayName: "API Key",
      subtitle:
        "API key for the OpenAI-compatible endpoint (e.g. sk-... for OpenAI, " +
        "sk-or-... for OpenRouter). Stored as a protected field.",
      isProtected: true,
      placeholder: "sk-...",
    },
    "",
  )
  // -------------------------------------------------------------------------
  // Base URL of the OpenAI-compatible endpoint
  // -------------------------------------------------------------------------
  .field(
    "baseUrl",
    "string",
    {
      displayName: "Base URL",
      subtitle:
        "Base URL of the OpenAI-compatible endpoint. " +
        "Examples: https://api.openai.com/v1, https://openrouter.ai/api/v1",
      placeholder: "https://api.openai.com/v1",
    },
    "https://api.openai.com/v1",
  )
  .build();
