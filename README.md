# pii-redact

An [LM Studio](https://lmstudio.ai/) plugin that detects and redacts personally identifiable information (PII) before prompts are sent to another LLM, and restores the originals in the model's response.

It uses a dedicated LLM for redaction, ideally running locally or on self-hosted infrastructure, to identify sensitive information and replace it with placeholders. The redacted prompt is sent to another LLM via an OpenAI-compatible API, and the plugin translates the placeholders in the response back to their original values — locally, so the originals never leave your machine.

## Example

The following example demonstrates how PII works when the skip confirmation option is set to true:

```text
              ┌─────────────────────────────────────────────────────────────┐
              │ User                                                        │
              ├─────────────────────────────────────────────────────────────┤
              │ Please generate a response to this email, that the account  │
              │ has been created:                                           │
              │                                                             │
              │ Hi Sally,                                                   │
              │ Could you please add a new user account for                 │
              │ john@our-business.com?                                      │
              │ Thanks,                                                     │
              │ Petra                                                       │
              └─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│ Assistant                                                   │
├─────────────────────────────────────────────────────────────┤
│ ✓ PII redacted successfully — forwarding without            │
│ confirmation. Detected 3 PII entity(ies): • [[[PERSON_1]]]  │
│ ← "Sally" (PERSON) • [[[EMAIL_1]]] ←                        │
│ "john@our-business.com" (EMAIL) • [[[PERSON_2]]] ← "Petra"  │
│ (PERSON)                                                    │
│                                                             │
│ ✓ Done predicting                                           │
│                                                             │
│                                                             │
│ Hi Petra,                                                   │
│                                                             │
│ The new user account for john@our-business.com has been     │
│ created successfully.                                       │
│                                                             │
│ Best,                                                       │
│ Sally                                                       │
└─────────────────────────────────────────────────────────────┘
```

The assistant target model receives this prompt:

```
Please generate a response to this email, that the account has been created:
Hi [[[PERSON_1]]],
Could you please add a new user account for [[[EMAIL_1]]]?
Thanks,
[[[PERSON_2]]]
```

It generates this response:
```
Hi [[[PERSON_2]]],

The new user account for [[[EMAIL_1]]] has been created successfully.

Best,
[[[PERSON_1]]]
```

## How it works

The plugin registers two hooks:

1. **Prompt preprocessor** — detects PII in your message, shows a redaction preview with the entity map, and waits for you to confirm with `--c`. Only the redacted text is ever forwarded.
2. **Generator** — replaces the local model. It re-redacts the entire chat history (earlier turns may still contain originals), sends it to the configured OpenAI-compatible endpoint, buffers the response, and translates the placeholders back to their originals before showing the response to you.

Because the plugin contains a generator, it does not appear in the plugins list. Instead, it appears in the **model dropdown** and acts as a model — select it instead of a regular model, and configure the redaction model and actual target model in the plugin settings.

A few details worth knowing:

- The entity map lives in the plugin's memory for the lifetime of the LM Studio process and is never transmitted. Identifiers stay consistent across turns and conversations (the same original value always maps to the same placeholder).
- The chat history is re-redacted before every API call, so earlier turns' originals are not leaked to the third-party model.
- Responses are buffered in full before un-redaction, so replies appear once complete rather than token by token.
- If PII detection fails after one retry, the request is aborted — the original prompt is never forwarded, so unredacted PII can never reach the third-party model.

## Configuration

Global settings (shared across all chats, so they persist when starting a new conversation):

| Setting | Type | Description |
|---|---|---|
| PII Detection Model | String | The LLM used for PII detection and redaction. Leave blank to use the currently loaded model. |
| Assistant Model | String | The model ID sent to the OpenAI-compatible endpoint, e.g. `gpt-4o-mini` (OpenAI). |
| Skip Confirmation | Boolean | When enabled, redacted prompts are forwarded immediately without requiring `--c`. Default: off. |
| API Key | String (protected) | API key for the OpenAI-compatible endpoint, e.g. `sk-...`. |
| Base URL | String | Base URL of the endpoint. Defaults to `https://api.openai.com/v1`.|

Confirmation is required by default: when PII is detected, the plugin shows the redaction preview and waits for a message containing `--c` before forwarding. Enable **Skip Confirmation** to forward the redacted prompt immediately — the redaction preview is still shown in the status panel, but no review step happens before it is sent.

## Development

```bash
npm install
npm run dev   # starts the LM Studio plugin dev server and rebuilds on changes
npm run build # type-checks and compiles src/ to the repo root
```

## Privacy note

This is a personal project and cannot guarantee complete anonymization. Undetected sensitive information may still reach the third-party target LLM. Use this plugin at your own risk.
